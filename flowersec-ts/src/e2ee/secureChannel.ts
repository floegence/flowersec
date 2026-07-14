import { RECORD_FLAG_APP, RECORD_FLAG_PING, RECORD_FLAG_REKEY } from "./constants.js";
import { decryptRecord, encryptRecord, maxPlaintextBytes } from "./record.js";
import { deriveRekeyKey } from "./kdf.js";

// BinaryTransport is the minimal interface for binary message exchange.
export type ReadBinaryOptions = Readonly<{
  /** Optional AbortSignal to cancel the pending operation. */
  signal?: AbortSignal;
  /** Optional timeout (milliseconds) for the pending operation. */
  timeoutMs?: number;
}>;

export type WriteBinaryOptions = Readonly<{
  /** Optional AbortSignal to cancel the pending operation. */
  signal?: AbortSignal;
}>;

export type BinaryTransport = {
  /** Reads the next binary frame from the underlying transport. */
  readBinary(opts?: ReadBinaryOptions): Promise<Uint8Array>;
  /** Writes a binary frame to the underlying transport. */
  writeBinary(frame: Uint8Array, opts?: WriteBinaryOptions): Promise<void>;
  /** Closes the transport and unblocks pending readers/writers. */
  close(): void;
};

// SecureChannelOptions exposes sizing limits for record processing.
export type SecureChannelOptions = Readonly<{
  /** Maximum encoded record size (header + ciphertext). */
  maxRecordBytes: number;
  /** Preferred plaintext bytes per outbound record. */
  outboundRecordChunkBytes?: number;
  /** Maximum queued inbound plaintext bytes before the channel is closed. */
  maxBufferedBytes?: number;
  /** Maximum queued outbound plaintext bytes (default 4 MiB; 0 uses default). */
  maxOutboundBufferedBytes?: number;
}>;

type Direction = 1 | 2;

type SendKind = "app" | "ping" | "rekey";

const maxRecordSeq = (1n << 64n) - 1n;

class RecordSeqExhaustedError extends Error {
  constructor() {
    super("record seq exhausted");
    this.name = "RecordSeqExhaustedError";
  }
}

type SendReq = {
  /** Outbound frame category (app payload, ping, rekey). */
  kind: SendKind;
  /** Application payload for app frames only. */
  payload?: Uint8Array;
  /** Plaintext bytes retained by this request until its write completes. */
  bufferedBytes: number;
  /** Resolve when the frame is sent or rejected. */
  resolve: () => void;
  /** Reject with transport/crypto errors. */
  reject: (e: unknown) => void;
};

// SecureChannel encrypts/decrypts records and buffers application payloads.
export class SecureChannel {
  // Underlying transport for encrypted record frames.
  private readonly transport: BinaryTransport;
  // Maximum allowed bytes per record frame.
  private readonly maxRecordBytes: number;
  private readonly outboundRecordChunkBytes: number;
  // Upper bound for buffered plaintext in memory.
  private readonly maxBufferedBytes: number;
  private readonly maxOutboundBufferedBytes: number;

  // Active encryption keys and nonce prefixes for the current epoch.
  private sendKey: Uint8Array;
  private recvKey: Uint8Array;
  private sendNoncePrefix: Uint8Array;
  private recvNoncePrefix: Uint8Array;
  // Rekey base secret derived from the handshake.
  private readonly rekeyBase: Uint8Array;
  // Transcript hash binding rekeys to the handshake.
  private readonly transcriptHash: Uint8Array;
  // Rekey direction identifiers for send/recv.
  private readonly sendDir: Direction;
  private readonly recvDir: Direction;

  // Monotonic record sequence numbers per direction.
  private sendSeq: bigint;
  private recvSeq: bigint;

  // Send queue and waiters for backpressure.
  private sendQueue: SendReq[] = [];
  private sendQueueHead = 0;
  private sendWaiters: Array<() => void> = [];
  private sendWaitersHead = 0;
  private sendQueueBytes = 0;
  private sendClosed = false;
  private sendErr: unknown = null;

  // Receive queue and waiters for plaintext delivery.
  private readonly recvQueue: Uint8Array[] = [];
  private recvQueueHead = 0;
  private recvQueueBytes = 0;
  private recvWaiters: Array<() => void> = [];
  private readErr: unknown = null;
  private closed = false;

  constructor(args: {
    transport: BinaryTransport;
    maxRecordBytes: number;
    outboundRecordChunkBytes?: number;
    maxBufferedBytes?: number;
    maxOutboundBufferedBytes?: number;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
    sendNoncePrefix: Uint8Array;
    recvNoncePrefix: Uint8Array;
    rekeyBase: Uint8Array;
    transcriptHash: Uint8Array;
    sendDir: Direction;
    recvDir: Direction;
    sendSeq?: bigint;
    recvSeq?: bigint;
  }) {
    this.transport = args.transport;
    this.maxRecordBytes = args.maxRecordBytes;
    const maxPlain = Math.max(1, maxPlaintextBytes(this.maxRecordBytes));
    this.outboundRecordChunkBytes = args.outboundRecordChunkBytes ?? Math.min(64 * 1024, maxPlain);
    if (!Number.isSafeInteger(this.outboundRecordChunkBytes) || this.outboundRecordChunkBytes <= 0 || this.outboundRecordChunkBytes > maxPlain) {
      throw new RangeError("outboundRecordChunkBytes must be a positive integer within the record plaintext limit");
    }
    this.maxBufferedBytes = Math.max(0, args.maxBufferedBytes ?? 4 * (1 << 20));
    const maxOutboundBufferedBytes = args.maxOutboundBufferedBytes ?? 4 * (1 << 20);
    if (!Number.isSafeInteger(maxOutboundBufferedBytes) || maxOutboundBufferedBytes < 0) {
      throw new RangeError("maxOutboundBufferedBytes must be a non-negative safe integer");
    }
    this.maxOutboundBufferedBytes = maxOutboundBufferedBytes === 0 ? 4 * (1 << 20) : maxOutboundBufferedBytes;
    this.sendKey = args.sendKey;
    this.recvKey = args.recvKey;
    this.sendNoncePrefix = args.sendNoncePrefix;
    this.recvNoncePrefix = args.recvNoncePrefix;
    this.rekeyBase = args.rekeyBase;
    this.transcriptHash = args.transcriptHash;
    this.sendDir = args.sendDir;
    this.recvDir = args.recvDir;
    this.sendSeq = args.sendSeq ?? 1n;
    this.recvSeq = args.recvSeq ?? 1n;
    void this.readLoop();
    void this.sendLoop();
  }

  // write splits payloads into record-sized chunks and queues them for send.
  async write(plaintext: Uint8Array): Promise<void> {
    if (plaintext.length === 0) return;
    await this.enqueueSend("app", plaintext);
  }

  // read resolves with the next plaintext chunk or throws on errors/close.
  async read(): Promise<Uint8Array> {
    while (true) {
      if (this.recvQueueHead < this.recvQueue.length) {
        const b = this.recvQueue[this.recvQueueHead]!;
        this.recvQueueHead++;
        if (this.recvQueueHead > 1024 && this.recvQueueHead * 2 > this.recvQueue.length) {
          this.recvQueue.splice(0, this.recvQueueHead);
          this.recvQueueHead = 0;
        }
        this.recvQueueBytes -= b.length;
        return b;
      }
      if (this.readErr != null) throw this.readErr;
      if (this.closed) throw new Error("closed");
      await new Promise<void>((resolve) => this.recvWaiters.push(resolve));
    }
  }

  // close shuts down the transport and rejects any pending senders.
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.sendClosed = true;
    this.rejectQueuedSenders(this.sendErr ?? new Error("closed"));
    this.wakeSendWaiters();
    this.transport.close();
    const ws = this.recvWaiters;
    this.recvWaiters = [];
    for (const w of ws) w();
  }

  // sendPing emits a keepalive record.
  async sendPing(): Promise<void> {
    await this.enqueueSend("ping");
  }

  // rekeyNow emits a rekey record and advances the send key.
  async rekeyNow(): Promise<void> {
    await this.enqueueSend("rekey");
  }

  private enqueueSend(kind: SendKind, payload?: Uint8Array): Promise<void> {
    if (this.sendErr != null) return Promise.reject(this.sendErr);
    if (this.closed || this.sendClosed) return Promise.reject(new Error("closed"));
    const bufferedBytes = payload?.byteLength ?? 0;
    if (this.sendQueueBytes + bufferedBytes > this.maxOutboundBufferedBytes) {
      return Promise.reject(new Error("secure channel outbound buffer exceeded"));
    }
    return new Promise<void>((resolve, reject) => {
      if (this.sendErr != null) {
        reject(this.sendErr);
        return;
      }
      if (this.closed || this.sendClosed) {
        reject(new Error("closed"));
        return;
      }
      if (this.sendQueueBytes + bufferedBytes > this.maxOutboundBufferedBytes) {
        reject(new Error("secure channel outbound buffer exceeded"));
        return;
      }
      const retainedPayload = payload?.slice();
      const req: SendReq = retainedPayload === undefined
        ? { kind, bufferedBytes, resolve, reject }
        : { kind, payload: retainedPayload, bufferedBytes, resolve, reject };
      this.sendQueueBytes += bufferedBytes;
      this.sendQueue.push(req);
      const w = this.shiftSendWaiter();
      if (w != null) w();
    });
  }

  private async nextSend(): Promise<SendReq | null> {
    const immediate = this.dequeueSend();
    if (immediate != null) return immediate;
    if (this.closed || this.sendClosed) return null;
    return await new Promise<SendReq | null>((resolve) => {
      this.sendWaiters.push(() => resolve(this.dequeueSend()));
    });
  }

  private dequeueSend(): SendReq | null {
    if (this.sendQueueHead >= this.sendQueue.length) return null;
    const req = this.sendQueue[this.sendQueueHead]!;
    this.sendQueueHead++;
    if (this.sendQueueHead > 1024 && this.sendQueueHead * 2 > this.sendQueue.length) {
      this.sendQueue.splice(0, this.sendQueueHead);
      this.sendQueueHead = 0;
    }
    return req;
  }

  private shiftSendWaiter(): (() => void) | undefined {
    if (this.sendWaitersHead >= this.sendWaiters.length) return undefined;
    const w = this.sendWaiters[this.sendWaitersHead];
    this.sendWaitersHead++;
    if (this.sendWaitersHead > 1024 && this.sendWaitersHead * 2 > this.sendWaiters.length) {
      this.sendWaiters.splice(0, this.sendWaitersHead);
      this.sendWaitersHead = 0;
    }
    return w;
  }

  private wakeSendWaiters(): void {
    const ws = this.sendWaiters;
    const start = this.sendWaitersHead;
    this.sendWaiters = [];
    this.sendWaitersHead = 0;
    for (let i = start; i < ws.length; i++) ws[i]!();
  }

  private rejectQueuedSenders(err: unknown): void {
    const queued = this.sendQueue;
    const start = this.sendQueueHead;
    this.sendQueue = [];
    this.sendQueueHead = 0;
    for (let i = start; i < queued.length; i++) {
      const req = queued[i]!;
      this.sendQueueBytes = Math.max(0, this.sendQueueBytes - req.bufferedBytes);
      req.reject(err);
    }
  }

  private failSend(err: unknown): void {
    if (this.sendErr != null) return;
    this.sendErr = err;
    this.rejectQueuedSenders(err);
    this.wakeSendWaiters();
  }

  private reserveSendSeq(): bigint {
    if (this.sendSeq >= maxRecordSeq) {
      const err = new RecordSeqExhaustedError();
      this.failSend(err);
      throw err;
    }
    const seq = this.sendSeq;
    this.sendSeq++;
    return seq;
  }

  private async sendLoop(): Promise<void> {
    while (true) {
      const req = await this.nextSend();
      if (req == null) return;
      try {
        if (this.sendErr != null) {
          req.reject(this.sendErr);
          continue;
        }
        if (this.closed || this.sendClosed) {
          req.reject(new Error("closed"));
          continue;
        }
        let frame: Uint8Array;
        if (req.kind === "app") {
          const payload = req.payload ?? new Uint8Array();
          for (let offset = 0; offset < payload.length; offset += this.outboundRecordChunkBytes) {
            const chunk = payload.subarray(offset, Math.min(payload.length, offset + this.outboundRecordChunkBytes));
            const seq = this.reserveSendSeq();
            frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_APP, seq, chunk, this.maxRecordBytes);
            await this.transport.writeBinary(frame);
          }
          req.resolve();
          continue;
        } else if (req.kind === "ping") {
          const seq = this.reserveSendSeq();
          frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_PING, seq, new Uint8Array(), this.maxRecordBytes);
        } else {
          const seq = this.reserveSendSeq();
          frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_REKEY, seq, new Uint8Array(), this.maxRecordBytes);
          // Update the send key after enqueuing the rekey frame.
          this.sendKey = deriveRekeyKey(this.rekeyBase, this.transcriptHash, seq, this.sendDir);
        }
        await this.transport.writeBinary(frame);
        req.resolve();
      } catch (e) {
        req.reject(e);
        this.failSend(e);
        this.close();
        return;
      } finally {
        this.sendQueueBytes = Math.max(0, this.sendQueueBytes - req.bufferedBytes);
      }
    }
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const frame = await this.transport.readBinary();
        const { flags, seq, plaintext } = decryptRecord(
          this.recvKey,
          this.recvNoncePrefix,
          frame,
          this.recvSeq,
          this.maxRecordBytes
        );
        if (seq >= maxRecordSeq) {
          throw new RecordSeqExhaustedError();
        }
        this.recvSeq = seq + 1n;
        if (flags === RECORD_FLAG_APP) {
          if (this.maxBufferedBytes > 0 && this.recvQueueBytes + plaintext.length > this.maxBufferedBytes) {
            throw new Error("recv buffer exceeded");
          }
          this.recvQueue.push(plaintext);
          this.recvQueueBytes += plaintext.length;
          const ws = this.recvWaiters;
          this.recvWaiters = [];
          for (const w of ws) w();
          continue;
        }
        if (flags === RECORD_FLAG_PING) continue;
        if (flags === RECORD_FLAG_REKEY) {
          this.recvKey = deriveRekeyKey(this.rekeyBase, this.transcriptHash, seq, this.recvDir);
          continue;
        }
        throw new Error(`unknown record flag ${flags}`);
      }
    } catch (e) {
      this.readErr = e;
      const ws = this.recvWaiters;
      this.recvWaiters = [];
      for (const w of ws) w();
      this.close();
    }
  }
}

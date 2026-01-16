import { RECORD_FLAG_APP, RECORD_FLAG_PING, RECORD_FLAG_REKEY } from "./constants.js";
import { decryptRecord, encryptRecord, maxPlaintextBytes } from "./record.js";
import { deriveRekeyKey } from "./kdf.js";

// BinaryTransport is the minimal interface for binary message exchange.
export type BinaryTransport = {
  /** Reads the next binary frame from the underlying transport. */
  readBinary(): Promise<Uint8Array>;
  /** Writes a binary frame to the underlying transport. */
  writeBinary(frame: Uint8Array): Promise<void>;
  /** Closes the transport and unblocks pending readers/writers. */
  close(): void;
};

// SecureChannelOptions exposes sizing limits for record processing.
export type SecureChannelOptions = Readonly<{
  /** Maximum encoded record size (header + ciphertext). */
  maxRecordBytes: number;
  /** Maximum queued plaintext bytes before backpressure/errors. */
  maxBufferedBytes?: number;
}>;

type Direction = 1 | 2;

type SendKind = "app" | "ping" | "rekey";

type SendReq = {
  /** Outbound frame category (app payload, ping, rekey). */
  kind: SendKind;
  /** Application payload for app frames only. */
  payload?: Uint8Array;
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
  // Upper bound for buffered plaintext in memory.
  private readonly maxBufferedBytes: number;

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
  private sendSeq = 1n;
  private recvSeq = 1n;

  // Send queue and waiters for backpressure.
  private sendQueue: SendReq[] = [];
  private sendWaiters: Array<() => void> = [];
  private sendClosed = false;
  private sendErr: unknown = null;

  // Receive queue and waiters for plaintext delivery.
  private readonly recvQueue: Uint8Array[] = [];
  private recvQueueBytes = 0;
  private recvWaiters: Array<() => void> = [];
  private readErr: unknown = null;
  private closed = false;

  constructor(args: {
    transport: BinaryTransport;
    maxRecordBytes: number;
    maxBufferedBytes?: number;
    sendKey: Uint8Array;
    recvKey: Uint8Array;
    sendNoncePrefix: Uint8Array;
    recvNoncePrefix: Uint8Array;
    rekeyBase: Uint8Array;
    transcriptHash: Uint8Array;
    sendDir: Direction;
    recvDir: Direction;
  }) {
    this.transport = args.transport;
    this.maxRecordBytes = args.maxRecordBytes;
    this.maxBufferedBytes = Math.max(0, args.maxBufferedBytes ?? 4 * (1 << 20));
    this.sendKey = args.sendKey;
    this.recvKey = args.recvKey;
    this.sendNoncePrefix = args.sendNoncePrefix;
    this.recvNoncePrefix = args.recvNoncePrefix;
    this.rekeyBase = args.rekeyBase;
    this.transcriptHash = args.transcriptHash;
    this.sendDir = args.sendDir;
    this.recvDir = args.recvDir;
    void this.readLoop();
    void this.sendLoop();
  }

  // write splits payloads into record-sized chunks and queues them for send.
  async write(plaintext: Uint8Array): Promise<void> {
    const maxPlain = Math.max(1, maxPlaintextBytes(this.maxRecordBytes) || plaintext.length);
    let off = 0;
    while (off < plaintext.length) {
      const chunk = plaintext.slice(off, Math.min(plaintext.length, off + maxPlain));
      await this.enqueueSend("app", chunk);
      off += chunk.length;
    }
  }

  // read resolves with the next plaintext chunk or throws on errors/close.
  async read(): Promise<Uint8Array> {
    while (true) {
      if (this.readErr != null) throw this.readErr;
      if (this.recvQueue.length > 0) {
        const b = this.recvQueue.shift()!;
        this.recvQueueBytes -= b.length;
        return b;
      }
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
    return new Promise<void>((resolve, reject) => {
      if (this.sendErr != null) {
        reject(this.sendErr);
        return;
      }
      if (this.closed || this.sendClosed) {
        reject(new Error("closed"));
        return;
      }
      const req: SendReq = payload === undefined ? { kind, resolve, reject } : { kind, payload, resolve, reject };
      this.sendQueue.push(req);
      const w = this.sendWaiters.shift();
      if (w != null) w();
    });
  }

  private async nextSend(): Promise<SendReq | null> {
    if (this.sendQueue.length > 0) return this.sendQueue.shift() ?? null;
    if (this.closed || this.sendClosed) return null;
    return await new Promise<SendReq | null>((resolve) => {
      this.sendWaiters.push(() => resolve(this.sendQueue.shift() ?? null));
    });
  }

  private wakeSendWaiters(): void {
    const ws = this.sendWaiters;
    this.sendWaiters = [];
    for (const w of ws) w();
  }

  private rejectQueuedSenders(err: unknown): void {
    const queued = this.sendQueue;
    this.sendQueue = [];
    for (const req of queued) req.reject(err);
  }

  private failSend(err: unknown): void {
    if (this.sendErr != null) return;
    this.sendErr = err;
    this.rejectQueuedSenders(err);
    this.wakeSendWaiters();
  }

  private async sendLoop(): Promise<void> {
    while (true) {
      const req = await this.nextSend();
      if (req == null) return;
      if (this.sendErr != null) {
        req.reject(this.sendErr);
        continue;
      }
      if (this.closed || this.sendClosed) {
        req.reject(new Error("closed"));
        continue;
      }
      try {
        let frame: Uint8Array;
        if (req.kind === "app") {
          const seq = this.sendSeq++;
          frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_APP, seq, req.payload ?? new Uint8Array(), this.maxRecordBytes);
        } else if (req.kind === "ping") {
          const seq = this.sendSeq++;
          frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_PING, seq, new Uint8Array(), this.maxRecordBytes);
        } else {
          const seq = this.sendSeq++;
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

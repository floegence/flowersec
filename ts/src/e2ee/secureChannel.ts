import { RECORD_FLAG_APP, RECORD_FLAG_PING, RECORD_FLAG_REKEY } from "./constants.js";
import { decryptRecord, encryptRecord, maxPlaintextBytes } from "./record.js";
import { deriveRekeyKey } from "./kdf.js";

export type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

export type SecureChannelOptions = Readonly<{
  maxRecordBytes: number;
  maxBufferedBytes?: number;
}>;

type Direction = 1 | 2;

export class SecureChannel {
  private readonly transport: BinaryTransport;
  private readonly maxRecordBytes: number;
  private readonly maxBufferedBytes: number;

  private sendKey: Uint8Array;
  private recvKey: Uint8Array;
  private sendNoncePrefix: Uint8Array;
  private recvNoncePrefix: Uint8Array;
  private readonly rekeyBase: Uint8Array;
  private readonly transcriptHash: Uint8Array;
  private readonly sendDir: Direction;
  private readonly recvDir: Direction;

  private sendSeq = 1n;
  private recvSeq = 1n;

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
  }

  async write(plaintext: Uint8Array): Promise<void> {
    const maxPlain = Math.max(1, maxPlaintextBytes(this.maxRecordBytes) || plaintext.length);
    let off = 0;
    while (off < plaintext.length) {
      const chunk = plaintext.slice(off, Math.min(plaintext.length, off + maxPlain));
      const seq = this.sendSeq++;
      const frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_APP, seq, chunk, this.maxRecordBytes);
      await this.transport.writeBinary(frame);
      off += chunk.length;
    }
  }

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

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.transport.close();
    const ws = this.recvWaiters;
    this.recvWaiters = [];
    for (const w of ws) w();
  }

  async sendPing(): Promise<void> {
    const seq = this.sendSeq++;
    const frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_PING, seq, new Uint8Array(), this.maxRecordBytes);
    await this.transport.writeBinary(frame);
  }

  async rekeyNow(): Promise<void> {
    const seq = this.sendSeq++;
    const frame = encryptRecord(this.sendKey, this.sendNoncePrefix, RECORD_FLAG_REKEY, seq, new Uint8Array(), this.maxRecordBytes);
    await this.transport.writeBinary(frame);
    this.sendKey = deriveRekeyKey(this.rekeyBase, this.transcriptHash, seq, this.sendDir);
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

import { ByteReader } from "./byteReader.js";
import { decodeHeader, encodeHeader, HEADER_LEN } from "./header.js";
import {
  DEFAULT_MAX_STREAM_WINDOW,
  FLAG_ACK,
  FLAG_RST,
  FLAG_SYN,
  TYPE_DATA,
  TYPE_GO_AWAY,
  TYPE_PING,
  TYPE_WINDOW_UPDATE,
  YAMUX_VERSION
} from "./constants.js";
import { YamuxStream } from "./stream.js";

export type ByteDuplex = {
  read(): Promise<Uint8Array>;
  write(chunk: Uint8Array): Promise<void>;
  close(): void;
};

export type YamuxSessionOptions = Readonly<{
  client: boolean;
  onIncomingStream?: (s: YamuxStream) => void;
  maxFrameBytes?: number;
}>;

export class YamuxSession {
  private readonly conn: ByteDuplex;
  private readonly reader: ByteReader;
  private readonly streams = new Map<number, YamuxStream>();
  private readonly onIncomingStream: ((s: YamuxStream) => void) | undefined;
  private readonly maxFrameBytes: number;

  private nextStreamId: number;
  private closed = false;
  private readonly sendWindowWaiters = new Map<number, Array<() => void>>();

  constructor(conn: ByteDuplex, opts: YamuxSessionOptions) {
    this.conn = conn;
    this.reader = new ByteReader(async () => {
      try {
        return await this.conn.read();
      } catch {
        return null;
      }
    });
    this.onIncomingStream = opts.onIncomingStream;
    this.maxFrameBytes = Math.max(0, opts.maxFrameBytes ?? DEFAULT_MAX_STREAM_WINDOW);
    this.nextStreamId = opts.client ? 1 : 2;
    void this.readLoop();
  }

  async openStream(): Promise<YamuxStream> {
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    const s = new YamuxStream(this, id, "init");
    this.streams.set(id, s);
    await s.open();
    return s;
  }

  getStream(id: number): YamuxStream | undefined {
    return this.streams.get(id);
  }

  async writeRaw(chunk: Uint8Array): Promise<void> {
    await this.conn.write(chunk);
  }

  async sendRst(id: number): Promise<void> {
    const hdr = encodeHeader({ type: TYPE_WINDOW_UPDATE, flags: FLAG_RST, streamId: id, length: 0 });
    if (this.closed) {
      this.streams.delete(id);
      return;
    }
    try {
      await this.writeRaw(hdr);
    } catch {
      // Best-effort reset; ignore errors when the session is closing.
    }
    this.streams.delete(id);
  }

  notifySendWindow(streamId: number): void {
    const ws = this.sendWindowWaiters.get(streamId);
    if (ws == null) return;
    this.sendWindowWaiters.delete(streamId);
    for (const w of ws) w();
  }

  waitForSendWindow(streamId: number): Promise<void> {
    if (this.closed) return Promise.reject(new Error("session closed"));
    return new Promise<void>((resolve, reject) => {
      if (this.closed) {
        reject(new Error("session closed"));
        return;
      }
      const ws = this.sendWindowWaiters.get(streamId) ?? [];
      ws.push(() => {
        if (this.closed) {
          reject(new Error("session closed"));
          return;
        }
        resolve();
      });
      this.sendWindowWaiters.set(streamId, ws);
    });
  }

  onStreamEstablished(_streamId: number): void {}

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.conn.close();
    this.wakeSendWindowWaiters();
    for (const s of this.streams.values()) s.reset(new Error("session closed"));
    this.streams.clear();
  }

  private wakeSendWindowWaiters(): void {
    for (const [streamId, ws] of this.sendWindowWaiters) {
      this.sendWindowWaiters.delete(streamId);
      for (const w of ws) w();
    }
  }

  private async readLoop(): Promise<void> {
    try {
      while (!this.closed) {
        const hdrBytes = await this.reader.readExactly(HEADER_LEN);
        const h = decodeHeader(hdrBytes, 0);
        if (h.version !== YAMUX_VERSION) {
          this.close();
          return;
        }
        if (h.type === TYPE_DATA) {
          if (this.maxFrameBytes > 0 && h.length > this.maxFrameBytes) {
            this.close();
            return;
          }
          const data = h.length > 0 ? await this.reader.readExactly(h.length) : new Uint8Array();
          await this.handleDataFrame(h.streamId, h.flags, data);
          continue;
        }
        if (h.type === TYPE_WINDOW_UPDATE) {
          await this.handleWindowUpdateFrame(h.streamId, h.flags, h.length);
          continue;
        }
        if (h.type === TYPE_PING) {
          await this.handlePing(h.flags, h.length);
          continue;
        }
        if (h.type === TYPE_GO_AWAY) {
          this.close();
          return;
        }
        this.close();
        return;
      }
    } catch {
      this.close();
    }
  }

  private async handlePing(flags: number, opaque: number): Promise<void> {
    if ((flags & FLAG_SYN) !== 0) {
      const hdr = encodeHeader({ type: TYPE_PING, flags: FLAG_ACK, streamId: 0, length: opaque >>> 0 });
      await this.writeRaw(hdr);
      return;
    }
  }

  private async handleDataFrame(streamId: number, flags: number, data: Uint8Array): Promise<void> {
    if (streamId === 0) {
      this.close();
      return;
    }
    let s = this.streams.get(streamId);
    if (s == null) {
      if ((flags & FLAG_SYN) !== 0) {
        s = new YamuxStream(this, streamId, "synReceived");
        this.streams.set(streamId, s);
        await s.open();
        this.onIncomingStream?.(s);
      } else {
        await this.sendRst(streamId);
        return;
      }
    }
    s.onData(data, flags);
  }

  private async handleWindowUpdateFrame(streamId: number, flags: number, delta: number): Promise<void> {
    if (streamId === 0) {
      this.close();
      return;
    }
    let s = this.streams.get(streamId);
    if (s == null) {
      if ((flags & FLAG_SYN) !== 0) {
        s = new YamuxStream(this, streamId, "synReceived");
        this.streams.set(streamId, s);
        await s.open();
        this.onIncomingStream?.(s);
      } else {
        await this.sendRst(streamId);
        return;
      }
    }
    s.onWindowUpdate(delta, flags);
  }
}

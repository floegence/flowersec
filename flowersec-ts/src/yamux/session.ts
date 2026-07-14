import { ByteReader } from "./byteReader.js";
import { decodeHeader, encodeHeader, HEADER_LEN } from "./header.js";
import {
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
import { YamuxResourceExhaustedError } from "./errors.js";

export type YamuxDiagnostic = Readonly<{
  code: "stream_rejected" | "resource_limit_reached";
  resource: string;
  current: number;
  limit: number;
}>;

export type YamuxLimits = Readonly<{
  maxActiveStreams: number;
  maxInboundStreams: number;
  maxFrameBytes: number;
  preferredOutboundFrameBytes: number;
  maxStreamReceiveBytes: number;
  maxSessionReceiveBytes: number;
}>;

export const DEFAULT_YAMUX_LIMITS: YamuxLimits = Object.freeze({
  maxActiveStreams: 64,
  maxInboundStreams: 32,
  maxFrameBytes: 256 * 1024,
  preferredOutboundFrameBytes: 64 * 1024,
  maxStreamReceiveBytes: 256 * 1024,
  maxSessionReceiveBytes: 16 * (1 << 20),
});

// ByteDuplex is a minimal async read/write/close abstraction.
export type ByteDuplex = {
  /** Reads the next chunk from the underlying connection. */
  read(): Promise<Uint8Array>;
  /** Writes a chunk to the underlying connection. */
  write(chunk: Uint8Array): Promise<void>;
  /** Closes the underlying connection. */
  close(): void;
};

// YamuxSessionOptions configures client/server IDs and limits.
export type YamuxSessionOptions = Readonly<{
  /** True when acting as the client side (odd stream IDs). */
  client: boolean;
  /** Optional callback for newly accepted inbound streams. */
  onIncomingStream?: (s: YamuxStream) => void;
  /** Maximum frame payload bytes accepted per stream frame. */
  maxFrameBytes?: number;
  /** Generic stream and receive-memory limits. */
  limits?: Partial<YamuxLimits>;
  /** Optional generic resource diagnostic callback. */
  onDiagnostic?: (event: YamuxDiagnostic) => void;
  /** Internal lifecycle callback for unexpected session termination. */
  onTerminal?: (error: Error) => void;
}>;

// YamuxSession multiplexes multiple streams over a single byte stream.
export class YamuxSession {
  // Underlying byte stream for yamux frames.
  private readonly conn: ByteDuplex;
  // Reader for fixed-length header/body reads.
  private readonly reader: ByteReader;
  // Active streams keyed by stream ID.
  private readonly streams = new Map<number, YamuxStream>();
  // Callback for inbound streams created from SYN frames.
  private readonly onIncomingStream: ((s: YamuxStream) => void) | undefined;
  // Maximum allowed DATA frame length.
  private readonly limits: YamuxLimits;
  private readonly onDiagnostic: ((event: YamuxDiagnostic) => void) | undefined;
  private readonly onTerminal: ((error: Error) => void) | undefined;

  // True when this side is the yamux client (odd local stream IDs).
  private readonly client: boolean;

  // Next stream ID to allocate (odd/even based on role).
  private nextStreamId: number;
  // Closed flag for terminating read loops and streams.
  private closed = false;
  // Writers waiting for send window credits per stream.
  private readonly sendWindowWaiters = new Map<number, Array<() => void>>();
  private readonly inboundStreams = new Set<number>();
  private sessionReceiveBytes = 0;
  private nextPingId = 1;
  private readonly pingWaiters = new Map<number, { startedAt: number; resolve: (rttMs: number) => void; reject: (e: unknown) => void; timer: ReturnType<typeof setTimeout> }>();
  private activeProbe: Promise<number> | undefined;

  constructor(conn: ByteDuplex, opts: YamuxSessionOptions) {
    this.conn = conn;
    this.reader = new ByteReader(() => this.conn.read());
    this.onIncomingStream = opts.onIncomingStream;
    this.limits = normalizeYamuxLimits({ ...opts.limits, ...(opts.maxFrameBytes === undefined ? {} : { maxFrameBytes: opts.maxFrameBytes }) });
    this.onDiagnostic = opts.onDiagnostic;
    this.onTerminal = opts.onTerminal;
    this.client = opts.client;
    this.nextStreamId = opts.client ? 1 : 2;
    void this.readLoop();
  }

  // openStream allocates a new stream and performs the SYN handshake.
  async openStream(opts: Readonly<{ signal?: AbortSignal }> = {}): Promise<YamuxStream> {
    if (this.closed) throw new Error("session closed");
    if (opts.signal?.aborted) throw abortError(opts.signal);
    if (this.streams.size >= this.limits.maxActiveStreams) {
      const error = new YamuxResourceExhaustedError("active_streams", this.streams.size, this.limits.maxActiveStreams);
      this.diagnostic({ code: "resource_limit_reached", resource: error.resource, current: error.current, limit: error.limit });
      throw error;
    }
    const id = this.nextStreamId;
    this.nextStreamId += 2;
    const s = new YamuxStream(this, id, "init");
    this.streams.set(id, s);
    try {
      await raceAbort(s.open(), opts.signal, () => {
        void s.reset(abortError(opts.signal!));
      });
      return s;
    } catch (error) {
      this.onStreamClosed(id);
      throw error;
    }
  }

  // getStream returns the stream for an ID, if any.
  getStream(id: number): YamuxStream | undefined {
    return this.streams.get(id);
  }

  // writeRaw writes a raw yamux frame to the underlying connection.
  async writeRaw(chunk: Uint8Array): Promise<void> {
    try {
      await this.conn.write(chunk);
    } catch (error) {
      this.fail(error);
      throw error;
    }
  }

  outboundFrameBytes(): number {
    return this.limits.preferredOutboundFrameBytes;
  }

  releaseReceiveBytes(bytes: number): void {
    this.sessionReceiveBytes = Math.max(0, this.sessionReceiveBytes - Math.max(0, bytes));
  }

  // probeLiveness performs a correlated yamux PING SYN/ACK round trip.
  async probeLiveness(timeoutMs = 10_000): Promise<number> {
    if (this.activeProbe != null) return await this.activeProbe;
    const probe = this.startLivenessProbe(timeoutMs);
    this.activeProbe = probe;
    try {
      return await probe;
    } finally {
      if (this.activeProbe === probe) this.activeProbe = undefined;
    }
  }

  private async startLivenessProbe(timeoutMs: number): Promise<number> {
    if (this.closed) throw new Error("session closed");
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RangeError("timeoutMs must be positive");
    let opaque = this.nextPingId >>> 0;
    do {
      opaque = this.nextPingId++ >>> 0;
      if (this.nextPingId > 0xffffffff) this.nextPingId = 1;
    } while (opaque === 0 || this.pingWaiters.has(opaque));
    const startedAt = monotonicMilliseconds();
    return await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pingWaiters.delete(opaque);
        const error = new Error("yamux ping timeout");
        reject(error);
        this.fail(error);
      }, timeoutMs);
      (timer as any)?.unref?.();
      this.pingWaiters.set(opaque, { startedAt, resolve, reject, timer });
      const hdr = encodeHeader({ type: TYPE_PING, flags: FLAG_SYN, streamId: 0, length: opaque });
      void this.writeRaw(hdr).catch((err) => {
        const waiter = this.pingWaiters.get(opaque);
        if (waiter == null) return;
        this.pingWaiters.delete(opaque);
        clearTimeout(waiter.timer);
        reject(err);
        this.fail(err);
      });
    });
  }

  // sendRst sends a reset frame and removes the stream.
  async sendRst(id: number): Promise<void> {
    const hdr = encodeHeader({ type: TYPE_WINDOW_UPDATE, flags: FLAG_RST, streamId: id, length: 0 });
    this.onStreamClosed(id);
    if (this.closed) {
      return;
    }
    try {
      await this.writeRaw(hdr);
    } catch {
      // Best-effort reset; ignore errors when the session is closing.
    }
  }

  // notifySendWindow wakes any writers waiting on window credit.
  notifySendWindow(streamId: number): void {
    const ws = this.sendWindowWaiters.get(streamId);
    if (ws == null) return;
    this.sendWindowWaiters.delete(streamId);
    for (const w of ws) w();
  }

  // waitForSendWindow blocks until send window credits are available.
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

  // onStreamClosed removes the stream and wakes any per-stream waiters.
  onStreamClosed(streamId: number): void {
    const stream = this.streams.get(streamId);
    if (stream != null) this.releaseReceiveBytes(stream.releaseBufferedReceiveBytes());
    this.streams.delete(streamId);
    this.inboundStreams.delete(streamId);
    this.notifySendWindow(streamId);
  }

  // close terminates the session and resets all streams.
  close(): void {
    this.closeInternal();
  }

  private fail(error: unknown): void {
    if (this.closed) return;
    const terminalError = error instanceof Error ? error : new Error(String(error));
    this.closeInternal();
    try {
      this.onTerminal?.(terminalError);
    } catch {
      // Lifecycle callbacks must not affect session shutdown.
    }
  }

  private closeInternal(): void {
    if (this.closed) return;
    this.closed = true;
    this.conn.close();
    this.wakeSendWindowWaiters();
    for (const waiter of this.pingWaiters.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error("session closed"));
    }
    this.pingWaiters.clear();
    const streams = Array.from(this.streams.values());
    this.streams.clear();
    for (const s of streams) s.reset(new Error("session closed"));
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
          this.fail(new Error("unsupported yamux version"));
          return;
        }
        if (h.type === TYPE_DATA) {
          if (h.length > this.limits.maxFrameBytes) {
            this.fail(new Error("yamux frame exceeds limit"));
            return;
          }
          if (h.streamId === 0) {
            this.fail(new Error("yamux data frame has stream id zero"));
            return;
          }
          const existing = this.streams.get(h.streamId);
          if (existing == null) {
            const inboundAllowed = (h.flags & FLAG_SYN) !== 0 && this.isInboundStreamIdValid(h.streamId);
            const resourceAllowed = this.streams.size < this.limits.maxActiveStreams && this.inboundStreams.size < this.limits.maxInboundStreams;
            if (!inboundAllowed || !resourceAllowed || h.length > this.limits.maxStreamReceiveBytes) {
              await this.reader.discardExactly(h.length);
              this.diagnostic({
                code: "stream_rejected",
                resource: !resourceAllowed ? "inbound_streams" : "stream_receive_bytes",
                current: !resourceAllowed ? this.inboundStreams.size : h.length,
                limit: !resourceAllowed ? this.limits.maxInboundStreams : this.limits.maxStreamReceiveBytes,
              });
              await this.sendRst(h.streamId);
              continue;
            }
          }
          if (existing != null && existing.bufferedReceiveBytes() + h.length > this.limits.maxStreamReceiveBytes) {
            await this.reader.discardExactly(h.length);
            this.diagnostic({ code: "resource_limit_reached", resource: "stream_receive_bytes", current: existing.bufferedReceiveBytes() + h.length, limit: this.limits.maxStreamReceiveBytes });
            await this.sendRst(h.streamId);
            continue;
          }
          if (this.sessionReceiveBytes + h.length > this.limits.maxSessionReceiveBytes) {
            this.diagnostic({ code: "resource_limit_reached", resource: "session_receive_bytes", current: this.sessionReceiveBytes + h.length, limit: this.limits.maxSessionReceiveBytes });
            this.fail(new Error("yamux session receive limit reached"));
            return;
          }
          const data = h.length > 0 ? await this.reader.readExactly(h.length) : new Uint8Array();
          if (data.length > 0) this.sessionReceiveBytes += data.length;
          const accepted = await this.handleDataFrame(h.streamId, h.flags, data);
          if (!accepted) this.releaseReceiveBytes(data.length);
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
          this.fail(new Error("yamux peer sent go away"));
          return;
        }
        this.fail(new Error("unsupported yamux frame type"));
        return;
      }
    } catch (error) {
      this.fail(error);
    }
  }

  private async handlePing(flags: number, opaque: number): Promise<void> {
    if ((flags & FLAG_SYN) !== 0) {
      const hdr = encodeHeader({ type: TYPE_PING, flags: FLAG_ACK, streamId: 0, length: opaque >>> 0 });
      await this.writeRaw(hdr);
      return;
    }
    if ((flags & FLAG_ACK) !== 0) {
      const waiter = this.pingWaiters.get(opaque >>> 0);
      if (waiter == null) return;
      this.pingWaiters.delete(opaque >>> 0);
      clearTimeout(waiter.timer);
      waiter.resolve(Math.max(0, monotonicMilliseconds() - waiter.startedAt));
    }
  }

  private async handleDataFrame(streamId: number, flags: number, data: Uint8Array): Promise<boolean> {
    if (streamId === 0) {
      this.fail(new Error("yamux data frame has stream id zero"));
      return false;
    }
    let s = this.streams.get(streamId);
    if (s == null) {
      if ((flags & FLAG_SYN) !== 0) {
        if (!this.isInboundStreamIdValid(streamId)) {
          await this.sendRst(streamId);
          return false;
        }
        if (this.streams.size >= this.limits.maxActiveStreams || this.inboundStreams.size >= this.limits.maxInboundStreams || data.length > this.limits.maxStreamReceiveBytes) {
          await this.sendRst(streamId);
          return false;
        }
        s = new YamuxStream(this, streamId, "synReceived");
        this.streams.set(streamId, s);
        this.inboundStreams.add(streamId);
        await s.open();
        this.onIncomingStream?.(s);
      } else {
        await this.sendRst(streamId);
        return false;
      }
    }
    return s.onData(data, flags);
  }

  private async handleWindowUpdateFrame(streamId: number, flags: number, delta: number): Promise<void> {
    if (streamId === 0) {
      this.fail(new Error("yamux window update has stream id zero"));
      return;
    }
    let s = this.streams.get(streamId);
    if (s == null) {
      if ((flags & FLAG_SYN) !== 0) {
        if (!this.isInboundStreamIdValid(streamId)) {
          await this.sendRst(streamId);
          return;
        }
        if (this.streams.size >= this.limits.maxActiveStreams || this.inboundStreams.size >= this.limits.maxInboundStreams) {
          await this.sendRst(streamId);
          return;
        }
        s = new YamuxStream(this, streamId, "synReceived");
        this.streams.set(streamId, s);
        this.inboundStreams.add(streamId);
        await s.open();
        this.onIncomingStream?.(s);
      } else {
        await this.sendRst(streamId);
        return;
      }
    }
    if (!s.onWindowUpdate(delta, flags)) {
      this.fail(new Error("yamux send window overflow"));
    }
  }

  private isInboundStreamIdValid(streamId: number): boolean {
    // yamux uses stream ID parity to identify the initiator:
    // client-initiated streams are odd, server-initiated streams are even.
    //
    // When we are the client, the peer is the server and must initiate even IDs.
    // When we are the server, the peer is the client and must initiate odd IDs.
    return (streamId & 1) === (this.client ? 0 : 1);
  }

  private diagnostic(event: YamuxDiagnostic): void {
    try { this.onDiagnostic?.(event); } catch { /* Diagnostics cannot affect transport behavior. */ }
  }
}

function abortError(signal: AbortSignal): Error {
  const reason = signal.reason;
  if (reason instanceof Error) return reason;
  if (typeof reason === "string" && reason !== "") return new Error(reason);
  return new Error("yamux open stream aborted");
}

async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal | undefined, onAbort: () => void): Promise<T> {
  if (signal == null) return await promise;
  if (signal.aborted) {
    onAbort();
    throw abortError(signal);
  }
  return await new Promise<T>((resolve, reject) => {
    const abort = () => {
      onAbort();
      reject(abortError(signal));
    };
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

function normalizeYamuxLimits(input: Partial<YamuxLimits> | undefined): YamuxLimits {
  const maxFrameBytes = input?.maxFrameBytes ?? DEFAULT_YAMUX_LIMITS.maxFrameBytes;
  const limits: YamuxLimits = {
    maxActiveStreams: input?.maxActiveStreams ?? DEFAULT_YAMUX_LIMITS.maxActiveStreams,
    maxInboundStreams: input?.maxInboundStreams ?? DEFAULT_YAMUX_LIMITS.maxInboundStreams,
    maxFrameBytes,
    preferredOutboundFrameBytes: input?.preferredOutboundFrameBytes ?? Math.min(DEFAULT_YAMUX_LIMITS.preferredOutboundFrameBytes, maxFrameBytes),
    maxStreamReceiveBytes: input?.maxStreamReceiveBytes ?? DEFAULT_YAMUX_LIMITS.maxStreamReceiveBytes,
    maxSessionReceiveBytes: input?.maxSessionReceiveBytes ?? DEFAULT_YAMUX_LIMITS.maxSessionReceiveBytes,
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} must be a positive integer`);
  }
  if (limits.maxInboundStreams > limits.maxActiveStreams) throw new RangeError("maxInboundStreams must not exceed maxActiveStreams");
  if (limits.preferredOutboundFrameBytes > limits.maxFrameBytes) throw new RangeError("preferredOutboundFrameBytes must not exceed maxFrameBytes");
  if (limits.maxFrameBytes > limits.maxStreamReceiveBytes) throw new RangeError("maxFrameBytes must not exceed maxStreamReceiveBytes");
  if (limits.maxStreamReceiveBytes < DEFAULT_YAMUX_LIMITS.maxStreamReceiveBytes) throw new RangeError("maxStreamReceiveBytes must cover the 256 KiB initial stream window");
  if (limits.maxStreamReceiveBytes > limits.maxSessionReceiveBytes) throw new RangeError("maxStreamReceiveBytes must not exceed maxSessionReceiveBytes");
  return Object.freeze(limits);
}

function monotonicMilliseconds(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

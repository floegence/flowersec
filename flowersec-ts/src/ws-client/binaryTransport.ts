import { AbortError, TimeoutError, throwIfAborted } from "../utils/errors.js";

export class WsCloseError extends Error {
  readonly code: number | undefined;
  readonly reason: string | undefined;

  constructor(code?: number, reason?: string) {
    const extra =
      code !== undefined && reason !== undefined && reason !== ""
        ? ` (code=${code} reason=${reason})`
        : code !== undefined
          ? ` (code=${code})`
          : reason !== undefined && reason !== ""
            ? ` (reason=${reason})`
            : "";
    super(`websocket closed${extra}`);
    this.name = "WsCloseError";
    this.code = code;
    this.reason = reason;
  }
}

// WebSocketLike abstracts browser/WS implementations used by the transport.
export type WebSocketLike = {
  binaryType: string;
  readyState: number;
  /** Bytes accepted by send() but not yet transmitted by the implementation. */
  readonly bufferedAmount: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
  removeEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
};

export type WebSocketLimits = Readonly<{
  maxInboundQueuedBytes: number;
  maxInboundQueuedMessages: number;
  outboundLowWatermarkBytes: number;
  outboundHighWatermarkBytes: number;
  outboundHardLimitBytes: number;
  outboundDrainTimeoutMs: number;
}>;

export const DEFAULT_WEB_SOCKET_LIMITS: WebSocketLimits = Object.freeze({
  maxInboundQueuedBytes: 4 * (1 << 20),
  maxInboundQueuedMessages: 1024,
  outboundLowWatermarkBytes: 256 * 1024,
  outboundHighWatermarkBytes: 1 << 20,
  outboundHardLimitBytes: 4 * (1 << 20),
  outboundDrainTimeoutMs: 10_000,
});

export type WebSocketBinaryTransportOptions = Readonly<{
  webSocketLimits?: Partial<WebSocketLimits>;
}>;

type ReadWaiter = {
  resolve: (b: Uint8Array) => void;
  reject: (e: unknown) => void;
  previous: ReadWaiter | undefined;
  next: ReadWaiter | undefined;
  cleanup: () => void;
};

// WebSocketBinaryTransport adapts WebSocket messages to binary reads/writes.
export class WebSocketBinaryTransport {
  // Underlying WebSocket instance (browser or polyfill).
  private readonly ws: WebSocketLike;
  // Buffered inbound frames when no reader is waiting.
  private readonly queue: Array<Uint8Array | undefined> = [];
  // Read cursor for queue to avoid Array.shift() O(n).
  private queueHead = 0;
  // Current buffered byte count for backpressure.
  private queueBytes = 0;
  // Maximum buffered bytes before closing the socket.
  private readonly limits: WebSocketLimits;
  private firstWaiter: ReadWaiter | undefined;
  private lastWaiter: ReadWaiter | undefined;
  // Serialize message handling to preserve arrival order across async Blob decoding.
  private messageChain: Promise<void> = Promise.resolve();
  private decodingBytes = 0;
  private decodingMessages = 0;
  // Sticky error state to fail all future reads/writes.
  private error: unknown = null;
  // Tracks whether the close is initiated locally to avoid double-reporting.
  private localCloseRequested = false;
  // Promise tail used to preserve write order and apply one shared backpressure lane.
  private writeChain: Promise<void> = Promise.resolve();
  private pendingOutboundBytes = 0;
  private closing: Promise<void> | undefined;

  constructor(
    ws: WebSocketLike,
    opts: WebSocketBinaryTransportOptions = {}
  ) {
    this.ws = ws;
    this.limits = normalizeWebSocketLimits(opts.webSocketLimits);
    this.ws.binaryType = "arraybuffer";
    this.ws.addEventListener("message", this.onMessage);
    this.ws.addEventListener("error", this.onError);
    this.ws.addEventListener("close", this.onClose);
  }

  // readBinary resolves with the next queued binary message.
  readBinary(opts: Readonly<{ signal?: AbortSignal; timeoutMs?: number }> = {}): Promise<Uint8Array> {
    if (opts.signal?.aborted) return Promise.reject(new AbortError("read aborted"));
    if (this.error != null) return Promise.reject(this.error);
    const b = this.shiftQueue();
    if (b != null) {
      this.queueBytes -= b.length;
      return Promise.resolve(b);
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      if (opts.signal?.aborted) {
        reject(new AbortError("read aborted"));
        return;
      }
      if (this.error != null) {
        reject(this.error);
        return;
      }
      const waiter: ReadWaiter = {
        resolve,
        reject,
        previous: this.lastWaiter,
        next: undefined,
        cleanup: () => {
          if (timeout != null) clearTimeout(timeout);
          opts.signal?.removeEventListener("abort", onAbort);
        },
      };
      if (this.lastWaiter === undefined) this.firstWaiter = waiter;
      else this.lastWaiter.next = waiter;
      this.lastWaiter = waiter;
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const onAbort = () => {
        this.removeWaiter(waiter);
        reject(new AbortError("read aborted"));
      };
      opts.signal?.addEventListener("abort", onAbort);
      const timeoutMs = Math.max(0, opts.timeoutMs ?? 0);
      if (timeoutMs > 0) {
        timeout = setTimeout(() => {
          this.removeWaiter(waiter);
          reject(new TimeoutError("read timeout"));
        }, timeoutMs);
      }
    });
  }

  // writeBinary sends a binary frame over the websocket.
  async writeBinary(frame: Uint8Array, opts: Readonly<{ signal?: AbortSignal }> = {}): Promise<void> {
    throwIfAborted(opts.signal, "write aborted");
    if (this.error != null) throw this.error;
    if (frame.byteLength > this.limits.outboundHardLimitBytes ||
        this.pendingOutboundBytes + this.ws.bufferedAmount + frame.byteLength > this.limits.outboundHardLimitBytes) {
      const err = new Error("ws send queue exceeds hard limit");
      this.failAndClose(err);
      throw err;
    }
    this.pendingOutboundBytes += frame.byteLength;
    let handedToWebSocket = false;
    const write = this.writeChain
      .then(() => this.sendWithBackpressure(frame, opts.signal, () => {
        handedToWebSocket = true;
        this.pendingOutboundBytes = Math.max(0, this.pendingOutboundBytes - frame.byteLength);
      }))
      .finally(() => {
        if (!handedToWebSocket) {
          this.pendingOutboundBytes = Math.max(0, this.pendingOutboundBytes - frame.byteLength);
        }
      });
    this.writeChain = write.catch(() => {});
    await write;
  }

  async flush(opts: Readonly<{ signal?: AbortSignal }> = {}): Promise<void> {
    throwIfAborted(opts.signal, "flush aborted");
    await this.writeChain;
    const startedAt = Date.now();
    while (this.ws.bufferedAmount > 0) {
      throwIfAborted(opts.signal, "flush aborted");
      if (this.error != null) throw this.error;
      if (Date.now() - startedAt >= this.limits.outboundDrainTimeoutMs) {
        throw new TimeoutError("ws send buffer drain timeout");
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }

  // close tears down listeners and rejects pending readers.
  close(code?: number, reason?: string): void {
    const sendClose = !this.localCloseRequested;
    this.localCloseRequested = true;
    this.fail(new Error("websocket closed"));
    this.ws.removeEventListener("message", this.onMessage);
    this.ws.removeEventListener("error", this.onError);
    this.ws.removeEventListener("close", this.onClose);
    if (sendClose) this.ws.close(code, reason);
  }

  async waitRemoteSessionClose(): Promise<boolean> {
    await this.waitClosed();
    return this.error instanceof WsCloseError && this.error.code === 4000 && this.error.reason === "session closed";
  }

  waitClosed(): Promise<void> {
    if (!this.closing) {
      const socketClosed = this.ws.readyState === 3 ? Promise.resolve() : new Promise<void>(resolve => {
        const closed = () => { this.ws.removeEventListener("close", closed); resolve(); };
        this.ws.addEventListener("close", closed);
      });
      this.closing = Promise.all([socketClosed, this.messageChain, this.writeChain]).then(() => undefined);
    }
    return this.closing;
  }

  // handleMessage normalizes browser message payloads into Uint8Array.
  private readonly onMessage = (ev: any): void => {
    if (this.error != null) return;
    const data: unknown = ev.data;
    let source: Uint8Array | Blob;
    if (data instanceof ArrayBuffer) source = new Uint8Array(data);
    else if (ArrayBuffer.isView(data)) source = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    else if (typeof Blob !== "undefined" && data instanceof Blob) source = data;
    else { this.failAndClose(new Error(typeof data === "string" ? "unexpected text frame" : "unexpected message type")); return; }
    const size = source instanceof Uint8Array ? source.byteLength : source.size;
    if (size === 0) { this.failAndClose(new Error("empty websocket transport message")); return; }
    const charge = source instanceof Uint8Array ? size : 2 * size;
    if (this.queueBytes + this.decodingBytes + charge > this.limits.maxInboundQueuedBytes ||
        this.queue.length - this.queueHead + this.decodingMessages >= this.limits.maxInboundQueuedMessages) {
      this.failAndClose(new Error("ws recv buffer exceeded")); return;
    }
    this.decodingBytes += charge;
    this.decodingMessages++;
    this.messageChain = this.messageChain.then(async () => {
      try {
        if (this.error != null) return;
        const bytes = source instanceof Uint8Array ? source : new Uint8Array(await source.arrayBuffer());
        if (this.error == null) this.push(bytes);
      } finally { this.decodingBytes -= charge; this.decodingMessages--; }
    }).catch(error => this.failAndClose(error instanceof Error ? error : new Error(String(error))));
  };

  private readonly onError = (): void => {
    this.fail(new Error("websocket error"));
  };

  private readonly onClose = (ev: any): void => {
    if (!this.localCloseRequested) {
      const code = typeof ev?.code === "number" ? ev.code : undefined;
      const reason = typeof ev?.reason === "string" ? ev.reason : undefined;
      this.fail(new WsCloseError(code, reason));
      return;
    }
    this.fail(new Error("websocket closed"));
  };

  // push enqueues a frame or delivers it to a waiting reader.
  private push(b: Uint8Array): void {
    const waiter = this.firstWaiter;
    if (waiter !== undefined) {
      this.removeWaiter(waiter);
      waiter.resolve(b);
      return;
    }
    if (this.queueBytes + b.length > this.limits.maxInboundQueuedBytes) {
      this.fail(new Error("ws recv buffer exceeded"));
      this.localCloseRequested = true;
      this.ws.close();
      return;
    }
    this.queue.push(b);
    this.queueBytes += b.length;
  }

  private async sendWithBackpressure(frame: Uint8Array, signal: AbortSignal | undefined, onHandedToWebSocket: () => void): Promise<void> {
    throwIfAborted(signal, "write aborted");
    if (this.error != null) throw this.error;
    if (frame.byteLength > this.limits.outboundHardLimitBytes) {
      const err = new Error("ws send frame exceeds hard limit");
      this.failAndClose(err);
      throw err;
    }

    const startedAt = Date.now();
    const mustDrain =
      this.ws.bufferedAmount + frame.byteLength > this.limits.outboundHighWatermarkBytes ||
      this.ws.bufferedAmount + frame.byteLength > this.limits.outboundHardLimitBytes;
    while (mustDrain) {
      throwIfAborted(signal, "write aborted");
      if (this.error != null) throw this.error;
      if (Date.now() - startedAt >= this.limits.outboundDrainTimeoutMs) {
        const err = new TimeoutError("ws send buffer drain timeout");
        this.failAndClose(err);
        throw err;
      }
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
      if (this.ws.bufferedAmount <= this.limits.outboundLowWatermarkBytes &&
          this.ws.bufferedAmount + frame.byteLength <= this.limits.outboundHardLimitBytes) {
        break;
      }
    }

    this.ws.send(frame);
    onHandedToWebSocket();
    if (this.ws.bufferedAmount > this.limits.outboundHardLimitBytes) {
      const err = new Error("ws send buffer exceeded");
      this.failAndClose(err);
      throw err;
    }
  }

  private failAndClose(err: Error): void {
    this.fail(err);
    if (!this.localCloseRequested) {
      this.localCloseRequested = true;
      this.ws.close();
    }
  }

  private shiftQueue(): Uint8Array | undefined {
    if (this.queueHead >= this.queue.length) return undefined;
    const b = this.queue[this.queueHead];
    this.queue[this.queueHead++] = undefined;
    if (this.queueHead === this.queue.length) {
      this.queue.length = 0;
      this.queueHead = 0;
    } else if (this.queueHead > 1024 && this.queueHead * 2 > this.queue.length) {
      this.queue.splice(0, this.queueHead);
      this.queueHead = 0;
    }
    return b;
  }

  private removeWaiter(waiter: ReadWaiter): void {
    if (waiter.previous === undefined) this.firstWaiter = waiter.next;
    else waiter.previous.next = waiter.next;
    if (waiter.next === undefined) this.lastWaiter = waiter.previous;
    else waiter.next.previous = waiter.previous;
    waiter.previous = waiter.next = undefined;
    waiter.cleanup();
  }

  // fail transitions the transport into a permanent error state.
  private fail(err: unknown): void {
    if (this.error != null) return;
    this.error = err;
    this.queue.length = 0;
    this.queueHead = 0;
    this.queueBytes = 0;
    while (this.firstWaiter !== undefined) {
      const waiter = this.firstWaiter;
      this.removeWaiter(waiter);
      waiter.reject(err);
    }
  }
}

function normalizeWebSocketLimits(input: Partial<WebSocketLimits> | undefined): WebSocketLimits {
  const limits: WebSocketLimits = {
    maxInboundQueuedBytes: input?.maxInboundQueuedBytes ?? DEFAULT_WEB_SOCKET_LIMITS.maxInboundQueuedBytes,
    maxInboundQueuedMessages: input?.maxInboundQueuedMessages ?? DEFAULT_WEB_SOCKET_LIMITS.maxInboundQueuedMessages,
    outboundLowWatermarkBytes: input?.outboundLowWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundLowWatermarkBytes,
    outboundHighWatermarkBytes: input?.outboundHighWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHighWatermarkBytes,
    outboundHardLimitBytes: input?.outboundHardLimitBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHardLimitBytes,
    outboundDrainTimeoutMs: input?.outboundDrainTimeoutMs ?? DEFAULT_WEB_SOCKET_LIMITS.outboundDrainTimeoutMs,
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative integer`);
  }
  if (limits.maxInboundQueuedBytes === 0 || limits.maxInboundQueuedMessages === 0 || limits.outboundHardLimitBytes === 0 || limits.outboundDrainTimeoutMs === 0) {
    throw new TypeError("websocket hard limits and drain timeout must be positive");
  }
  if (limits.outboundLowWatermarkBytes > limits.outboundHighWatermarkBytes ||
      limits.outboundHighWatermarkBytes > limits.outboundHardLimitBytes) {
    throw new TypeError("websocket outbound watermarks must satisfy low <= high <= hard");
  }
  return Object.freeze(limits);
}

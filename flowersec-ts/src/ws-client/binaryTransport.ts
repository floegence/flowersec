import { emitObserverDiagnostic, normalizeObserver, type ClientObserver, type ClientObserverLike, type WsErrorReason } from "../observability/observer.js";
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
  outboundLowWatermarkBytes: number;
  outboundHighWatermarkBytes: number;
  outboundHardLimitBytes: number;
  outboundDrainTimeoutMs: number;
}>;

export const DEFAULT_WEB_SOCKET_LIMITS: WebSocketLimits = Object.freeze({
  maxInboundQueuedBytes: 4 * (1 << 20),
  outboundLowWatermarkBytes: 256 * 1024,
  outboundHighWatermarkBytes: 1 << 20,
  outboundHardLimitBytes: 4 * (1 << 20),
  outboundDrainTimeoutMs: 10_000,
});

export type WebSocketBinaryTransportOptions = Readonly<{
  webSocketLimits?: Partial<WebSocketLimits>;
  observer?: ClientObserverLike;
}>;

type ReadWaiter = {
  resolve: (b: Uint8Array) => void;
  reject: (e: unknown) => void;
  settled: boolean;
  cleanup: () => void;
};

// WebSocketBinaryTransport adapts WebSocket messages to binary reads/writes.
export class WebSocketBinaryTransport {
  // Underlying WebSocket instance (browser or polyfill).
  private readonly ws: WebSocketLike;
  // Observer for websocket-level errors.
  private readonly observer: ClientObserver;
  // Buffered inbound frames when no reader is waiting.
  private readonly queue: Uint8Array[] = [];
  // Read cursor for queue to avoid Array.shift() O(n).
  private queueHead = 0;
  // Current buffered byte count for backpressure.
  private queueBytes = 0;
  // Maximum buffered bytes before closing the socket.
  private readonly limits: WebSocketLimits;
  // Pending readers waiting for the next frame.
  private waiters: ReadWaiter[] = [];
  // Read cursor for waiters to avoid Array.shift() O(n).
  private waitersHead = 0;
  // Tracks how many waiters have settled (timeout/abort) without being compacted away yet.
  private waitersSettled = 0;
  // Serialize message handling to preserve arrival order across async Blob decoding.
  private messageChain: Promise<void> = Promise.resolve();
  // Sticky error state to fail all future reads/writes.
  private error: unknown = null;
  // Tracks whether the close is initiated locally to avoid double-reporting.
  private localCloseRequested = false;
  // Promise tail used to preserve write order and apply one shared backpressure lane.
  private writeChain: Promise<void> = Promise.resolve();
  private pendingOutboundBytes = 0;

  constructor(
    ws: WebSocketLike,
    opts: WebSocketBinaryTransportOptions = {}
  ) {
    this.ws = ws;
    this.observer = normalizeObserver(opts.observer);
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
      const waiter = {
        resolve,
        reject,
        settled: false,
        cleanup: () => {}
      };
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const onAbort = () => {
        if (waiter.settled) return;
        waiter.settled = true;
        waiter.cleanup();
        this.waitersSettled++;
        this.compactWaitersMaybe();
        reject(new AbortError("read aborted"));
      };
      const cleanup = () => {
        if (timeout != null) clearTimeout(timeout);
        timeout = undefined;
        opts.signal?.removeEventListener("abort", onAbort);
      };
      waiter.cleanup = cleanup;
      opts.signal?.addEventListener("abort", onAbort);
      const timeoutMs = Math.max(0, opts.timeoutMs ?? 0);
      if (timeoutMs > 0) {
        timeout = setTimeout(() => {
          if (waiter.settled) return;
          waiter.settled = true;
          cleanup();
          this.waitersSettled++;
          this.compactWaitersMaybe();
          reject(new TimeoutError("read timeout"));
        }, timeoutMs);
      }
      this.waiters.push(waiter);
    });
  }

  // writeBinary sends a binary frame over the websocket.
  async writeBinary(frame: Uint8Array, opts: Readonly<{ signal?: AbortSignal }> = {}): Promise<void> {
    throwIfAborted(opts.signal, "write aborted");
    if (this.error != null) throw this.error;
    if (frame.byteLength > this.limits.outboundHardLimitBytes ||
        this.pendingOutboundBytes + this.ws.bufferedAmount + frame.byteLength > this.limits.outboundHardLimitBytes) {
      const err = new Error("ws send queue exceeds hard limit");
      this.failAndClose(err, "send_buffer_exceeded");
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

  // close tears down listeners and rejects pending readers.
  close(): void {
    if (!this.localCloseRequested) {
      this.localCloseRequested = true;
      if (this.error == null) this.observer.onWsClose("local");
    }
    this.fail(new Error("websocket closed"));
    this.ws.removeEventListener("message", this.onMessage);
    this.ws.removeEventListener("error", this.onError);
    this.ws.removeEventListener("close", this.onClose);
    this.queue.length = 0;
    this.queueHead = 0;
    this.queueBytes = 0;
    this.ws.close();
  }

  // handleMessage normalizes browser message payloads into Uint8Array.
  private async handleMessage(data: unknown): Promise<void> {
    if (this.error != null) return;
    if (typeof data === "string") {
      this.fail(new Error("unexpected text frame"), "unexpected_text_frame");
      return;
    }
    if (data instanceof Uint8Array) {
      this.push(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      if (this.queueBytes + data.byteLength > this.limits.maxInboundQueuedBytes) {
        this.fail(new Error("ws recv buffer exceeded"), "recv_buffer_exceeded");
        this.localCloseRequested = true;
        this.observer.onWsClose("local");
        this.ws.close();
        return;
      }
      this.push(new Uint8Array(data));
      return;
    }
    if (ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      if (this.queueBytes + view.byteLength > this.limits.maxInboundQueuedBytes) {
        this.fail(new Error("ws recv buffer exceeded"), "recv_buffer_exceeded");
        this.localCloseRequested = true;
        this.observer.onWsClose("local");
        this.ws.close();
        return;
      }
      this.push(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
      return;
    }
    if (typeof Blob !== "undefined" && data instanceof Blob) {
      if (this.queueBytes + data.size > this.limits.maxInboundQueuedBytes) {
        this.fail(new Error("ws recv buffer exceeded"), "recv_buffer_exceeded");
        this.localCloseRequested = true;
        this.observer.onWsClose("local");
        this.ws.close();
        return;
      }
      const ab = await data.arrayBuffer();
      if (this.error != null) return;
      this.push(new Uint8Array(ab));
      return;
    }
    this.fail(new Error("unexpected message type"), "unexpected_message_type");
  }

  private readonly onMessage = (ev: any): void => {
    const data = ev.data;
    this.messageChain = this.messageChain.then(() => this.handleMessage(data)).catch((err) => {
      const e = err instanceof Error ? err : new Error(String(err));
      this.fail(e, "error");
    });
  };

  private readonly onError = (): void => {
    this.fail(new Error("websocket error"), "error");
  };

  private readonly onClose = (ev: any): void => {
    if (!this.localCloseRequested) {
      const code = typeof ev?.code === "number" ? ev.code : undefined;
      const reason = typeof ev?.reason === "string" ? ev.reason : undefined;
      this.observer.onWsClose("peer_or_error", code);
      this.fail(new WsCloseError(code, reason));
      return;
    }
    this.fail(new Error("websocket closed"));
  };

  // push enqueues a frame or delivers it to a waiting reader.
  private push(b: Uint8Array): void {
    const w = this.shiftWaiter();
    if (w != null) {
      if (!w.settled) {
        w.settled = true;
        w.cleanup();
      }
      w.resolve(b);
      return;
    }
    if (this.queueBytes + b.length > this.limits.maxInboundQueuedBytes) {
      this.fail(new Error("ws recv buffer exceeded"), "recv_buffer_exceeded");
      this.localCloseRequested = true;
      this.observer.onWsClose("local");
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
      this.failAndClose(err, "send_buffer_exceeded");
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
        this.failAndClose(err, "send_buffer_timeout");
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
      this.failAndClose(err, "send_buffer_exceeded");
      throw err;
    }
  }

  private failAndClose(err: Error, reason: WsErrorReason): void {
    emitObserverDiagnostic(this.observer, {
      stage: "transport",
      code_domain: "event",
      code: reason === "send_buffer_timeout" ? "queue_pressure" : "resource_limit_reached",
      result: "fail",
      resource: "websocket_outbound_bytes",
      current: this.ws.bufferedAmount + this.pendingOutboundBytes,
      limit: this.limits.outboundHardLimitBytes,
    });
    this.fail(err, reason);
    if (!this.localCloseRequested) {
      this.localCloseRequested = true;
      this.observer.onWsClose("local");
      this.ws.close();
    }
  }

  private shiftQueue(): Uint8Array | undefined {
    if (this.queueHead >= this.queue.length) return undefined;
    const b = this.queue[this.queueHead];
    this.queueHead++;
    // Periodic compaction to release references and keep array bounded.
    if (this.queueHead > 1024 && this.queueHead * 2 > this.queue.length) {
      this.queue.splice(0, this.queueHead);
      this.queueHead = 0;
    }
    return b;
  }

  private shiftWaiter(): ReadWaiter | undefined {
    while (this.waitersHead < this.waiters.length) {
      const w = this.waiters[this.waitersHead];
      this.waitersHead++;
      if (w != null && !w.settled) {
        if (this.waitersHead > 1024 && this.waitersHead * 2 > this.waiters.length) {
          this.waiters.splice(0, this.waitersHead);
          this.waitersHead = 0;
          this.waitersSettled = 0;
        }
        return w;
      }
    }
    if (this.waitersHead > 1024 && this.waitersHead * 2 > this.waiters.length) {
      this.waiters.splice(0, this.waitersHead);
      this.waitersHead = 0;
      this.waitersSettled = 0;
    }
    return undefined;
  }

  private compactWaitersMaybe(): void {
    // Timeouts/cancellations can settle waiters without any incoming messages,
    // so we compact based on how many settled entries we're carrying around.
    if (this.waiters.length < 64) return;
    if (this.waitersSettled < 32) return;
    if (this.waitersSettled * 2 <= this.waiters.length) return;

    const next: ReadWaiter[] = [];
    for (let i = this.waitersHead; i < this.waiters.length; i++) {
      const w = this.waiters[i]!;
      if (!w.settled) next.push(w);
    }
    this.waiters = next;
    this.waitersHead = 0;
    this.waitersSettled = 0;
  }

  // fail transitions the transport into a permanent error state.
  private fail(err: unknown, reason?: WsErrorReason): void {
    if (this.error != null) return;
    this.error = err;
    if (reason != null) {
      this.observer.onWsError(reason);
    }
    const ws = this.waiters;
    const start = this.waitersHead;
    this.waiters = [];
    this.waitersHead = 0;
    for (let i = start; i < ws.length; i++) {
      const w = ws[i];
      if (w == null || w.settled) continue;
      w.settled = true;
      w.cleanup();
      w.reject(err);
    }
  }
}

function normalizeWebSocketLimits(input: Partial<WebSocketLimits> | undefined): WebSocketLimits {
  const limits: WebSocketLimits = {
    maxInboundQueuedBytes: input?.maxInboundQueuedBytes ?? DEFAULT_WEB_SOCKET_LIMITS.maxInboundQueuedBytes,
    outboundLowWatermarkBytes: input?.outboundLowWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundLowWatermarkBytes,
    outboundHighWatermarkBytes: input?.outboundHighWatermarkBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHighWatermarkBytes,
    outboundHardLimitBytes: input?.outboundHardLimitBytes ?? DEFAULT_WEB_SOCKET_LIMITS.outboundHardLimitBytes,
    outboundDrainTimeoutMs: input?.outboundDrainTimeoutMs ?? DEFAULT_WEB_SOCKET_LIMITS.outboundDrainTimeoutMs,
  };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative integer`);
  }
  if (limits.maxInboundQueuedBytes === 0 || limits.outboundHardLimitBytes === 0 || limits.outboundDrainTimeoutMs === 0) {
    throw new TypeError("websocket hard limits and drain timeout must be positive");
  }
  if (limits.outboundLowWatermarkBytes > limits.outboundHighWatermarkBytes ||
      limits.outboundHighWatermarkBytes > limits.outboundHardLimitBytes) {
    throw new TypeError("websocket outbound watermarks must satisfy low <= high <= hard");
  }
  return Object.freeze(limits);
}

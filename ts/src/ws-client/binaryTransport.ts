import { normalizeObserver, type ClientObserver, type ClientObserverLike, type WsErrorReason } from "../observability/observer.js";

// WebSocketLike abstracts browser/WS implementations used by the transport.
export type WebSocketLike = {
  binaryType: string;
  readyState: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
  removeEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
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
  private readonly maxQueuedBytes: number;
  // Pending readers waiting for the next frame.
  private waiters: Array<{ resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  // Read cursor for waiters to avoid Array.shift() O(n).
  private waitersHead = 0;
  // Serialize message handling to preserve arrival order across async Blob decoding.
  private messageChain: Promise<void> = Promise.resolve();
  // Sticky error state to fail all future reads/writes.
  private error: unknown = null;
  // Tracks whether the close is initiated locally to avoid double-reporting.
  private localCloseRequested = false;

  constructor(
    ws: WebSocketLike,
    opts: Readonly<{ maxQueuedBytes?: number; observer?: ClientObserverLike }> = {}
  ) {
    this.ws = ws;
    this.observer = normalizeObserver(opts.observer);
    this.maxQueuedBytes = Math.max(0, opts.maxQueuedBytes ?? 4 * (1 << 20));
    this.ws.binaryType = "arraybuffer";
    this.ws.addEventListener("message", this.onMessage);
    this.ws.addEventListener("error", this.onError);
    this.ws.addEventListener("close", this.onClose);
  }

  // readBinary resolves with the next queued binary message.
  readBinary(): Promise<Uint8Array> {
    if (this.error != null) return Promise.reject(this.error);
    const b = this.shiftQueue();
    if (b != null) {
      this.queueBytes -= b.length;
      return Promise.resolve(b);
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      if (this.error != null) {
        reject(this.error);
        return;
      }
      this.waiters.push({ resolve, reject });
    });
  }

  // writeBinary sends a binary frame over the websocket.
  async writeBinary(frame: Uint8Array): Promise<void> {
    if (this.error != null) throw this.error;
    this.ws.send(frame);
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
      if (this.maxQueuedBytes > 0 && this.queueBytes + data.byteLength > this.maxQueuedBytes) {
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
      if (this.maxQueuedBytes > 0 && this.queueBytes + view.byteLength > this.maxQueuedBytes) {
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
      if (this.maxQueuedBytes > 0 && this.queueBytes + data.size > this.maxQueuedBytes) {
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
      this.observer.onWsClose("peer_or_error", code);
    }
    this.fail(new Error("websocket closed"));
  };

  // push enqueues a frame or delivers it to a waiting reader.
  private push(b: Uint8Array): void {
    const w = this.shiftWaiter();
    if (w != null) {
      w.resolve(b);
      return;
    }
    if (this.maxQueuedBytes > 0 && this.queueBytes + b.length > this.maxQueuedBytes) {
      this.fail(new Error("ws recv buffer exceeded"), "recv_buffer_exceeded");
      this.localCloseRequested = true;
      this.observer.onWsClose("local");
      this.ws.close();
      return;
    }
    this.queue.push(b);
    this.queueBytes += b.length;
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

  private shiftWaiter(): { resolve: (b: Uint8Array) => void; reject: (e: unknown) => void } | undefined {
    if (this.waitersHead >= this.waiters.length) return undefined;
    const w = this.waiters[this.waitersHead];
    this.waitersHead++;
    if (this.waitersHead > 1024 && this.waitersHead * 2 > this.waiters.length) {
      this.waiters.splice(0, this.waitersHead);
      this.waitersHead = 0;
    }
    return w;
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
    for (let i = start; i < ws.length; i++) ws[i]!.reject(err);
  }
}

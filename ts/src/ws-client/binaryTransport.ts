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
  private readonly ws: WebSocketLike;
  private readonly queue: Uint8Array[] = [];
  private queueBytes = 0;
  private readonly maxQueuedBytes: number;
  private waiters: Array<{ resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  // Serialize message handling to preserve arrival order across async Blob decoding.
  private messageChain: Promise<void> = Promise.resolve();
  private error: unknown = null;

  constructor(ws: WebSocketLike, opts: Readonly<{ maxQueuedBytes?: number }> = {}) {
    this.ws = ws;
    this.maxQueuedBytes = Math.max(0, opts.maxQueuedBytes ?? 4 * (1 << 20));
    this.ws.binaryType = "arraybuffer";
    this.ws.addEventListener("message", this.onMessage);
    this.ws.addEventListener("error", this.onError);
    this.ws.addEventListener("close", this.onClose);
  }

  // readBinary resolves with the next queued binary message.
  readBinary(): Promise<Uint8Array> {
    if (this.error != null) return Promise.reject(this.error);
    const b = this.queue.shift();
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
    this.fail(new Error("websocket closed"));
    this.ws.removeEventListener("message", this.onMessage);
    this.ws.removeEventListener("error", this.onError);
    this.ws.removeEventListener("close", this.onClose);
    this.queue.length = 0;
    this.queueBytes = 0;
    this.ws.close();
  }

  // handleMessage normalizes browser message payloads into Uint8Array.
  private async handleMessage(data: unknown): Promise<void> {
    if (this.error != null) return;
    if (typeof data === "string") {
      throw new Error("unexpected text frame");
    }
    if (data instanceof Uint8Array) {
      this.push(data);
      return;
    }
    if (data instanceof ArrayBuffer) {
      this.push(new Uint8Array(data));
      return;
    }
    if (ArrayBuffer.isView(data)) {
      const view = data as ArrayBufferView;
      this.push(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
      return;
    }
    if (typeof Blob !== "undefined" && data instanceof Blob) {
      const ab = await data.arrayBuffer();
      if (this.error != null) return;
      this.push(new Uint8Array(ab));
      return;
    }
    throw new Error("unexpected message type");
  }

  private readonly onMessage = (ev: any): void => {
    const data = ev.data;
    this.messageChain = this.messageChain.then(() => this.handleMessage(data)).catch((err) => {
      const e = err instanceof Error ? err : new Error(String(err));
      this.fail(e);
    });
  };

  private readonly onError = (): void => {
    this.fail(new Error("websocket error"));
  };

  private readonly onClose = (): void => {
    this.fail(new Error("websocket closed"));
  };

  // push enqueues a frame or delivers it to a waiting reader.
  private push(b: Uint8Array): void {
    const w = this.waiters.shift();
    if (w != null) {
      w.resolve(b);
      return;
    }
    if (this.maxQueuedBytes > 0 && this.queueBytes + b.length > this.maxQueuedBytes) {
      this.fail(new Error("ws recv buffer exceeded"));
      this.ws.close();
      return;
    }
    this.queue.push(b);
    this.queueBytes += b.length;
  }

  // fail transitions the transport into a permanent error state.
  private fail(err: unknown): void {
    if (this.error != null) return;
    this.error = err;
    const ws = this.waiters;
    this.waiters = [];
    for (const w of ws) w.reject(err);
  }
}

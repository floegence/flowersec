export type WebSocketLike = {
  binaryType: string;
  readyState: number;
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
  removeEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void;
};

export class WebSocketBinaryTransport {
  private readonly ws: WebSocketLike;
  private readonly queue: Uint8Array[] = [];
  private queueBytes = 0;
  private readonly maxQueuedBytes: number;
  private waiters: Array<{ resolve: (b: Uint8Array) => void; reject: (e: unknown) => void }> = [];
  private error: unknown = null;

  constructor(ws: WebSocketLike, opts: Readonly<{ maxQueuedBytes?: number }> = {}) {
    this.ws = ws;
    this.maxQueuedBytes = Math.max(0, opts.maxQueuedBytes ?? 4 * (1 << 20));
    this.ws.binaryType = "arraybuffer";
    this.ws.addEventListener("message", this.onMessage);
    this.ws.addEventListener("error", this.onError);
    this.ws.addEventListener("close", this.onClose);
  }

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

  async writeBinary(frame: Uint8Array): Promise<void> {
    if (this.error != null) throw this.error;
    this.ws.send(frame);
  }

  close(): void {
    this.fail(new Error("websocket closed"));
    this.ws.removeEventListener("message", this.onMessage);
    this.ws.removeEventListener("error", this.onError);
    this.ws.removeEventListener("close", this.onClose);
    this.queue.length = 0;
    this.queueBytes = 0;
    this.ws.close();
  }

  private readonly onMessage = (ev: any): void => {
    const data = ev.data as ArrayBuffer | Blob;
    if (typeof data === "string") {
      this.fail(new Error("unexpected text frame"));
      return;
    }
    if (data instanceof ArrayBuffer) {
      this.push(new Uint8Array(data));
      return;
    }
    if (typeof Blob !== "undefined" && data instanceof Blob) {
      void data.arrayBuffer().then((ab) => this.push(new Uint8Array(ab)));
      return;
    }
    this.fail(new Error("unexpected message type"));
  };

  private readonly onError = (): void => {
    this.fail(new Error("websocket error"));
  };

  private readonly onClose = (): void => {
    this.fail(new Error("websocket closed"));
  };

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

  private fail(err: unknown): void {
    if (this.error != null) return;
    this.error = err;
    const ws = this.waiters;
    this.waiters = [];
    for (const w of ws) w.reject(err);
  }
}

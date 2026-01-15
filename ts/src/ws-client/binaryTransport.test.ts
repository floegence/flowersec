import { describe, expect, test } from "vitest";
import { WebSocketBinaryTransport, type WebSocketLike } from "./binaryTransport.js";

class FakeWebSocket implements WebSocketLike {
  binaryType = "arraybuffer";
  readyState = 1;
  closed = false;
  private readonly listeners = new Map<string, Set<(ev: any) => void>>();

  send(_data: string | ArrayBuffer | Uint8Array): void {}

  close(): void {
    this.closed = true;
    this.emit("close", {});
  }

  addEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void {
    const set = this.listeners.get(type) ?? new Set<(ev: any) => void>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: "open" | "message" | "error" | "close", listener: (ev: any) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  emit(type: "open" | "message" | "error" | "close", ev: any): void {
    const set = this.listeners.get(type);
    if (set == null) return;
    for (const listener of set) listener(ev);
  }
}

async function flushAsync(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

async function waitForClosed(ws: FakeWebSocket, attempts = 5): Promise<void> {
  for (let i = 0; i < attempts && !ws.closed; i++) {
    await flushAsync();
  }
}

class DelayedBlob extends Blob {
  private readonly delayMs: number;

  constructor(parts: BlobPart[], delayMs: number) {
    super(parts);
    this.delayMs = delayMs;
  }

  override async arrayBuffer(): Promise<ArrayBuffer> {
    await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    return await super.arrayBuffer();
  }
}

const testWithBlob = typeof Blob === "undefined" ? test.skip : test;

describe("WebSocketBinaryTransport", () => {
  test("fails fast when queued bytes exceed limit", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws, { maxQueuedBytes: 4 });

    ws.emit("message", { data: new Uint8Array([1, 2, 3]).buffer });
    ws.emit("message", { data: new Uint8Array([4, 5]).buffer });

    await waitForClosed(ws);
    expect(ws.closed).toBe(true);
    await expect(transport.readBinary()).rejects.toThrow(/ws recv buffer exceeded/);
  });

  test("supports array buffer views", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws);

    const read = transport.readBinary();
    ws.emit("message", { data: new Uint8Array([7, 8, 9]) });

    await expect(read).resolves.toEqual(new Uint8Array([7, 8, 9]));
  });

  test("rejects text frames", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws);

    const read = transport.readBinary();
    ws.emit("message", { data: "text" });

    await expect(read).rejects.toThrow(/unexpected text frame/);
  });

  testWithBlob("preserves message order across async blob decoding", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws);

    const first = transport.readBinary();
    const second = transport.readBinary();

    const slow = new DelayedBlob([new Uint8Array([1])], 20);
    const fast = new DelayedBlob([new Uint8Array([2])], 0);
    ws.emit("message", { data: slow });
    ws.emit("message", { data: fast });

    await expect(first).resolves.toEqual(new Uint8Array([1]));
    await expect(second).resolves.toEqual(new Uint8Array([2]));
  });
});

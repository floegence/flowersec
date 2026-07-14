import { describe, expect, test, vi } from "vitest";
import { WebSocketBinaryTransport, WsCloseError, type WebSocketLike } from "./binaryTransport.js";

class FakeWebSocket implements WebSocketLike {
  binaryType = "arraybuffer";
  readyState = 1;
  bufferedAmount = 0;
  closed = false;
  private readonly listeners = new Map<string, Set<(ev: any) => void>>();

  readonly sent: Array<string | ArrayBuffer | Uint8Array> = [];
  send(data: string | ArrayBuffer | Uint8Array): void { this.sent.push(data); }

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
  test("readBinary supports AbortSignal without consuming future messages", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws);

    const ac = new AbortController();
    const abortedRead = transport.readBinary({ signal: ac.signal });
    ac.abort();
    await expect(abortedRead).rejects.toThrow(/read aborted/);

    ws.emit("message", { data: new Uint8Array([9]).buffer });
    await expect(transport.readBinary()).resolves.toEqual(new Uint8Array([9]));
  });

  test("readBinary supports timeout without consuming future messages", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws);

    const timed = transport.readBinary({ timeoutMs: 30 });
    await expect(timed).rejects.toThrow(/read timeout/);

    ws.emit("message", { data: new Uint8Array([8]).buffer });
    await expect(transport.readBinary()).resolves.toEqual(new Uint8Array([8]));
  });

  test("fails fast when queued bytes exceed limit", async () => {
    const ws = new FakeWebSocket();
    const onWsError = vi.fn();
    const onWsClose = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { webSocketLimits: { maxInboundQueuedBytes: 4 }, observer: { onWsClose, onWsError } });

    ws.emit("message", { data: new Uint8Array([1, 2, 3]).buffer });
    ws.emit("message", { data: new Uint8Array([4, 5]).buffer });

    await waitForClosed(ws);
    expect(ws.closed).toBe(true);
    await expect(transport.readBinary()).rejects.toThrow(/ws recv buffer exceeded/);
    expect(onWsError).toHaveBeenCalledWith("recv_buffer_exceeded");
    expect(onWsClose).toHaveBeenCalledWith("local", undefined);
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
    const onWsError = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsError } });

    const read = transport.readBinary();
    ws.emit("message", { data: "text" });

    await expect(read).rejects.toThrow(/unexpected text frame/);
    expect(onWsError).toHaveBeenCalledWith("unexpected_text_frame");
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

  test("readBinary rejects on websocket error event", async () => {
    const ws = new FakeWebSocket();
    const onWsError = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsError } });

    const read = transport.readBinary();
    ws.emit("error", {});

    await expect(read).rejects.toThrow(/websocket error/);
    expect(onWsError).toHaveBeenCalledWith("error");
  });

  test("readBinary rejects on websocket close event", async () => {
    const ws = new FakeWebSocket();
    const onWsClose = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsClose } });

    const read = transport.readBinary();
    ws.emit("close", { code: 1008, reason: "invalid_token" });

    await expect(read).rejects.toBeInstanceOf(WsCloseError);
    await expect(read).rejects.toMatchObject({ code: 1008, reason: "invalid_token" });
    expect(onWsClose).toHaveBeenCalledWith("peer_or_error", 1008);
  });

  test("close rejects pending readers", async () => {
    const ws = new FakeWebSocket();
    const onWsClose = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsClose } });

    const read = transport.readBinary();
    transport.close();

    await expect(read).rejects.toThrow(/websocket closed/);
    expect(ws.closed).toBe(true);
    expect(onWsClose).toHaveBeenCalledWith("local", undefined);
  });

  test("rejects unexpected message types", async () => {
    const ws = new FakeWebSocket();
    const onWsError = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsError } });

    const read = transport.readBinary();
    ws.emit("message", { data: 123 });

    await expect(read).rejects.toThrow(/unexpected message type/);
    expect(onWsError).toHaveBeenCalledWith("unexpected_message_type");
  });

  testWithBlob("messageChain propagates blob decode errors", async () => {
    class BadBlob extends Blob {
      override async arrayBuffer(): Promise<ArrayBuffer> {
        throw new Error("boom");
      }
    }

    const ws = new FakeWebSocket();
    const onWsError = vi.fn();
    const transport = new WebSocketBinaryTransport(ws, { observer: { onWsError } });

    const read = transport.readBinary();
    ws.emit("message", { data: new BadBlob([new Uint8Array([1])]) });

    await expect(read).rejects.toThrow(/boom/);
    expect(onWsError).toHaveBeenCalledWith("error");
  });

  test("maxInboundQueuedBytes allows exact limit then fails on overflow", async () => {
    const ws = new FakeWebSocket();
    const transport = new WebSocketBinaryTransport(ws, { webSocketLimits: { maxInboundQueuedBytes: 3 } });

    ws.emit("message", { data: new Uint8Array([1, 2, 3]).buffer });
    const read = transport.readBinary();
    await expect(read).resolves.toEqual(new Uint8Array([1, 2, 3]));

    ws.emit("message", { data: new Uint8Array([4, 5, 6, 7]).buffer });
    await waitForClosed(ws);
    expect(ws.closed).toBe(true);
  });

  test("serializes writes while the websocket drains below its low watermark", async () => {
    vi.useFakeTimers();
    try {
      const ws = new FakeWebSocket();
      ws.bufferedAmount = 5;
      const transport = new WebSocketBinaryTransport(ws, { webSocketLimits: {
        outboundLowWatermarkBytes: 1,
        outboundHighWatermarkBytes: 4,
        outboundHardLimitBytes: 10,
        outboundDrainTimeoutMs: 100,
      } });
      const first = transport.writeBinary(new Uint8Array([1]));
      const second = transport.writeBinary(new Uint8Array([2]));
      await vi.advanceTimersByTimeAsync(20);
      expect(ws.sent).toHaveLength(0);
      ws.bufferedAmount = 3;
      await vi.advanceTimersByTimeAsync(10);
      expect(ws.sent).toHaveLength(0);
      ws.bufferedAmount = 1;
      await vi.advanceTimersByTimeAsync(10);
      await Promise.all([first, second]);
      expect(ws.sent.map((b) => Array.from(b as Uint8Array))).toEqual([[1], [2]]);
    } finally { vi.useRealTimers(); }
  });

  test("closes when outbound drain exceeds the configured timeout", async () => {
    vi.useFakeTimers();
    try {
      const ws = new FakeWebSocket();
      ws.bufferedAmount = 5;
      const onDiagnosticEvent = vi.fn();
      const transport = new WebSocketBinaryTransport(ws, { observer: { onDiagnosticEvent }, webSocketLimits: {
        outboundLowWatermarkBytes: 1,
        outboundHighWatermarkBytes: 4,
        outboundHardLimitBytes: 10,
        outboundDrainTimeoutMs: 20,
      } });
      const write = transport.writeBinary(new Uint8Array([1]));
      const expected = expect(write).rejects.toThrow(/drain timeout/);
      await vi.advanceTimersByTimeAsync(30);
      await expected;
      expect(ws.closed).toBe(true);
      expect(onDiagnosticEvent).toHaveBeenCalledWith(expect.objectContaining({
        code_domain: "event",
        code: "queue_pressure",
        stage: "transport",
      }));
    } finally { vi.useRealTimers(); }
  });

  test("counts queued serialized writes against the outbound hard limit", async () => {
    const ws = new FakeWebSocket();
    ws.bufferedAmount = 5;
    const transport = new WebSocketBinaryTransport(ws, { webSocketLimits: {
      outboundLowWatermarkBytes: 1,
      outboundHighWatermarkBytes: 4,
      outboundHardLimitBytes: 10,
      outboundDrainTimeoutMs: 100,
    } });
    const first = transport.writeBinary(new Uint8Array(3));
    const firstRejected = expect(first).rejects.toThrow();
    await expect(transport.writeBinary(new Uint8Array(3))).rejects.toThrow(/hard limit/);
    await firstRejected;
    expect(ws.closed).toBe(true);
  });
});

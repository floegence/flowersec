import { describe, expect, test, vi } from "vitest";

import { readU32be, u32be } from "../utils/bin.js";
import type { YamuxStream } from "../yamux/stream.js";
import { PROXY_KIND_WS } from "./constants.js";

const wsModule = vi.hoisted(() => ({ WebSocket: undefined as unknown }));

vi.mock("node:module", () => ({
  createRequire: () => () => ({ WebSocket: wsModule.WebSocket }),
}));

import { serveProxyStream } from "./server.js";

type Listener = (...args: any[]) => void;

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static openError: Error | null = null;
  static holdSendCallbacks = false;
  static throwOnSend = false;
  static autoClose = true;
  static greeting: Uint8Array | null = null;

  static reset(): void {
    this.instances = [];
    this.openError = null;
    this.holdSendCallbacks = false;
    this.throwOnSend = false;
    this.autoClose = true;
    this.greeting = null;
  }

  readonly protocol = "test-protocol";
  readonly sendCalls: Array<{ payload: Uint8Array; binary: boolean }> = [];
  readonly closeCalls: Array<{ code?: number; reason?: string }> = [];
  readyState = 0;
  private paused = false;
  private pendingGreeting: Uint8Array | null = null;
  private readonly listeners = new Map<string, Set<Listener>>();
  private readonly onceListeners = new Map<string, Set<Listener>>();
  private readonly sendCallbacks: Array<(error?: Error | null) => void> = [];

  constructor() {
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      if (FakeWebSocket.openError != null) {
        this.readyState = 3;
        this.emit("error", FakeWebSocket.openError);
        return;
      }
      this.readyState = 1;
      this.emit("open");
      if (FakeWebSocket.greeting != null) {
        if (this.paused) this.pendingGreeting = FakeWebSocket.greeting;
        else this.emit("message", FakeWebSocket.greeting, true);
      }
    });
  }

  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
    if (this.pendingGreeting == null) return;
    const greeting = this.pendingGreeting;
    this.pendingGreeting = null;
    this.emit("message", greeting, true);
  }

  on(type: string, listener: Listener): this {
    this.add(this.listeners, type, listener);
    return this;
  }

  once(type: string, listener: Listener): this {
    this.add(this.onceListeners, type, listener);
    return this;
  }

  off(type: string, listener: Listener): this {
    this.listeners.get(type)?.delete(listener);
    this.onceListeners.get(type)?.delete(listener);
    return this;
  }

  send(payload: Uint8Array, options: { binary: boolean }, callback: (error?: Error | null) => void): void {
    if (FakeWebSocket.throwOnSend) throw new Error("secret synchronous send failure");
    this.sendCalls.push({ payload: payload.slice(), binary: options.binary });
    if (FakeWebSocket.holdSendCallbacks) this.sendCallbacks.push(callback);
    else queueMicrotask(() => callback());
  }

  ping(_payload: Uint8Array, _mask: unknown, callback: (error?: Error | null) => void): void {
    queueMicrotask(() => callback());
  }

  pong(_payload: Uint8Array, _mask: unknown, callback: (error?: Error | null) => void): void {
    queueMicrotask(() => callback());
  }

  close(code?: number, reason?: string): void {
    this.closeCalls.push({ ...(code === undefined ? {} : { code }), ...(reason === undefined ? {} : { reason }) });
    if (this.readyState >= 2) return;
    this.readyState = 2;
    if (FakeWebSocket.autoClose) queueMicrotask(() => this.emitClose(code ?? 1000, reason ?? ""));
  }

  emitMessage(payload: readonly number[], binary = true): void {
    this.emit("message", new Uint8Array(payload), binary);
  }

  emitError(error: Error): void {
    this.emit("error", error);
  }

  emitClose(code: number, reason: string): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    this.emit("close", code, new TextEncoder().encode(reason));
  }

  releaseNextSend(error?: Error): void {
    const callback = this.sendCallbacks.shift();
    if (callback == null) throw new Error("missing pending send callback");
    callback(error);
  }

  private add(map: Map<string, Set<Listener>>, type: string, listener: Listener): void {
    let listeners = map.get(type);
    if (listeners == null) {
      listeners = new Set();
      map.set(type, listeners);
    }
    listeners.add(listener);
  }

  private emit(type: string, ...args: unknown[]): void {
    for (const listener of this.listeners.get(type) ?? []) listener(...args);
    const once = [...(this.onceListeners.get(type) ?? [])];
    this.onceListeners.delete(type);
    for (const listener of once) listener(...args);
  }
}

class TestStream {
  readonly output: Uint8Array[] = [];
  readCalls = 0;
  writeCalls = 0;
  closed = false;
  blockWritesAfter = Number.POSITIVE_INFINITY;
  private readonly input: Uint8Array[];
  private readonly readWaiters: Array<(value: Uint8Array | null) => void> = [];
  private readonly writeWaiters: Array<Readonly<{
    bytes: Uint8Array;
    resolve: () => void;
    reject: (error: Error) => void;
  }>> = [];

  constructor(input: Uint8Array[]) {
    this.input = [...input];
  }

  get remainingInput(): number {
    return this.input.length;
  }

  async read(): Promise<Uint8Array | null> {
    this.readCalls += 1;
    const next = this.input.shift();
    if (next != null) return next;
    return await new Promise((resolve) => this.readWaiters.push(resolve));
  }

  async write(bytes: Uint8Array): Promise<void> {
    this.writeCalls += 1;
    if (this.writeCalls > this.blockWritesAfter) {
      return await new Promise<void>((resolve, reject) => {
        this.writeWaiters.push({ bytes: bytes.slice(), resolve, reject });
      });
    }
    this.output.push(bytes.slice());
  }

  releaseNextWrite(): void {
    const waiter = this.writeWaiters.shift();
    if (waiter == null) throw new Error("missing pending stream write");
    this.output.push(waiter.bytes);
    waiter.resolve();
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    for (const resolve of this.readWaiters.splice(0)) resolve(null);
    for (const waiter of this.writeWaiters.splice(0)) waiter.reject(new Error("stream closed"));
  }

  reset(error: Error): void {
    void this.close();
    for (const waiter of this.writeWaiters.splice(0)) waiter.reject(error);
  }
}

describe("Node proxy WebSocket backpressure", () => {
  test("preserves an upstream greeting emitted immediately after open", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.greeting = new Uint8Array([7, 8, 9]);
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([wsOpenMeta("immediate-greeting")]);
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());
    const raw = await openedWebSocket();

    await waitFor(() => stream.output.length >= 3);
    raw.emitClose(1000, "done");
    await serving;

    const frame = firstWebSocketOutput(stream.output);
    expect(frame.op).toBe(2);
    expect(Array.from(frame.payload)).toEqual([7, 8, 9]);
  });

  test("handles an upstream error while the open response write is blocked", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.autoClose = false;
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([wsOpenMeta("blocked-open-error")]);
    stream.blockWritesAfter = 0;
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());
    const raw = await openedWebSocket();
    await waitFor(() => stream.writeCalls === 1);

    raw.emitError(new Error("upstream failed after open"));

    await serving;
    expect(stream.closed).toBe(true);
    expect(raw.closeCalls.length).toBeGreaterThan(0);
  });

  test("queues an upstream close behind a blocked open response", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.autoClose = false;
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([wsOpenMeta("blocked-open-close")]);
    stream.blockWritesAfter = 0;
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());
    const raw = await openedWebSocket();
    await waitFor(() => stream.writeCalls === 1);

    raw.emitClose(1000, "closed during open response");
    stream.releaseNextWrite();
    await waitFor(() => stream.writeCalls === 2);
    stream.releaseNextWrite();
    await waitFor(() => stream.writeCalls === 3);
    stream.releaseNextWrite();
    await serving;

    expect(firstJsonOutput(stream.output)).toMatchObject({ ok: true });
    const frame = firstWebSocketOutput(stream.output);
    expect(frame.op).toBe(8);
    expect(new TextDecoder().decode(frame.payload.subarray(2))).toBe("closed during open response");
  });

  test("waits for the upstream send callback before reading the next Yamux frame", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.holdSendCallbacks = true;
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([
      wsOpenMeta("callback-gating"),
      wsFrame(2, [1, 2, 3]),
      wsFrame(2, [4, 5, 6]),
    ]);
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());
    const raw = await openedWebSocket();

    await waitFor(() => raw.sendCalls.length === 1);
    expect(stream.remainingInput).toBe(1);
    raw.releaseNextSend();
    await waitFor(() => raw.sendCalls.length === 2);
    expect(stream.remainingInput).toBe(0);
    raw.releaseNextSend();
    raw.emitClose(1000, "done");

    await serving;
    expect(raw.sendCalls.map((call) => Array.from(call.payload))).toEqual([
      [1, 2, 3],
      [4, 5, 6],
    ]);
  });

  test("session cancellation interrupts a pending upstream send callback", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.holdSendCallbacks = true;
    FakeWebSocket.autoClose = false;
    wsModule.WebSocket = FakeWebSocket;
    const stop = new AbortController();
    const stream = new TestStream([
      wsOpenMeta("callback-cancel"),
      wsFrame(2, [1, 2, 3]),
    ]);
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options(), stop.signal);
    const raw = await openedWebSocket();

    await waitFor(() => raw.sendCalls.length === 1);
    stop.abort(new Error("session stopped"));

    await serving;
    expect(raw.closeCalls.length).toBeGreaterThan(0);
    expect(stream.closed).toBe(true);
  });

  test("closes when upstream frames exceed the per-connection queued byte limit", async () => {
    FakeWebSocket.reset();
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([wsOpenMeta("queue-limit")]);
    stream.blockWritesAfter = 1;
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, {
      ...options(),
      maxWsFrameBytes: 64,
      maxWsQueuedBytes: 12,
    });
    const raw = await openedWebSocket();

    raw.emitMessage([1, 2, 3]);
    raw.emitMessage([4, 5, 6]);

    await serving;
    expect(raw.closeCalls).toContainEqual({ code: 1011, reason: "proxy buffer limit exceeded" });
    expect(stream.closed).toBe(true);
    expect(stream.output).toHaveLength(1);
  });

  test("handles a synchronous upstream send failure", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.throwOnSend = true;
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([
      wsOpenMeta("sync-send"),
      wsFrame(1, [1]),
    ]);

    await serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());

    expect(FakeWebSocket.instances[0]?.closeCalls.length).toBeGreaterThan(0);
    expect(stream.closed).toBe(true);
  });

  test("waits for upstream close and writes the final close frame", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.autoClose = false;
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([
      wsOpenMeta("close-handshake"),
      wsFrame(8, closePayload(1000, "client done")),
    ]);
    let settled = false;
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options())
      .finally(() => { settled = true; });
    await waitFor(() => FakeWebSocket.instances.length === 1);
    const raw = FakeWebSocket.instances[0]!;

    await waitFor(() => raw.closeCalls.length === 1);
    await Promise.resolve();
    expect(settled).toBe(false);
    raw.emitClose(1000, "upstream done");
    await serving;

    const frame = firstWebSocketOutput(stream.output);
    expect(frame.op).toBe(8);
    expect((frame.payload[0]! << 8) | frame.payload[1]!).toBe(1000);
    expect(new TextDecoder().decode(frame.payload.subarray(2))).toBe("upstream done");
  });

  test("session cancellation interrupts a pending upstream close handshake", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.autoClose = false;
    wsModule.WebSocket = FakeWebSocket;
    const stop = new AbortController();
    const stream = new TestStream([
      wsOpenMeta("close-cancel"),
      wsFrame(8, closePayload(1000, "client done")),
    ]);
    const serving = serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options(), stop.signal);
    await waitFor(() => FakeWebSocket.instances.length === 1);
    const raw = FakeWebSocket.instances[0]!;

    await waitFor(() => raw.closeCalls.length === 1);
    stop.abort(new Error("session stopped"));

    await serving;
    expect(stream.closed).toBe(true);
  });

  test("sanitizes upstream WebSocket dial errors", async () => {
    FakeWebSocket.reset();
    FakeWebSocket.openError = new Error("connect secret.internal.example:9443 token=do-not-return");
    wsModule.WebSocket = FakeWebSocket;
    const stream = new TestStream([wsOpenMeta("dial-error")]);

    await serveProxyStream(PROXY_KIND_WS, stream as unknown as YamuxStream, options());

    const response = firstJsonOutput(stream.output);
    expect(response).toMatchObject({
      ok: false,
      error: {
        code: "upstream_ws_dial_failed",
        message: "upstream WebSocket connection failed",
      },
    });
    expect(JSON.stringify(response)).not.toContain("secret.internal.example");
  });
});

function options() {
  return {
    upstream: "http://127.0.0.1",
    maxWsFrameBytes: 1024,
    maxWsQueuedBytes: 2048,
  } as const;
}

function wsOpenMeta(connId: string): Uint8Array {
  return jsonFrame({ v: 1, conn_id: connId, path: "/socket", headers: [] });
}

function jsonFrame(value: unknown): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(value));
  const frame = new Uint8Array(4 + json.length);
  frame.set(u32be(json.length), 0);
  frame.set(json, 4);
  return frame;
}

function wsFrame(op: number, payload: readonly number[] | Uint8Array): Uint8Array {
  const bytes = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const frame = new Uint8Array(5 + bytes.length);
  frame[0] = op;
  frame.set(u32be(bytes.length), 1);
  frame.set(bytes, 5);
  return frame;
}

function closePayload(code: number, reason: string): Uint8Array {
  const reasonBytes = new TextEncoder().encode(reason);
  const payload = new Uint8Array(2 + reasonBytes.length);
  payload[0] = (code >>> 8) & 0xff;
  payload[1] = code & 0xff;
  payload.set(reasonBytes, 2);
  return payload;
}

function firstJsonOutput(chunks: readonly Uint8Array[]): Record<string, unknown> {
  const bytes = concat(chunks);
  const length = readU32be(bytes, 0);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + length))) as Record<string, unknown>;
}

function firstWebSocketOutput(chunks: readonly Uint8Array[]): Readonly<{ op: number; payload: Uint8Array }> {
  const bytes = concat(chunks);
  const jsonLength = readU32be(bytes, 0);
  const offset = 4 + jsonLength;
  const payloadLength = readU32be(bytes, offset + 1);
  return {
    op: bytes[offset]!,
    payload: bytes.subarray(offset + 5, offset + 5 + payloadLength),
  };
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

async function openedWebSocket(): Promise<FakeWebSocket> {
  await waitFor(() => FakeWebSocket.instances.length === 1 && FakeWebSocket.instances[0]?.readyState === 1);
  return FakeWebSocket.instances[0]!;
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("timed out waiting for proxy WebSocket state");
}

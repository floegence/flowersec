import { afterEach, describe, expect, it } from "vitest";

import { u16be, u32be } from "../utils/bin.js";
import type { ByteStream, OperationOptions } from "../public/contract.js";
import type { ProxyRuntimeLimits } from "./types.js";
import { installWebSocketPatch } from "./wsPatch.js";

const savedGlobals = new Map<PropertyKey, PropertyDescriptor | undefined>();

function setGlobal(name: PropertyKey, value: unknown): void {
  if (!savedGlobals.has(name)) savedGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
}

afterEach(() => {
  for (const [name, descriptor] of savedGlobals) {
    if (descriptor === undefined) delete (globalThis as Record<PropertyKey, unknown>)[name];
    else Object.defineProperty(globalThis, name, descriptor);
  }
  savedGlobals.clear();
});

class TestCloseEvent extends Event {
  readonly code: number;
  readonly reason: string;
  readonly wasClean: boolean;

  constructor(type: string, init: CloseEventInit = {}) {
    super(type);
    this.code = init.code ?? 0;
    this.reason = init.reason ?? "";
    this.wasClean = init.wasClean ?? false;
  }
}

class ControlledStream implements ByteStream {
  readonly kind = "test";
  terminalError = undefined;
  readonly writes: Uint8Array[] = [];
  resetCalled = false;
  closed = false;
  failWrites = false;
  private readonly reads: Uint8Array[] = [];
  private readonly waiters: Array<Readonly<{
    resolve(value: Uint8Array): void;
    reject(error: unknown): void;
    signal?: AbortSignal;
    onAbort?: () => void;
  }>> = [];

  constructor(private readonly observeAbort = false) {}

  push(value: Uint8Array): void {
    const waiter = this.waiters.shift();
    if (waiter === undefined) this.reads.push(value);
    else {
      waiter.signal?.removeEventListener("abort", waiter.onAbort!);
      waiter.resolve(value);
    }
  }

  async read(options: OperationOptions = {}): Promise<Uint8Array | null> {
    const value = this.reads.shift();
    if (value !== undefined) return value;
    return await new Promise<Uint8Array>((resolve, reject) => {
      const waiter: {
        resolve(value: Uint8Array): void;
        reject(error: unknown): void;
        signal?: AbortSignal;
        onAbort?: () => void;
      } = { resolve, reject };
      if (this.observeAbort && options.signal !== undefined) {
        waiter.signal = options.signal;
        waiter.onAbort = () => {
          const index = this.waiters.indexOf(waiter);
          if (index >= 0) this.waiters.splice(index, 1);
          reject(options.signal?.reason ?? new Error("aborted"));
        };
        if (options.signal.aborted) waiter.onAbort();
        else {
          options.signal.addEventListener("abort", waiter.onAbort, { once: true });
          this.waiters.push(waiter);
        }
      } else this.waiters.push(waiter);
    });
  }

  async write(data: Uint8Array): Promise<number> {
    if (this.failWrites) throw new Error("write failed");
    const count = Math.min(2, data.length);
    this.writes.push(data.subarray(0, count).slice());
    return count;
  }

  async closeWrite(): Promise<void> { this.read = async () => null; }
  async reset(): Promise<void> { this.resetCalled = true; }
  async close(): Promise<void> { this.closed = true; }
}

const limits: ProxyRuntimeLimits = {
  maxJsonFrameBytes: 1024,
  maxChunkBytes: 1024,
  maxBodyBytes: 4096,
  maxWsFrameBytes: 1024,
  maxWsBufferedAmountBytes: 4096,
  maxConcurrentHttpStreams: 4,
  maxConcurrentEventStreams: 2,
  maxQueuedHttpRequests: 8,
  maxQueuedHttpBodyBytes: 8192,
};

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function frame(opcode: number, payload: Uint8Array): Uint8Array {
  return concat([new Uint8Array([opcode]), u32be(payload.length), payload]);
}

function writtenOpcodes(chunks: readonly Uint8Array[]): number[] {
  const value = concat(chunks);
  const result: number[] = [];
  for (let offset = 0; offset < value.length;) {
    result.push(value[offset]!);
    const length = new DataView(value.buffer, value.byteOffset + offset + 1, 4).getUint32(0);
    offset += 5 + length;
  }
  return result;
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("condition was not reached");
}

class NativeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  readonly input: string | URL;
  readonly protocols: string | string[] | undefined;

  constructor(input: string | URL, protocols?: string | string[]) {
    this.input = input;
    this.protocols = protocols;
  }
}

function installBrowserGlobals(): void {
  setGlobal("CloseEvent", TestCloseEvent);
  setGlobal("WebSocket", NativeWebSocket);
  setGlobal("location", new URL("https://app.example/workbench"));
}

describe("WebSocket v2 proxy patch", () => {
  it("dispatches property handlers at their registered position", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream();
    installWebSocketPatch({ runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) } });
    const socket = new WebSocket("wss://app.example/socket");
    const calls: string[] = [];
    const old = () => calls.push("old");
    socket.addEventListener("message", () => calls.push("first"));
    socket.onmessage = old;
    socket.addEventListener("message", () => calls.push("last"));
    socket.onmessage = function (event) {
      if (this === socket && event.target === socket) calls.push("replacement");
    };
    socket.dispatchEvent(new MessageEvent("message"));
    socket.onmessage = null;
    socket.onmessage = old;
    socket.dispatchEvent(new MessageEvent("message"));
    expect(calls).toEqual(["first", "replacement", "last", "first", "last", "old"]);
    stream.push(frame(8, new Uint8Array()));
    await waitFor(() => socket.readyState === WebSocket.CLOSED);
  });

  it("releases a late handshake without reopening a closed socket", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream(true);
    let complete!: (value: { stream: ByteStream; protocol: string }) => void;
    const handshake = new Promise<{ stream: ByteStream; protocol: string }>(resolve => { complete = resolve; });
    installWebSocketPatch({ runtime: { limits, openWebSocketStream: () => handshake } });
    const socket = new WebSocket("wss://app.example/socket");
    const events: string[] = [];
    for (const type of ["error", "close", "open"]) socket.addEventListener(type, () => events.push(type));
    socket.close();
    complete({ stream, protocol: "late" });
    await waitFor(() => stream.resetCalled);
    expect(events).toEqual(["error", "close"]);
    expect(socket.readyState).toBe(WebSocket.CLOSED);
    expect(socket.protocol).toBe("");
  });

  it("bounds pending empty data messages and reuses drained slots", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream(true);
    let delivered = 0;
    stream.write = async data => { delivered++; return data.length; };
    installWebSocketPatch({ runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) } });
    const socket = new WebSocket("wss://app.example/socket");
    await new Promise<void>(resolve => socket.addEventListener("open", () => resolve(), { once: true }));
    for (let count = 0; count < 1024; count++) socket.send("");
    await waitFor(() => delivered === 1024);
    for (let count = 0; count < 1024; count++) socket.send(new Uint8Array());
    expect(socket.bufferedAmount).toBe(0);
    expect(socket.readyState).toBe(WebSocket.OPEN);
    socket.send("");
    expect(socket.readyState).toBe(WebSocket.CLOSED);
    expect(stream.resetCalled).toBe(true);
  });

  it("keeps each outbound frame in one stream write without a header-only encrypted record", async () => {
    installBrowserGlobals();
    class FullWriteStream extends ControlledStream {
      override async write(data: Uint8Array): Promise<number> {
        this.writes.push(data.slice());
        return data.length;
      }
    }
    const stream = new FullWriteStream(true);
    installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
      shouldProxy: () => true,
    });
    const socket = new WebSocket("wss://app.example/socket");
    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));
    const binary = new Uint8Array([1, 2, 3]);
    socket.send(binary);
    socket.send("key");
    await waitFor(() => socket.bufferedAmount === 0);
    expect(stream.writes).toEqual([
      frame(2, binary), frame(1, new TextEncoder().encode("key")),
    ]);
    stream.push(frame(8, u16be(1000)));
    await waitFor(() => stream.closed);
  });

  it("completes a locally initiated close handshake without reporting 1006", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream();
    installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
      shouldProxy: () => true,
      closeHandshakeTimeoutMs: 100,
    });
    const socket = new WebSocket("wss://app.example/socket");
    const events: string[] = [];
    socket.addEventListener("error", () => events.push("error"));
    socket.addEventListener("close", () => events.push("close"));
    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));
    socket.close(1000, "done");
    await waitFor(() => writtenOpcodes(stream.writes).includes(8));
    expect(socket.readyState).toBe(WebSocket.CLOSING);
    expect(events).toEqual([]);
    const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", (event) => resolve(event as CloseEvent), { once: true }));
    stream.push(frame(8, concat([u16be(1000), new TextEncoder().encode("done")])));
    const close = await closed;
    expect(close).toMatchObject({ code: 1000, reason: "done", wasClean: true });
    expect(events).toEqual(["close"]);
    await waitFor(() => stream.closed);
  });

  it("exposes an empty peer close as no status", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream();
    installWebSocketPatch({ runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) }, shouldProxy: () => true });
    const socket = new WebSocket("wss://app.example/socket");
    const closed = new Promise<CloseEvent>(resolve => socket.addEventListener("close", resolve));
    stream.push(frame(8, new Uint8Array()));
    await expect(closed).resolves.toMatchObject({ code: 1005, wasClean: true });
  });

  it("reports timeout and close-frame write failures as error then unclean close", async () => {
    for (const mode of ["timeout_ignores_abort", "timeout_observes_abort", "write_failure"] as const) {
      installBrowserGlobals();
      const stream = new ControlledStream(mode === "timeout_observes_abort");
      installWebSocketPatch({
        runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
        shouldProxy: () => true,
        closeHandshakeTimeoutMs: 10,
      });
      const socket = new WebSocket("wss://app.example/socket");
      const events: string[] = [];
      socket.addEventListener("error", () => events.push("error"));
      await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));
      if (mode === "write_failure") stream.failWrites = true;
      const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", (event) => {
        events.push("close");
        resolve(event as CloseEvent);
      }, { once: true }));
      socket.close(1000);
      await expect(closed).resolves.toMatchObject({ code: 1006, wasClean: false });
      expect(events).toEqual(["error", "close"]);
      expect(stream.resetCalled).toBe(true);
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(events).toEqual(["error", "close"]);
    }
  });

  it("completes a simultaneous local and peer close exactly once", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream(true);
    installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
      shouldProxy: () => true,
      closeHandshakeTimeoutMs: 100,
    });
    const socket = new WebSocket("wss://app.example/socket");
    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));
    const events: string[] = [];
    socket.addEventListener("error", () => events.push("error"));
    const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", (event) => {
      events.push("close");
      resolve(event as CloseEvent);
    }));
    socket.close(1000, "same-time");
    stream.push(frame(8, concat([u16be(1000), new TextEncoder().encode("same-time")])));
    await expect(closed).resolves.toMatchObject({ code: 1000, reason: "same-time", wasClean: true });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(events).toEqual(["close"]);
    expect(writtenOpcodes(stream.writes).filter((opcode) => opcode === 8)).toHaveLength(1);
  });

  it.each([false, true])("bounds queued writes after peer close (local close: %s)", async localClose => {
    installBrowserGlobals();
    const stream = new ControlledStream(true);
    let resume!: (count: number) => void;
    stream.write = () => new Promise<number>(resolve => { resume = resolve; });
    installWebSocketPatch({ runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) }, shouldProxy: () => true, closeHandshakeTimeoutMs: 20 });
    const socket = new WebSocket("wss://app.example/socket");
    await new Promise<void>(resolve => socket.addEventListener("open", () => resolve()));
    const closed = new Promise<CloseEvent>(resolve => socket.addEventListener("close", resolve));
    socket.send("blocked");
    if (localClose) socket.close();
    stream.push(frame(8, u16be(1000)));
    await expect(closed).resolves.toMatchObject({ code: 1006, wasClean: false });
    expect(stream.resetCalled).toBe(true);
    resume(0);
  });

  it("proxies same-origin frames while preserving native cross-origin sockets", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream();
    const opens: Array<Readonly<{ path: string; protocols: readonly string[] | undefined }>> = [];
    const patch = installWebSocketPatch({
      runtime: {
        limits,
        async openWebSocketStream(path, options) {
          opens.push({ path, protocols: options?.protocols });
          return { stream, protocol: "chat" };
        },
      },
    });

    const native = new WebSocket("wss://elsewhere.example/socket", "native") as unknown as NativeWebSocket;
    expect(native).toBeInstanceOf(NativeWebSocket);
    expect(native.protocols).toBe("native");

    const socket = new WebSocket("wss://app.example/socket?q=1", "chat");
    const messages: unknown[] = [];
    let objectListenerCalls = 0;
    const objectListener = { handleEvent: () => { objectListenerCalls++; } };
    socket.addEventListener("message", objectListener);
    let singleCalls = 0;
    let canceledCalls = 0;
    const subscription = new AbortController();
    socket.addEventListener("message", () => { singleCalls++; }, { once: true });
    socket.addEventListener("message", () => { canceledCalls++; }, { signal: subscription.signal });
    subscription.abort();
    socket.addEventListener("message", (event) => messages.push((event as MessageEvent).data));
    socket.onmessage = () => { throw new Error("application listener failure"); };
    await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));

    expect(opens).toEqual([{ path: "/socket?q=1", protocols: ["chat"] }]);
    expect(socket.readyState).toBe(WebSocket.OPEN);
    expect(socket.protocol).toBe("chat");
    socket.binaryType = "arraybuffer";
    socket.send("hello");
    socket.send(new Blob([new Uint8Array([1, 2])]));
    socket.send(new Uint8Array([3, 4]));
    socket.send(new Uint8Array([5, 6]).buffer);
    await waitFor(() => socket.bufferedAmount === 0);

    const closePayload = concat([u16be(1000), new TextEncoder().encode("done")]);
    const closed = new Promise<CloseEvent>((resolve) => socket.addEventListener("close", (event) => resolve(event as CloseEvent), { once: true }));
    stream.push(concat([
      frame(9, new Uint8Array([8])),
      frame(1, new TextEncoder().encode("reply")),
      frame(2, new Uint8Array([9, 7])),
      frame(8, closePayload),
    ]));
    const closeEvent = await closed;
    await waitFor(() => writtenOpcodes(stream.writes).length === 6);

    expect(messages[0]).toBe("reply");
    expect(new Uint8Array(messages[1] as ArrayBuffer)).toEqual(new Uint8Array([9, 7]));
    expect(objectListenerCalls).toBe(2);
    expect(singleCalls).toBe(1);
    expect(canceledCalls).toBe(0);
    socket.removeEventListener("message", objectListener);
    socket.dispatchEvent(new MessageEvent("message", { data: "local" }));
    expect(objectListenerCalls).toBe(2);
    expect(writtenOpcodes(stream.writes)).toEqual([1, 2, 2, 2, 10, 8]);
    expect(closeEvent).toMatchObject({ code: 1000, reason: "done", wasClean: true });
    expect(socket.readyState).toBe(WebSocket.CLOSED);

    patch.uninstall();
    expect(globalThis.WebSocket).toBe(NativeWebSocket);
  });

  it("fails closed for invalid limits, oversized sends, and connector failures", async () => {
    installBrowserGlobals();
    const stream = new ControlledStream();
    expect(() => installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
      maxWsFrameBytes: 0,
    })).toThrow(TypeError);

    installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => ({ stream, protocol: "" }) },
      shouldProxy: () => true,
      maxWsFrameBytes: 4,
      maxWsBufferedAmountBytes: 4,
    });
    const oversized = new WebSocket("wss://app.example/socket");
    await new Promise<void>((resolve) => oversized.addEventListener("open", () => resolve(), { once: true }));
    const failed = new Promise<CloseEvent>((resolve) => oversized.addEventListener("close", (event) => resolve(event as CloseEvent), { once: true }));
    oversized.send("12345");
    expect(await failed).toMatchObject({ code: 1006, wasClean: false });
    expect(oversized.readyState).toBe(WebSocket.CLOSED);
    expect(() => oversized.send("x")).toThrow(DOMException);

    setGlobal("WebSocket", NativeWebSocket);
    installWebSocketPatch({
      runtime: { limits, openWebSocketStream: async () => { throw new Error("private connector detail"); } },
      shouldProxy: () => true,
    });
    const rejected = new WebSocket("wss://app.example/rejected");
    const rejectedClose = await new Promise<CloseEvent>((resolve) => rejected.addEventListener("close", (event) => resolve(event as CloseEvent), { once: true }));
    expect(rejectedClose).toMatchObject({ code: 1006, reason: "proxy WebSocket failed" });
  });

  it("is a no-op when the browser has no WebSocket constructor", () => {
    setGlobal("WebSocket", undefined);
    const patch = installWebSocketPatch({
      runtime: {
        limits,
        openWebSocketStream: async () => { throw new Error("unused"); },
      },
    });
    patch.uninstall();
    expect(globalThis.WebSocket).toBeUndefined();
  });
});

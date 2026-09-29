import { describe, expect, it, vi } from "vitest";

import { u32be } from "../utils/bin.js";
import type { ByteStream, Session, StreamOpenOptions } from "../public/contract.js";
import { createProxyRuntimeWithStreams as createProxyRuntime } from "./runtime.js";
import {encodeProxyMetadata,decodeProxyMetadata} from "./wire.js";
import { matchesPathPrefix, normalizeSubtreePath } from "./policy.js";
import { registerProxyRuntimeServiceWorkerBridge } from "./serviceWorkerRuntime.js";

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

function bodyEnd(): Uint8Array { return concat([u32be(0),metadataFrame({v:2,trailers:[]})]); }

function metadataFrame(value: unknown): Uint8Array {
  const v=value as Record<string,unknown>;
  const payload = encodeProxyMetadata(Object.hasOwn(v,"trailers")?"ProxyBodyEnd":Object.hasOwn(v,"request_id")?"ProxyHTTPResponse":"ProxyWebSocketResponse",v);
  return concat([u32be(payload.length), payload]);
}

class FakeStream implements ByteStream {
  readonly kind = "fake";
  terminalError = undefined;
  readonly writes: Uint8Array[] = [];
  wsResponseProtocol: string | undefined;
  wsFirstFrame: Uint8Array = new Uint8Array();
  readCalls = 0;
  closed = false;
  resetCalled = false;
  private readonly reads: Array<Uint8Array | Error | null>;

  constructor(reads: Array<Uint8Array | Error | null>, private readonly partialWrite = 3) { this.reads = reads; }
  async read(): Promise<Uint8Array | null> {
    this.readCalls++;
    if(this.wsResponseProtocol !== undefined && this.readCalls===1) return concat([metadataFrame({v:2,conn_id:firstWrittenMetadata(this).conn_id,ok:true,protocol:this.wsResponseProtocol}), this.wsFirstFrame]);
    const value = this.reads.shift() ?? null;
    if (value instanceof Error) throw value;
    return value;
  }
  async write(data: Uint8Array): Promise<number> {
    const count = Math.min(this.partialWrite, data.length);
    this.writes.push(data.subarray(0, count).slice());
    return count;
  }
  async closeWrite(): Promise<void> {}
  async reset(): Promise<void> { this.resetCalled = true; }
  async close(): Promise<void> { this.closed = true; }
}

class FakeSession implements Session {
  readonly rpc = {} as Session["rpc"];
  readonly termination = new Promise<never>(() => undefined);
  readonly opens: Array<Readonly<{ kind: string; options: StreamOpenOptions | undefined }>> = [];
  constructor(private readonly streams: FakeStream[]) {}
  async openStream(kind: string, options?: StreamOpenOptions): Promise<ByteStream> {
    this.opens.push({ kind, options });
    const stream = this.streams.shift();
    if (stream === undefined) throw new Error("missing fake stream");
    return stream;
  }
  async acceptStream(): Promise<never> { throw new Error("unused"); }
  async rekey(): Promise<void> {}
  async probeLiveness(): Promise<number> { return 0; }
  async waitTermination(): Promise<never> { return await this.termination; }
  async close(): Promise<void> {}
}

async function collectPort(port: MessagePort, terminal: string): Promise<Record<string, unknown>[]> {
  return await new Promise((resolve, reject) => {
    const values: Record<string, unknown>[] = [];
    const timer = setTimeout(() => reject(new Error("message collection timed out")), 1_000);
    port.onmessage = (event) => {
      values.push(event.data as Record<string, unknown>);
      if (event.data?.type === terminal || event.data?.type === "flowersec-proxy:response_error") {
        clearTimeout(timer);
        port.close();
        resolve(values);
      }
    };
    port.start();
  });
}

describe("Session proxy runtime", () => {
  it("rejects hidden length mismatches before opening a stream", async () => {
    const session = new FakeSession([]);
    const runtime = createProxyRuntime({ session });
    const channel = new MessageChannel();
    const result = collectPort(channel.port2, "flowersec-proxy:response_error");
    runtime.dispatchFetch({ id: "mismatch", method: "POST", path: "/", headers: [
      { name: "connection", value: "content-length" }, { name: "content-length", value: "9" },
    ], body: new Uint8Array([1]).buffer }, channel.port1);
    expect((await result)[0]?.type).toBe("flowersec-proxy:response_error");
    expect(session.opens).toHaveLength(0);
    runtime.dispose();
  });

  it.each([false, true])("validates response length before the terminal even when Connection hides it: %s", async (hidden) => {
    const fields = [{ name: "content-length", value: "3" }];
    if (hidden) fields.push({ name: "connection", value: "content-length" });
    const stream = new FakeStream([concat([
      metadataFrame({ v: 2, request_id: "short", ok: true, status: 200, headers: fields }),
      u32be(2), new Uint8Array([111, 107]), bodyEnd(),
    ])]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
    const channel = new MessageChannel();
    const result = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({ id: "short", method: "GET", path: "/", headers: [] }, channel.port1);
    const messages = await result;
    expect(messages.map(message => message.type)).toEqual(["flowersec-proxy:response_meta", "flowersec-proxy:response_chunk", "flowersec-proxy:response_error"]);
    expect(messages[0]?.headers).toEqual(hidden ? [] : [{ name: "content-length", value: "3" }]);
    expect(stream.resetCalled).toBe(true);
    runtime.dispose();
  });

  it("requires the bounded terminal after a zero-length body marker", async () => {
    const stream = new FakeStream([concat([
      metadataFrame({ v: 2, request_id: "truncated", ok: true, status: 204, headers: [] }), u32be(0),
    ])]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
    const channel = new MessageChannel();
    const result = collectPort(channel.port2, "flowersec-proxy:response_error");
    runtime.dispatchFetch({ id: "truncated", method: "GET", path: "/", headers: [] }, channel.port1);
    expect((await result).map(message => message.type)).toEqual(["flowersec-proxy:response_error"]);
    expect(stream.resetCalled).toBe(true);
    runtime.dispose();
  });

  it("forwards declared HTTP headers without expanding WebSocket access", async () => {
    const stream = new FakeStream([concat([
      metadataFrame({ v: 2, request_id: "platform", ok: true, status: 200, headers: [] }), bodyEnd(),
    ])]);
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({
      session,
      pathPolicy: {
        allowedPathPrefixes: ["/app/", "/platform/api/"],
        allowedWebSocketPathPrefixes: ["/app/"],
      },
      extraRequestHeaders: ["X-Platform-CSRF"],
    });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({
      id: "platform", method: "POST", path: "/platform/api/catalog/query",
      headers: [
        { name: "Content-Type", value: "application/json" },
        { name: "X-Platform-CSRF", value: "proof" },
        { name: "Authorization", value: "secret" },
        { name: "X-Unlisted", value: "private" },
      ],
      body: new TextEncoder().encode("{}").buffer,
    }, channel.port1);
    expect(await collecting).toContainEqual(expect.objectContaining({ status: 200 }));
    expect(firstWrittenMetadata(stream)).toMatchObject({ headers: [
      { name: "content-type", value: "application/json" },
      { name: "x-platform-csrf", value: "proof" },
    ] });
    await expect(runtime.openWebSocketStream("/platform/api/events")).rejects.toThrow(/not allowed/);
    for (const path of ["/private/", "/platform/api-other/", "/platform/api/../../private/"]) {
      const blocked = new MessageChannel();
      const result = collectPort(blocked.port2, "flowersec-proxy:response_error");
      runtime.dispatchFetch({ id: "denied", method: "GET", path, headers: [] }, blocked.port1);
      expect(await result).toContainEqual(expect.objectContaining({ status: path.includes("..") ? 400 : 403 }));
    }
    expect(session.opens).toHaveLength(1);
    runtime.dispose();
  });

  it("canonicalizes HTTP and WebSocket paths before applying policy and sending upstream", async () => {
    for (const path of [
      "/safe/../admin",
      "/safe/./../admin",
      "/safe/%2e%2e/admin",
      "/safe\\..\\admin",
      "/%61dmin",
    ]) {
      const session = new FakeSession([]);
      const runtime = createProxyRuntime({ session, pathPolicy: { deniedPathPrefixes: ["/admin"] } });
      const channel = new MessageChannel();
      const collecting = collectPort(channel.port2, "flowersec-proxy:response_error");
      runtime.dispatchFetch({ id: path, method: "GET", path, headers: [] }, channel.port1);
      await expect(collecting).resolves.toEqual([
        expect.objectContaining(path === "/%61dmin" ? { status: 403, code: "policy_denied" } : { status: 400, code: "invalid_request" }),
      ]);
      expect(session.opens).toEqual([]);
      await expect(runtime.openWebSocketStream(path)).rejects.toThrow();
      runtime.dispose();
    }

    const httpStream = new FakeStream([concat([
      metadataFrame({ v: 2, request_id: "canonical", ok: true, status: 204, headers: [] }),
      bodyEnd(),
    ])]);
    const wsStream = new FakeStream([]);
    wsStream.wsResponseProtocol="";
    const session = new FakeSession([httpStream, wsStream]);
    const runtime = createProxyRuntime({ session, pathPolicy: { allowedPathPrefixes: ["/api"] } });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({
      id: "canonical", method: "GET", path: "/api//items?q=%7euser", headers: [],
    }, channel.port1);
    await collecting;
    expect(firstWrittenMetadata(httpStream)).toMatchObject({ path: "/api//items?q=%7euser" });
    await runtime.openWebSocketStream("/api//socket?q=1");
    expect(firstWrittenMetadata(wsStream)).toMatchObject({ path: "/api//socket?q=1" });
    for (const path of ["/api/%2fadmin", "/api/%5cadmin"]) {
      const rejectedChannel = new MessageChannel();
      const rejected = collectPort(rejectedChannel.port2, "flowersec-proxy:response_error");
      runtime.dispatchFetch({ id: path, method: "GET", path, headers: [] }, rejectedChannel.port1);
      await expect(rejected).resolves.toEqual([
        expect.objectContaining({ status: 400, code: "invalid_request" }),
      ]);
      await expect(runtime.openWebSocketStream(path)).rejects.toThrow(/encoded separator|forbidden segment/);
    }
    runtime.dispose();
  });

  it("streams an HTTP request with partial writes and returns bounded response messages", async () => {
    const response = concat([
      metadataFrame({ v: 2, request_id: "request-1", ok: true, status: 201, headers: [{ name: "content-type", value: "text/plain" }] }),
      u32be(2), new Uint8Array([111, 107]), bodyEnd(),
    ]);
    const stream = new FakeStream([response, null]);
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({ session, maxChunkBytes: 8, maxBodyBytes: 64 });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({
      id: "request-1",
      method: "POST",
      path: "/api?q=1",
      headers: [{ name: "content-type", value: "text/plain" }, { name: "authorization", value: "secret" }],
      body: new Uint8Array([1, 2, 3]).buffer,
    }, channel.port1);
    const messages = await collecting;

    expect(session.opens).toEqual([{
      kind: "flowersec-proxy/http1",
      options: expect.objectContaining({
        metadata: expect.objectContaining({ values: { protocol: "flowersec.proxy.http", version: 2 } }),
      }),
    }]);
    expect(messages.map((message) => message.type)).toEqual([
      "flowersec-proxy:response_meta",
      "flowersec-proxy:response_chunk",
      "flowersec-proxy:response_end",
    ]);
    expect(new TextDecoder().decode(new Uint8Array(messages[1]!.data as ArrayBuffer))).toBe("ok");
    expect(new TextDecoder().decode(concat(stream.writes))).not.toContain("secret");
    expect(stream.closed).toBe(true);
    runtime.dispose();
  });

  it("redacts internal stream failures", async () => {
    const stream = new FakeStream([new Error("private endpoint detail")]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_error");
    runtime.dispatchFetch({ id: "failure", method: "GET", path: "/", headers: [] }, channel.port1);
    const [failure] = await collecting;
    expect(failure).toMatchObject({ status: 502, code: "operation_failed", message: "proxy request failed" });
    expect(JSON.stringify(failure)).not.toContain("private endpoint detail");
    expect(stream.resetCalled).toBe(true);
    runtime.dispose();
  });

  it("does not read the next response chunk without Service Worker credit", async () => {
    const stream = new FakeStream([
      metadataFrame({ v: 2, request_id: "credit", ok: true, status: 200, headers: [] }),
      concat([u32be(1), Uint8Array.of(1)]),
      concat([u32be(1), Uint8Array.of(2)]),
      bodyEnd(),
    ]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]), maxChunkBytes: 8, maxBodyBytes: 64 });
    const serviceWorker = new EventTarget();
    const bridge = registerProxyRuntimeServiceWorkerBridge(
      runtime,
      serviceWorker as ServiceWorkerContainer,
    );
    const channel = new MessageChannel();
    channel.port2.start();
    const metadata = nextPortMessage(channel.port2);
    serviceWorker.dispatchEvent(new MessageEvent("message", {
      data: {
        type: "flowersec-proxy:fetch",
        req: {
          id: "credit", method: "GET", path: "/stream", headers: [],
          response_flow_control: "chunk_credit_v2",
        },
      },
      ports: [channel.port1],
    }));
    await expect(metadata).resolves.toMatchObject({ type: "flowersec-proxy:response_meta", status: 200 });
    await eventLoopTurn();
    expect(stream.readCalls).toBe(1);

    let message = nextPortMessage(channel.port2);
    channel.port2.postMessage({ type: "flowersec-proxy:response_credit" });
    await expect(message).resolves.toMatchObject({ type: "flowersec-proxy:response_chunk" });
    await eventLoopTurn();
    expect(stream.readCalls).toBe(2);

    message = nextPortMessage(channel.port2);
    channel.port2.postMessage({ type: "flowersec-proxy:abort" });
    await expect(message).resolves.toMatchObject({
      type: "flowersec-proxy:response_error", status: 499, code: "canceled",
    });
    expect(stream.resetCalled).toBe(true);
    channel.port2.close();
    bridge.dispose();
    runtime.dispose();
  });

  it("opens WebSockets through a carrier-neutral ByteStream", async () => {
    const stream = new FakeStream([]); stream.wsResponseProtocol="chat";
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({ session });
    const opened = await runtime.openWebSocketStream("/socket", { protocols: ["chat"] });
    expect(opened.protocol).toBe("chat");
    expect(opened.stream).not.toBe(stream);
    expect(session.opens[0]).toEqual({
      kind: "flowersec-proxy/ws",
      options: {
        signal: expect.any(AbortSignal),
        metadata: expect.objectContaining({ values: { protocol: "flowersec.proxy.websocket", version: 2 } }),
      },
    });
    runtime.dispose();
    await expect.poll(() => stream.resetCalled).toBe(true);
  });

  it("removes queued admission abort listeners on dequeue and runtime close", async () => {
    const add = vi.spyOn(AbortSignal.prototype, "addEventListener");
    const remove = vi.spyOn(AbortSignal.prototype, "removeEventListener");
    try {
      const first = new ControlledReadStream();
      const second = new FakeStream([concat([
        metadataFrame({ v: 2, request_id: "second", ok: true, status: 204, headers: [] }),
        bodyEnd(),
      ])]);
      const runtime = createProxyRuntime({
        session: new FakeSession([first, second]),
        maxConcurrentHttpStreams: 1,
        maxQueuedHttpRequests: 2,
      });
      const firstChannel = new MessageChannel();
      const secondChannel = new MessageChannel();
      const abortedChannel = new MessageChannel();
      const firstDone = collectPort(firstChannel.port2, "flowersec-proxy:response_end");
      const secondDone = collectPort(secondChannel.port2, "flowersec-proxy:response_end");
      const abortedDone = collectPort(abortedChannel.port2, "flowersec-proxy:response_error");
      runtime.dispatchFetch({ id: "first", method: "GET", path: "/first", headers: [] }, firstChannel.port1);
      runtime.dispatchFetch({ id: "second", method: "GET", path: "/second", headers: [] }, secondChannel.port1);
      runtime.dispatchFetch({ id: "aborted", method: "GET", path: "/aborted", headers: [] }, abortedChannel.port1);
      await eventLoopTurn();
      abortedChannel.port2.postMessage({ type: "flowersec-proxy:abort" });
      await expect(abortedDone).resolves.toEqual([
        expect.objectContaining({ status: 499, code: "canceled" }),
      ]);
      first.respond(concat([
        metadataFrame({ v: 2, request_id: "first", ok: true, status: 204, headers: [] }),
        bodyEnd(),
      ]));
      await Promise.all([firstDone, secondDone]);
      const addedAfterDequeue = add.mock.calls.filter(([type]) => type === "abort").length;
      const removedAfterDequeue = remove.mock.calls.filter(([type]) => type === "abort").length;
      expect(removedAfterDequeue).toBe(addedAfterDequeue);

      const active = new ControlledReadStream();
      const closingRuntime = createProxyRuntime({
        session: new FakeSession([active]),
        maxConcurrentHttpStreams: 1,
        maxQueuedHttpRequests: 1,
      });
      const activeChannel = new MessageChannel();
      const queuedChannel = new MessageChannel();
      activeChannel.port2.start();
      queuedChannel.port2.start();
      closingRuntime.dispatchFetch({ id: "active", method: "GET", path: "/active", headers: [] }, activeChannel.port1);
      closingRuntime.dispatchFetch({ id: "queued", method: "GET", path: "/queued", headers: [] }, queuedChannel.port1);
      await eventLoopTurn();
      closingRuntime.dispose();
      await eventLoopTurn();
      const totalAdded = add.mock.calls.filter(([type]) => type === "abort").length;
      const totalRemoved = remove.mock.calls.filter(([type]) => type === "abort").length;
      expect(totalRemoved).toBe(totalAdded);
      active.respond(new Error("runtime closed"));
      runtime.dispose();
      activeChannel.port2.close();
      queuedChannel.port2.close();
    } finally {
      add.mockRestore();
      remove.mockRestore();
    }
  });
});

it("preserves a WebSocket frame coalesced with the opening response", async () => {
  const stream = new FakeStream([]); stream.wsResponseProtocol = "chat";
  stream.wsFirstFrame = new Uint8Array([2, 0, 0, 0, 2, 7, 9]);
  const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
  try {
    const opened = await runtime.openWebSocketStream("/socket");
    expect(await opened.stream.read()).toEqual(stream.wsFirstFrame);
    expect(stream.readCalls).toBe(1);
    expect(await opened.stream.read()).toBeNull();
    await opened.stream.close(); expect(stream.resetCalled).toBe(true);
  } finally { runtime.dispose(); }
});

it("resets a late WebSocket OPEN result after runtime disposal", async () => {
  const stream = new FakeStream([]);
  let resolve!: (stream: ByteStream) => void;
  let openingObserved!: () => void;
  const observed = new Promise<void>(yes => { openingObserved = yes; });
  const runtime = createProxyRuntime({ session: { openStream: () => new Promise(yes => { resolve = yes; openingObserved(); }) } });
  const opening = runtime.openWebSocketStream("/socket");
  const failed = expect(opening).rejects.toThrow();
  await observed;
  runtime.dispose(); resolve(stream); await failed;
  expect(stream.resetCalled).toBe(true); expect(stream.writes).toHaveLength(0);
});

it("retains request admission through authenticated Finish and actual cleanup", async () => {
  let drain!: () => void, clean!: () => void, finishEntered = false;
  class TailStream extends FakeStream {
    constructor() { super([]); }
    override async read(): Promise<Uint8Array | null> {
      if (this.readCalls++ > 0) return null;
      return concat([metadataFrame({ v: 2, request_id: firstWrittenMetadata(this).request_id, ok: true, status: 200, headers: [] }), bodyEnd()]);
    }
    async finish(): Promise<void> { finishEntered = true; await new Promise<void>(resolve => { drain = resolve; }); }
    dispose(onCleanup?: () => void): void { if (onCleanup !== undefined) clean = onCleanup; }
  }
  const stream = new TailStream();
  const runtime = createProxyRuntime({ session: new FakeSession([stream, new FetchResponseStream("text/plain", [])]), maxConcurrentHttpStreams: 1 });
  try {
    const response = await runtime.fetch("/first"), consuming = response.text();
    await expect.poll(() => finishEntered).toBe(true);
    await expect(runtime.fetch("/blocked-by-drain")).rejects.toMatchObject({ code: "resource_exhausted" });
    drain(); expect(await consuming).toBe("");
    await expect(runtime.fetch("/blocked-by-cleanup")).rejects.toMatchObject({ code: "resource_exhausted" });
    clean(); expect(await (await runtime.fetch("/next")).text()).toBe("");
    expect(stream.resetCalled).toBe(false);
  } finally { runtime.dispose(); }
});

class ControlledReadStream extends FakeStream {
  private resolveRead: ((value: Uint8Array | null) => void) | undefined;
  private rejectRead: ((error: unknown) => void) | undefined;

  constructor() { super([]); }

  override async read(): Promise<Uint8Array | null> {
    this.readCalls++;
    return await new Promise<Uint8Array | null>((resolve, reject) => {
      this.resolveRead = resolve;
      this.rejectRead = reject;
    });
  }

  override async reset(): Promise<void> {
    await super.reset();
    this.rejectRead?.(new Error("stream reset"));
  }

  respond(value: Uint8Array | Error): void {
    if (value instanceof Error) this.rejectRead?.(value);
    else this.resolveRead?.(value);
  }
}

function firstWrittenMetadata(stream: FakeStream): Record<string, unknown> {
  const bytes = concat(stream.writes);
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  return decodeProxyMetadata(stream.wsResponseProtocol === undefined ? "ProxyHTTPRequest" : "ProxyWebSocketOpen",bytes.subarray(4, 4 + length));
}

async function nextPortMessage(port: MessagePort): Promise<Record<string, unknown>> {
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("proxy message timed out")), 1_000);
    port.addEventListener("message", (event) => {
      clearTimeout(timer);
      resolve(event.data as Record<string, unknown>);
    }, { once: true });
  });
}

async function eventLoopTurn(): Promise<void> {
  await new Promise<void>((resolve) => { setImmediate(resolve); });
}

class FetchResponseStream extends FakeStream {
  private initialized = false;
  constructor(private readonly contentType: string, private readonly chunks: Uint8Array[]) { super([], 65536); }
  override async read(): Promise<Uint8Array | null> {
    this.readCalls++;
    if (!this.initialized) {
      this.initialized = true;
      return metadataFrame({ v: 2, request_id: firstWrittenMetadata(this).request_id, ok: true, status: 200,
        headers: [{ name: "content-type", value: this.contentType }] });
    }
    const chunk = this.chunks.shift();
    return chunk === undefined ? bodyEnd() : concat([u32be(chunk.length), chunk]);
  }
}

describe("session fetch", () => {
  it("returns a standard streaming Response and exempts confirmed events from the cumulative body limit", async () => {
    const stream = new FetchResponseStream("text/event-stream; charset=utf-8", [new Uint8Array(8), new Uint8Array(8)]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]), maxBodyBytes: 8 });
    try {
      const response = await runtime.fetch("/events", { headers: { Accept: "text/event-stream" } });
      expect(response).toBeInstanceOf(Response);
      expect(stream.readCalls).toBe(1);
      expect((await response.arrayBuffer()).byteLength).toBe(16);
      expect(stream.closed).toBe(true);
    } finally { runtime.dispose(); }
  });

  it("keeps finite response limits when either event negotiation header is absent", async () => {
    for (const [accept, contentType] of [["text/event-stream", "text/plain"], ["text/plain", "text/event-stream"]]) {
      const stream = new FetchResponseStream(contentType!, [new Uint8Array(8), new Uint8Array(8)]);
      const runtime = createProxyRuntime({ session: new FakeSession([stream]), maxBodyBytes: 8 });
      try {
        const response = await runtime.fetch("/events", { headers: { accept: accept! } });
        await expect(response.arrayBuffer()).rejects.toThrow();
        expect(stream.resetCalled).toBe(true);
      } finally { runtime.dispose(); }
    }
  });

  it("reserves finite-request slots and releases unread streams on disposal", async () => {
    const streams = Array.from({ length: 17 }, () => new FetchResponseStream("text/event-stream", []));
    const session = new FakeSession([...streams]);
    const runtime = createProxyRuntime({ session });
    const responses: Response[] = [];
    try {
      for (let i = 0; i < 16; i++) responses.push(await runtime.fetch("/events", { headers: { Accept: "text/event-stream" } }));
      await expect(runtime.fetch("/events", { headers: { Accept: "text/event-stream" } })).rejects.toMatchObject({ code: "resource_exhausted" });
      const finite = await runtime.fetch("/api");
      await finite.text();
      expect(session.opens).toHaveLength(17);
      runtime.dispose();
      for (const response of responses) await expect(response.text()).rejects.toThrow();
      expect(streams.slice(0,16).every(stream => stream.resetCalled)).toBe(true);
    } finally { runtime.dispose(); }
  });
});

describe("event stream deadlines and cancellation", () => {
  it("outlives the finite deadline while consuming events and times out an idle reader", async () => {
    vi.useFakeTimers();
    const stream = new FetchResponseStream("text/event-stream", Array.from({ length: 8 }, () => Uint8Array.of(1)));
    const runtime = createProxyRuntime({ session: new FakeSession([stream]), timeoutMs: 10, eventStreamIdleTimeoutMs: 20 });
    try {
      const response = await runtime.fetch("/events", { headers: { Accept: "text/event-stream" } });
      const reader = response.body!.getReader();
      for (let i = 0; i < 8; i++) {
        await vi.advanceTimersByTimeAsync(9);
        expect(await reader.read()).toMatchObject({ done: false });
      }
      const closed = expect(reader.closed).rejects.toThrow();
      await vi.advanceTimersByTimeAsync(21);
      await closed;
      expect(stream.resetCalled).toBe(true);
    } finally { runtime.dispose(); vi.useRealTimers(); }
  });

  it("cancels before admission, during a read, and while a response is unread", async () => {
    const first = new ControlledReadStream();
    const unread = new FetchResponseStream("text/event-stream", []);
    const session = new FakeSession([first, unread]);
    const runtime = createProxyRuntime({ session });
    try {
      const aborted = new AbortController(); aborted.abort();
      await expect(runtime.fetch("/events", { signal: aborted.signal })).rejects.toThrow();
      expect(session.opens).toHaveLength(0);
      const controller = new AbortController();
      const pending = runtime.fetch("/events", { signal: controller.signal });
      await vi.waitFor(() => expect(first.readCalls).toBeGreaterThan(0));
      controller.abort();
      await expect(pending).rejects.toThrow();
      expect(first.resetCalled).toBe(true);
      const response = await runtime.fetch("/events", { headers: { Accept: "text/event-stream" } });
      await response.body!.cancel();
      expect(unread.resetCalled).toBe(true);
    } finally { runtime.dispose(); }
  });
});

it("consumes more than 64 MiB of events without accumulating a lifetime response budget", async () => {
  const chunk = new Uint8Array(64 * 1024);
  const stream = new FetchResponseStream("text/event-stream", Array.from({ length: 1025 }, () => chunk));
  const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
  try {
    const response = await runtime.fetch("/events", { headers: { accept: "text/event-stream" } });
    const reader = response.body!.getReader();
    let received = 0;
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      received += next.value.byteLength;
    }
    expect(received).toBe(64 * 1024 * 1025);
    expect(stream.closed).toBe(true);
  } finally { runtime.dispose(); }
});

it("requires consumer credit for event dispatch and releases a stalled bridge on disposal", async () => {
  const stream = new FetchResponseStream("text/event-stream", [Uint8Array.of(1)]);
  const runtime = createProxyRuntime({ session: new FakeSession([stream]) });
  const channel = new MessageChannel(); channel.port2.start();
  try {
    const metadata = nextPortMessage(channel.port2);
    runtime.dispatchFetch({ id: "events", method: "GET", path: "/events", headers: [{ name: "accept", value: "text/event-stream" }] }, channel.port1);
    await expect(metadata).resolves.toMatchObject({ type: "flowersec-proxy:response_meta" });
    await eventLoopTurn();
    expect(stream.readCalls).toBe(1);
    const error = nextPortMessage(channel.port2);
    runtime.dispose();
    await expect(error).resolves.toMatchObject({ type: "flowersec-proxy:response_error" });
    expect(stream.resetCalled).toBe(true);
  } finally { runtime.dispose(); channel.port2.close(); }
});

it("supports HTTP direct pages where secure-context randomUUID is unavailable", async () => {
  const secureCrypto = globalThis.crypto;
  vi.stubGlobal("crypto", { getRandomValues: secureCrypto.getRandomValues.bind(secureCrypto) });
  const runtime = createProxyRuntime({ session: new FakeSession([new FetchResponseStream("text/plain", [])]) });
  try { expect(await (await runtime.fetch("/api")).text()).toBe(""); }
  finally { runtime.dispose(); vi.unstubAllGlobals(); }
});


it("reserves the original request slot before reading any second upload", async () => {
  const responseStream = new FetchResponseStream("text/plain", []);
  const runtime = createProxyRuntime({ session: new FakeSession([responseStream]), maxConcurrentHttpStreams: 1, maxConcurrentEventStreams: 1, maxQueuedHttpBodyBytes: 8 });
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let started!: () => void;
  const reading = new Promise<void>(resolve => { started = resolve; });
  const body = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, pull() { started(); } }, { highWaterMark: 0 });
  let otherReads = 0;
  const other = new ReadableStream<Uint8Array>({ pull() { otherReads++; } }, { highWaterMark: 0 });
  try {
    const first = runtime.fetch("/api", { method: "POST", body, duplex: "half" } as RequestInit);
    await reading;
    await expect(runtime.fetch("/api", { method: "POST", body: other, duplex: "half" } as RequestInit)).rejects.toMatchObject({ code: "resource_exhausted" });
    expect(otherReads).toBe(0);
    controller.enqueue(Uint8Array.of(1)); controller.close();
    const response = await first;
    await expect(runtime.fetch("/api")).rejects.toMatchObject({ code: "resource_exhausted" });
    await response.arrayBuffer();
  } finally { runtime.dispose(); await other.cancel(); }
});

it.each(["/objects/a%2Fb?q=%2f&x=%41+", "/literal%25", "/a;b", "/a//b?", "//a/b"])('preserves whole-upstream target %s', async (path) => {
  const stream = new FakeStream([concat([metadataFrame({ v: 2, request_id: "whole", ok: true, status: 204, headers: [] }), bodyEnd()])]);
  const runtime = createProxyRuntime({ session: new FakeSession([stream]), pathPolicy: { allowedWebSocketPathPrefixes: ["/socket/"] } });
  const channel = new MessageChannel();
  try {
    const done = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({ id: "whole", method: "GET", path, headers: [] }, channel.port1);
    expect(await done).toContainEqual(expect.objectContaining({ type: "flowersec-proxy:response_end" }));
    expect(firstWrittenMetadata(stream)).toMatchObject({ path });
  } finally { runtime.dispose(); channel.port2.close(); }
});


it("compares subtree UTF-8 segments without stripping BOM or folding escapes into a different target", () => {
  const path = "/files/%EF%BB%BFname";
  expect(normalizeSubtreePath(path)).toBe(path);
  expect(matchesPathPrefix(path, "/files/name")).toBe(false);
  expect(matchesPathPrefix("/files/%6eame", "/files/name")).toBe(true);
  expect(matchesPathPrefix("/files//name", "/files/name")).toBe(false);
});

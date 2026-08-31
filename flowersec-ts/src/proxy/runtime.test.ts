import { describe, expect, it, vi } from "vitest";

import { u32be } from "../utils/bin.js";
import type { ByteStream, Session, StreamOpenOptions } from "../public/contract.js";
import { createProxyRuntime } from "./runtime.js";

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

function jsonFrame(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  return concat([u32be(payload.length), payload]);
}

class FakeStream implements ByteStream {
  readonly kind = "fake";
  terminalError = undefined;
  readonly writes: Uint8Array[] = [];
  readCalls = 0;
  closed = false;
  resetCalled = false;
  private readonly reads: Array<Uint8Array | Error | null>;

  constructor(reads: Array<Uint8Array | Error | null>, private readonly partialWrite = 3) { this.reads = reads; }
  async read(): Promise<Uint8Array | null> {
    this.readCalls++;
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
        expect.objectContaining({ status: 403, code: "policy_denied" }),
      ]);
      expect(session.opens).toEqual([]);
      await expect(runtime.openWebSocketStream(path)).rejects.toThrow(/denied/);
      runtime.dispose();
    }

    const httpStream = new FakeStream([concat([
      jsonFrame({ v: 1, request_id: "canonical", ok: true, status: 204, headers: [] }),
      u32be(0),
    ])]);
    const wsStream = new FakeStream([jsonFrame({ v: 1, ok: true, protocol: "" })]);
    const session = new FakeSession([httpStream, wsStream]);
    const runtime = createProxyRuntime({ session, pathPolicy: { allowedPathPrefixes: ["/api"] } });
    const channel = new MessageChannel();
    const collecting = collectPort(channel.port2, "flowersec-proxy:response_end");
    runtime.dispatchFetch({
      id: "canonical", method: "GET", path: "/public/../api//items?q=%7euser", headers: [],
    }, channel.port1);
    await collecting;
    expect(firstWrittenJSON(httpStream)).toMatchObject({ path: "/api/items?q=~user" });
    await runtime.openWebSocketStream("/public/../api//socket?q=1");
    expect(firstWrittenJSON(wsStream)).toMatchObject({ path: "/api/socket?q=1" });
    for (const path of ["/api/%2fadmin", "/api/%5cadmin"]) {
      const rejectedChannel = new MessageChannel();
      const rejected = collectPort(rejectedChannel.port2, "flowersec-proxy:response_error");
      runtime.dispatchFetch({ id: path, method: "GET", path, headers: [] }, rejectedChannel.port1);
      await expect(rejected).resolves.toEqual([
        expect.objectContaining({ status: 400, code: "invalid_request" }),
      ]);
      await expect(runtime.openWebSocketStream(path)).rejects.toThrow(/encoded separator/);
    }
    runtime.dispose();
  });

  it("streams an HTTP request with partial writes and returns bounded response messages", async () => {
    const response = concat([
      jsonFrame({ v: 1, request_id: "request-1", ok: true, status: 201, headers: [{ name: "content-type", value: "text/plain" }] }),
      u32be(2), new Uint8Array([111, 107]), u32be(0),
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
      jsonFrame({ v: 1, request_id: "credit", ok: true, status: 200, headers: [] }),
      concat([u32be(1), Uint8Array.of(1)]),
      concat([u32be(1), Uint8Array.of(2)]),
      u32be(0),
    ]);
    const runtime = createProxyRuntime({ session: new FakeSession([stream]), maxChunkBytes: 8, maxBodyBytes: 64 });
    const channel = new MessageChannel();
    channel.port2.start();
    const metadata = nextPortMessage(channel.port2);
    runtime.dispatchFetch({
      id: "credit", method: "GET", path: "/stream", headers: [], responseFlowControl: "chunk_credit_v2",
    }, channel.port1);
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
    runtime.dispose();
  });

  it("opens WebSockets through a carrier-neutral ByteStream", async () => {
    const stream = new FakeStream([jsonFrame({ v: 1, ok: true, protocol: "chat" })]);
    const session = new FakeSession([stream]);
    const runtime = createProxyRuntime({ session });
    const opened = await runtime.openWebSocketStream("/socket", { protocols: ["chat"] });
    expect(opened).toEqual({ stream, protocol: "chat" });
    expect(session.opens[0]).toEqual({
      kind: "flowersec-proxy/ws",
      options: {
        metadata: expect.objectContaining({ values: { protocol: "flowersec.proxy.websocket", version: 2 } }),
      },
    });
    runtime.dispose();
  });

  it("removes queued admission abort listeners on dequeue and runtime close", async () => {
    const add = vi.spyOn(AbortSignal.prototype, "addEventListener");
    const remove = vi.spyOn(AbortSignal.prototype, "removeEventListener");
    try {
      const first = new ControlledReadStream();
      const second = new FakeStream([concat([
        jsonFrame({ v: 1, request_id: "second", ok: true, status: 204, headers: [] }),
        u32be(0),
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
        jsonFrame({ v: 1, request_id: "first", ok: true, status: 204, headers: [] }),
        u32be(0),
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

  respond(value: Uint8Array | Error): void {
    if (value instanceof Error) this.rejectRead?.(value);
    else this.resolveRead?.(value);
  }
}

function firstWrittenJSON(stream: FakeStream): Record<string, unknown> {
  const bytes = concat(stream.writes);
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(4, 4 + length))) as Record<string, unknown>;
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

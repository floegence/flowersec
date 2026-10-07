import { describe, expect, it } from "vitest";

import type { OperationOptions } from "../public/contract.js";
import type { StreamMetadata } from "../public/streamMetadata.js";
import type { V4CloseResult, V4ReadResult, V4WriteProgress } from "../generated/transportV4APIResults.js";
import type { V4Session, V4StreamOwner } from "../v4/public.js";
import { registerStreamAdapter, type StreamAdapterOwner } from "../v4/runtime/streamAdapter.js";
import { u32be } from "../utils/bin.js";
import { createProxyRuntime, createProxyRuntimeWithStreams } from "./runtime.js";
import { createProxySurface } from "./surface.js";
import { currentProxyStream } from "./currentStream.js";
import { decodeProxyMetadata, encodeProxyMetadata } from "./wire.js";
import type { ProxyStream } from "./stream.js";

const complete = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const);
const pending = Object.freeze({ status: "pending", core_cleanup: "pending", pending_callbacks: 1n } as const);
const closeResult: V4CloseResult = { direction: "c2s", send_drained: true, read_terminal: "eof", cleanup_status: complete };
const resetResult: V4CloseResult = { ...closeResult, send_drained: false, cleanup_status: pending };
const canceledRead: V4ReadResult = {
  data: new Uint8Array(), progress: { offset: 0n, filled: 0n }, wait_status: "wait_canceled", stream_status: "open",
};
const pendingRead = Symbol("pending read");
const responseMetadata = Symbol("response metadata");
const websocketResponse = Symbol("websocket response");
type ScriptedRead = Uint8Array | Error | null | typeof pendingRead | typeof responseMetadata | typeof websocketResponse;
type ResponseShape = Readonly<{ status: number; headers: ReadonlyArray<{ name: string; value: string }> }>;
type StreamOpenOptions = OperationOptions & Readonly<{ metadata?: StreamMetadata }>;

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}

function metadataFrame(value: unknown, kind: "ProxyHTTPResponse" | "ProxyWebSocketResponse" | "ProxyBodyEnd"): Uint8Array {
  const payload = encodeProxyMetadata(kind, value);
  return concat([u32be(payload.length), payload]);
}

function bodyEnd(): Uint8Array { return metadataFrame({ v: 2, trailers: [] }, "ProxyBodyEnd"); }

function writtenMetadata(writes: readonly Uint8Array[], schema: "ProxyHTTPRequest" | "ProxyWebSocketOpen"): Record<string, unknown> {
  const bytes = concat(writes);
  const length = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  return decodeProxyMetadata(schema, bytes.subarray(4, 4 + length));
}

function requestID(writes: readonly Uint8Array[]): string {
  return writtenMetadata(writes, "ProxyHTTPRequest").request_id as string;
}

function connectionID(writes: readonly Uint8Array[]): string {
  return writtenMetadata(writes, "ProxyWebSocketOpen").conn_id as string;
}

class CurrentStreamFixture {
  readonly source = {} as V4StreamOwner;
  readonly stream: ProxyStream;
  readonly writes: Uint8Array[] = [];
  readonly resetStarted: Promise<void>;
  readonly pendingReadStarted: Promise<void>;
  resetCalled = false;
  released = false;
  private physicalReady: boolean;
  private cleanupNotify: (() => void) | undefined;
  private resetResolve: (() => void) | undefined;
  private readResolve: ((result: V4ReadResult) => void) | undefined;
  private readonly reads: ScriptedRead[];
  private responseShape: ResponseShape = { status: 200, headers: [] };
  private resetStartedResolve!: () => void;
  private pendingReadStartedResolve!: () => void;

  constructor(reads: ScriptedRead[], holdCleanup = true) {
    this.reads = reads;
    this.physicalReady = !holdCleanup;
    this.resetStarted = new Promise(resolve => { this.resetStartedResolve = resolve; });
    this.pendingReadStarted = new Promise(resolve => { this.pendingReadStartedResolve = resolve; });
    const owner: StreamAdapterOwner = {
      readBytes: 65536,
      check: () => undefined,
      read: async () => await this.read(),
      write: async (bytes): Promise<V4WriteProgress> => {
        this.writes.push(bytes.slice());
        return { requested_bytes: BigInt(bytes.length), accepted_bytes: BigInt(bytes.length), phase: "terminal", terminal_reason: "complete", cleanup_status: complete };
      },
      closeWrite: async () => closeResult,
      finish: async () => closeResult,
      reset: async () => await this.reset(),
      abortRead: async () => resetResult,
      abortWrite: async () => resetResult,
      cleanupStatus: () => this.physicalReady ? complete : pending,
      invalidateWith: () => undefined,
      sendStoppedWith: () => undefined,
      cleanupWith: callback => {
        this.cleanupNotify = callback;
        if (this.physicalReady) callback();
      },
      rollback: () => undefined,
      release: () => { this.released = true; },
    };
    registerStreamAdapter(this.source, () => owner);
    this.stream = currentProxyStream(this.source, {
      readBytes: 65536,
      inputBackingBytes: 65536,
      finishTimeoutMS: 1_000,
      cleanupTimeoutMS: 1_000,
    });
  }

  setResponse(response: ResponseShape): void { this.responseShape = response; }

  releasePhysicalCleanup(): void {
    this.physicalReady = true;
    this.cleanupNotify?.();
    this.resetResolve?.();
  }

  async read(): Promise<V4ReadResult> {
    const value = this.reads.shift();
    if (value === responseMetadata) {
      const payload = { v: 2, request_id: requestID(this.writes), ok: true, status: this.responseShape.status, headers: this.responseShape.headers };
      return { data: metadataFrame(payload, "ProxyHTTPResponse"), progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "open" };
    }
    if (value === websocketResponse) {
      const payload = { v: 2, conn_id: connectionID(this.writes), ok: true, protocol: "chat" };
      return { data: concat([metadataFrame(payload, "ProxyWebSocketResponse")]), progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "open" };
    }
    if (value === pendingRead) {
      this.pendingReadStartedResolve();
      return await new Promise<V4ReadResult>(resolve => { this.readResolve = resolve; });
    }
    if (value instanceof Error) throw value;
    if (value === null || value === undefined) return { data: new Uint8Array(), progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "eof" };
    if (typeof value === "symbol") throw new Error("unexpected scripted read");
    return { data: value, progress: { offset: 0n, filled: 0n }, wait_status: "ready", stream_status: "open" };
  }

  async reset(): Promise<V4CloseResult> {
    this.resetCalled = true;
    this.resetStartedResolve();
    this.readResolve?.(canceledRead);
    this.readResolve = undefined;
    if (this.physicalReady) return resetResult;
    await new Promise<void>(resolve => { this.resetResolve = resolve; });
    return resetResult;
  }
}

class CurrentSession {
  readonly rpc = {};
  readonly termination = new Promise<never>(() => undefined);
  readonly opens: Array<Readonly<{ kind: string; options: StreamOpenOptions | undefined }>> = [];

  constructor(private readonly fixtures: CurrentStreamFixture[]) {}

  async openStream(kind: string, options?: StreamOpenOptions): Promise<ProxyStream> {
    this.opens.push({ kind, options });
    const fixture = this.fixtures.shift();
    if (fixture === undefined) throw new Error("missing current stream fixture");
    return fixture.stream;
  }
  async acceptStream(): Promise<never> { throw new Error("unused"); }
  async rekey(): Promise<void> {}
  async probeLiveness(): Promise<number> { return 0; }
  async waitTermination(): Promise<never> { return await this.termination; }
  async close(): Promise<void> {}
}

class CurrentPublicSession {
  readonly rpc = {};
  readonly termination = new Promise<never>(() => undefined);
  readonly opens: Array<Readonly<{ kind: string; options: StreamOpenOptions | undefined }>> = [];
  private deferredOpen: Promise<V4StreamOwner> | undefined;

  constructor(private readonly fixtures: CurrentStreamFixture[], deferredOpen?: Promise<V4StreamOwner>) {
    this.deferredOpen = deferredOpen;
  }

  async openStream(kind: string, options?: StreamOpenOptions): Promise<V4StreamOwner> {
    this.opens.push({ kind, options });
    if (this.deferredOpen !== undefined) {
      const pending = this.deferredOpen;
      this.deferredOpen = undefined;
      return await pending;
    }
    const fixture = this.fixtures.shift();
    if (fixture === undefined) throw new Error("missing current stream fixture");
    return fixture.source;
  }
  async acceptStream(): Promise<never> { throw new Error("unused"); }
  async rekey(): Promise<void> {}
  async probeLiveness(): Promise<number> { return 0; }
  async waitTermination(): Promise<never> { return await this.termination; }
  async close(): Promise<void> {}
}

class RejectingPublicSession extends CurrentPublicSession {
  private rejectNext = true;

  override async openStream(kind: string, options?: StreamOpenOptions): Promise<V4StreamOwner> {
    if (this.rejectNext) {
      this.rejectNext = false;
      this.opens.push({ kind, options });
      throw new Error("private open failure");
    }
    return await super.openStream(kind, options);
  }
}

describe("proxy runtime with the original current stream adapter", () => {
  it("holds public fetch admission after premetadata response failure until reset cleanup", async () => {
    const failure = new CurrentStreamFixture([new Error("private response detail")]);
    const next = new CurrentStreamFixture([responseMetadata, concat([u32be(4), new TextEncoder().encode("next")]), u32be(0), bodyEnd()], false);
    const session = new CurrentSession([failure, next]);
    const runtime = createProxyRuntimeWithStreams({ session, maxConcurrentHttpStreams: 1 });
    try {
      const first = runtime.fetch("/failure");
      await failure.resetStarted;
      await expect(runtime.fetch("/blocked")).rejects.toMatchObject({ code: "resource_exhausted" });
      failure.releasePhysicalCleanup();
      await expect(first).rejects.toMatchObject({ code: "operation_failed" });
      expect(failure.released).toBe(true);
      expect(await (await runtime.fetch("/next")).text()).toBe("next");
    } finally { runtime.dispose(); }
  });

  it("preserves public response metadata and prefix while cancellation waits for current stream cleanup", async () => {
    const prefix = new TextEncoder().encode("prefix");
    const held = new CurrentStreamFixture([responseMetadata, concat([u32be(prefix.length), prefix]), pendingRead]);
    held.setResponse({ status: 206, headers: [
      { name: "content-type", value: "text/plain" },
      { name: "content-range", value: "bytes 0-5/6" },
    ] });
    const next = new CurrentStreamFixture([responseMetadata, u32be(0), bodyEnd()], false);
    const session = new CurrentSession([held, next]);
    const runtime = createProxyRuntimeWithStreams({ session, maxConcurrentHttpStreams: 1 });
    const cancellation = new AbortController();
    try {
      const response = await runtime.fetch("/held", { signal: cancellation.signal });
      expect(response.status).toBe(206);
      expect(response.headers.get("content-type")).toBe("text/plain");
      expect(response.headers.get("content-range")).toBe("bytes 0-5/6");
      const reader = response.body!.getReader();
      await expect(reader.read()).resolves.toEqual({ done: false, value: prefix });
      const pending = reader.read();
      await held.pendingReadStarted;
      cancellation.abort();
      await held.resetStarted;
      await expect(runtime.fetch("/blocked")).rejects.toMatchObject({ code: "resource_exhausted" });
      held.releasePhysicalCleanup();
      await expect(pending).rejects.toThrow();
      expect(held.released).toBe(true);
      expect(await (await runtime.fetch("/next")).text()).toBe("");
    } finally { runtime.dispose(); }
  });

  it("holds admission across a current stream reset deadline until the original cleanup tail exits", async () => {
    const held = new CurrentStreamFixture([responseMetadata, concat([u32be(1), Uint8Array.of(7)]), pendingRead]);
    const next = new CurrentStreamFixture([responseMetadata, u32be(0), bodyEnd()], false);
    const session = new CurrentSession([held, next]);
    const runtime = createProxyRuntimeWithStreams({ session, maxConcurrentHttpStreams: 1, timeoutMs: 25 });
    try {
      const response = await runtime.fetch("/deadline");
      const reader = response.body!.getReader();
      await expect(reader.read()).resolves.toMatchObject({ done: false, value: Uint8Array.of(7) });
      const pending = reader.read();
      await held.pendingReadStarted;
      const pendingFailure = expect(pending).rejects.toThrow();
      await new Promise(resolve => setTimeout(resolve, 35));
      await held.resetStarted;
      await expect(runtime.fetch("/blocked")).rejects.toMatchObject({ code: "resource_exhausted" });
      held.releasePhysicalCleanup();
      await pendingFailure;
      await new Promise<void>(resolve => { setImmediate(resolve); });
      expect(held.released).toBe(true);
      expect(await (await runtime.fetch("/next")).text()).toBe("");
    } finally { runtime.dispose(); }
  });

  it("releases public runtime cleanup after a pre-canceled WebSocket open", async () => {
    const session = new CurrentPublicSession([]);
    const runtime = createProxyRuntime({ session: session as unknown as V4Session });
    const cancellation = new AbortController();
    cancellation.abort(new Error("pre-canceled"));
    try {
      await expect(runtime.openWebSocketStream("/socket", { signal: cancellation.signal })).rejects.toThrow();
      expect(runtime.cleanupStatus?.()).toMatchObject({ status: "complete", pending_callbacks: 0n });
      expect(session.opens).toHaveLength(0);
    } finally { runtime.dispose(); }
  });

  it("releases public runtime cleanup when openStream rejects and remains reusable", async () => {
    const next = new CurrentStreamFixture([websocketResponse], false);
    const session = new RejectingPublicSession([next]);
    const runtime = createProxyRuntime({ session: session as unknown as V4Session });
    try {
      await expect(runtime.openWebSocketStream("/rejected")).rejects.toMatchObject({ code: "operation_failed" });
      expect(runtime.cleanupStatus?.()).toMatchObject({ status: "complete", pending_callbacks: 0n });
      const opened = await runtime.openWebSocketStream("/next");
      expect(opened.protocol).toBe("chat");
      await opened.stream.close(); opened.stream.dispose?.();
      expect(next.released).toBe(true);
    } finally { runtime.dispose(); }
  });

  it("holds public runtime cleanup for a late WebSocket open until physical cleanup, then remains reusable", async () => {
    const held = new CurrentStreamFixture([websocketResponse], true);
    const next = new CurrentStreamFixture([websocketResponse], false);
    let resolveOpen!: (stream: V4StreamOwner) => void;
    const openingSource = new Promise<V4StreamOwner>(resolve => { resolveOpen = resolve; });
    const session = new CurrentPublicSession([next], openingSource);
    const runtime = createProxyRuntime({ session: session as unknown as V4Session });
    const cancellation = new AbortController();
    try {
      const opening = runtime.openWebSocketStream("/late", { signal: cancellation.signal });
      await expect.poll(() => session.opens).toHaveLength(1);
      cancellation.abort(new Error("canceled"));
      expect(runtime.cleanupStatus?.()).toMatchObject({ status: "pending", pending_callbacks: 1n });
      resolveOpen(held.source);
      await held.resetStarted;
      expect(runtime.cleanupStatus?.()).toMatchObject({ status: "pending", pending_callbacks: 1n });
      held.releasePhysicalCleanup();
      await expect(opening).rejects.toThrow();
      await expect.poll(() => runtime.cleanupStatus?.().pending_callbacks).toBe(0n);
      expect(held.released).toBe(true);
      const opened = await runtime.openWebSocketStream("/after-cleanup");
      expect(opened.protocol).toBe("chat");
      await opened.stream.close(); opened.stream.dispose?.();
      expect(next.released).toBe(true);
    } finally { runtime.dispose(); }
  });

  it("surfaces pre-canceled WebSocket cleanup through public ProxySurface and stays reusable", async () => {
    const next = new CurrentStreamFixture([websocketResponse], false);
    const session = new CurrentPublicSession([next]);
    const surface = await createProxySurface({
      mode: "trusted",
      binding: { mode: "fixed", session: session as unknown as V4Session },
      hostOrigin: "https://flowersec.test",
      contentOrigin: "https://flowersec.test",
      requestPolicy: { methods: ["GET"], paths: {}, allowWebSocket: true },
    });
    const cancellation = new AbortController();
    cancellation.abort(new Error("pre-canceled"));
    try {
      await expect(surface.runtime.openWebSocketStream("/canceled", { signal: cancellation.signal })).rejects.toThrow();
      expect(surface.cleanupStatus()).toMatchObject({ status: "complete", pending_callbacks: 0n });
      const opened = await surface.runtime.openWebSocketStream("/next");
      expect(opened.protocol).toBe("chat");
      await opened.stream.close(); opened.stream.dispose?.();
      expect(next.released).toBe(true);
      expect(surface.cleanupStatus()).toMatchObject({ status: "complete", pending_callbacks: 0n });
    } finally { await surface.dispose(); }
  });
});

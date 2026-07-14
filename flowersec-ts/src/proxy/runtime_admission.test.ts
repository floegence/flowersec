import { describe, expect, it } from "vitest";

import type { Client } from "../client.js";
import { u32be } from "../utils/bin.js";

import { PROXY_KIND_HTTP1, PROXY_KIND_WS, PROXY_PROTOCOL_VERSION } from "./constants.js";
import { createProxyRuntime, type ProxyRuntime } from "./runtime.js";

const te = new TextEncoder();

function jsonFrame(value: unknown): Uint8Array {
  const json = te.encode(JSON.stringify(value));
  const out = new Uint8Array(4 + json.length);
  out.set(u32be(json.length), 0);
  out.set(json, 4);
  return out;
}

async function waitFor(predicate: () => boolean, message = "condition"): Promise<void> {
  for (let i = 0; i < 500; i++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error(`timed out waiting for ${message}`);
}

class TestPort {
  onmessage: ((event: MessageEvent) => void) | null = null;
  readonly messages: unknown[] = [];
  closed = false;

  constructor(private readonly onClose?: () => void) {}

  postMessage(message: unknown): void {
    this.messages.push(message);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.onClose?.();
  }

  abort(): void {
    this.onmessage?.({ data: { type: "flowersec-proxy:abort" } } as MessageEvent);
  }

  has(type: string): boolean {
    return this.messages.some((message) => (message as { type?: unknown })?.type === type);
  }

  find(type: string): Record<string, unknown> | undefined {
    return this.messages.find((message) => (message as { type?: unknown })?.type === type) as
      | Record<string, unknown>
      | undefined;
  }
}

class ControlledHttpStream {
  readonly writes: Uint8Array[] = [];
  private readonly reads: Array<Uint8Array | null> = [];
  private readonly readWaiters: Array<(value: Uint8Array | null) => void> = [];
  private released = false;

  constructor(private readonly onReleased: () => void) {}

  async write(data: Uint8Array): Promise<void> {
    this.writes.push(data);
  }

  async read(): Promise<Uint8Array | null> {
    if (this.reads.length > 0) return this.reads.shift() ?? null;
    return await new Promise<Uint8Array | null>((resolve) => this.readWaiters.push(resolve));
  }

  async close(): Promise<void> {
    this.release();
  }

  reset(): void {
    this.release();
  }

  finish(requestID: string): void {
    this.pushRead(
      jsonFrame({
        v: PROXY_PROTOCOL_VERSION,
        request_id: requestID,
        ok: true,
        status: 200,
        headers: [],
      }),
    );
    this.pushRead(u32be(0));
  }

  private pushRead(value: Uint8Array | null): void {
    const waiter = this.readWaiters.shift();
    if (waiter != null) {
      waiter(value);
      return;
    }
    this.reads.push(value);
  }

  private release(): void {
    if (this.released) return;
    this.released = true;
    this.onReleased();
  }
}

class ImmediateWebSocketStream {
  readonly writes: Uint8Array[] = [];
  private readonly reads = [
    jsonFrame({ v: PROXY_PROTOCOL_VERSION, conn_id: "ws", ok: true, protocol: "demo" }),
  ];

  async write(data: Uint8Array): Promise<void> {
    this.writes.push(data);
  }

  async read(): Promise<Uint8Array | null> {
    return this.reads.shift() ?? null;
  }

  async close(): Promise<void> {}

  reset(): void {}
}

function dispatch(runtime: ProxyRuntime, id: string, onClose?: () => void, bodyBytes = 0): TestPort {
  const port = new TestPort(onClose);
  runtime.dispatchFetch(
    {
      id,
      method: "GET",
      path: `/${id}.js`,
      headers: [],
      ...(bodyBytes === 0 ? {} : { body: new Uint8Array(bodyBytes).buffer }),
    },
    port as unknown as MessagePort,
  );
  return port;
}

function createControlledClient(): Readonly<{
  client: Client;
  streams: ControlledHttpStream[];
  openedKinds: string[];
  active: () => number;
  peakActive: () => number;
}> {
  const streams: ControlledHttpStream[] = [];
  const openedKinds: string[] = [];
  let active = 0;
  let peakActive = 0;

  const client: Client = {
    path: "tunnel",
    rpc: null as never,
    openStream: async (kind: string) => {
      openedKinds.push(kind);
      if (kind === PROXY_KIND_WS) return new ImmediateWebSocketStream() as never;
      expect(kind).toBe(PROXY_KIND_HTTP1);
      active++;
      peakActive = Math.max(peakActive, active);
      const stream = new ControlledHttpStream(() => {
        active--;
      });
      streams.push(stream);
      return stream as never;
    },
    ping: async () => {},
    probeLiveness: async () => 0,
    close: () => {},
  };

  return {
    client,
    streams,
    openedKinds,
    active: () => active,
    peakActive: () => peakActive,
  };
}

describe("proxy runtime HTTP stream admission", () => {
  it("drains a 55-request burst without exceeding the default 24 HTTP streams", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({ client: controlled.client });
    const ports = Array.from({ length: 55 }, (_, index) => dispatch(runtime, `req-${index}`));

    expect(runtime.limits.maxConcurrentHttpStreams).toBe(24);
    expect(runtime.limits.maxQueuedHttpRequests).toBe(128);
    expect(runtime.limits.maxQueuedHttpBodyBytes).toBe(64 * (1 << 20));
    expect(runtime.limits.maxWsBufferedAmountBytes).toBe(4 * (1 << 20));
    await waitFor(() => controlled.streams.length === 24, "first admission batch");
    expect(controlled.peakActive()).toBe(24);

    for (let i = 0; i < 24; i++) controlled.streams[i]!.finish(`req-${i}`);
    await waitFor(() => controlled.streams.length === 48, "second admission batch");
    expect(controlled.peakActive()).toBe(24);

    for (let i = 24; i < 48; i++) controlled.streams[i]!.finish(`req-${i}`);
    await waitFor(() => controlled.streams.length === 55, "final admission batch");
    expect(controlled.peakActive()).toBe(24);

    for (let i = 48; i < 55; i++) controlled.streams[i]!.finish(`req-${i}`);
    await waitFor(() => ports.every((port) => port.has("flowersec-proxy:response_end")), "all responses");

    expect(ports.some((port) => port.has("flowersec-proxy:response_error"))).toBe(false);
    expect(controlled.active()).toBe(0);
    expect(controlled.openedKinds).toHaveLength(55);
    runtime.dispose();
  });

  it("removes a canceled queued request and admits the next waiter", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 1,
    });

    const active = dispatch(runtime, "active");
    const canceled = dispatch(runtime, "canceled");
    await waitFor(() => controlled.streams.length === 1, "active request");

    canceled.abort();
    await waitFor(() => canceled.closed, "queued cancellation");
    const next = dispatch(runtime, "next");
    expect(controlled.streams).toHaveLength(1);

    controlled.streams[0]!.finish("active");
    await waitFor(() => controlled.streams.length === 2, "next queued request");
    controlled.streams[1]!.finish("next");
    await waitFor(() => active.has("flowersec-proxy:response_end") && next.has("flowersec-proxy:response_end"));

    expect(canceled.find("flowersec-proxy:response_error")?.message).toContain("canceled");
    expect(controlled.peakActive()).toBe(1);
    runtime.dispose();
  });

  it("returns stable resource_exhausted semantics when the bounded queue is full", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 1,
    });

    const active = dispatch(runtime, "active");
    const queued = dispatch(runtime, "queued");
    const overflow = dispatch(runtime, "overflow");
    await waitFor(() => overflow.has("flowersec-proxy:response_error"), "queue overflow response");

    expect(overflow.find("flowersec-proxy:response_error")).toMatchObject({
      status: 503,
    });
    expect(String(overflow.find("flowersec-proxy:response_error")?.message)).toContain("(resource_exhausted)");
    expect(String(overflow.find("flowersec-proxy:response_error")?.message)).toContain("queue is full");

    controlled.streams[0]!.finish("active");
    await waitFor(() => controlled.streams.length === 2, "queued request admission");
    controlled.streams[1]!.finish("queued");
    await waitFor(() => active.has("flowersec-proxy:response_end") && queued.has("flowersec-proxy:response_end"));
    runtime.dispose();
  });

  it("bounds queued request bodies by bytes and releases canceled reservations", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 2,
      maxQueuedHttpBodyBytes: 4,
    });

    const active = dispatch(runtime, "active", undefined, 8);
    await waitFor(() => controlled.streams.length === 1, "active request");
    const canceled = dispatch(runtime, "canceled", undefined, 3);
    const overflow = dispatch(runtime, "overflow", undefined, 2);
    await waitFor(() => overflow.has("flowersec-proxy:response_error"), "body queue overflow response");
    expect(overflow.find("flowersec-proxy:response_error")).toMatchObject({ status: 503 });
    expect(String(overflow.find("flowersec-proxy:response_error")?.message)).toContain("body queue is full");

    canceled.abort();
    await waitFor(() => canceled.closed, "queued body cancellation");
    const replacement = dispatch(runtime, "replacement", undefined, 4);
    expect(replacement.has("flowersec-proxy:response_error")).toBe(false);

    controlled.streams[0]!.finish("active");
    await waitFor(() => controlled.streams.length === 2, "replacement admission");
    controlled.streams[1]!.finish("replacement");
    await waitFor(() => active.has("flowersec-proxy:response_end") && replacement.has("flowersec-proxy:response_end"));
    runtime.dispose();
  });

  it("releases queued body bytes when a waiter becomes active", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 2,
      maxQueuedHttpBodyBytes: 4,
    });

    const first = dispatch(runtime, "first");
    await waitFor(() => controlled.streams.length === 1, "first request");
    const second = dispatch(runtime, "second", undefined, 4);
    controlled.streams[0]!.finish("first");
    await waitFor(() => controlled.streams.length === 2, "second request");

    const third = dispatch(runtime, "third", undefined, 4);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(third.has("flowersec-proxy:response_error")).toBe(false);

    controlled.streams[1]!.finish("second");
    await waitFor(() => controlled.streams.length === 3, "third request");
    controlled.streams[2]!.finish("third");
    await waitFor(() => [first, second, third].every((port) => port.has("flowersec-proxy:response_end")));
    runtime.dispose();
  });

  it("exposes custom limits and supports zero queue capacity", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 2,
      maxQueuedHttpRequests: 0,
    });

    expect(runtime.limits.maxConcurrentHttpStreams).toBe(2);
    expect(runtime.limits.maxQueuedHttpRequests).toBe(0);

    const first = dispatch(runtime, "first");
    const second = dispatch(runtime, "second");
    const overflow = dispatch(runtime, "overflow");
    await waitFor(() => controlled.streams.length === 2, "configured concurrent streams");
    await waitFor(() => overflow.has("flowersec-proxy:response_error"), "zero-capacity queue rejection");

    expect(overflow.find("flowersec-proxy:response_error")).toMatchObject({ status: 503 });
    expect(String(overflow.find("flowersec-proxy:response_error")?.message)).toContain("(resource_exhausted)");

    controlled.streams[0]!.finish("first");
    controlled.streams[1]!.finish("second");
    await waitFor(() => first.has("flowersec-proxy:response_end") && second.has("flowersec-proxy:response_end"));
    runtime.dispose();
  });

  it("rejects queued and future requests when the runtime is disposed", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 2,
    });

    const active = dispatch(runtime, "active");
    const queued = dispatch(runtime, "queued");
    await waitFor(() => controlled.streams.length === 1, "active request");
    runtime.dispose();

    const afterDispose = dispatch(runtime, "after-dispose");
    await waitFor(
      () => queued.has("flowersec-proxy:response_error") && afterDispose.has("flowersec-proxy:response_error"),
      "dispose rejections",
    );
    expect(queued.find("flowersec-proxy:response_error")).toMatchObject({ status: 503 });
    expect(afterDispose.find("flowersec-proxy:response_error")).toMatchObject({ status: 503 });
    expect(String(queued.find("flowersec-proxy:response_error")?.message)).toContain("(not_connected)");
    expect(String(afterDispose.find("flowersec-proxy:response_error")?.message)).toContain("(not_connected)");
    expect(controlled.streams).toHaveLength(1);

    controlled.streams[0]!.finish("active");
    await waitFor(() => active.has("flowersec-proxy:response_end"));
    expect(controlled.active()).toBe(0);
  });

  it("does not open a queued stream when disposal wins the permit handoff", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 1,
    });

    const active = dispatch(runtime, "active", () => runtime.dispose());
    const queued = dispatch(runtime, "queued");
    await waitFor(() => controlled.streams.length === 1, "active request");

    controlled.streams[0]!.finish("active");
    await waitFor(
      () => active.has("flowersec-proxy:response_end") && queued.has("flowersec-proxy:response_error"),
      "disposed handoff rejection",
    );

    expect(queued.find("flowersec-proxy:response_error")).toMatchObject({ status: 503 });
    expect(String(queued.find("flowersec-proxy:response_error")?.message)).toContain("(not_connected)");
    expect(controlled.streams).toHaveLength(1);
    expect(controlled.active()).toBe(0);
  });

  it("keeps WebSocket opens independent from HTTP admission", async () => {
    const controlled = createControlledClient();
    const runtime = createProxyRuntime({
      client: controlled.client,
      maxConcurrentHttpStreams: 1,
      maxQueuedHttpRequests: 1,
    });

    const first = dispatch(runtime, "first");
    const second = dispatch(runtime, "second");
    await waitFor(() => controlled.streams.length === 1, "active HTTP request");

    const websocket = await runtime.openWebSocketStream("/socket", { protocols: ["demo"] });
    expect(websocket.protocol).toBe("demo");
    expect(controlled.openedKinds).toEqual([PROXY_KIND_HTTP1, PROXY_KIND_WS]);

    controlled.streams[0]!.finish("first");
    await waitFor(() => controlled.streams.length === 2, "queued HTTP request");
    controlled.streams[1]!.finish("second");
    await waitFor(() => first.has("flowersec-proxy:response_end") && second.has("flowersec-proxy:response_end"));
    runtime.dispose();
  });

  it("validates admission limits", () => {
    const controlled = createControlledClient();
    expect(() => createProxyRuntime({ client: controlled.client, maxConcurrentHttpStreams: 0 })).toThrow(
      /positive safe integer/,
    );
    expect(() => createProxyRuntime({ client: controlled.client, maxConcurrentHttpStreams: 1.5 })).toThrow(
      /positive safe integer/,
    );
    expect(() => createProxyRuntime({ client: controlled.client, maxQueuedHttpRequests: -1 })).toThrow(
      /non-negative safe integer/,
    );
    expect(() => createProxyRuntime({ client: controlled.client, maxQueuedHttpRequests: 1.5 })).toThrow(
      /non-negative safe integer/,
    );
    expect(() => createProxyRuntime({ client: controlled.client, maxQueuedHttpBodyBytes: -1 })).toThrow(
      /non-negative safe integer/,
    );
    expect(() => createProxyRuntime({ client: controlled.client, maxQueuedHttpBodyBytes: 1.5 })).toThrow(
      /non-negative safe integer/,
    );
  });
});

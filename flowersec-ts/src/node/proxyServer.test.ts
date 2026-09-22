import type { AddressInfo } from "node:net";
import type { Session } from "../public/contract.js";
import { expect, expectTypeOf, test } from "vitest";

import {
  ProxyServer,
  type ProxyServerOptions,
  SessionHandlers,
  StreamHandlers,
} from "./index.js";
import type { StreamHandlerRegistrar } from "./proxyServer.js";
import { freezeStreamHandlers } from "../public/streamHandlers.js";
import { createStreamMetadata, type ByteStream } from "../facade.js";

test.each(["metadata", "GET", "POST"])("bounds incomplete proxy %s intake", async (stage) => {
  const server = new ProxyServer({
    upstream: "http://127.0.0.1:1", upstreamOrigin: "http://127.0.0.1:1",
    defaultHTTPRequestTimeoutMs: 20, maxHTTPRequestTimeoutMs: 40,
  });
  const handlers = new StreamHandlers();
  server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const payload = new TextEncoder().encode(JSON.stringify({ v: 1, request_id: "stalled", method: stage, path: "/", headers: [], timeout_ms: 20 }));
  const frame = new Uint8Array(payload.length + 4);
  new DataView(frame.buffer).setUint32(0, payload.length);
  frame.set(payload, 4);
  let delivered = stage === "metadata";
  let reset = false;
  let rejectRead: ((error: Error) => void) | undefined;
  const stream: ByteStream = {
    kind,
    async read() {
      if (!delivered) { delivered = true; return frame; }
      if (reset) throw new Error("reset");
      return await new Promise<Uint8Array>((_resolve, reject) => { rejectRead = reject; });
    },
    async write(data) { if (reset) throw new Error("reset"); return data.length; },
    async closeWrite() {},
    async reset() { reset = true; rejectRead?.(new Error("reset")); },
    async close() {},
  };
  await handler({ kind, metadata: createStreamMetadata({}), stream }, {});
  expect(reset).toBe(true);
  expect(server.activeCount).toBe(0);
  await server.close();
}, 1_000);

test("exposes a native Node ProxyServer with bounded loopback upstream policy", async () => {
  const options = {
    upstream: "http://127.0.0.1:18080",
    upstreamOrigin: "http://127.0.0.1:18080",
    maxBodyBytes: 1024,
    maxWebSocketFrameBytes: 1024,
  } satisfies ProxyServerOptions;
  expectTypeOf<ProxyServerOptions["upstream"]>().toEqualTypeOf<string>();
  const server = new ProxyServer(options);
  const handlers = new SessionHandlers();
  expect(() => server.register(handlers)).not.toThrow();
  await expect(server.close()).resolves.toBeUndefined();
  await expect(server.close()).resolves.toBeUndefined();
});

test("registers atomically into role-neutral StreamHandlers", async () => {
  const server = new ProxyServer({
    upstream: "http://127.0.0.1:18080",
    upstreamOrigin: "http://127.0.0.1:18080",
  });
  const handlers = new StreamHandlers();
  expect(() => server.register(handlers)).not.toThrow();
  expect(() => server.register(handlers)).toThrow(/handler_registration/u);
  await server.close();
});

test("rejects a forged registrar without invoking caller-controlled code", async () => {
  const server = new ProxyServer({
    upstream: "http://127.0.0.1:18080",
    upstreamOrigin: "http://127.0.0.1:18080",
  });
  const forged = Object.create(StreamHandlers.prototype) as StreamHandlerRegistrar;

  expect(() => server.register(forged)).toThrow(/handler_registration/u);
  expect(Object.getOwnPropertySymbols(StreamHandlers.prototype)).toEqual([]);
  await server.close();
});

test("rejects upstream and header policies that could escape the configured authority", () => {
  expect(() => new ProxyServer({
    upstream: "http://192.0.2.10:8080",
    upstreamOrigin: "http://192.0.2.10:8080",
  })).toThrow(/invalid_options/u);
  expect(() => new ProxyServer({
    upstream: "http://127.0.0.1:8080",
    upstreamOrigin: "http://127.0.0.1:8080",
    extraRequestHeaders: ["authorization"],
  })).toThrow(/invalid_options/u);
  expect(() => new ProxyServer({
    upstream: "http://127.0.0.1:8080",
    upstreamOrigin: "http://127.0.0.1:8080/path",
  })).toThrow(/invalid_options/u);
});

test("streams negotiated events beyond finite limits and cancels idle upstream work with the session", async () => {
  const { createServer } = await import("node:http");
  const { once } = await import("node:events");
  const { createProxyRuntime } = await import("../proxy/runtime.js");
  const upstream = createServer((_request, response) => {
    response.writeHead(200, { "Content-Type": "text/event-stream" });
    response.flushHeaders();
    const timer = setInterval(() => response.write("data: alive\n\n"), 15);
    response.on("close", () => clearInterval(timer));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const address = upstream.address() as AddressInfo;
  const origin = `http://127.0.0.1:${address.port}`;
  // Leave enough time for the initial HTTP response under parallel test load;
  // then explicitly keep the event stream alive beyond that finite deadline.
  const finiteTimeoutMs = 1_000;
  const server = new ProxyServer({ upstream: origin, upstreamOrigin: origin, maxBodyBytes: 16,
    defaultHTTPRequestTimeoutMs: finiteTimeoutMs, maxHTTPRequestTimeoutMs: finiteTimeoutMs });
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const operations: Promise<void>[] = [];
  const session = {
    async openStream() {
      const up = new TransformStream<Uint8Array, Uint8Array>();
      const down = new TransformStream<Uint8Array, Uint8Array>();
      const controller = new AbortController();
      const end = (readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>): ByteStream => {
        const reader = readable.getReader(); const writer = writable.getWriter();
        return {
          kind,
          async read(options) {
            const cancel = () => { void reader.cancel().catch(() => undefined); };
            options?.signal?.addEventListener("abort", cancel, { once: true });
            try { const result = await reader.read(); return result.done ? null : result.value; }
            finally { options?.signal?.removeEventListener("abort", cancel); }
          },
          async write(bytes) { await writer.write(bytes.slice()); return bytes.length; },
          async closeWrite() { await writer.close(); },
          async reset() { controller.abort(); await Promise.allSettled([reader.cancel(), writer.abort()]); },
          async close() { controller.abort(); await Promise.allSettled([reader.cancel(), writer.close()]); },
        };
      };
      const peer = end(up.readable, down.writable);
      operations.push(handler({ kind, stream: peer, metadata: createStreamMetadata({}) }, { signal: controller.signal }));
      return end(down.readable, up.writable);
    },
  } as Session;
  const runtime = createProxyRuntime({ session, maxBodyBytes: 16, timeoutMs: finiteTimeoutMs });
  try {
    const response = await runtime.fetch("/events", { headers: { accept: "text/event-stream" } });
    const reader = response.body!.getReader();
    await new Promise<void>(resolve => setTimeout(resolve, finiteTimeoutMs + 100));
    let bytes = 0;
    for (let i = 0; i < 10; i++) { const chunk = await reader.read(); bytes += chunk.value?.length ?? 0; }
    expect(bytes).toBeGreaterThan(16);
    await reader.cancel();
    await Promise.all(operations);
    expect(server.activeCount).toBe(0);
  } finally {
    runtime.dispose(); await server.close();
    upstream.closeAllConnections(); await new Promise<void>(done => upstream.close(() => done()));
  }
}, 5_000);

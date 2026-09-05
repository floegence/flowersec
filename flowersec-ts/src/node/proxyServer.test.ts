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

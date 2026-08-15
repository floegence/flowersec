import { expect, expectTypeOf, test } from "vitest";

import {
  ProxyServer,
  type ProxyServerOptions,
  SessionHandlers,
  type StreamHandlerRegistrar,
  StreamHandlers,
} from "./index.js";

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

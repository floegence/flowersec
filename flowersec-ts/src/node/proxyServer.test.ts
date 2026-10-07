import { encodeProxyMetadata, decodeProxyMetadata } from "../proxy/wire.js";
import type { V4StreamOpenAuthorizer } from "../v4/streamHandlers.js";
import type { AddressInfo } from "node:net";
import { expect, expectTypeOf, test } from "vitest";
import { ProxyServer, ResourceRoot, ResourceVector, ClockRate, TransportEnvironment, createTransportEnvironment,
  type ProxyServerOptions } from "./index.js";
import { captureProxyProtocolHandlers } from "./proxyServer.js";
import { captureHandlerPlan } from "../v4/handlerPlan.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import type { ProxyStream } from "../proxy/stream.js";
import type { ProxyStreamSource } from "../proxy/runtime.js";

function registrationEnvironment() {
  const limit = new ResourceVector([256n << 20n, 64n << 20n, 64n << 20n, 100000n, 100000n, 1024n, 1024n, 1024n, 1024n, 1024n, 1024n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 32, reservations: 128, references: 256,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const beginning = performance.now();
  const environment = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32),
    runtimeBytes: 1024n, namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, dependencies: 8, acquireMS: 1000n, cleanupMS: 100,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }),
      initial: () => ({ lowerMS: 1000n, upperMS: 1000n }) }, random: bytes => { crypto.getRandomValues(bytes); } });
  return { root, environment, owner: originalEnvironment(environment), async close() { await environment.close(); await environment.waitCleanup(); root.close(); } };
}
const registrationOptions = Object.freeze({ authorize: () => true, applicationBytes: 1024n });

test.each(["metadata", "GET", "POST"])("bounds incomplete proxy %s intake", async (stage) => {
  const server = new ProxyServer({
    upstream: "http://127.0.0.1:1", upstreamOrigin: "http://127.0.0.1:1",
    defaultHTTPRequestTimeoutMs: 20, maxHTTPRequestTimeoutMs: 40,
  });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const payload = encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "stalled", method: stage, path: "/", headers: [], timeout_ms: 20 });
  const frame = new Uint8Array(payload.length + 4);
  new DataView(frame.buffer).setUint32(0, payload.length);
  frame.set(payload, 4);
  let delivered = stage === "metadata";
  let reset = false;
  let rejectRead: ((error: Error) => void) | undefined;
  const stream: ProxyStream = {
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
  await handler({ stream }, { signal: new AbortController().signal });
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
  const fixture = registrationEnvironment();
  const plan = server.register(fixture.environment, registrationOptions);
  try {
    const captured = captureHandlerPlan(plan, fixture.owner, undefined);
    try { expect(captured.raw.map(stream => stream.kind)).toEqual(["flowersec-proxy/http1", "flowersec-proxy/ws"]); }
    finally { captured.release(); }
    await expect(server.close()).resolves.toBeUndefined();
    await expect(server.close()).resolves.toBeUndefined();
  } finally { plan.close(); await fixture.close(); }
});

test("publishes a complete immutable current plan and preserves existing captures after close", async () => {
  const server = new ProxyServer({ upstream: "http://127.0.0.1:18080", upstreamOrigin: "http://127.0.0.1:18080" });
  const fixture = registrationEnvironment(), other = registrationEnvironment();
  const plan = server.register(fixture.environment, registrationOptions);
  const captured = captureHandlerPlan(plan, fixture.owner, undefined);
  try {
    expect(captured.raw).toHaveLength(2);
    expect(() => captureHandlerPlan(plan, other.owner, undefined)).toThrow("owner_unavailable");
    plan.close();
    expect(captured.raw.map(stream => stream.kind)).toEqual(["flowersec-proxy/http1", "flowersec-proxy/ws"]);
    expect(() => captureHandlerPlan(plan, fixture.owner, undefined)).toThrow("owner_unavailable");
  } finally { captured.release(); plan.close(); await server.close(); await other.close(); await fixture.close(); }
});

test("rejects a forged Environment before reading caller-controlled registration options", async () => {
  const server = new ProxyServer({ upstream: "http://127.0.0.1:18080", upstreamOrigin: "http://127.0.0.1:18080" });
  const forged = Object.create(TransportEnvironment.prototype) as TransportEnvironment;
  let reads = 0;
  const options = { get authorize(): V4StreamOpenAuthorizer { reads++; throw new Error("caller getter"); }, applicationBytes: 1024n };
  expect(() => server.register(forged, options)).toThrow(/handler_registration/u);
  expect(reads).toBe(0);
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
  const { createProxyRuntimeWithStreams: createProxyRuntime } = await import("../proxy/runtime.js");
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
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const operations: Promise<void>[] = [];
  const session: ProxyStreamSource = {
    async openStream() {
      const up = new TransformStream<Uint8Array, Uint8Array>();
      const down = new TransformStream<Uint8Array, Uint8Array>();
      const controller = new AbortController();
      const end = (readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>): ProxyStream => {
        const reader = readable.getReader(); const writer = writable.getWriter();
        return {
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
      operations.push(handler({ stream: peer }, { signal: controller.signal }));
      return end(down.readable, up.writable);
    },
  };
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


test("retains repeated request fields and origin content-coded response bytes", async () => {
  const { createServer } = await import("node:http");
  const { once } = await import("node:events");
  const { gzipSync } = await import("node:zlib");
  const coded = gzipSync(Buffer.from("origin representation"));
  let observed: string[] = [];
  const upstream = createServer((request, response) => {
    observed = request.rawHeaders;
    response.writeHead(200, { "Content-Encoding": "gzip", "Content-Type": "text/plain" });
    response.end(coded);
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const server = new ProxyServer({ upstream: origin, upstreamOrigin: origin });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "coded", method: "GET", path: "/", headers: [
    { name: "if-match", value: '"one"' }, { name: "if-match", value: '"two"' },
  ] }));
  const requestBytes = requestWithEnd(meta);
  const writes: Buffer[] = [];
  let delivered = false;
  const stream: ProxyStream = {
    async read() { if (delivered) return null; delivered = true; return requestBytes; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ stream }, { signal: new AbortController().signal });
    const matches = observed.flatMap((name, index) => index % 2 === 0 && name.toLowerCase() === "if-match" ? [observed[index + 1]] : []);
    expect(matches).toEqual(['"one"', '"two"']);
    expect(observed.some(name => name.toLowerCase() === "accept-encoding")).toBe(false);
    const wire = Buffer.concat(writes);
    const metadataBytes = wire.readUInt32BE();
    const response = decodeProxyMetadata("ProxyHTTPResponse",wire.subarray(4, 4 + metadataBytes));
    expect(response.headers).toContainEqual({ name: "content-encoding", value: "gzip" });
    const chunks: Buffer[] = [];
    for (let offset = 4 + metadataBytes; offset < wire.length;) {
      const size = wire.readUInt32BE(offset); offset += 4;
      if (size === 0) { const n=wire.readUInt32BE(offset); expect(decodeProxyMetadata("ProxyBodyEnd",wire.subarray(offset+4,offset+4+n))).toEqual({v:2,trailers:[]}); expect(offset+4+n).toBe(wire.length); break; }
      chunks.push(wire.subarray(offset, offset + size)); offset += size;
    }
    expect(Buffer.concat(chunks)).toEqual(coded);
    expect(server.activeCount).toBe(0);
  } finally {
    await server.close(); upstream.closeAllConnections();
    await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});


test.each([
  ["HEAD", 200, "/large?"], ["GET", 304, "/large?q=%2f&x=%41+"],
  ["GET", 204, "/objects/a%2Fb"], ["GET", 204, "/a//b"], ["GET", 204, "//a/b"],
] as const)("preserves %s/%s target and bodyless metadata for %s", async (method, status, path) => {
  const { createServer } = await import("node:http");
  const { once } = await import("node:events");
  let observed: string | undefined;
  const upstream = createServer((request, response) => {
    observed = request.url;
    response.writeHead(status, status === 204 ? {} : { "Content-Length": "1073741824" });
    response.end();
  });
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const server = new ProxyServer({ upstream: origin, upstreamOrigin: origin, maxBodyBytes: 8 });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "bodyless", method, path, headers: [] }));
  const input = requestWithEnd(meta);
  const writes: Buffer[] = []; let delivered = false;
  const stream: ProxyStream = {
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ stream }, { signal: new AbortController().signal });
    expect(observed).toBe(path);
    const wire = Buffer.concat(writes), length = wire.readUInt32BE();
    const response = decodeProxyMetadata("ProxyHTTPResponse",wire.subarray(4, 4 + length));
    expect(response).toMatchObject({ ok: true, status });
    if (status !== 204) expect(response.headers).toContainEqual({ name: "content-length", value: "1073741824" });
    expect(wire.subarray(4 + length)).toEqual(bodyEndFrame());
  } finally {
    await server.close(); upstream.closeAllConnections();
    await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

function bodyEndFrame(): Buffer {
 const end=Buffer.from(encodeProxyMetadata("ProxyBodyEnd",{v:2,trailers:[]}));
 const bytes=Buffer.alloc(8+end.length);bytes.writeUInt32BE(end.length,4);end.copy(bytes,8);return bytes;
}
function requestWithEnd(meta:Buffer):Buffer {
 const prefix=Buffer.alloc(4);prefix.writeUInt32BE(meta.length);return Buffer.concat([prefix,meta,bodyEndFrame()]);
}

test.each(["extra_input", "hidden_coding", "method_case"])("enforces native proxy integrity at %s", async failure => {
  const { createServer } = await import("node:net");
  const { once } = await import("node:events");
  let connections = 0, request = "";
  const upstream = createServer(socket => {
    connections++;
    socket.on("data", data => {
      request += data.toString();
      if (request.endsWith("\r\n\r\n")) socket.end(failure === "hidden_coding"
        ? "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nConnection: close, content-encoding\r\nContent-Length: 5\r\n\r\ncoded"
        : "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    });
  });
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const server = new ProxyServer({ upstream: origin, upstreamOrigin: origin });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest", { v: 2, request_id: failure, method: "x-Custom", path: "/", headers: [] }));
  const input = Buffer.concat([requestWithEnd(meta), ...(failure === "extra_input" ? [Buffer.from([1])] : [])]);
  const writes: Buffer[] = []; let delivered = false;
  const stream: ProxyStream = {
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ stream }, { signal: new AbortController().signal });
    const output = Buffer.concat(writes), response = decodeProxyMetadata("ProxyHTTPResponse", output.subarray(4, 4 + output.readUInt32BE()));
    expect(response.ok).toBe(failure === "method_case");
    if (failure === "extra_input") expect(connections).toBe(0);
    else expect(request.startsWith("x-Custom / HTTP/1.1\r\n")).toBe(true);
  } finally {
    await server.close(); await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

test.each(["", "body"])("forwards separate native trailers for request body %j", async body => {
  const { createServer } = await import("node:http");
  const { once } = await import("node:events");
  let observed: string[] = [];
  let received = "";
  let requestTarget = "";
  let authority = "";
  const upstream = createServer((request, response) => {
    requestTarget = request.url!;
    authority = request.headers.host!;
    request.on("data", chunk => { received += chunk.toString(); });
    request.on("end", () => {
      observed = request.rawTrailers;
      response.writeHead(200, { Trailer: "X-Check" });
      response.write("ok");
      response.addTrailers([["X-Check", "first"], ["X-Check", "ÿ"]]);
      response.end();
    });
  });
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const origin = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const logicalOrigin = origin.replace("127.0.0.1", "localhost");
  const server = new ProxyServer({ upstream: logicalOrigin, upstreamOrigin: logicalOrigin, allowedUpstreamHosts: ["localhost"], allowedUpstreamAddresses: ["127.0.0.1", "::1"], extraRequestHeaders: ["x-check"], extraResponseHeaders: ["x-check"] });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.includes("http"))!;
  const frame = (schema: "ProxyHTTPRequest" | "ProxyBodyEnd", value: unknown): Buffer => {
    const bytes = Buffer.from(encodeProxyMetadata(schema, value)), length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]);
  };
  const chunk = Buffer.alloc(4 + body.length); chunk.writeUInt32BE(body.length); chunk.write(body, 4);
  const input = Buffer.concat([
    frame("ProxyHTTPRequest", { v: 2, request_id: "trailers", method: "POST", path: "//fixed/path?", headers: [{ name: "connection", value: "content-length" }, { name: "content-length", value: String(body.length) }] }),
    ...(body === "" ? [] : [chunk]), Buffer.alloc(4),
    frame("ProxyBodyEnd", { v: 2, trailers: [{ name: "x-check", value: "one" }, { name: "x-check", value: "é" }] }),
  ]);
  const writes: Buffer[] = []; let delivered = false;
  const stream: ProxyStream = {
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ stream }, { signal: new AbortController().signal });
    expect(received).toBe(body);
    expect(requestTarget).toBe("//fixed/path?");
    expect(authority).toBe(new URL(logicalOrigin).host);
    expect(observed.map((value, index) => index % 2 === 0 ? value.toLowerCase() : value)).toEqual(["x-check", "one", "x-check", "é"]);
    const output = Buffer.concat(writes);
    const n = output.readUInt32BE();
    expect(decodeProxyMetadata("ProxyHTTPResponse", output.subarray(4, 4 + n))).toMatchObject({ ok: true });
    let at = n + 4;
    for (;;) {
      const n = output.readUInt32BE(at); at += 4;
      if (n === 0) break;
      at += n;
    }
    const nEnd = output.readUInt32BE(at);
    expect(decodeProxyMetadata("ProxyBodyEnd", output.subarray(at + 4, at + 4 + nEnd))).toEqual({ v: 2, trailers: [{ name: "x-check", value: "first" }, { name: "x-check", value: "ÿ" }] });
  } finally {
    await server.close(); upstream.closeAllConnections();
    await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

test.each(["//fixed/path?", "/public/../api//items?q=%7euser"])("WebSocket preserves exact origin-form target %s with a numeric policy", async path => {
  const { createServer } = await import("node:http");
  const { once } = await import("node:events");
  const { WebSocketServer } = await import("ws");
  const upstream = createServer();
  const websocket = new WebSocketServer({ server: upstream });
  let authority: string | undefined, target: string | undefined;
  websocket.on("connection", (socket, request) => { authority = request.headers.host; target = request.url; socket.close(); });
  upstream.listen(0, "127.0.0.1"); await once(upstream, "listening");
  const origin = `http://localhost:${(upstream.address() as AddressInfo).port}`;
  const server = new ProxyServer({ upstream: origin, upstreamOrigin: origin, allowedUpstreamHosts: ["localhost"], allowedUpstreamAddresses: ["127.0.0.1", "::1"] });
  const handlers = captureProxyProtocolHandlers(server);
  const [, handler] = [...handlers].find(([name]) => name.endsWith("/ws"))!;
  const metadata = Buffer.from(encodeProxyMetadata("ProxyWebSocketOpen", { v: 2, conn_id: "network", path, headers: [] }));
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(metadata.length);
  let delivered = false, resolveRead: ((value: Uint8Array | null) => void) | undefined;
  let closeReply: Uint8Array | undefined;
  const writes: Buffer[] = [];
  const stream: ProxyStream = {
    async read(options) {
      options?.signal?.throwIfAborted();
      if (!delivered) { delivered = true; return Buffer.concat([prefix, metadata]); }
      if (closeReply !== undefined) { const reply = closeReply; closeReply = undefined; return reply; }
      return await new Promise<Uint8Array | null>((resolve, reject) => {
        const canceled = () => { resolveRead = undefined; reject(new Error("canceled")); };
        resolveRead = value => { options?.signal?.removeEventListener("abort", canceled); resolve(value); };
        options?.signal?.addEventListener("abort", canceled, { once: true });
      });
    },
    async write(bytes) {
      writes.push(Buffer.from(bytes));
      if (bytes[0] === 8) {
        const reply = Uint8Array.from(bytes);
        if (resolveRead === undefined) closeReply = reply;
        else { const resume = resolveRead; resolveRead = undefined; resume(reply); }
      }
      return bytes.length;
    },
    async closeWrite() {}, async reset() { resolveRead?.(null); }, async close() { resolveRead?.(null); },
  };
  try {
    await handler({ stream }, { signal: new AbortController().signal });
    expect(authority).toBe(new URL(origin).host); expect(target).toBe(path);
    const output = Buffer.concat(writes);
    expect(decodeProxyMetadata("ProxyWebSocketResponse", output.subarray(4, 4 + output.readUInt32BE()))).toMatchObject({ ok: true });
  } finally {
    await server.close(); for (const socket of websocket.clients) socket.terminate();
    await new Promise<void>(resolve => websocket.close(() => resolve()));
    await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

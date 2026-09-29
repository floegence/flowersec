import { encodeProxyMetadata, decodeProxyMetadata } from "../proxy/wire.js";
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
  const payload = encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "stalled", method: stage, path: "/", headers: [], timeout_ms: 20 });
  const frame = new Uint8Array(payload.length + 4);
  new DataView(frame.buffer).setUint32(0, payload.length);
  frame.set(payload, 4);
  let delivered = stage === "metadata";
  let reset = false;
  let rejectRead: ((error: Error) => void) | undefined;
  const stream: ByteStream = {
    kind,
    terminalError: undefined,
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const operations: Promise<void>[] = [];
  const termination = new Promise<never>(() => undefined);
  const session: Session = {
    rpc: {
      async call() { throw new Error("unused RPC call"); },
      async notify() { throw new Error("unused RPC notification"); },
      onNotify() { throw new Error("unused RPC subscription"); },
    },
    async acceptStream() { throw new Error("unused stream accept"); },
    async rekey() { throw new Error("unused rekey"); },
    async probeLiveness() { throw new Error("unused liveness probe"); },
    async waitTermination() { return await termination; },
    async close() { throw new Error("unused session close"); },
    async openStream() {
      const up = new TransformStream<Uint8Array, Uint8Array>();
      const down = new TransformStream<Uint8Array, Uint8Array>();
      const controller = new AbortController();
      const end = (readable: ReadableStream<Uint8Array>, writable: WritableStream<Uint8Array>): ByteStream => {
        const reader = readable.getReader(); const writer = writable.getWriter();
        return {
          kind,
          terminalError: undefined,
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "coded", method: "GET", path: "/", headers: [
    { name: "if-match", value: '"one"' }, { name: "if-match", value: '"two"' },
  ] }));
  const requestBytes = requestWithEnd(meta);
  const writes: Buffer[] = [];
  let delivered = false;
  const stream: ByteStream = { kind, terminalError: undefined,
    async read() { if (delivered) return null; delivered = true; return requestBytes; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ kind, stream, metadata: createStreamMetadata({}) }, {});
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest",{ v: 2, request_id: "bodyless", method, path, headers: [] }));
  const input = requestWithEnd(meta);
  const writes: Buffer[] = []; let delivered = false;
  const stream: ByteStream = { kind, terminalError: undefined,
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ kind, stream, metadata: createStreamMetadata({}) }, {});
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
  const meta = Buffer.from(encodeProxyMetadata("ProxyHTTPRequest", { v: 2, request_id: failure, method: "x-Custom", path: "/", headers: [] }));
  const input = Buffer.concat([requestWithEnd(meta), ...(failure === "extra_input" ? [Buffer.from([1])] : [])]);
  const writes: Buffer[] = []; let delivered = false;
  const stream: ByteStream = { kind, terminalError: undefined,
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ kind, stream, metadata: createStreamMetadata({}) }, {});
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.includes("http"))!;
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
  const stream: ByteStream = { kind, terminalError: undefined,
    async read() { if (delivered) return null; delivered = true; return input; },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() {}, async close() {},
  };
  try {
    await handler({ kind, stream, metadata: createStreamMetadata({}) }, {});
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
  const handlers = new StreamHandlers(); server.register(handlers);
  const [kind, handler] = [...freezeStreamHandlers(handlers).streams].find(([name]) => name.endsWith("/ws"))!;
  const metadata = Buffer.from(encodeProxyMetadata("ProxyWebSocketOpen", { v: 2, conn_id: "network", path, headers: [] }));
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(metadata.length);
  let delivered = false, resolveRead: ((value: null) => void) | undefined;
  const writes: Buffer[] = [];
  const stream: ByteStream = { kind, terminalError: undefined,
    async read(options) {
      options?.signal?.throwIfAborted();
      if (!delivered) { delivered = true; return Buffer.concat([prefix, metadata]); }
      return await new Promise<null>((resolve, reject) => {
        const canceled = () => { resolveRead = undefined; reject(new Error("canceled")); };
        resolveRead = value => { options?.signal?.removeEventListener("abort", canceled); resolve(value); };
        options?.signal?.addEventListener("abort", canceled, { once: true });
      });
    },
    async write(bytes) { writes.push(Buffer.from(bytes)); return bytes.length; },
    async closeWrite() {}, async reset() { resolveRead?.(null); }, async close() { resolveRead?.(null); },
  };
  try {
    await handler({ kind, stream, metadata: createStreamMetadata({}) }, {});
    expect(authority).toBe(new URL(origin).host); expect(target).toBe(path);
    const output = Buffer.concat(writes);
    expect(decodeProxyMetadata("ProxyWebSocketResponse", output.subarray(4, 4 + output.readUInt32BE()))).toMatchObject({ ok: true });
  } finally {
    await server.close(); for (const socket of websocket.clients) socket.terminate();
    await new Promise<void>(resolve => websocket.close(() => resolve()));
    await new Promise<void>(resolve => upstream.close(() => resolve()));
  }
});

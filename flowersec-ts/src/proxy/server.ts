import { createRequire } from "node:module";

import type { Session } from "../endpoint/index.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { RpcRouter, RpcServer, type RpcServerOptions } from "../rpc/server.js";
import { createByteReader } from "../streamio/index.js";
import { readU32be, u32be } from "../utils/bin.js";
import type { YamuxStream } from "../yamux/stream.js";
import {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_CHUNK_BYTES,
  DEFAULT_MAX_WS_FRAME_BYTES,
  PROXY_KIND_HTTP1,
  PROXY_KIND_WS,
  PROXY_PROTOCOL_VERSION,
} from "./constants.js";
import { filterRequestHeaders, filterResponseHeaders, filterWsOpenHeaders, isSafeHeaderValue, isValidHeaderName, normalizeHeaderName } from "./headerPolicy.js";
import type { Header, HttpRequestMetaV1, HttpResponseMetaV1, WsOpenMetaV1, WsOpenRespV1 } from "./types.js";

export type ProxyServerOptions = Readonly<{
  upstream: string;
  upstreamOrigin?: string;
  allowedUpstreamHosts?: readonly string[];
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  defaultTimeoutMs?: number;
  maxTimeoutMs?: number;
  maxConcurrentStreams?: number;
  extraRequestHeaders?: readonly string[];
  extraResponseHeaders?: readonly string[];
  blockedResponseHeaders?: readonly string[];
  extraWsHeaders?: readonly string[];
  forbiddenCookieNames?: readonly string[];
  forbiddenCookieNamePrefixes?: readonly string[];
  fetch?: typeof fetch;
  rpcRouter?: RpcRouter;
  rpcServerOptions?: RpcServerOptions;
}>;

type CompiledOptions = Readonly<{
  upstream: URL;
  upstreamOrigin: string;
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  defaultTimeoutMs: number;
  maxTimeoutMs: number;
  maxConcurrentStreams: number;
  extraRequestHeaders: readonly string[];
  extraResponseHeaders: readonly string[];
  blockedResponseHeaders: ReadonlySet<string>;
  extraWsHeaders: readonly string[];
  forbiddenCookieNames: ReadonlySet<string>;
  forbiddenCookieNamePrefixes: readonly string[];
  fetch: typeof fetch;
}>;

export async function serveProxySession(session: Session, options: ProxyServerOptions, signal?: AbortSignal): Promise<void> {
  const compiled = compileOptions(options);
  const active = new Set<Promise<void>>();
  try {
    while (!signal?.aborted) {
      const accepted = await session.acceptStream(signal === undefined ? {} : { signal });
      if (accepted.kind === "rpc") {
        if (active.size >= compiled.maxConcurrentStreams) {
          await accepted.stream.reset(new Error("proxy stream concurrency exhausted"));
          continue;
        }
        const task = serveRPCStream(accepted.stream, options.rpcRouter ?? new RpcRouter(), options.rpcServerOptions, signal)
          .catch(() => {})
          .finally(() => active.delete(task));
        active.add(task);
        continue;
      }
      if (accepted.kind !== PROXY_KIND_HTTP1 && accepted.kind !== PROXY_KIND_WS) {
        await accepted.stream.reset(new Error(`unsupported proxy stream kind ${accepted.kind}`));
        continue;
      }
      if (active.size >= compiled.maxConcurrentStreams) {
        await accepted.stream.reset(new Error("proxy stream concurrency exhausted"));
        continue;
      }
      const task = serveProxyStreamCompiled(accepted.kind, accepted.stream, compiled, signal)
        .catch(() => {})
        .finally(() => active.delete(task));
      active.add(task);
    }
  } finally {
    await Promise.allSettled(active);
  }
}

async function serveRPCStream(
  stream: YamuxStream,
  router: RpcRouter,
  options: RpcServerOptions | undefined,
  signal?: AbortSignal,
): Promise<void> {
  const reader = createByteReader(stream, signal === undefined ? {} : { signal });
  const server = new RpcServer(
    {
      readExactly: (length) => reader.readExactly(length),
      write: (bytes) => stream.write(bytes),
      close: (error) => { void stream.reset(asError(error)); },
    },
    options,
    router,
  );
  await server.serve(signal);
}

export function serveProxyStream(
  kind: typeof PROXY_KIND_HTTP1 | typeof PROXY_KIND_WS,
  stream: YamuxStream,
  options: ProxyServerOptions,
  signal?: AbortSignal,
): Promise<void> {
  return serveProxyStreamCompiled(kind, stream, compileOptions(options), signal);
}

async function serveProxyStreamCompiled(
  kind: typeof PROXY_KIND_HTTP1 | typeof PROXY_KIND_WS,
  stream: YamuxStream,
  options: CompiledOptions,
  signal?: AbortSignal,
): Promise<void> {
  try {
    if (kind === PROXY_KIND_HTTP1) await serveHTTP(stream, options, signal);
    else await serveWebSocket(stream, options, signal);
  } finally {
    try { await stream.close(); } catch { /* The peer may already have reset the stream. */ }
  }
}

async function serveHTTP(stream: YamuxStream, options: CompiledOptions, signal?: AbortSignal): Promise<void> {
  const reader = createByteReader(stream, signal === undefined ? {} : { signal });
  let requestId = "unknown";
  try {
    const meta = assertHTTPRequestMeta(await readJsonFrame(reader, options.maxJsonFrameBytes));
    requestId = meta.request_id;
    const path = parsePath(meta.path);
    const body = await readBody(reader, options.maxChunkBytes, options.maxBodyBytes);
    const headers = requestHeaders(meta.headers, options);
    applyExternalOrigin(headers, meta.external_origin);
    const target = new URL(options.upstream);
    target.pathname = path.pathname;
    target.search = path.search;
    target.hash = "";

    const timeoutMs = resolveTimeout(meta.timeout_ms, options);
    const controller = new AbortController();
    const onAbort = () => controller.abort(signal?.reason);
    signal?.addEventListener("abort", onAbort, { once: true });
    const timer = timeoutMs > 0 ? setTimeout(() => controller.abort(new Error("upstream request timeout")), timeoutMs) : undefined;
    try {
      const method = meta.method.trim().toUpperCase();
      const response = await options.fetch(target, {
        method,
        headers,
        redirect: "manual",
        signal: controller.signal,
        ...((method === "GET" || method === "HEAD") ? {} : { body: body.slice().buffer as ArrayBuffer }),
      });
      const responseHeaders = collectResponseHeaders(response.headers, options);
      const responseMeta: HttpResponseMetaV1 = {
        v: PROXY_PROTOCOL_VERSION,
        request_id: requestId,
        ok: true,
        status: response.status,
        headers: responseHeaders,
      };
      await writeJsonFrame(stream, responseMeta);
      if (response.body == null) {
        await stream.write(u32be(0));
        return;
      }
      const bodyReader = response.body.getReader();
      let total = 0;
      while (true) {
        const next = await bodyReader.read();
        if (next.done) break;
        const bytes = next.value;
        total += bytes.length;
        if (total > options.maxBodyBytes) throw new ProxyServerError("response_body_too_large", "response body too large");
        for (let offset = 0; offset < bytes.length; offset += options.maxChunkBytes) {
          const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + options.maxChunkBytes));
          await stream.write(u32be(chunk.length));
          await stream.write(chunk);
        }
      }
      await stream.write(u32be(0));
    } finally {
      if (timer != null) clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  } catch (error) {
    await writeHTTPError(stream, requestId, classifyHTTPError(error), error);
  }
}

async function serveWebSocket(stream: YamuxStream, options: CompiledOptions, signal?: AbortSignal): Promise<void> {
  const reader = createByteReader(stream, signal === undefined ? {} : { signal });
  let connId = "unknown";
  let raw: any;
  try {
    const meta = assertWSOpenMeta(await readJsonFrame(reader, options.maxJsonFrameBytes));
    connId = meta.conn_id;
    const path = parsePath(meta.path);
    const target = new URL(options.upstream);
    target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
    target.pathname = path.pathname;
    target.search = path.search;
    target.hash = "";

    const filtered = serverWSHeaders(meta.headers, options);
    const protocolsHeader = filtered.find((header) => header.name === "sec-websocket-protocol")?.value ?? "";
    const protocols = protocolsHeader.split(",").map((value) => value.trim()).filter((value) => value !== "");
    const headers: Record<string, string> = { Origin: options.upstreamOrigin };
    for (const header of filtered) {
      if (header.name === "sec-websocket-protocol") continue;
      headers[header.name] = headers[header.name] == null ? header.value : `${headers[header.name]}, ${header.value}`;
    }
    const require = createRequire(import.meta.url);
    const module = require("ws") as any;
    const WebSocketCtor = module.WebSocket ?? module;
    raw = new WebSocketCtor(target.toString(), protocols, {
      headers,
      maxPayload: options.maxWsFrameBytes,
      perMessageDeflate: false,
      handshakeTimeout: Math.min(options.defaultTimeoutMs, options.maxTimeoutMs),
    });
    await waitForUpstreamOpen(raw, signal);
    const response: WsOpenRespV1 = {
      v: PROXY_PROTOCOL_VERSION,
      conn_id: connId,
      ok: true,
      protocol: String(raw.protocol ?? ""),
    };
    await writeJsonFrame(stream, response);

    let writeChain = Promise.resolve();
    let terminalResolve!: (error?: Error) => void;
    const terminal = new Promise<Error | undefined>((resolve) => { terminalResolve = resolve; });
    const writeFrame = (op: number, payload: Uint8Array) => {
      const write = writeChain.then(() => writeWSFrame(stream, op, payload, options.maxWsFrameBytes));
      writeChain = write.catch(() => {});
      void write.catch((error) => terminalResolve(asError(error)));
    };
    raw.on("message", (data: unknown, isBinary: boolean) => writeFrame(isBinary ? 2 : 1, toBytes(data)));
    raw.on("ping", (data: unknown) => writeFrame(9, toBytes(data)));
    raw.on("pong", (data: unknown) => writeFrame(10, toBytes(data)));
    raw.on("close", (code: number, reason: unknown) => {
      const reasonBytes = toBytes(reason);
      const payload = new Uint8Array(2 + reasonBytes.length);
      payload[0] = (code >>> 8) & 0xff;
      payload[1] = code & 0xff;
      payload.set(reasonBytes, 2);
      writeFrame(8, payload);
      terminalResolve();
    });
    raw.on("error", (error: Error) => terminalResolve(error));

    const inbound = (async () => {
      while (true) {
        const frame = await readWSFrame(reader, options.maxWsFrameBytes);
        switch (frame.op) {
          case 1: raw.send(frame.payload, { binary: false }); break;
          case 2: raw.send(frame.payload, { binary: true }); break;
          case 8:
            raw.close(frame.payload.length >= 2 ? (frame.payload[0]! << 8) | frame.payload[1]! : 1000, new TextDecoder().decode(frame.payload.subarray(2)));
            return;
          case 9: raw.ping(frame.payload); break;
          case 10: raw.pong(frame.payload); break;
          default: throw new Error("invalid websocket frame operation");
        }
      }
    })();
    const result = await Promise.race([inbound.then(() => undefined), terminal]);
    if (result != null) throw result;
    await writeChain;
  } catch (error) {
    if (raw == null || raw.readyState !== 1) await writeWSOpenError(stream, connId, classifyWSError(error), error);
  } finally {
    try { raw?.close(); } catch { /* Best effort. */ }
  }
}

function compileOptions(input: ProxyServerOptions): CompiledOptions {
  const upstream = new URL(input.upstream);
  if ((upstream.protocol !== "http:" && upstream.protocol !== "https:") || upstream.username !== "" || upstream.password !== "") {
    throw new Error("upstream must be an http(s) URL without credentials");
  }
  const allowedHosts = new Set((input.allowedUpstreamHosts?.length ? input.allowedUpstreamHosts : ["127.0.0.1"]).map((host) => host.trim().toLowerCase()));
  if (!allowedHosts.has(upstream.hostname.toLowerCase())) throw new Error("upstream host is not allowed");
  const upstreamOrigin = normalizeOrigin(input.upstreamOrigin ?? upstream.origin);
  const maxJsonFrameBytes = positive(input.maxJsonFrameBytes, DEFAULT_MAX_JSON_FRAME_BYTES, "maxJsonFrameBytes");
  const maxChunkBytes = positive(input.maxChunkBytes, DEFAULT_MAX_CHUNK_BYTES, "maxChunkBytes");
  const maxBodyBytes = positive(input.maxBodyBytes, DEFAULT_MAX_BODY_BYTES, "maxBodyBytes");
  const maxWsFrameBytes = positive(input.maxWsFrameBytes, DEFAULT_MAX_WS_FRAME_BYTES, "maxWsFrameBytes");
  const defaultTimeoutMs = nonNegative(input.defaultTimeoutMs, 30_000, "defaultTimeoutMs");
  const maxTimeoutMs = nonNegative(input.maxTimeoutMs, 300_000, "maxTimeoutMs");
  if (maxTimeoutMs > 0 && defaultTimeoutMs > maxTimeoutMs) throw new Error("defaultTimeoutMs exceeds maxTimeoutMs");
  return {
    upstream,
    upstreamOrigin,
    maxJsonFrameBytes,
    maxChunkBytes,
    maxBodyBytes,
    maxWsFrameBytes,
    defaultTimeoutMs,
    maxTimeoutMs,
    maxConcurrentStreams: positive(input.maxConcurrentStreams, 64, "maxConcurrentStreams"),
    extraRequestHeaders: input.extraRequestHeaders ?? [],
    extraResponseHeaders: input.extraResponseHeaders ?? [],
    blockedResponseHeaders: normalizeNames(input.blockedResponseHeaders),
    extraWsHeaders: input.extraWsHeaders ?? [],
    forbiddenCookieNames: normalizeNames(input.forbiddenCookieNames),
    forbiddenCookieNamePrefixes: [...normalizeNames(input.forbiddenCookieNamePrefixes)],
    fetch: input.fetch ?? globalThis.fetch.bind(globalThis),
  };
}

function assertHTTPRequestMeta(input: unknown): HttpRequestMetaV1 {
  if (typeof input !== "object" || input == null || Array.isArray(input)) throw new ProxyServerError("invalid_request_meta", "invalid HTTP request meta");
  const meta = input as Partial<HttpRequestMetaV1>;
  if (meta.v !== PROXY_PROTOCOL_VERSION || typeof meta.request_id !== "string" || meta.request_id.trim() === "") throw new ProxyServerError("invalid_request_meta", "invalid request ID");
  if (typeof meta.method !== "string" || meta.method.trim() === "" || typeof meta.path !== "string" || !Array.isArray(meta.headers)) throw new ProxyServerError("invalid_request_meta", "invalid HTTP request meta");
  if (meta.timeout_ms !== undefined && (!Number.isSafeInteger(meta.timeout_ms) || meta.timeout_ms < 0)) throw new ProxyServerError("invalid_request_meta", "invalid timeout_ms");
  return { ...meta, request_id: meta.request_id.trim(), method: meta.method.trim() } as HttpRequestMetaV1;
}

function assertWSOpenMeta(input: unknown): WsOpenMetaV1 {
  if (typeof input !== "object" || input == null || Array.isArray(input)) throw new ProxyServerError("invalid_ws_open_meta", "invalid websocket open meta");
  const meta = input as Partial<WsOpenMetaV1>;
  if (meta.v !== PROXY_PROTOCOL_VERSION || typeof meta.conn_id !== "string" || meta.conn_id.trim() === "" || typeof meta.path !== "string" || !Array.isArray(meta.headers)) {
    throw new ProxyServerError("invalid_ws_open_meta", "invalid websocket open meta");
  }
  return { ...meta, conn_id: meta.conn_id.trim() } as WsOpenMetaV1;
}

function parsePath(input: string): URL {
  const path = input.trim();
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("://") || /[\r\n\t ]/.test(path)) throw new ProxyServerError("invalid_request_meta", "invalid path");
  return new URL(path, "http://flowersec.invalid");
}

function requestHeaders(input: readonly Header[], options: CompiledOptions): Headers {
  const filtered = filterRequestHeaders(input, { extraAllowed: options.extraRequestHeaders });
  const headers = new Headers();
  for (const header of filtered) headers.append(header.name, header.value);
  for (const header of input) {
    if (normalizeHeaderName(header.name) !== "cookie" || !isSafeHeaderValue(header.value)) continue;
    const cookie = filterCookie(header.value, options);
    if (cookie !== "") headers.append("cookie", cookie);
  }
  return headers;
}

function serverWSHeaders(input: readonly Header[], options: CompiledOptions): Header[] {
  const filtered = filterWsOpenHeaders(input, { extraAllowed: options.extraWsHeaders });
  return filtered.flatMap((header) => header.name === "cookie" ? [{ ...header, value: filterCookie(header.value, options) }] : [header]).filter((header) => header.value !== "");
}

function filterCookie(input: string, options: CompiledOptions): string {
  return input.split(";").map((part) => part.trim()).filter((part) => {
    const index = part.indexOf("=");
    if (index <= 0) return false;
    const name = part.slice(0, index).trim().toLowerCase();
    if (options.forbiddenCookieNames.has(name)) return false;
    return !options.forbiddenCookieNamePrefixes.some((prefix) => name.startsWith(prefix));
  }).join("; ");
}

function collectResponseHeaders(input: Headers, options: CompiledOptions): Header[] {
  const raw: Header[] = [];
  const setCookies = (input as Headers & { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  input.forEach((value, name) => {
    if (name.toLowerCase() !== "set-cookie") raw.push({ name, value });
  });
  for (const value of setCookies) raw.push({ name: "set-cookie", value });
  return filterResponseHeaders(raw, { extraAllowed: options.extraResponseHeaders }).passthrough
    .concat(raw.filter((header) => normalizeHeaderName(header.name) === "set-cookie"))
    .filter((header) => !options.blockedResponseHeaders.has(normalizeHeaderName(header.name)));
}

function applyExternalOrigin(headers: Headers, input: string | undefined): void {
  if (input == null || input.trim() === "") return;
  const external = normalizeOrigin(input);
  const current = headers.get("origin");
  if (current != null && normalizeOrigin(current) !== external) throw new ProxyServerError("invalid_request_meta", "external_origin conflicts with origin header");
  headers.set("x-forwarded-proto", new URL(external).protocol.slice(0, -1));
  headers.set("host", new URL(external).host);
}

async function readBody(reader: ReturnType<typeof createByteReader>, maxChunkBytes: number, maxBodyBytes: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const length = readU32be(await reader.readExactly(4), 0);
    if (length === 0) break;
    if (length > maxChunkBytes) throw new ProxyServerError("request_body_too_large", "request chunk too large");
    total += length;
    if (total > maxBodyBytes) throw new ProxyServerError("request_body_too_large", "request body too large");
    chunks.push(await reader.readExactly(length));
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return body;
}

async function writeHTTPError(stream: YamuxStream, requestId: string, code: string, error: unknown): Promise<void> {
  const meta: HttpResponseMetaV1 = { v: PROXY_PROTOCOL_VERSION, request_id: requestId.trim() || "unknown", ok: false, error: { code, message: asError(error).message } };
  try { await writeJsonFrame(stream, meta); await stream.write(u32be(0)); } catch { /* The peer may be gone. */ }
}

async function readWSFrame(reader: ReturnType<typeof createByteReader>, maxBytes: number): Promise<{ op: number; payload: Uint8Array }> {
  const header = await reader.readExactly(5);
  const length = readU32be(header, 1);
  if (length > maxBytes) throw new Error("websocket frame too large");
  return { op: header[0]!, payload: await reader.readExactly(length) };
}

async function writeWSFrame(stream: YamuxStream, op: number, payload: Uint8Array, maxBytes: number): Promise<void> {
  if (payload.length > maxBytes) throw new Error("websocket frame too large");
  const header = new Uint8Array(5);
  header[0] = op;
  header.set(u32be(payload.length), 1);
  await stream.write(header);
  if (payload.length > 0) await stream.write(payload);
}

async function writeWSOpenError(stream: YamuxStream, connId: string, code: string, error: unknown): Promise<void> {
  const response: WsOpenRespV1 = { v: PROXY_PROTOCOL_VERSION, conn_id: connId.trim() || "unknown", ok: false, error: { code, message: asError(error).message } };
  try { await writeJsonFrame(stream, response); } catch { /* The peer may be gone. */ }
}

function waitForUpstreamOpen(websocket: any, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => { websocket.off("open", onOpen); websocket.off("error", onError); signal?.removeEventListener("abort", onAbort); };
    const onOpen = () => { cleanup(); resolve(); };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onAbort = () => { cleanup(); reject(signal?.reason ?? new Error("aborted")); };
    websocket.once("open", onOpen);
    websocket.once("error", onError);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function resolveTimeout(input: number | undefined, options: CompiledOptions): number {
  const timeout = input == null || input === 0 ? options.defaultTimeoutMs : input;
  return options.maxTimeoutMs > 0 ? Math.min(timeout, options.maxTimeoutMs) : timeout;
}

function normalizeOrigin(input: string): string {
  const url = new URL(input);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username !== "" || url.password !== "" || (url.pathname !== "" && url.pathname !== "/") || url.search !== "" || url.hash !== "") throw new Error("invalid origin");
  return url.origin;
}

function normalizeNames(input: readonly string[] | undefined): ReadonlySet<string> {
  const result = new Set<string>();
  for (const item of input ?? []) {
    const name = normalizeHeaderName(item);
    if (name === "" || !isValidHeaderName(name)) throw new Error("invalid policy name");
    result.add(name);
  }
  return result;
}

function positive(input: number | undefined, fallback: number, name: string): number {
  const value = input ?? fallback;
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`);
  return value;
}

function nonNegative(input: number | undefined, fallback: number, name: string): number {
  const value = input ?? fallback;
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  return value;
}

function classifyHTTPError(error: unknown): string {
  if (error instanceof ProxyServerError) return error.code;
  if (asError(error).name === "AbortError") return "timeout";
  return "upstream_request_failed";
}

function classifyWSError(error: unknown): string {
  if (error instanceof ProxyServerError) return error.code;
  return "upstream_ws_dial_failed";
}

function toBytes(input: unknown): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  return new TextEncoder().encode(String(input ?? ""));
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

class ProxyServerError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "ProxyServerError";
  }
}

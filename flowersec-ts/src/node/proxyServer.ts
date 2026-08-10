import { createRequire } from "node:module";

import type { ByteStream } from "../public/contract.js";
import { SessionError } from "../public/contract.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { ProxyByteReader, writeAll } from "../proxy/stream.js";
import { SessionHandlers, type StreamHandler } from "./acceptor.js";

const HTTP_KIND = "flowersec-proxy/http1";
const WS_KIND = "flowersec-proxy/ws";
const WIRE_VERSION = 1;
const DEFAULT_MAX_JSON = 1 << 20;
const DEFAULT_MAX_CHUNK = 256 * 1024;
const DEFAULT_MAX_BODY = 64 * 1024 * 1024;
const DEFAULT_MAX_WS = 1 << 20;
const DEFAULT_TIMEOUT = 30_000;
const MAX_TIMEOUT = 300_000;
const FORBIDDEN_HEADERS = new Set(["authorization", "connection", "host", "keep-alive", "proxy-authorization", "set-cookie", "transfer-encoding", "upgrade"]);
const REQUEST_HEADERS = new Set(["accept", "accept-language", "content-type", "if-match", "if-none-match", "range"]);
const RESPONSE_HEADERS = new Set(["accept-ranges", "cache-control", "content-disposition", "content-language", "content-range", "content-type", "etag", "expires", "last-modified", "location"]);
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

export type ProxyServerOptions = Readonly<{
  upstream: string;
  upstreamOrigin: string;
  allowedUpstreamHosts?: readonly string[];
  allowedOrigins?: readonly string[];
  maxConcurrentStreams?: number;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWebSocketFrameBytes?: number;
  defaultHTTPRequestTimeoutMs?: number;
  maxHTTPRequestTimeoutMs?: number;
  extraRequestHeaders?: readonly string[];
  extraResponseHeaders?: readonly string[];
  blockedResponseHeaders?: readonly string[];
  extraWebSocketHeaders?: readonly string[];
  onError?: (error: unknown) => void;
}>;

export class ProxyServerError extends Error {
  constructor(readonly code: "invalid_options" | "handler_registration" | "closed") {
    super(`Flowersec proxy server failed (code=${code})`);
    this.name = "ProxyServerError";
  }
}

type Config = Readonly<{
  upstream: URL;
  upstreamOrigin: string;
  allowedOrigins: ReadonlySet<string>;
  requestHeaders: ReadonlySet<string>;
  responseHeaders: ReadonlySet<string>;
  blockedResponseHeaders: ReadonlySet<string>;
  websocketHeaders: ReadonlySet<string>;
  maxConcurrent: number;
  maxJSON: number;
  maxChunk: number;
  maxBody: number;
  maxWS: number;
  defaultTimeout: number;
  maxTimeout: number;
  report?: (error: unknown) => void;
}>;

type HTTPMeta = Readonly<{
  v: number;
  request_id: string;
  method: string;
  path: string;
  headers: readonly Header[];
  external_origin?: string;
  timeout_ms?: number;
}>;
type WSOpen = Readonly<{ v: number; conn_id: string; path: string; headers: readonly Header[] }>;
type Header = Readonly<{ name: string; value: string }>;

export class ProxyServer {
  readonly #config: Config;
  readonly #active = new Set<AbortController>();
  readonly #permits: Set<unknown> = new Set();
  #closed = false;

  constructor(options: ProxyServerOptions) {
    this.#config = compileConfig(options);
  }

  register(handlers: SessionHandlers): void {
    if (this.#closed) throw new ProxyServerError("closed");
    if (!(handlers instanceof SessionHandlers)) throw new ProxyServerError("handler_registration");
    try {
      handlers.handleStream(HTTP_KIND, this.#httpHandler());
      handlers.handleStream(WS_KIND, this.#webSocketHandler());
    } catch (error) {
      this.#report(error);
      throw new ProxyServerError("handler_registration");
    }
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const controller of this.#active) controller.abort(new SessionError("closed"));
    this.#active.clear();
    this.#permits.clear();
  }

  /** @internal */
  get activeCount(): number { return this.#active.size; }

  #httpHandler(): StreamHandler {
    return async (incoming, options) => {
      const release = this.#acquire(incoming.stream);
      if (release === undefined) return;
      const controller = this.#track(options.signal);
      try { await this.#serveHTTP(incoming.stream, controller.signal); }
      catch (error) { this.#report(error); }
      finally { this.#untrack(controller); release(); }
    };
  }

  #webSocketHandler(): StreamHandler {
    return async (incoming, options) => {
      const release = this.#acquire(incoming.stream);
      if (release === undefined) return;
      const controller = this.#track(options.signal);
      try { await this.#serveWebSocket(incoming.stream, controller.signal); }
      catch (error) { this.#report(error); }
      finally { this.#untrack(controller); release(); }
    };
  }

  #acquire(stream: ByteStream): (() => void) | undefined {
    if (this.#closed || this.#permits.size >= this.#config.maxConcurrent) {
      void stream.reset().catch(() => undefined);
      this.#report(new ProxyServerError(this.#closed ? "closed" : "handler_registration"));
      return undefined;
    }
    const token = Object.freeze({});
    this.#permits.add(token);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.#permits.delete(token);
    };
  }

  #track(parent?: AbortSignal): AbortController {
    const controller = new AbortController();
    if (this.#closed) controller.abort(new SessionError("closed"));
    if (parent !== undefined) {
      if (parent.aborted) controller.abort(parent.reason);
      else parent.addEventListener("abort", () => controller.abort(parent.reason), { once: true });
    }
    this.#active.add(controller);
    return controller;
  }
  #untrack(controller: AbortController): void { this.#active.delete(controller); }
  #report(error: unknown): void { try { this.#config.report?.(error); } catch { /* reporting is isolated */ } }

  async #serveHTTP(stream: ByteStream, signal: AbortSignal): Promise<void> {
    const reader = new ProxyByteReader(stream, { signal });
    let meta: HTTPMeta;
    try { meta = decodeHTTPMeta(await readFrame(reader, this.#config.maxJSON)); }
    catch { await writeHTTPError(stream, "unknown", "invalid_request_meta"); return; }
    const requestID = meta.request_id.trim();
    const path = normalizePath(meta.path);
    if (meta.v !== WIRE_VERSION || requestID === "" || meta.method.trim() === "" || path === undefined) {
      await writeHTTPError(stream, requestID, "invalid_request_meta"); return;
    }
    const timeout = normalizeTimeout(meta.timeout_ms, this.#config.defaultTimeout, this.#config.maxTimeout);
    if (timeout === undefined) { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
    const body = await readBody(reader, this.#config.maxChunk, this.#config.maxBody);
    if (body === undefined) { await writeHTTPError(stream, requestID, "request_body_invalid"); return; }
    const externalOrigin = validateOrigin(meta.external_origin, this.#config.allowedOrigins);
    if (meta.external_origin !== undefined && externalOrigin === undefined) { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
    const headers = Object.fromEntries(filterHeaders(meta.headers, REQUEST_HEADERS, this.#config.requestHeaders).map((header) => [header.name, header.value]));
    const target = new URL(path, this.#config.upstream);
    const requestInit: RequestInit & { duplex?: "half" } = {
      method: meta.method.trim().toUpperCase(), headers, redirect: "manual", signal,
      ...(body.byteLength === 0 ? {} : { body: body.slice().buffer as ArrayBuffer, duplex: "half" }),
    };
    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(), timeout);
    const linked = linkSignals(signal, timeoutController.signal);
    try {
      requestInit.signal = linked.signal;
      const response = await fetch(target, requestInit);
      const responseBody = new Uint8Array(await response.arrayBuffer());
      if (responseBody.byteLength > this.#config.maxBody) { await writeHTTPError(stream, requestID, "response_body_too_large"); return; }
      await writeFrame(stream, {
        v: WIRE_VERSION, request_id: requestID, ok: true, status: response.status,
        headers: filterHeaders(responseHeaderList(response.headers), RESPONSE_HEADERS, this.#config.responseHeaders, this.#config.blockedResponseHeaders),
      }, signal);
      await writeChunks(stream, responseBody, this.#config.maxChunk, signal);
    } catch (error) {
      const code = timeoutController.signal.aborted ? "timeout" : signal.aborted ? "canceled" : "upstream_request_failed";
      await writeHTTPError(stream, requestID, code);
      this.#report(error);
    } finally {
      clearTimeout(timer);
      linked.dispose();
    }
    void externalOrigin;
  }

  async #serveWebSocket(stream: ByteStream, signal: AbortSignal): Promise<void> {
    const reader = new ProxyByteReader(stream, { signal });
    let open: WSOpen;
    try { open = decodeWSOpen(await readFrame(reader, this.#config.maxJSON)); }
    catch { await writeWSError(stream, "unknown", "invalid_ws_open_meta"); return; }
    const path = normalizePath(open.path);
    if (open.v !== WIRE_VERSION || open.conn_id.trim() === "" || path === undefined) { await writeWSError(stream, open.conn_id, "invalid_ws_open_meta"); return; }
    const upstreamURL = new URL(path, this.#config.upstream);
    upstreamURL.protocol = upstreamURL.protocol === "https:" ? "wss:" : "ws:";
    const require = createRequire(import.meta.url);
    const wsModule = require("ws") as any;
    const WebSocketCtor = wsModule?.WebSocket ?? wsModule;
    const protocols = open.headers.find((header) => header.name.toLowerCase() === "sec-websocket-protocol")?.value;
    const headers = filterHeaders(open.headers, new Set(["sec-websocket-protocol"]), this.#config.websocketHeaders);
    const socket = new WebSocketCtor(upstreamURL.toString(), protocols === undefined ? undefined : protocols.split(",").map((item: string) => item.trim()), {
      headers: { Origin: this.#config.upstreamOrigin }, maxPayload: this.#config.maxWS, perMessageDeflate: false,
      ...(headers.length === 0 ? {} : { headers: Object.fromEntries(headers.map((header) => [header.name, header.value])) }),
    });
    try {
      await onceEvent(socket, "open", signal);
      await writeFrame(stream, { v: WIRE_VERSION, conn_id: open.conn_id.trim(), ok: true, protocol: socket.protocol ?? "" }, signal);
      await relayWebSocket(socket, stream, reader, this.#config.maxWS, signal);
    } catch (error) {
      await writeWSError(stream, open.conn_id, signal.aborted ? "canceled" : "upstream_ws_dial_failed");
      this.#report(error);
    } finally {
      try { socket.close(); } catch { /* cleanup */ }
      await stream.close().catch(() => undefined);
    }
  }
}

function compileConfig(options: ProxyServerOptions): Config {
  let upstream: URL;
  let origin: URL;
  try { upstream = new URL(options.upstream); origin = new URL(options.upstreamOrigin); } catch { throw new ProxyServerError("invalid_options"); }
  if ((upstream.protocol !== "http:" && upstream.protocol !== "https:") || upstream.pathname !== "/" || upstream.search || upstream.hash || upstream.username || upstream.hostname === "") throw new ProxyServerError("invalid_options");
  if ((origin.protocol !== "http:" && origin.protocol !== "https:") || origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.origin !== origin.toString().replace(/\/$/u, "")) throw new ProxyServerError("invalid_options");
  const allowedHosts = new Set((options.allowedUpstreamHosts ?? ["127.0.0.1", "::1"]).map((value) => value.trim().toLowerCase()));
  if (!allowedHosts.has(upstream.hostname.toLowerCase())) throw new ProxyServerError("invalid_options");
  const allowedOrigins = new Set(options.allowedOrigins ?? [origin.origin]);
  for (const allowed of allowedOrigins) { try { if (new URL(allowed).origin !== allowed) throw new Error(); } catch { throw new ProxyServerError("invalid_options"); } }
  const positive = (value: number | undefined, fallback: number) => value === undefined ? fallback : value;
  const maxConcurrent = positive(options.maxConcurrentStreams, 64);
  const maxJSON = positive(options.maxJsonFrameBytes, DEFAULT_MAX_JSON);
  const maxChunk = positive(options.maxChunkBytes, DEFAULT_MAX_CHUNK);
  const maxBody = positive(options.maxBodyBytes, DEFAULT_MAX_BODY);
  const maxWS = positive(options.maxWebSocketFrameBytes, DEFAULT_MAX_WS);
  const defaultTimeout = positive(options.defaultHTTPRequestTimeoutMs, DEFAULT_TIMEOUT);
  const maxTimeout = positive(options.maxHTTPRequestTimeoutMs, MAX_TIMEOUT);
  if ([maxConcurrent, maxJSON, maxChunk, maxBody, maxWS, defaultTimeout, maxTimeout].some((value) => !Number.isSafeInteger(value) || value < 1) || defaultTimeout > maxTimeout) throw new ProxyServerError("invalid_options");
  const normalizeHeaders = (values: readonly string[] | undefined) => new Set((values ?? []).map((name) => {
    const lower = name.trim().toLowerCase();
    if (!HEADER_NAME.test(lower) || FORBIDDEN_HEADERS.has(lower)) throw new ProxyServerError("invalid_options");
    return lower;
  }));
  return { upstream, upstreamOrigin: origin.origin, allowedOrigins, requestHeaders: normalizeHeaders(options.extraRequestHeaders), responseHeaders: normalizeHeaders(options.extraResponseHeaders), blockedResponseHeaders: normalizeHeaders(options.blockedResponseHeaders), websocketHeaders: normalizeHeaders(options.extraWebSocketHeaders), maxConcurrent, maxJSON, maxChunk, maxBody, maxWS, defaultTimeout, maxTimeout, ...(options.onError === undefined ? {} : { report: options.onError }) };
}

function filterHeaders(input: readonly Header[], base: ReadonlySet<string>, extra: ReadonlySet<string>, blocked?: ReadonlySet<string>): Header[] {
  const result: Header[] = [];
  for (const header of input) {
    const name = header.name.trim().toLowerCase();
    if ((!base.has(name) && !extra.has(name)) || FORBIDDEN_HEADERS.has(name) || !HEADER_NAME.test(name) || /[\r\n]/u.test(header.value) || blocked?.has(name)) continue;
    result.push({ name, value: header.value });
  }
  return result;
}
function responseHeaderList(headers: Headers): Header[] {
  const values: Header[] = [];
  headers.forEach((value, name) => values.push({ name, value }));
  return values;
}

async function readFrame(reader: ProxyByteReader, maximum: number): Promise<unknown> {
  const frame = await reader.readExactly(4);
  const length = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false);
  if (length > maximum) throw new Error("frame too large");
  return JSON.parse(new TextDecoder().decode(await reader.readExactly(length))) as unknown;
}
async function writeFrame(stream: ByteStream, value: unknown, signal?: AbortSignal): Promise<void> {
  await writeJsonFrame({ write: async (data) => await writeAll(stream, data, signal === undefined ? {} : { signal }) }, value);
}
async function writeHTTPError(stream: ByteStream, requestID: string, code: string): Promise<void> {
  await writeFrame(stream, { v: WIRE_VERSION, request_id: requestID.trim() || "unknown", ok: false, error: { code, message: "proxy operation failed" } }).catch(() => undefined);
  await writeChunks(stream, new Uint8Array(), 1, undefined).catch(() => undefined);
}
async function writeWSError(stream: ByteStream, connID: string, code: string): Promise<void> {
  await writeFrame(stream, { v: WIRE_VERSION, conn_id: connID.trim() || "unknown", ok: false, error: { code, message: "proxy operation failed" } }).catch(() => undefined);
}
async function writeChunks(stream: ByteStream, body: Uint8Array, chunkSize: number, signal?: AbortSignal): Promise<void> {
  for (let offset = 0; offset < body.length; offset += chunkSize) {
    const chunk = body.subarray(offset, Math.min(body.length, offset + chunkSize));
    const bytes = new Uint8Array(4 + chunk.length);
    new DataView(bytes.buffer).setUint32(0, chunk.length, false); bytes.set(chunk, 4);
    await writeAll(stream, bytes, signal === undefined ? {} : { signal });
  }
  await writeAll(stream, new Uint8Array(4), signal === undefined ? {} : { signal });
}
async function readBody(reader: ProxyByteReader, maxChunk: number, maxBody: number): Promise<Uint8Array | undefined> {
  const chunks: Uint8Array[] = []; let total = 0;
  try {
    while (true) {
      const header = await reader.readExactly(4); const length = new DataView(header.buffer, header.byteOffset, 4).getUint32(0, false);
      if (length === 0) return concat(chunks);
      if (length > maxChunk || total + length > maxBody) return undefined;
      const chunk = await reader.readExactly(length); chunks.push(chunk); total += length;
    }
  } catch { return undefined; }
}
function concat(chunks: readonly Uint8Array[]): Uint8Array { const out = new Uint8Array(chunks.reduce((sum, item) => sum + item.length, 0)); let offset = 0; for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; } return out; }
function normalizePath(value: string): string | undefined { if (value.trim() !== value || !value.startsWith("/") || value.startsWith("//") || value.includes("://") || /[\u0000-\u0020\u007f]/u.test(value)) return undefined; try { const parsed = new URL(value, "http://flowersec.invalid"); return parsed.origin === "http://flowersec.invalid" && !parsed.hash ? `${parsed.pathname}${parsed.search}` : undefined; } catch { return undefined; } }
function normalizeTimeout(value: number | undefined, fallback: number, maximum: number): number | undefined { if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) return undefined; return Math.min(value === undefined || value === 0 ? fallback : value, maximum); }
function validateOrigin(value: string | undefined, allowed: ReadonlySet<string>): string | undefined { if (value === undefined || value === "") return undefined; try { const origin = new URL(value); return origin.pathname === "/" && !origin.search && !origin.hash && origin.origin === value && allowed.has(origin.origin) ? origin.origin : undefined; } catch { return undefined; } }
function linkSignals(parent: AbortSignal, timeout: AbortSignal): { signal: AbortSignal; dispose(): void } { const controller = new AbortController(); const abort = (event: Event) => controller.abort((event.target as AbortSignal).reason); parent.addEventListener("abort", abort, { once: true }); timeout.addEventListener("abort", abort, { once: true }); return { signal: controller.signal, dispose: () => { parent.removeEventListener("abort", abort); timeout.removeEventListener("abort", abort); } }; }
function decodeHTTPMeta(value: unknown): HTTPMeta { if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.request_id !== "string" || typeof value.method !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers) || (value.external_origin !== undefined && typeof value.external_origin !== "string") || (value.timeout_ms !== undefined && typeof value.timeout_ms !== "number")) throw new Error("invalid HTTP metadata"); return { v: value.v, request_id: value.request_id, method: value.method, path: value.path, headers: value.headers.filter(isHeader), ...(value.external_origin === undefined ? {} : { external_origin: value.external_origin }), ...(value.timeout_ms === undefined ? {} : { timeout_ms: value.timeout_ms }) }; }
function decodeWSOpen(value: unknown): WSOpen { if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.conn_id !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers)) throw new Error("invalid WS metadata"); return { v: value.v, conn_id: value.conn_id, path: value.path, headers: value.headers.filter(isHeader) }; }
function isHeader(value: unknown): value is Header { return isRecord(value) && typeof value.name === "string" && typeof value.value === "string"; }
function isRecord(value: unknown): value is Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function onceEvent(socket: any, event: string, signal: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const onAbort = () => { cleanup(); reject(signal.reason ?? new Error("aborted")); }; const onOpen = () => { cleanup(); resolve(); }; const onError = (error: unknown) => { cleanup(); reject(error); }; const cleanup = () => { signal.removeEventListener("abort", onAbort); socket.off?.(event, onOpen); socket.off?.("error", onError); }; socket.once(event, onOpen); socket.once("error", onError); signal.addEventListener("abort", onAbort, { once: true }); }); }
async function relayWebSocket(socket: any, stream: ByteStream, reader: ProxyByteReader, maximum: number, signal: AbortSignal): Promise<void> { let done = false; const upstream = new Promise<void>((resolve, reject) => { socket.on("message", async (data: Uint8Array, isBinary: boolean) => { if (done) return; try { const payload = data instanceof Uint8Array ? data : new Uint8Array(data); if (payload.length > maximum) throw new Error("websocket frame too large"); const frame = new Uint8Array(5 + payload.length); frame[0] = isBinary ? 2 : 1; new DataView(frame.buffer).setUint32(1, payload.length, false); frame.set(payload, 5); await writeAll(stream, frame, { signal }); } catch (error) { reject(error); } }); socket.once("close", () => resolve()); socket.once("error", reject); }); const downstream = (async () => { while (!done) { const frame = await reader.readExactly(5); const operation = frame[0]!; const length = new DataView(frame.buffer, frame.byteOffset, 5).getUint32(1, false); if (length > maximum || ![1, 2, 8, 9, 10].includes(operation)) throw new Error("invalid websocket frame"); const payload = await reader.readExactly(length); if (operation === 8) { socket.close(); return; } socket.send(payload); } })(); try { await Promise.race([upstream, downstream]); } finally { done = true; try { socket.close(); } catch { /* cleanup */ } } }

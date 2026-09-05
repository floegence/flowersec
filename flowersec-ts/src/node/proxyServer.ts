import { createRequire } from "node:module";

import type { ByteStream } from "../public/contract.js";
import { SessionError } from "../public/contract.js";
import { writeJsonFrame } from "../framing/jsonframe.js";
import { ProxyByteReader, writeAll } from "../proxy/stream.js";
import {
  StreamHandlers,
  registerStreamHandlersAtomically,
  type StreamHandler,
} from "../public/streamHandlers.js";
import {
  SessionHandlersV3,
  registerSessionStreamHandlersAtomically,
} from "./acceptor.js";

export type StreamHandlerRegistrar = StreamHandlers | SessionHandlersV3;

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
  forbiddenCookieNames?: readonly string[];
  forbiddenCookieNamePrefixes?: readonly string[];
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
  forbiddenCookies: ReadonlySet<string>;
  forbiddenCookiePrefixes: readonly string[];
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
  readonly #completion: Promise<void>;
  #resolveCompletion!: () => void;
  #closed = false;

  constructor(options: ProxyServerOptions) {
    this.#config = compileConfig(options);
    this.#completion = new Promise<void>((resolve) => { this.#resolveCompletion = resolve; });
  }

  register(handlers: StreamHandlerRegistrar): void {
    if (this.#closed) throw new ProxyServerError("closed");
    try {
      const registrations = [
        [HTTP_KIND, this.#httpHandler()],
        [WS_KIND, this.#webSocketHandler()],
      ] as const;
      if (handlers instanceof StreamHandlers) {
        registerStreamHandlersAtomically(handlers, registrations);
      } else if (handlers instanceof SessionHandlersV3) {
        registerSessionStreamHandlersAtomically(handlers, registrations);
      } else {
        throw new TypeError("invalid Flowersec stream handler registrar");
      }
    } catch (error) {
      this.#report(error);
      throw new ProxyServerError("handler_registration");
    }
  }

  async close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      for (const controller of this.#active) controller.abort(new SessionError("closed"));
      if (this.#active.size === 0) this.#resolveCompletion();
    }
    await this.#completion;
  }

  /** @internal */
  get activeCount(): number { return this.#active.size; }

  #httpHandler(): StreamHandler {
    return async (incoming, options) => {
      const release = this.#acquire(incoming.stream);
      if (release === undefined) return;
      const controller = this.#track(options.signal);
      try { await this.#serveHTTP(incoming.stream, controller.signal); }
      catch (error) { await incoming.stream.reset().catch(() => undefined); this.#report(error); }
      finally { this.#untrack(controller); release(); }
    };
  }

  #webSocketHandler(): StreamHandler {
    return async (incoming, options) => {
      const release = this.#acquire(incoming.stream);
      if (release === undefined) return;
      const controller = this.#track(options.signal);
      try { await this.#serveWebSocket(incoming.stream, controller.signal); }
      catch (error) { await incoming.stream.reset().catch(() => undefined); this.#report(error); }
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
    if (this.#closed) {
      controller.abort(new SessionError("closed"));
      return controller;
    }
    if (parent !== undefined) {
      if (parent.aborted) controller.abort(parent.reason);
      else parent.addEventListener("abort", () => controller.abort(parent.reason), { once: true });
    }
    this.#active.add(controller);
    return controller;
  }
  #untrack(controller: AbortController): void {
    this.#active.delete(controller);
    if (this.#closed && this.#active.size === 0) this.#resolveCompletion();
  }
  #report(error: unknown): void { try { this.#config.report?.(error); } catch { /* reporting is isolated */ } }

  async #serveHTTP(stream: ByteStream, parentSignal: AbortSignal): Promise<void> {
    const started = performance.now();
    const timeoutController = new AbortController();
    let timer = setTimeout(() => timeoutController.abort(), this.#config.maxTimeout);
    const linked = linkSignals(parentSignal, timeoutController.signal);
    const signal = linked.signal;
    let reset: Promise<void> | undefined;
    const abort = () => { reset ??= stream.reset().catch(() => undefined); };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    try {
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
      clearTimeout(timer);
      const remaining = timeout - (performance.now() - started);
      if (remaining <= 0) timeoutController.abort();
      else timer = setTimeout(() => timeoutController.abort(), remaining);
      const body = await readBody(reader, this.#config.maxChunk, this.#config.maxBody);
      if (body === undefined) { await writeHTTPError(stream, requestID, "request_body_invalid"); return; }
      const externalOrigin = validateOrigin(meta.external_origin, this.#config.allowedOrigins);
      if (meta.external_origin !== undefined && externalOrigin === undefined) { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      const requestHeaders = filterRequestHeaders(meta.headers, this.#config);
      if (externalOrigin !== undefined) {
        const explicitOrigin = requestHeaders.find((header) => header.name === "origin")?.value;
        if (explicitOrigin !== undefined && explicitOrigin !== externalOrigin) {
          await writeHTTPError(stream, requestID, "invalid_request_meta"); return;
        }
        const origin = new URL(externalOrigin);
        requestHeaders.push({ name: "x-forwarded-proto", value: origin.protocol.slice(0, -1) });
      }
      const headers = Object.fromEntries(requestHeaders.map((header) => [header.name, header.value]));
      const target = new URL(path, this.#config.upstream);
      const requestInit: RequestInit & { duplex?: "half" } = {
        method: meta.method.trim().toUpperCase(), headers, redirect: "manual", signal,
        ...(body.byteLength === 0 ? {} : { body: body.slice().buffer as ArrayBuffer, duplex: "half" }),
      };
      try {
        const response = await fetch(target, requestInit);
        const contentLength = response.headers.get("content-length");
        if (contentLength !== null && Number(contentLength) > this.#config.maxBody) {
          await writeHTTPError(stream, requestID, "response_body_too_large"); return;
        }
        await writeFrame(stream, {
          v: WIRE_VERSION, request_id: requestID, ok: true, status: response.status,
          headers: filterHeaders(responseHeaderList(response.headers), RESPONSE_HEADERS, this.#config.responseHeaders, this.#config.blockedResponseHeaders),
        }, signal);
        let total = 0;
        const reader = response.body?.getReader();
        if (reader !== undefined) {
          while (true) {
            const result = await reader.read();
            if (result.done) break;
            total += result.value.length;
            if (total > this.#config.maxBody) throw new Error("upstream response body exceeds limit");
            for (let offset = 0; offset < result.value.length; offset += this.#config.maxChunk) {
              await writeChunk(stream, result.value.subarray(offset, offset + this.#config.maxChunk), signal);
            }
          }
        }
        await writeChunk(stream, new Uint8Array(), signal);
      } catch (error) {
        if (signal.aborted) throw error;
        const code = timeoutController.signal.aborted ? "timeout" : signal.aborted ? "canceled" : "upstream_request_failed";
        await writeHTTPError(stream, requestID, code);
        this.#report(error);
      }
    } finally {
      clearTimeout(timer);
      linked.dispose();
      signal.removeEventListener("abort", abort);
      await reset;
    }
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
    const headers = filterHeaders(open.headers, new Set(["sec-websocket-protocol"]), this.#config.websocketHeaders)
      .filter((header) => header.name !== "origin");
    const socket = new WebSocketCtor(upstreamURL.toString(), protocols === undefined ? undefined : protocols.split(",").map((item: string) => item.trim()), {
      headers: {
        ...Object.fromEntries(headers.map((header) => [header.name, header.value])),
        Origin: this.#config.upstreamOrigin,
      },
      maxPayload: this.#config.maxWS,
      perMessageDeflate: false,
    });
    let opened = false;
    try {
      await onceEvent(socket, "open", signal);
      await writeFrame(stream, { v: WIRE_VERSION, conn_id: open.conn_id.trim(), ok: true, protocol: socket.protocol ?? "" }, signal);
      opened = true;
      await relayWebSocket(socket, stream, reader, this.#config.maxWS, signal);
    } catch (error) {
      if (!opened) await writeWSError(stream, open.conn_id, signal.aborted ? "canceled" : "upstream_ws_dial_failed");
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
  const normalizeCookieValues = (values: readonly string[] | undefined) => (values ?? []).map((value) => {
    const normalized = value.trim().toLowerCase();
    if (normalized === "" || /[;=\s]/u.test(normalized)) throw new ProxyServerError("invalid_options");
    return normalized;
  });
  return {
    upstream,
    upstreamOrigin: origin.origin,
    allowedOrigins,
    requestHeaders: normalizeHeaders(options.extraRequestHeaders),
    responseHeaders: normalizeHeaders(options.extraResponseHeaders),
    blockedResponseHeaders: normalizeHeaders(options.blockedResponseHeaders),
    websocketHeaders: normalizeHeaders(options.extraWebSocketHeaders),
    forbiddenCookies: new Set(normalizeCookieValues(options.forbiddenCookieNames)),
    forbiddenCookiePrefixes: normalizeCookieValues(options.forbiddenCookieNamePrefixes),
    maxConcurrent, maxJSON, maxChunk, maxBody, maxWS, defaultTimeout, maxTimeout,
    ...(options.onError === undefined ? {} : { report: options.onError }),
  };
}

function filterRequestHeaders(input: readonly Header[], config: Config): Header[] {
  const headers = filterHeaders(input, REQUEST_HEADERS, config.requestHeaders);
  return headers.flatMap((header) => {
    if (header.name !== "cookie") return [header];
    const value = header.value.split(";").flatMap((part) => {
      const item = part.trim();
      const separator = item.indexOf("=");
      if (separator < 1) return [];
      const name = item.slice(0, separator).trim().toLowerCase();
      if (config.forbiddenCookies.has(name) || config.forbiddenCookiePrefixes.some((prefix) => name.startsWith(prefix))) return [];
      return [item];
    }).join("; ");
    return value === "" ? [] : [{ name: header.name, value }];
  });
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
    await writeChunk(stream, body.subarray(offset, Math.min(body.length, offset + chunkSize)), signal);
  }
  await writeChunk(stream, new Uint8Array(), signal);
}
async function writeChunk(stream: ByteStream, chunk: Uint8Array, signal?: AbortSignal): Promise<void> {
  const bytes = new Uint8Array(4 + chunk.length);
  new DataView(bytes.buffer).setUint32(0, chunk.length, false); bytes.set(chunk, 4);
  await writeAll(stream, bytes, signal === undefined ? {} : { signal });
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
function linkSignals(parent: AbortSignal, timeout: AbortSignal): { signal: AbortSignal; dispose(): void } { const controller = new AbortController(); const abort = (event: Event) => controller.abort((event.target as AbortSignal).reason); parent.addEventListener("abort", abort, { once: true }); timeout.addEventListener("abort", abort, { once: true }); if (parent.aborted) controller.abort(parent.reason); else if (timeout.aborted) controller.abort(timeout.reason); return { signal: controller.signal, dispose: () => { parent.removeEventListener("abort", abort); timeout.removeEventListener("abort", abort); } }; }
function decodeHTTPMeta(value: unknown): HTTPMeta { if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.request_id !== "string" || typeof value.method !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers) || (value.external_origin !== undefined && typeof value.external_origin !== "string") || (value.timeout_ms !== undefined && typeof value.timeout_ms !== "number")) throw new Error("invalid HTTP metadata"); return { v: value.v, request_id: value.request_id, method: value.method, path: value.path, headers: value.headers.filter(isHeader), ...(value.external_origin === undefined ? {} : { external_origin: value.external_origin }), ...(value.timeout_ms === undefined ? {} : { timeout_ms: value.timeout_ms }) }; }
function decodeWSOpen(value: unknown): WSOpen { if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.conn_id !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers)) throw new Error("invalid WS metadata"); return { v: value.v, conn_id: value.conn_id, path: value.path, headers: value.headers.filter(isHeader) }; }
function isHeader(value: unknown): value is Header { return isRecord(value) && typeof value.name === "string" && typeof value.value === "string"; }
function isRecord(value: unknown): value is Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function onceEvent(socket: any, event: string, signal: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const onAbort = () => { cleanup(); reject(signal.reason ?? new Error("aborted")); }; const onOpen = () => { cleanup(); resolve(); }; const onError = (error: unknown) => { cleanup(); reject(error); }; const cleanup = () => { signal.removeEventListener("abort", onAbort); socket.off?.(event, onOpen); socket.off?.("error", onError); }; socket.once(event, onOpen); socket.once("error", onError); signal.addEventListener("abort", onAbort, { once: true }); }); }
async function relayWebSocket(
  socket: any,
  stream: ByteStream,
  reader: ProxyByteReader,
  maximum: number,
  signal: AbortSignal,
): Promise<void> {
  let done = false;
  let writeChain = Promise.resolve();
  const enqueue = (task: () => Promise<void>): Promise<void> => {
    const current = writeChain.then(task);
    writeChain = current.catch(() => undefined);
    return current;
  };
  const upstream = new Promise<"upstream_close">((resolve, reject) => {
    socket.on("message", (data: Uint8Array, isBinary: boolean) => {
      if (done) return;
      const payload = data instanceof Uint8Array ? data : new Uint8Array(data);
      if (payload.length > maximum) { reject(new Error("websocket frame too large")); return; }
      void enqueue(async () => {
        const frame = new Uint8Array(5 + payload.length);
        frame[0] = isBinary ? 2 : 1;
        new DataView(frame.buffer).setUint32(1, payload.length, false);
        frame.set(payload, 5);
        await writeAll(stream, frame, { signal });
      }).catch(reject);
    });
    socket.once("close", (code: number, reason: Buffer) => {
      const closePayload = encodeWebSocketClose(code, reason);
      void enqueue(async () => {
        const frame = new Uint8Array(5 + closePayload.length);
        frame[0] = 8;
        new DataView(frame.buffer).setUint32(1, closePayload.length, false);
        frame.set(closePayload, 5);
        await writeAll(stream, frame, { signal });
      }).then(() => resolve("upstream_close"), reject);
    });
    socket.once("error", reject);
  });
  const downstream = (async (): Promise<"downstream_close"> => {
    while (!done) {
      const frame = await reader.readExactly(5);
      const operation = frame[0]!;
      const length = new DataView(frame.buffer, frame.byteOffset, 5).getUint32(1, false);
      if (length > maximum || ![1, 2, 8, 9, 10].includes(operation)) throw new Error("invalid websocket frame");
      const payload = await reader.readExactly(length);
      if (operation === 8) {
        const close = decodeWebSocketClose(payload);
        socket.close(close.code, close.reason);
        return "downstream_close";
      }
      if (operation === 9) { await sendSocketControl(socket, "ping", payload); continue; }
      if (operation === 10) { await sendSocketControl(socket, "pong", payload); continue; }
      if (operation === 1) {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
        await sendSocketFrame(socket, text, undefined);
      } else {
        await sendSocketFrame(socket, payload, true);
      }
    }
    return "downstream_close";
  })();
  try {
    const winner = await Promise.race([upstream, downstream]);
    if (winner === "downstream_close") {
      await Promise.race([upstream, new Promise<void>((resolve) => setTimeout(resolve, 1_000))]);
    }
  } finally {
    done = true;
    try { socket.close(); } catch { /* cleanup */ }
  }
}

async function sendSocketFrame(socket: any, payload: unknown, binary: boolean | undefined): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const callback = (error?: Error | null) => error == null ? resolve() : reject(error);
    socket.send(payload, { binary: binary === true }, callback);
  });
}

async function sendSocketControl(socket: any, operation: "ping" | "pong", payload: Uint8Array): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket[operation](payload, (error?: Error | null) => error == null ? resolve() : reject(error));
  });
}

function encodeWebSocketClose(code: number, reason: Buffer | Uint8Array | undefined): Uint8Array {
  if (!Number.isInteger(code) || code < 0 || code > 65_535 || code === 1004 || code === 1005 || code === 1006) return new Uint8Array();
  const payload = new Uint8Array(2 + (reason?.length ?? 0));
  new DataView(payload.buffer).setUint16(0, code, false);
  if (reason !== undefined) payload.set(reason, 2);
  return payload;
}

function decodeWebSocketClose(payload: Uint8Array): Readonly<{ code?: number; reason?: string }> {
  if (payload.length === 0) return {};
  if (payload.length < 2) throw new Error("invalid websocket close frame");
  const code = new DataView(payload.buffer, payload.byteOffset, 2).getUint16(0, false);
  if (code === 1004 || code === 1005 || code === 1006) throw new Error("invalid websocket close code");
  const reason = new TextDecoder("utf-8", { fatal: true }).decode(payload.subarray(2));
  return { code, reason };
}

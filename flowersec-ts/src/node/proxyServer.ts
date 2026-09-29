import { createRequire } from "node:module";
import { Agent as HTTPAgent, request as requestHTTP, type ClientRequest } from "node:http";
import { Agent as HTTPSAgent, request as requestHTTPS } from "node:https";
import { Readable } from "node:stream";

import { SessionError } from "../public/contract.js";
import { PROXY_WIRE_VERSION, readProxyFrame, writeProxyFrame, validateProxyTrailers, type ProxySchema } from "../proxy/wire.js";
import { ProxyByteReader, writeAll, type ProxyStream } from "../proxy/stream.js";
import { currentProxyStream } from "../proxy/currentStream.js";
import type { V4ControllerStreamDeclaration } from "../v4/controller.js";
import type { V4StreamOpenAuthorizer, V4StreamRegistrationOptions } from "../v4/streamHandlers.js";
import { inspectProxyHeaders, type ProxyHeaderFacts } from "../proxy/headers.js";
import {
  StreamHandlers,
  registerStreamHandlersAtomically,
  type StreamHandler,
} from "../public/streamHandlers.js";
import {
  SessionHandlersV3,
  registerSessionStreamHandlersAtomically,
} from "./acceptor.js";
import { normalizePath as normalizeProxyPath } from "../proxy/policy.js";
import { ProxyNetworkPolicy, proxyUpstreamHost, type ProxyConnection } from "./proxyNetwork.js";

export type StreamHandlerRegistrar = StreamHandlers | SessionHandlersV3;

const HTTP_KIND = "flowersec-proxy/http1";
const WS_KIND = "flowersec-proxy/ws";
const WIRE_VERSION = PROXY_WIRE_VERSION;
const DEFAULT_MAX_JSON = 1 << 20;
const DEFAULT_MAX_CHUNK = 256 * 1024;
const DEFAULT_MAX_BODY = 64 * 1024 * 1024;
const DEFAULT_MAX_WS = 1 << 20;
const DEFAULT_TIMEOUT = 30_000;
const MAX_TIMEOUT = 300_000;
const FORBIDDEN_HEADERS = new Set(["authorization", "connection", "host", "keep-alive", "proxy-authorization", "proxy-authenticate", "proxy-connection", "te", "trailer", "set-cookie", "transfer-encoding", "upgrade"]);
const REQUEST_HEADERS = new Set(["accept", "accept-language", "content-type", "if-match", "if-none-match", "range"]);
const RESPONSE_HEADERS = new Set(["accept-ranges", "cache-control", "content-disposition", "content-encoding", "content-language", "content-length", "content-range", "content-type", "etag", "expires", "last-modified", "location"]);
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;

export type ProxyServerOptions = Readonly<{
  upstream: string;
  upstreamOrigin: string;
  allowedUpstreamHosts?: readonly string[];
  /** Numeric addresses or canonical CIDRs; required for DNS upstreams. */
  allowedUpstreamAddresses?: readonly string[];
  allowedOrigins?: readonly string[];
  maxConcurrentStreams?: number;
  maxConcurrentHTTPStreams?: number;
  maxConcurrentEventStreams?: number;
  eventStreamIdleTimeoutMs?: number;
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
  network: ProxyNetworkPolicy;
  upstreamOrigin: string;
  allowedOrigins: ReadonlySet<string>;
  requestHeaders: ReadonlySet<string>;
  responseHeaders: ReadonlySet<string>;
  blockedResponseHeaders: ReadonlySet<string>;
  websocketHeaders: ReadonlySet<string>;
  forbiddenCookies: ReadonlySet<string>;
  forbiddenCookiePrefixes: readonly string[];
  maxConcurrent: number;
  maxHTTP: number;
  maxEvents: number;
  eventIdleTimeout: number;
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
  readonly #abortLinks = new WeakMap<AbortController, () => void>();
  readonly #permits: Set<unknown> = new Set();
  readonly #completion: Promise<void>;
  #resolveCompletion!: () => void;
  #closed = false;
  #httpCount = 0;
  #eventCount = 0;

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

  /** Install these declarations on the current candidate before publication.
   * Authorization receives the authenticated peer for this configured upstream.
   * All declarations share this server's aggregate admission and shutdown. */
  streamHandlers(authorize: V4StreamOpenAuthorizer,
    options: Pick<V4StreamRegistrationOptions, "applicationBytes" | "applicationTimeoutMS">): readonly V4ControllerStreamDeclaration[] {
    if (this.#closed) throw new ProxyServerError("closed");
    if (typeof authorize !== "function" || typeof options?.applicationBytes !== "bigint" || options.applicationBytes < 1n ||
        this.#config.maxConcurrent > 128) throw new ProxyServerError("handler_registration");
    const inputBackingBytes = Math.max(8192, this.#config.maxBody, this.#config.maxJSON + 4, this.#config.maxChunk + 4, this.#config.maxWS + 5);
    if (!Number.isSafeInteger(inputBackingBytes) || inputBackingBytes > 0x7fffffff) throw new ProxyServerError("handler_registration");
    // The application reservation includes body assembly and metadata/WS
    // workspaces; the stream adapter separately owns its read and input tails.
    const applicationBytes = options.applicationBytes + 2n * (BigInt(this.#config.maxBody) + BigInt(this.#config.maxJSON) + BigInt(this.#config.maxWS)) + 16384n;
    const registration = Object.freeze({ applicationBytes, workClass: "resident" as const,
      maxConcurrentStreams: this.#config.maxConcurrent,
      applicationTimeoutMS: options.applicationTimeoutMS ?? BigInt(this.#config.maxTimeout),
      metadataNamespaces: Object.freeze([Object.freeze({ namespace: "application/json", version: 1 })]),
    });
    const allowed: V4StreamOpenAuthorizer = async (context, metadata) => {
      if (this.#closed || context.signal.aborted) return false;
      return await authorize(context, metadata);
    };
    return Object.freeze([HTTP_KIND, WS_KIND].map(kind => Object.freeze({
      kind, authorize: allowed, options: registration,
      handler: async (owner, context) => {
        let stream: ReturnType<typeof currentProxyStream> | undefined;
        let release: (() => void) | undefined;
        const controller = this.#track(context.signal);
        const stopped = () => controller.abort(new SessionError("stream_reset"));
        try {
          stream = currentProxyStream(owner, { readBytes: 65536, inputBackingBytes,
            finishTimeoutMS: this.#config.maxTimeout, cleanupTimeoutMS: 5000 });
          stream.signal.addEventListener("abort", stopped, { once: true });
          if (stream.signal.aborted) stopped();
          release = this.#acquire(stream);
          if (release === undefined) { await stream.reset(); return; }
          if (kind === HTTP_KIND) await this.#serveHTTP(stream, controller.signal);
          else await this.#serveWebSocket(stream, controller.signal);
          await stream.finish({ signal: controller.signal });
        } catch (error) {
          await owner.reset().catch(() => undefined);
          this.#report(error);
          throw error;
        } finally { stream?.signal.removeEventListener("abort", stopped); stream?.dispose(); this.#untrack(controller); release?.(); }
      },
    } satisfies V4ControllerStreamDeclaration)));
  }

  async close(): Promise<void> {
    if (!this.#closed) {
      this.#closed = true;
      for (const controller of this.#active) controller.abort(new SessionError("closed"));
      if (this.#active.size === 0) this.#resolveCompletion();
    }
    await this.#completion;
    await this.#config.network.close();
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

  #acquire(stream: ProxyStream): (() => void) | undefined {
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
      const abort = () => controller.abort(parent.reason);
      if (parent.aborted) abort();
      else {
        parent.addEventListener("abort", abort, { once: true });
        this.#abortLinks.set(controller, () => parent.removeEventListener("abort", abort));
      }
    }
    this.#active.add(controller);
    return controller;
  }
  #untrack(controller: AbortController): void {
    this.#abortLinks.get(controller)?.();
    this.#abortLinks.delete(controller);
    this.#active.delete(controller);
    if (this.#closed && this.#active.size === 0) this.#resolveCompletion();
  }
  #report(error: unknown): void { try { this.#config.report?.(error); } catch { /* reporting is isolated */ } }

  async #serveHTTP(stream: ProxyStream, parentSignal: AbortSignal): Promise<void> {
    const started = performance.now();
    const timeoutController = new AbortController();
    let timer = setTimeout(() => timeoutController.abort(), this.#config.maxTimeout);
    const linked = linkSignals(parentSignal, timeoutController.signal);
    const signal = linked.signal;
    let reset: Promise<void> | undefined;
    let peerWatch: Promise<void> | undefined;
    let responseReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let closeResponse: (() => Promise<void>) | undefined;
    let httpPermit = false;
    let eventPermit = false;
    const releaseEvent = () => { if (eventPermit) { eventPermit = false; this.#eventCount--; } };
    const abort = () => { reset ??= stream.reset().catch(() => undefined); };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    try {
      const reader = new ProxyByteReader(stream, { signal });
      let meta: HTTPMeta;
      try { meta = decodeHTTPMeta(await readProxyFrame(reader, "ProxyHTTPRequest", this.#config.maxJSON)); }
      catch { await writeHTTPError(stream, "unknown", "invalid_request_meta"); return; }
      const requestID = meta.request_id.trim();
      let path: string;
      try { path = normalizeProxyPath(meta.path); } catch { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      if (meta.v !== WIRE_VERSION || requestID === "" || meta.method.trim() === "" || path === undefined) {
        await writeHTTPError(stream, requestID, "invalid_request_meta"); return;
      }
      const timeout = normalizeTimeout(meta.timeout_ms, this.#config.defaultTimeout, this.#config.maxTimeout);
      if (timeout === undefined) { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      clearTimeout(timer);
      const remaining = timeout - (performance.now() - started);
      if (remaining <= 0) timeoutController.abort();
      else timer = setTimeout(() => timeoutController.abort(), remaining);
      let requestFacts: ProxyHeaderFacts;
      try {
        requestFacts = inspectProxyHeaders(meta.headers);
        if (requestFacts.transferEncoding) throw new Error("structured request has transfer coding");
      } catch { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      const incomingBody = await readBody(reader, this.#config.maxChunk, this.#config.maxBody, this.#config.maxJSON, requestFacts);
      if (incomingBody === undefined || reader.bufferedBytes !== 0) { await writeHTTPError(stream, requestID, "request_body_invalid"); return; }
      const { body, trailers: inputTrailers } = incomingBody;
      let requestHeaders: Header[];
      try { requestHeaders = filterRequestHeaders(requestFacts, this.#config, body.byteLength); }
      catch { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      // A peer reset cancels the upstream even when it has no next event to write.
      // A FIN only closes request writes and is valid during response streaming.
      peerWatch = stream.read({ signal }).then((chunk) => {
        if (chunk !== null) timeoutController.abort(new SessionError("canceled"));
      }, () => { timeoutController.abort(new SessionError("canceled")); });
      if (this.#httpCount >= this.#config.maxHTTP) {
        await writeHTTPError(stream, requestID, "resource_exhausted"); return;
      }
      httpPermit = true;
      this.#httpCount++;
      const eventRequested = meta.headers.some(({ name, value }) => name.toLowerCase() === "accept" && value.split(",").some(acceptsEventStream));
      if (eventRequested) {
        if (this.#eventCount >= this.#config.maxEvents) {
          await writeHTTPError(stream, requestID, "resource_exhausted"); return;
        }
        eventPermit = true;
        this.#eventCount++;
      }
      const externalOrigin = validateOrigin(meta.external_origin, this.#config.allowedOrigins);
      if (meta.external_origin !== undefined && externalOrigin === undefined) { await writeHTTPError(stream, requestID, "invalid_request_meta"); return; }
      if (externalOrigin !== undefined) {
        const explicitOrigin = requestHeaders.find((header) => header.name === "origin")?.value;
        if (explicitOrigin !== undefined && explicitOrigin !== externalOrigin) {
          await writeHTTPError(stream, requestID, "invalid_request_meta"); return;
        }
        const origin = new URL(externalOrigin);
        requestHeaders.push({ name: "x-forwarded-proto", value: origin.protocol.slice(0, -1) });
      }
      const target = this.#config.upstream;
      let responsePublished = false;
      try {
        const method = meta.method;
        const response = await requestCodedResponse(target, this.#config.network, path, method, requestHeaders, body, filterHeaders(inspectProxyHeaders(inputTrailers), REQUEST_HEADERS, this.#config.requestHeaders), signal, this.#config.maxJSON);
        closeResponse = response.close;
        const responseFacts = inspectProxyHeaders(response.headerList);
        if (responseFacts.connection.has("content-encoding") && responseFacts.fields.some(field => field.name === "content-encoding")) {
          throw new Error("content coding cannot lose its representation label");
        }
        const hasBody = method !== "HEAD" && response.status !== 204 && response.status !== 304 && response.status !== 205 && !(response.status >= 100 && response.status < 200);
        responseReader = response.body.getReader();
        const persistent = eventRequested && isEventStream(response.headers.get("content-type") ?? "");
        const activity = () => {
          if (!persistent) return;
          clearTimeout(timer);
          timer = setTimeout(() => timeoutController.abort(), this.#config.eventIdleTimeout);
        };
        if (persistent) activity(); else releaseEvent();
        const contentLength = responseFacts.contentLength;
        if (hasBody && !persistent && contentLength !== undefined && contentLength > BigInt(this.#config.maxBody)) {
          await writeHTTPError(stream, requestID, "response_body_too_large"); return;
        }
        responsePublished = true;
        await writeFrame(stream, {
          v: WIRE_VERSION, request_id: requestID, ok: true, status: response.status,
          headers: filterHeaders(responseFacts, RESPONSE_HEADERS, this.#config.responseHeaders, this.#config.blockedResponseHeaders, this.#config.responseHeaders.has("set-cookie")),
        }, signal);
        let total = 0;
        let remainingLength = hasBody ? contentLength : undefined;
        const reader = responseReader;
        if (reader !== undefined) {
          while (true) {
            const result = await reader.read();
            if (result.done) break;
            activity();
            if (remainingLength !== undefined) {
              remainingLength -= BigInt(result.value.length);
              if (remainingLength < 0n) throw new Error("upstream content length mismatch");
            }
            if(!hasBody && result.value.length!==0)throw new Error("unexpected body");
            if (!persistent) total += result.value.length;
            if (total > this.#config.maxBody) throw new Error("upstream response body exceeds limit");
            for (let offset = 0; offset < result.value.length; offset += this.#config.maxChunk) {
              await writeChunk(stream, result.value.subarray(offset, offset + this.#config.maxChunk), signal);
            }
          }
          if (remainingLength !== undefined && remainingLength !== 0n) throw new Error("upstream content length mismatch");
        }
        const trailers = response.trailers();
        validateProxyTrailers(trailers, responseFacts.connection);
        await writeBodyEnd(stream, filterHeaders(inspectProxyHeaders(trailers),RESPONSE_HEADERS,this.#config.responseHeaders,this.#config.blockedResponseHeaders), signal);
      } catch (error) {
        if (responsePublished || signal.aborted) throw error;
        const code = timeoutController.signal.aborted ? "timeout" : signal.aborted ? "canceled" : "upstream_request_failed";
        await writeHTTPError(stream, requestID, code);
        this.#report(error);
      }
    } finally {
      clearTimeout(timer);
      releaseEvent();
      if (httpPermit) this.#httpCount--;
      linked.dispose();
      signal.removeEventListener("abort", abort);
      timeoutController.abort();
      await responseReader?.cancel().catch(() => undefined);
      responseReader?.releaseLock();
      await closeResponse?.();
      await peerWatch;
      await reset;
    }
  }

  async #serveWebSocket(stream: ProxyStream, signal: AbortSignal): Promise<void> {
    const stopRead = new AbortController();
    const relaySignal = AbortSignal.any([signal, stopRead.signal]);
    const reader = new ProxyByteReader(stream, { signal: relaySignal });
    let open: WSOpen;
    try { open = decodeWSOpen(await readProxyFrame(reader, "ProxyWebSocketOpen", this.#config.maxJSON)); }
    catch { await writeWSError(stream, "unknown", "invalid_ws_open_meta"); return; }
    let path: string;
    try { path = normalizeProxyPath(open.path); } catch { await writeWSError(stream, open.conn_id, "invalid_ws_open_meta"); return; }
    if (open.v !== WIRE_VERSION || open.conn_id.trim() === "" || path === undefined) { await writeWSError(stream, open.conn_id, "invalid_ws_open_meta"); return; }
    // Only authority enters URL parsing. finishRequest supplies the validated
    // origin-form spelling before native header serialization.
    const upstreamURL = new URL(this.#config.upstream.origin);
    upstreamURL.protocol = upstreamURL.protocol === "https:" ? "wss:" : "ws:";
    const require = createRequire(import.meta.url);
    const wsModule = require("ws") as any;
    const WebSocketCtor = wsModule?.WebSocket ?? wsModule;
    let fields: Header[];
    try {
      const facts = inspectProxyHeaders(open.headers);
      if (facts.transferEncoding || facts.contentLength !== undefined && facts.contentLength !== 0n) throw new Error("invalid WebSocket framing");
      fields = filterHeaders(facts, new Set(["sec-websocket-protocol"]), this.#config.websocketHeaders);
    } catch { await writeWSError(stream, open.conn_id, "invalid_ws_open_meta"); return; }
    const protocols = fields.filter(header => header.name === "sec-websocket-protocol").flatMap(header => header.value.split(",").map(value => value.trim()));
    // Native Node headers support arrays. Repeated fields retain their order;
    // only the protocol list is combined using its defined list grammar.
    const headers: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
    for (const field of fields) {
      if (field.name === "origin" || field.name === "sec-websocket-protocol") continue;
      (headers[field.name] ??= []).push(field.value);
    }
    headers.origin = [this.#config.upstreamOrigin];
    let socket: any;
    let connection: ProxyConnection | undefined;
    const preparation = new AbortController();
    const timer = setTimeout(() => preparation.abort(new Error("proxy WebSocket establishment timed out")), 10_000);
    const establishmentSignal = AbortSignal.any([signal, preparation.signal]);
    let opened = false;
    try {
      connection = await this.#config.network.connect(upstreamURL.protocol === "wss:", establishmentSignal);
      let used = false;
      socket = new WebSocketCtor(upstreamURL.toString(), protocols.length === 0 ? undefined : protocols, {
        headers, maxPayload: this.#config.maxWS, maxHeaderSize: this.#config.maxJSON,
        perMessageDeflate: false, followRedirects: false, autoPong: false,
        allowSynchronousEvents: false, maxFragments: 128, maxBufferedChunks: 256,
        finishRequest: (request: ClientRequest) => { request.path = path; request.end(); },
        createConnection: () => {
          establishmentSignal.throwIfAborted();
          if (used) throw new Error("proxy connection already used");
          used = true; return connection!.socket;
        },
      });
      await onceEvent(socket, "open", establishmentSignal);
      clearTimeout(timer);
      opened = true;
      await relayWebSocket(socket, stream, reader, this.#config.maxWS, relaySignal,
        async () => { stopRead.abort(new SessionError("canceled")); },
        () => writeFrame(stream, { v: WIRE_VERSION, conn_id: open.conn_id.trim(), ok: true, protocol: socket.protocol ?? "" }, signal));
    } catch (error) {
      if (!opened) await writeWSError(stream, open.conn_id, signal.aborted ? "canceled" : "upstream_ws_dial_failed");
      this.#report(error);
      if (opened) throw error;
    } finally {
      clearTimeout(timer);
      preparation.abort();
      try { socket?.terminate(); } catch { /* cleanup */ }
      await connection?.close();
    }
  }
}

function compileConfig(options: ProxyServerOptions): Config {
  let upstream: URL;
  let origin: URL;
  let host: string;
  try { host = proxyUpstreamHost(options.upstream); upstream = new URL(options.upstream); origin = new URL(options.upstreamOrigin); } catch { throw new ProxyServerError("invalid_options"); }
  if ((upstream.protocol !== "http:" && upstream.protocol !== "https:") || upstream.pathname !== "/" || upstream.search || upstream.hash || upstream.username || upstream.hostname === "") throw new ProxyServerError("invalid_options");
  if ((origin.protocol !== "http:" && origin.protocol !== "https:") || origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.origin !== origin.toString().replace(/\/$/u, "")) throw new ProxyServerError("invalid_options");
  if (options.blockedResponseHeaders?.some(name => name.trim().toLowerCase() === "content-encoding")) throw new ProxyServerError("invalid_options");
  const allowedHosts = new Set((options.allowedUpstreamHosts ?? ["127.0.0.1", "::1"]).map((value) => value.trim().toLowerCase()));
  if (!allowedHosts.has(host)) throw new ProxyServerError("invalid_options");
  const allowedOrigins = new Set(options.allowedOrigins ?? [origin.origin]);
  for (const allowed of allowedOrigins) { try { if (new URL(allowed).origin !== allowed) throw new Error(); } catch { throw new ProxyServerError("invalid_options"); } }
  const positive = (value: number | undefined, fallback: number) => value === undefined ? fallback : value;
  const maxConcurrent = positive(options.maxConcurrentStreams, 64);
  const maxHTTP = positive(options.maxConcurrentHTTPStreams, Math.min(24, maxConcurrent));
  const maxEvents = positive(options.maxConcurrentEventStreams, Math.max(1, Math.min(16, Math.floor(maxHTTP * 2 / 3))));
  const eventIdleTimeout = positive(options.eventStreamIdleTimeoutMs, 45_000);
  if (maxHTTP > maxConcurrent || maxEvents > maxHTTP) throw new ProxyServerError("invalid_options");
  const maxJSON = positive(options.maxJsonFrameBytes, DEFAULT_MAX_JSON);
  const maxChunk = positive(options.maxChunkBytes, DEFAULT_MAX_CHUNK);
  const maxBody = positive(options.maxBodyBytes, DEFAULT_MAX_BODY);
  const maxWS = positive(options.maxWebSocketFrameBytes, DEFAULT_MAX_WS);
  const defaultTimeout = positive(options.defaultHTTPRequestTimeoutMs, DEFAULT_TIMEOUT);
  const maxTimeout = positive(options.maxHTTPRequestTimeoutMs, MAX_TIMEOUT);
  if ([maxConcurrent, maxHTTP, maxEvents, eventIdleTimeout, maxJSON, maxChunk, maxBody, maxWS, defaultTimeout, maxTimeout].some((value) => !Number.isSafeInteger(value) || value < 1) || defaultTimeout > maxTimeout) throw new ProxyServerError("invalid_options");
  let network: ProxyNetworkPolicy;
  try { network = new ProxyNetworkPolicy(host, Number(upstream.port || (upstream.protocol === "https:" ? 443 : 80)), options.allowedUpstreamAddresses ?? [], maxConcurrent, upstream.protocol === "https:"); }
  catch { throw new ProxyServerError("invalid_options"); }
  const normalizeHeaders = (values: readonly string[] | undefined) => new Set((values ?? []).map((name) => {
    const lower = name.trim().toLowerCase();
    if (!HEADER_NAME.test(lower) || FORBIDDEN_HEADERS.has(lower) || lower === "content-length" || lower === "te" || lower === "trailer") throw new ProxyServerError("invalid_options");
    return lower;
  }));
  const normalizeResponseHeaders = (values: readonly string[] | undefined) => new Set((values ?? []).map((name) => {
    const lower = name.trim().toLowerCase();
    if (!HEADER_NAME.test(lower) || (FORBIDDEN_HEADERS.has(lower) && lower !== "set-cookie")) throw new ProxyServerError("invalid_options");
    return lower;
  }));
  const normalizeCookieValues = (values: readonly string[] | undefined) => (values ?? []).map((value) => {
    const normalized = value.trim().toLowerCase();
    if (normalized === "" || /[;=\s]/u.test(normalized)) throw new ProxyServerError("invalid_options");
    return normalized;
  });
  return {
    upstream,
    network,
    upstreamOrigin: origin.origin,
    allowedOrigins,
    requestHeaders: normalizeHeaders(options.extraRequestHeaders),
    responseHeaders: normalizeResponseHeaders(options.extraResponseHeaders),
    blockedResponseHeaders: normalizeHeaders(options.blockedResponseHeaders),
    websocketHeaders: normalizeHeaders(options.extraWebSocketHeaders),
    forbiddenCookies: new Set(normalizeCookieValues(options.forbiddenCookieNames)),
    forbiddenCookiePrefixes: normalizeCookieValues(options.forbiddenCookieNamePrefixes),
    maxConcurrent, maxHTTP, maxEvents, eventIdleTimeout, maxJSON, maxChunk, maxBody, maxWS, defaultTimeout, maxTimeout,
    ...(options.onError === undefined ? {} : { report: options.onError }),
  };
}

function filterRequestHeaders(facts: ProxyHeaderFacts, config: Config, bodyLength: number): Header[] {
  if (facts.transferEncoding) throw new Error("transfer coding is not allowed");
  if (facts.contentLength !== undefined && facts.contentLength !== BigInt(bodyLength)) throw new Error("content length mismatch");
  const headers = filterHeaders(facts, REQUEST_HEADERS, config.requestHeaders);
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

function filterHeaders(facts: ProxyHeaderFacts, base: ReadonlySet<string>, extra: ReadonlySet<string>, blocked?: ReadonlySet<string>, allowSetCookie = false): Header[] {
  const result: Header[] = [];
  let lengthAdded = false;
  for (const header of facts.fields) {
    const name = header.name;
    if (facts.connection.has(name) || (!base.has(name) && !extra.has(name)) || (FORBIDDEN_HEADERS.has(name) && !(allowSetCookie && name === "set-cookie" && extra.has(name))) || blocked?.has(name)) continue;
    if (name === "content-length") {
      if (lengthAdded) continue;
      lengthAdded = true;
      result.push({ name, value: String(facts.contentLength) });
    } else result.push(header);
  }
  return result;
}
// Native HTTP retains the content-coded representation and ordered repeated
// fields. The browser bridge owns final decoding; fetch would decode here.
async function requestCodedResponse(target: URL, network: ProxyNetworkPolicy, path: string, method: string, fields: readonly Header[], body: Uint8Array, trailers: readonly Header[], signal: AbortSignal, maxHeaderSize: number): Promise<{
  status: number; headers: Headers; headerList: Header[]; body: ReadableStream<Uint8Array>; trailers(): Header[]; close(): Promise<void>;
}> {
  const connection = await network.connect(target.protocol === "https:", signal);
  const agent = target.protocol === "https:" ? new HTTPSAgent({ keepAlive: false, maxSockets: 1 }) : new HTTPAgent({ keepAlive: false, maxSockets: 1 });
  let used = false;
  agent.createConnection = () => {
    signal.throwIfAborted();
    if (used) throw new Error("proxy connection already used");
    used = true; return connection.socket;
  };
  const close = async (): Promise<void> => { agent.destroy(); await connection.close(); };
  try { return await new Promise((resolve, reject) => {
    const headers: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
    headers.host = [target.host];
    for (const { name, value } of fields) (headers[name] ??= []).push(value);
    if (trailers.length !== 0) {
      headers["transfer-encoding"] = ["chunked"];
      headers.trailer = [[...new Set(trailers.map(field => field.name))].join(", ")];
    } else headers["content-length"] = [String(body.byteLength)];
    const request = (target.protocol === "https:" ? requestHTTPS : requestHTTP)(target, {
      method, path, signal, agent, maxHeaderSize, setHost: false,
    }, (response) => {
      const headerList: Header[] = [];
      const responseHeaders = new Headers();
      for (let index = 0; index < response.rawHeaders.length; index += 2) {
        const name = response.rawHeaders[index]!;
        const value = response.rawHeaders[index + 1]!;
        headerList.push({ name: name.toLowerCase(), value });
        responseHeaders.append(name, value);
      }
      resolve({ status: response.statusCode!, headers: responseHeaders, headerList, close,
        body: Readable.toWeb(response) as ReadableStream<Uint8Array>,
        trailers: () => { const fields: Header[]=[]; for(let i=0;i<response.rawTrailers.length;i+=2) fields.push({name:response.rawTrailers[i]!.toLowerCase(),value:response.rawTrailers[i+1]!}); return fields; } });
    });
    request.on("error", reject);
    // ClientRequest normalizes constructor input. Restore the validated token
    // before its first header encoding so extension methods retain exact case.
    request.method = method;
    for (const [name, values] of Object.entries(headers)) request.setHeader(name, values);
    if (trailers.length !== 0) request.addTrailers(trailers.map(({ name, value }): [string, string] => [name, value]));
    request.end(body.byteLength === 0 ? undefined : body);
  }); } catch (error) { await close(); throw error; }
}

async function writeFrame(stream: ProxyStream, value: unknown, signal?: AbortSignal): Promise<void> {
  const schema: ProxySchema = Object.hasOwn(value as object,"request_id") ? "ProxyHTTPResponse" : "ProxyWebSocketResponse";
  await writeProxyFrame({write: async data => await writeAll(stream,data,signal === undefined ? {} : {signal})},schema,value);
}
async function writeBodyEnd(stream: ProxyStream, trailers: readonly Header[], signal?: AbortSignal): Promise<void> {
 validateProxyTrailers(trailers);
 await writeChunk(stream,new Uint8Array(),signal);
 await writeProxyFrame({write: async data => await writeAll(stream,data,signal === undefined ? {} : {signal})},"ProxyBodyEnd",{v:WIRE_VERSION,trailers});
}
async function writeHTTPError(stream: ProxyStream, requestID: string, code: string): Promise<void> {
  await writeFrame(stream, { v: WIRE_VERSION, request_id: requestID.trim() || "unknown", ok: false, error: { code, message: "proxy operation failed" } }).catch(() => undefined);
  await writeChunks(stream, new Uint8Array(), 1, undefined).catch(() => undefined);
}
async function writeWSError(stream: ProxyStream, connID: string, code: string): Promise<void> {
  await writeFrame(stream, { v: WIRE_VERSION, conn_id: connID.trim() || "unknown", ok: false, error: { code, message: "proxy operation failed" } }).catch(() => undefined);
}
async function writeChunks(stream: ProxyStream, body: Uint8Array, chunkSize: number, signal?: AbortSignal): Promise<void> {
  for (let offset = 0; offset < body.length; offset += chunkSize) {
    await writeChunk(stream, body.subarray(offset, Math.min(body.length, offset + chunkSize)), signal);
  }
  await writeBodyEnd(stream, [], signal);
}
async function writeChunk(stream: ProxyStream, chunk: Uint8Array, signal?: AbortSignal): Promise<void> {
  const bytes = new Uint8Array(4 + chunk.length);
  new DataView(bytes.buffer).setUint32(0, chunk.length, false); bytes.set(chunk, 4);
  await writeAll(stream, bytes, signal === undefined ? {} : { signal });
}
async function readBody(reader: ProxyByteReader, maxChunk: number, maxBody: number, maxMetadata: number, facts: ProxyHeaderFacts): Promise<{ body: Uint8Array; trailers: Header[] } | undefined> {
  const chunks: Uint8Array[] = []; let total = 0;
  try {
    while (true) {
      const header = await reader.readExactly(4); const length = new DataView(header.buffer, header.byteOffset, 4).getUint32(0, false);
      if (length === 0) {
        const terminal = await readProxyFrame(reader, "ProxyBodyEnd", maxMetadata);
        validateProxyTrailers(terminal.trailers, facts.connection);
        return { body: concat(chunks), trailers: terminal.trailers as Header[] };
      }
      if (length > maxChunk || total + length > maxBody) return undefined;
      const chunk = await reader.readExactly(length); chunks.push(chunk); total += length;
    }
  } catch { return undefined; }
}
function concat(chunks: readonly Uint8Array[]): Uint8Array { const out = new Uint8Array(chunks.reduce((sum, item) => sum + item.length, 0)); let offset = 0; for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; } return out; }
function normalizeTimeout(value: number | undefined, fallback: number, maximum: number): number | undefined { if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) return undefined; return Math.min(value === undefined || value === 0 ? fallback : value, maximum); }
function validateOrigin(value: string | undefined, allowed: ReadonlySet<string>): string | undefined { if (value === undefined || value === "") return undefined; try { const origin = new URL(value); return origin.pathname === "/" && !origin.search && !origin.hash && origin.origin === value && allowed.has(origin.origin) ? origin.origin : undefined; } catch { return undefined; } }
function linkSignals(parent: AbortSignal, timeout: AbortSignal): { signal: AbortSignal; dispose(): void } { const controller = new AbortController(); const abort = (event: Event) => controller.abort((event.target as AbortSignal).reason); parent.addEventListener("abort", abort, { once: true }); timeout.addEventListener("abort", abort, { once: true }); if (parent.aborted) controller.abort(parent.reason); else if (timeout.aborted) controller.abort(timeout.reason); return { signal: controller.signal, dispose: () => { parent.removeEventListener("abort", abort); timeout.removeEventListener("abort", abort); } }; }
function decodeHTTPMeta(value: unknown): HTTPMeta {
  if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.request_id !== "string" || typeof value.method !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers) || (value.external_origin !== undefined && typeof value.external_origin !== "string") || (value.timeout_ms !== undefined && typeof value.timeout_ms !== "number")) throw new Error("invalid HTTP metadata");
  const headers = decodeHeaders(value.headers);
  return { v: value.v, request_id: value.request_id, method: value.method, path: value.path, headers, ...(value.external_origin === undefined ? {} : { external_origin: value.external_origin }), ...(value.timeout_ms === undefined ? {} : { timeout_ms: value.timeout_ms }) };
}
function decodeWSOpen(value: unknown): WSOpen {
  if (!isRecord(value) || value.v !== WIRE_VERSION || typeof value.conn_id !== "string" || typeof value.path !== "string" || !Array.isArray(value.headers)) throw new Error("invalid WS metadata");
  return { v: value.v, conn_id: value.conn_id, path: value.path, headers: decodeHeaders(value.headers) };
}
function decodeHeaders(value: readonly unknown[]): Header[] {
  // The enclosing metadata frame is already bounded at 1 MiB. Keep a wide
  // count guard for parser work accounting without silently reducing that
  // established metadata capability to the old 256-field fixture limit.
  if (value.length > 65_535 || !value.every(isHeader)) throw new Error("invalid header list");
  return value.map((header) => {
    const name = header.name.trim().toLowerCase();
    if (!HEADER_NAME.test(name) || /[\r\n]/u.test(header.value)) throw new Error("invalid header");
    return { name, value: header.value };
  });
}
function isHeader(value: unknown): value is Header { return isRecord(value) && typeof value.name === "string" && typeof value.value === "string"; }
function isRecord(value: unknown): value is Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function onceEvent(socket: any, event: string, signal: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const onAbort = () => { cleanup(); reject(signal.reason ?? new Error("aborted")); }; const onOpen = () => { cleanup(); resolve(); }; const onError = (error: unknown) => { cleanup(); reject(error); }; const cleanup = () => { signal.removeEventListener("abort", onAbort); socket.off?.(event, onOpen); socket.off?.("error", onError); }; socket.once(event, onOpen); socket.once("error", onError); signal.addEventListener("abort", onAbort, { once: true }); if (signal.aborted) onAbort(); }); }
async function relayWebSocket(
  socket: any,
  stream: ProxyStream,
  reader: ProxyByteReader,
  maximum: number,
  signal: AbortSignal,
  stopInput: () => Promise<void>,
  publishResponse: () => Promise<void>,
): Promise<void> {
  let done = false, queuedItems = 0, queuedBytes = 0;
  let writeChain = Promise.resolve();
  let resolveUpstream!: () => void, rejectUpstream!: (error: unknown) => void;
  const upstream = new Promise<void>((resolve, reject) => { resolveUpstream = resolve; rejectUpstream = reject; });
  // Install all native listeners before publishing the response. Early frames
  // share the same bounded queue and remain ordered after response metadata.
  writeChain = Promise.resolve().then(publishResponse).catch(rejectUpstream);
  const enqueue = (operation: number, payload: Uint8Array): void => {
    if (done) return;
    const terminal = operation === 8;
    // One bounded data window plus a terminal control reserve. Pausing native
    // reads also prevents a slow Flowersec writer from growing a Promise queue.
    if (queuedItems >= (terminal ? 17 : 16) || payload.length > (operation >= 8 ? 125 : maximum) ||
        queuedBytes > maximum - (terminal ? 0 : payload.length)) {
      rejectUpstream(new Error("proxy WebSocket receive capacity exhausted")); return;
    }
    queuedItems++; queuedBytes += payload.length; socket.pause();
    const current = writeChain.then(async () => {
      if (done) return;
      const frame = new Uint8Array(5 + payload.length);
      frame[0] = operation; new DataView(frame.buffer).setUint32(1, payload.length, false); frame.set(payload, 5);
      await writeAll(stream, frame, { signal });
      if (terminal) resolveUpstream();
    }).finally(() => {
      queuedItems--; queuedBytes -= payload.length;
      if (!done && queuedItems === 0) socket.resume();
    });
    writeChain = current.catch(rejectUpstream);
  };
  const message = (data: Uint8Array, binary: boolean): void => enqueue(binary ? 2 : 1, data);
  const ping = (data: Uint8Array): void => enqueue(9, data);
  const pong = (data: Uint8Array): void => enqueue(10, data);
  const closed = (code: number, reason: Buffer): void => enqueue(8, encodeWebSocketClose(code, reason));
  const aborted = (): void => rejectUpstream(signal.reason ?? new Error("proxy WebSocket canceled"));
  socket.on("message", message); socket.on("ping", ping); socket.on("pong", pong);
  socket.once("close", closed); socket.on("error", rejectUpstream);
  signal.addEventListener("abort", aborted, { once: true });
  if (signal.aborted) aborted();
  const downstream = (async (): Promise<void> => {
    while (!done) {
      const frame = await reader.readExactly(5);
      if (done) return;
      const operation = frame[0]!, length = new DataView(frame.buffer, frame.byteOffset, 5).getUint32(1, false);
      if (length > maximum || ![1, 2, 8, 9, 10].includes(operation) || operation >= 8 && length > 125) throw new Error("invalid websocket frame");
      const payload = await reader.readExactly(length);
      if (done) return;
      if (operation === 8) {
        const close = decodeWebSocketClose(payload); socket.close(close.code, close.reason); return;
      }
      if (operation === 9) { await sendSocketControl(socket, "ping", payload); continue; }
      if (operation === 10) { await sendSocketControl(socket, "pong", payload); continue; }
      if (operation === 1) await sendSocketFrame(socket, new TextDecoder("utf-8", { fatal: true }).decode(payload), false);
      else await sendSocketFrame(socket, payload, true);
    }
  })();
  let closeTimer: ReturnType<typeof setTimeout> | undefined;
  try {
    const winner = await Promise.race([upstream.then(() => "upstream"), downstream.then(() => "downstream")]);
    if (winner === "downstream") {
      await Promise.race([upstream, new Promise<void>(resolve => { closeTimer = setTimeout(resolve, 1_000); })]);
    }
  } finally {
    done = true; clearTimeout(closeTimer);
    socket.off("message", message); socket.off("ping", ping); socket.off("pong", pong); socket.off("close", closed);
    signal.removeEventListener("abort", aborted);
    try { socket.terminate(); } catch { /* already closed */ }
    // Logical completion cannot release the handler while a real read or
    // output callback still owns the original stream and backing.
    await Promise.allSettled([stopInput(), downstream, writeChain]);
    socket.off("error", rejectUpstream);
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

function isEventStream(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "text/event-stream";
}
function acceptsEventStream(value: string): boolean {
  return isEventStream(value) && !/;\s*q=0(?:\.0*)?\s*(?:;|$)/iu.test(value);
}

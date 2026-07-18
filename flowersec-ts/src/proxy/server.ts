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
  DEFAULT_MAX_CONCURRENT_STREAMS,
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
  maxWsQueuedBytes?: number;
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
  maxWsQueuedBytes: number;
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
  const activeProxy = new Set<Promise<void>>();
  const activeRPC = new Set<Promise<void>>();
  try {
    while (!signal?.aborted) {
      const accepted = await session.acceptStream(signal === undefined ? {} : { signal });
      if (accepted.kind === "rpc") {
        const task = serveRPCStream(accepted.stream, options.rpcRouter ?? new RpcRouter(), options.rpcServerOptions, signal)
          .catch(() => {})
          .finally(() => activeRPC.delete(task));
        activeRPC.add(task);
        continue;
      }
      if (accepted.kind !== PROXY_KIND_HTTP1 && accepted.kind !== PROXY_KIND_WS) {
        await accepted.stream.reset(new Error(`unsupported proxy stream kind ${accepted.kind}`));
        continue;
      }
      if (activeProxy.size >= compiled.maxConcurrentStreams) {
        await accepted.stream.reset(new Error("proxy stream concurrency exhausted"));
        continue;
      }
      const task = serveProxyStreamCompiled(accepted.kind, accepted.stream, compiled, signal)
        .catch(() => {})
        .finally(() => activeProxy.delete(task));
      activeProxy.add(task);
    }
  } finally {
    await Promise.allSettled([...activeProxy, ...activeRPC]);
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
  const compiled = compileOptions(options);
  return serveProxyStreamCompiled(
    kind,
    stream,
    compiled,
    signal,
  );
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

async function serveHTTP(
  stream: YamuxStream,
  options: CompiledOptions,
  signal?: AbortSignal,
): Promise<void> {
  const reader = createByteReader(stream);
  let requestId = "unknown";
  let responseStarted = false;
  let streamReset = false;
  let requestBody: StreamingRequestBody | undefined;
  let responseBodyReader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let controller: AbortController | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  const resetStream = async (error: Error): Promise<void> => {
    if (streamReset) return;
    streamReset = true;
    try { await stream.reset(error); } catch { /* The peer may already have reset the stream. */ }
  };
  try {
    const meta = assertHTTPRequestMeta(await readJsonFrame(reader, options.maxJsonFrameBytes));
    requestId = meta.request_id;
    const path = parsePath(meta.path);
    const knownRequestLength = contentLength(meta.headers, "request");
    if (knownRequestLength != null && knownRequestLength > options.maxBodyBytes) {
      throw new ProxyServerError("request_body_too_large", "request body too large");
    }

    if (signal?.aborted) throw new ProxyServerError("canceled", "proxy request canceled");
    const headers = requestHeaders(meta.headers, options);
    applyExternalOrigin(headers, meta.external_origin);
    const target = new URL(options.upstream);
    target.pathname = path.pathname;
    target.search = path.search;
    target.hash = "";

    controller = new AbortController();
    const abortUpstream = (error: Error) => {
      if (!controller!.signal.aborted) controller!.abort(error);
      requestBody?.abort(error);
      if (responseStarted) void resetStream(error);
    };
    const onAbort = () => abortUpstream(new ProxyServerError("canceled", "proxy request canceled"));
    signal?.addEventListener("abort", onAbort, { once: true });
    removeAbortListener = () => signal?.removeEventListener("abort", onAbort);
    if (signal?.aborted) onAbort();
    const timeoutMs = resolveTimeout(meta.timeout_ms, options);
    timer = timeoutMs > 0
      ? setTimeout(() => abortUpstream(new ProxyServerError("timeout", "upstream request timeout")), timeoutMs)
      : undefined;

    requestBody = createStreamingRequestBody(reader, options.maxChunkBytes, options.maxBodyBytes, abortUpstream);
    const method = meta.method.trim().toUpperCase();
    const requestInit: RequestInit & { duplex?: "half" } = {
      method,
      headers,
      redirect: "manual",
      signal: controller.signal,
    };
    if (method === "GET" || method === "HEAD") {
      requestBody.drain();
    } else {
      requestInit.body = requestBody.stream;
      requestInit.duplex = "half";
    }

    if (controller.signal.aborted) throw controller.signal.reason;
    const response = await options.fetch(target, requestInit);
    if (requestBody.error != null) throw requestBody.error;
    requestBody.drain();

    const knownResponseLength = contentLength(response.headers, "response");
    if (knownResponseLength != null && knownResponseLength > options.maxBodyBytes) {
      await response.body?.cancel();
      throw new ProxyServerError("response_body_too_large", "response body too large");
    }

    const responseHeaders = collectResponseHeaders(response.headers, options);
    const responseMeta: HttpResponseMetaV1 = {
      v: PROXY_PROTOCOL_VERSION,
      request_id: requestId,
      ok: true,
      status: response.status,
      headers: responseHeaders,
    };
    await writeJsonFrame(stream, responseMeta);
    responseStarted = true;
    if (response.body == null) {
      await stream.write(u32be(0));
      const requestError = await requestBody.completion;
      if (requestError != null) throw requestError;
      return;
    }

    responseBodyReader = response.body.getReader();
    let total = 0;
    while (true) {
      const next = await Promise.race([
        responseBodyReader.read(),
        requestBody.failure.then((error) => { throw error; }),
      ]);
      if (next.done) break;
      const bytes = next.value;
      const nextTotal = total + bytes.length;
      if (!Number.isSafeInteger(nextTotal) || nextTotal > options.maxBodyBytes) {
        throw new ProxyServerError("response_body_too_large", "response body too large");
      }
      total = nextTotal;
      for (let offset = 0; offset < bytes.length; offset += options.maxChunkBytes) {
        const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + options.maxChunkBytes));
        await stream.write(u32be(chunk.length));
        await stream.write(chunk);
      }
    }
    await stream.write(u32be(0));
    const requestError = await requestBody.completion;
    if (requestError != null) throw requestError;
  } catch (error) {
    const effective = requestBody?.error ?? controller?.signal.reason ?? asError(error);
    if (controller != null && !controller.signal.aborted) controller.abort(effective);
    if (responseStarted) await resetStream(effective);
    else await writeHTTPError(stream, requestId, classifyHTTPError(effective));
  } finally {
    if (timer != null) clearTimeout(timer);
    removeAbortListener?.();
    requestBody?.stop();
    try { await responseBodyReader?.cancel(); } catch { /* The upstream body may already be closed. */ }
  }
}

async function serveWebSocket(stream: YamuxStream, options: CompiledOptions, signal?: AbortSignal): Promise<void> {
  const reader = createByteReader(stream, signal === undefined ? {} : { signal });
  let connId = "unknown";
  let raw: any;
  let upstreamOpened = false;
  let removePostOpenAbortListener: (() => void) | undefined;
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
      handshakeTimeout: resolveTimeout(undefined, options),
    });
    let writeChain: Promise<void> = Promise.resolve();
    let queuedWriteBytes = 0;
    let terminalSettled = false;
    let terminalError: Error | undefined;
    let terminalResolve!: (error?: Error) => void;
    const terminal = new Promise<Error | undefined>((resolve) => { terminalResolve = resolve; });
    const settleTerminal = (error?: Error) => {
      if (terminalSettled) return;
      terminalSettled = true;
      terminalError = error;
      terminalResolve(error);
    };
    const queueFrame = (op: number, payload: Uint8Array, allowCloseFrame = false): Promise<void> => {
      if (terminalSettled) return Promise.reject(new Error("proxy WebSocket is closed"));
      const frameBytes = payload.byteLength + 5;
      const nextQueuedWriteBytes = queuedWriteBytes + frameBytes;
      if (!Number.isSafeInteger(nextQueuedWriteBytes)
        || (!allowCloseFrame && nextQueuedWriteBytes > options.maxWsQueuedBytes)) {
        const error = new ProxyServerError("resource_exhausted", "proxy WebSocket write queue exhausted");
        settleTerminal(error);
        try { raw.close(1011, "proxy buffer limit exceeded"); } catch { /* Best effort. */ }
        return Promise.reject(error);
      }
      queuedWriteBytes = nextQueuedWriteBytes;
      const write = writeChain
        .then(() => {
          if (terminalSettled) throw terminalError ?? new Error("proxy WebSocket is closed");
          return writeWSFrame(stream, op, payload, options.maxWsFrameBytes);
        })
        .finally(() => {
          queuedWriteBytes = Math.max(0, queuedWriteBytes - frameBytes);
        });
      writeChain = write;
      void write.catch((error) => settleTerminal(asError(error)));
      return write;
    };
    const queueEventFrame = (op: number, payload: Uint8Array) => {
      void queueFrame(op, payload).catch(() => {});
    };
    raw.on("close", (code: number, reason: unknown) => {
      if (terminalSettled) return;
      if (!upstreamOpened) {
        settleTerminal(new Error("upstream WebSocket closed before open"));
        return;
      }
      const reasonBytes = toBytes(reason);
      const payload = new Uint8Array(2 + reasonBytes.length);
      payload[0] = (code >>> 8) & 0xff;
      payload[1] = code & 0xff;
      payload.set(reasonBytes, 2);
      void queueFrame(8, payload, true).then(
        () => settleTerminal(),
        (error) => settleTerminal(asError(error)),
      );
    });
    raw.on("error", (error: Error) => settleTerminal(error));

    await waitForUpstreamOpen(raw, signal);
    upstreamOpened = true;
    const response: WsOpenRespV1 = {
      v: PROXY_PROTOCOL_VERSION,
      conn_id: connId,
      ok: true,
      protocol: String(raw.protocol ?? ""),
    };
    const openResponseWrite = writeJsonFrame(stream, response);
    writeChain = openResponseWrite;
    void openResponseWrite.catch((error) => settleTerminal(asError(error)));

    raw.on("message", (data: unknown, isBinary: boolean) => queueEventFrame(isBinary ? 2 : 1, toBytes(data)));
    raw.on("ping", (data: unknown) => queueEventFrame(9, toBytes(data)));
    raw.on("pong", (data: unknown) => queueEventFrame(10, toBytes(data)));
    const onPostOpenAbort = () => {
      const error = asError(signal?.reason ?? new Error("proxy WebSocket aborted"));
      settleTerminal(error);
      try {
        if (typeof raw.terminate === "function") raw.terminate();
        else raw.close();
      } catch {
        // The terminal error is already authoritative.
      }
    };
    if (signal != null) {
      signal.addEventListener("abort", onPostOpenAbort, { once: true });
      removePostOpenAbortListener = () => signal.removeEventListener("abort", onPostOpenAbort);
      if (signal.aborted) onPostOpenAbort();
    }

    const openResponseResult = await Promise.race([
      openResponseWrite.then(() => undefined),
      terminal,
    ]);
    if (openResponseResult != null) throw openResponseResult;
    try {
      if (!terminalSettled && typeof raw.resume === "function") raw.resume();
    } catch (error) {
      settleTerminal(asError(error));
      throw error;
    }

    const inbound = (async () => {
      while (true) {
        const frame = await readWSFrame(reader, options.maxWsFrameBytes);
        switch (frame.op) {
          case 1:
            await sendUpstreamFrame(raw, 1, frame.payload);
            break;
          case 2:
            await sendUpstreamFrame(raw, 2, frame.payload);
            break;
          case 8: {
            raw.close(frame.payload.length >= 2 ? (frame.payload[0]! << 8) | frame.payload[1]! : 1000, new TextDecoder().decode(frame.payload.subarray(2)));
            const closeError = await terminal;
            if (closeError != null) throw closeError;
            return;
          }
          case 9:
            await sendUpstreamFrame(raw, 9, frame.payload);
            break;
          case 10:
            await sendUpstreamFrame(raw, 10, frame.payload);
            break;
          default: throw new Error("invalid websocket frame operation");
        }
      }
    })();
    const result = await Promise.race([inbound.then(() => undefined), terminal]);
    if (result != null) throw result;
    await writeChain;
  } catch (error) {
    if (!upstreamOpened) await writeWSOpenError(stream, connId, classifyWSError(error));
  } finally {
    removePostOpenAbortListener?.();
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
  const defaultMaxWsQueuedBytes = maxWsFrameBytes <= Number.MAX_SAFE_INTEGER - 5
    ? maxWsFrameBytes + 5
    : maxWsFrameBytes;
  const maxWsQueuedBytes = positive(input.maxWsQueuedBytes, defaultMaxWsQueuedBytes, "maxWsQueuedBytes");
  if (maxWsQueuedBytes < 5) throw new Error("maxWsQueuedBytes must be at least 5");
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
    maxWsQueuedBytes,
    defaultTimeoutMs,
    maxTimeoutMs,
    maxConcurrentStreams: positive(input.maxConcurrentStreams, DEFAULT_MAX_CONCURRENT_STREAMS, "maxConcurrentStreams"),
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

type StreamingRequestBody = Readonly<{
  stream: ReadableStream<Uint8Array>;
  failure: Promise<Error>;
  completion: Promise<Error | undefined>;
  readonly error: Error | undefined;
  drain: () => void;
  abort: (error: Error) => void;
  stop: () => void;
}>;

function createStreamingRequestBody(
  reader: ReturnType<typeof createByteReader>,
  maxChunkBytes: number,
  maxBodyBytes: number,
  onFailure: (error: Error) => void,
): StreamingRequestBody {
  let total = 0;
  let finished = false;
  let draining = false;
  let readChain: Promise<void> = Promise.resolve();
  let error: Error | undefined;
  let streamController: ReadableStreamDefaultController<Uint8Array> | undefined;
  let resolveFailure!: (error: Error) => void;
  const failure = new Promise<Error>((resolve) => { resolveFailure = resolve; });
  let resolveCompletion!: (error: Error | undefined) => void;
  const completion = new Promise<Error | undefined>((resolve) => { resolveCompletion = resolve; });

  const fail = (cause: unknown): Error => {
    if (error != null) return error;
    const raw = asError(cause);
    error = raw instanceof ProxyServerError
      ? raw
      : new ProxyServerError("request_body_invalid", raw.message);
    finished = true;
    try { streamController?.error(error); } catch { /* The body consumer may already be gone. */ }
    resolveFailure(error);
    resolveCompletion(error);
    onFailure(error);
    return error;
  };

  const readChunkUnserialized = async (): Promise<Uint8Array | null> => {
    try {
      const length = readU32be(await reader.readExactly(4), 0);
      if (length === 0) {
        finished = true;
        resolveCompletion(undefined);
        return null;
      }
      if (length > maxChunkBytes) {
        throw new ProxyServerError("request_body_too_large", "request chunk too large");
      }
      const nextTotal = total + length;
      if (!Number.isSafeInteger(nextTotal) || nextTotal > maxBodyBytes) {
        throw new ProxyServerError("request_body_too_large", "request body too large");
      }
      const chunk = await reader.readExactly(length);
      total = nextTotal;
      return chunk;
    } catch (cause) {
      throw fail(cause);
    }
  };

  const readChunk = (): Promise<Uint8Array | null> => {
    const next = readChain.then(readChunkUnserialized);
    readChain = next.then(() => {}, () => {});
    return next;
  };

  const drain = () => {
    if (draining || finished) return;
    draining = true;
    try { streamController?.close(); } catch { /* A pending pull will observe draining below. */ }
    void (async () => {
      while (!finished) await readChunk();
    })().catch(() => {});
  };

  const stream = new ReadableStream<Uint8Array>({
    start(controller) { streamController = controller; },
    async pull(controller) {
      if (finished) {
        if (error == null) controller.close();
        return;
      }
      const chunk = await readChunk();
      if (draining) return;
      if (chunk == null) controller.close();
      else controller.enqueue(chunk);
    },
    cancel() { drain(); },
  }, { highWaterMark: 0 });

  return {
    stream,
    failure,
    completion,
    get error() { return error; },
    drain,
    abort: (cause) => { if (!finished) fail(cause); },
    stop: () => {
      if (finished) return;
      finished = true;
      try { streamController?.close(); } catch { /* The fetch implementation may own the stream. */ }
      resolveCompletion(undefined);
    },
  };
}

function contentLength(headers: readonly Header[] | Headers, side: "request" | "response"): number | undefined {
  const rawValues = headers instanceof Headers
    ? (headers.get("content-length") == null ? [] : [headers.get("content-length")!])
    : headers
      .filter((header) => normalizeHeaderName(header.name) === "content-length")
      .map((header) => header.value.trim());
  if (rawValues.length === 0) return undefined;
  if (rawValues.length !== 1 || !/^(0|[1-9][0-9]*)$/.test(rawValues[0]!)) {
    throw new ProxyServerError(
      side === "request" ? "invalid_request_meta" : "upstream_request_failed",
      `invalid ${side} content-length`,
    );
  }
  const value = Number(rawValues[0]);
  if (!Number.isSafeInteger(value)) {
    throw new ProxyServerError(
      side === "request" ? "invalid_request_meta" : "upstream_request_failed",
      `invalid ${side} content-length`,
    );
  }
  return value;
}

async function writeHTTPError(stream: YamuxStream, requestId: string, code: string): Promise<void> {
  const meta: HttpResponseMetaV1 = {
    v: PROXY_PROTOCOL_VERSION,
    request_id: requestId.trim() || "unknown",
    ok: false,
    error: { code, message: publicHTTPErrorMessage(code) },
  };
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

async function writeWSOpenError(stream: YamuxStream, connId: string, code: string): Promise<void> {
  const response: WsOpenRespV1 = {
    v: PROXY_PROTOCOL_VERSION,
    conn_id: connId.trim() || "unknown",
    ok: false,
    error: { code, message: publicWSErrorMessage(code) },
  };
  try { await writeJsonFrame(stream, response); } catch { /* The peer may be gone. */ }
}

function waitForUpstreamOpen(websocket: any, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      websocket.off("open", onOpen);
      websocket.off("error", onError);
      websocket.off("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const onOpen = () => {
      try {
        if (typeof websocket.pause === "function") websocket.pause();
      } catch (error) {
        cleanup();
        reject(asError(error));
        return;
      }
      cleanup();
      resolve();
    };
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onClose = () => { cleanup(); reject(new Error("upstream WebSocket closed before open")); };
    const onAbort = () => { cleanup(); reject(signal?.reason ?? new Error("aborted")); };
    websocket.once("open", onOpen);
    websocket.once("error", onError);
    websocket.once("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}

function sendUpstreamFrame(websocket: any, op: number, payload: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    const finish = (error?: Error | null) => {
      if (error == null) resolve();
      else reject(asError(error));
    };
    try {
      switch (op) {
        case 1:
          websocket.send(payload, { binary: false }, finish);
          return;
        case 2:
          websocket.send(payload, { binary: true }, finish);
          return;
        case 9:
          websocket.ping(payload, undefined, finish);
          return;
        case 10:
          websocket.pong(payload, undefined, finish);
          return;
        default:
          reject(new Error("invalid upstream WebSocket operation"));
      }
    } catch (error) {
      reject(asError(error));
    }
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

function publicHTTPErrorMessage(code: string): string {
  switch (code) {
    case "invalid_request_meta":
      return "invalid proxy request";
    case "request_body_too_large":
    case "response_body_too_large":
      return "proxy body limit exceeded";
    case "resource_exhausted":
      return "proxy resource limit exceeded";
    case "timeout":
      return "upstream request timed out";
    case "canceled":
      return "proxy request canceled";
    default:
      return "upstream request failed";
  }
}

function publicWSErrorMessage(code: string): string {
  switch (code) {
    case "invalid_ws_open_meta":
      return "invalid proxy WebSocket request";
    case "resource_exhausted":
      return "proxy WebSocket resource limit exceeded";
    default:
      return "upstream WebSocket connection failed";
  }
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

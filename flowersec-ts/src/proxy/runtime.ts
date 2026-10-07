import { bindProxyRequestAssociation, proxyRequestAssociation } from "./requestAssociation.js";
import { PROXY_CREDENTIAL_CONTROL_PATH, registerProxyCredentialControl } from "./credentialControl.js";
import { prepareProxyFetch } from "./fetch.js";
import { StreamAdmission, type StreamPermit } from "./admission.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { PROXY_WIRE_VERSION, readProxyFrame, writeProxyFrame, validateProxyTrailers } from "./wire.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
import { SessionError, type OperationOptions } from "../public/contract.js";
import { createStreamMetadata } from "../public/streamMetadata.js";

import { InvalidProxyPathError, matchesPathPrefix, normalizePath, normalizeSubtreePath, normalizePrefixes, normalizeHeaderNames, FORBIDDEN_HEADERS } from "./policy.js";
import { ProxyByteReader, writeAll, type ProxyStream } from "./stream.js";
import { currentProxyStream } from "./currentStream.js";
import type { StreamMetadata } from "../public/streamMetadata.js";
import { inspectProxyHeaders, type ProxyHeaderFacts } from "./headers.js";
import {
  registerProxyRuntimeServiceWorkerBridge,
  usesServiceWorkerResponseFlowControl,
} from "./serviceWorkerRuntime.js";
import type {
  ProxyFetchRequest,
  ProxyHeader,
  ProxyRuntime,
  ProxyRuntimeOptions,
  ProxyRuntimePathPolicy,
} from "./types.js";

const PROXY_HTTP_STREAM_KIND = "flowersec-proxy/http1";
const PROXY_WEBSOCKET_STREAM_KIND = "flowersec-proxy/ws";
const DEFAULT_MAX_WS_BUFFERED_AMOUNT_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_CONCURRENT_HTTP_STREAMS = 24;
const DEFAULT_MAX_QUEUED_HTTP_REQUESTS = 128;
const DEFAULT_MAX_QUEUED_HTTP_BODY_BYTES = 64 * 1024 * 1024;

type ResponseMeta = Readonly<{
  v: number;
  request_id: string;
  ok: boolean;
  status?: number;
  headers?: readonly ProxyHeader[];
  error?: Readonly<{ code?: string; message?: string }>;
}>;

type WebSocketOpenResponse = Readonly<{
  v: number;
  conn_id: string;
  ok: boolean;
  protocol?: string;
  error?: Readonly<{ code?: string; message?: string }>;
}>;

class ProxyPolicyError extends Error {}

function isEventStream(value: string): boolean {
  return value.split(";", 1)[0]?.trim().toLowerCase() === "text/event-stream";
}
function acceptsEventStream(value: string): boolean {
  return value.split(",").some((part) => isEventStream(part) && !/;\s*q=0(?:\.0*)?\s*(?:;|$)/iu.test(part));
}

function randomID(): string {
  const bytes = new Uint8Array(18);
  if (globalThis.crypto?.getRandomValues !== undefined) globalThis.crypto.getRandomValues(bytes);
  else for (let index = 0; index < bytes.length; index++) bytes[index] = Math.floor(Math.random() * 256);
  return base64urlEncode(bytes);
}

function positiveLimit(name: string, input: number | undefined, fallback: number): number {
  if (input === undefined || input === 0) return fallback;
  if (!Number.isSafeInteger(input) || input < 0) throw new TypeError(`${name} must be a non-negative safe integer`);
  return input;
}

function strictlyPositiveLimit(name: string, input: number | undefined, fallback: number): number {
  if (input === undefined) return fallback;
  if (!Number.isSafeInteger(input) || input <= 0) throw new TypeError(`${name} must be a positive safe integer`);
  return input;
}

function normalizeTimeout(input: number | undefined): number {
  if (input === undefined) return 0;
  if (!Number.isSafeInteger(input) || input < 0 || input > SDK_DEFAULTS.proxy.maxTimeoutMs) {
    throw new TypeError("timeoutMs must be within the proxy timeout contract");
  }
  return input;
}

function pathName(path: string): string {
  const query = path.indexOf("?");
  return query < 0 ? path : path.slice(0, query);
}

function normalizePathPolicy(policy: ProxyRuntimePathPolicy | undefined): Required<ProxyRuntimePathPolicy> {
  return {
    allowedPathPrefixes: normalizePrefixes("allowedPathPrefixes", policy?.allowedPathPrefixes),
    deniedPathPrefixes: normalizePrefixes("deniedPathPrefixes", policy?.deniedPathPrefixes),
    allowedWebSocketPathPrefixes: normalizePrefixes("allowedWebSocketPathPrefixes", policy?.allowedWebSocketPathPrefixes),
    deniedWebSocketPathPrefixes: normalizePrefixes("deniedWebSocketPathPrefixes", policy?.deniedWebSocketPathPrefixes),
  };
}

function enforcePathPolicy(
  kind: "http" | "websocket",
  path: string,
  policy: Required<ProxyRuntimePathPolicy>,
): void {
  const denied = kind === "websocket"
    ? [...policy.deniedPathPrefixes, ...policy.deniedWebSocketPathPrefixes]
    : policy.deniedPathPrefixes;
  const allowed = kind === "websocket" && policy.allowedWebSocketPathPrefixes.length > 0
    ? policy.allowedWebSocketPathPrefixes
    : policy.allowedPathPrefixes;
  const scoped = denied.length > 0 || allowed.length > 0;
  const candidate = pathName(scoped ? normalizeSubtreePath(path) : path);
  if (denied.some((prefix) => matchesPathPrefix(candidate, prefix))) throw new ProxyPolicyError("proxy path denied");
  if (allowed.length > 0 && !allowed.some((prefix) => matchesPathPrefix(candidate, prefix))) {
    throw new ProxyPolicyError("proxy path not allowed");
  }
}

function normalizeOrigin(input: string | undefined): string | undefined {
  if (input === undefined || input === "") return undefined;
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new TypeError("externalOrigin must be an HTTP origin");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.origin !== input || parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("externalOrigin must be an HTTP origin");
  }
  return input;
}

function normalizeToken(input: string | undefined): string | undefined {
  if (input === undefined || input === "") return undefined;
  if (input !== input.trim() || /[\u0000-\u0020\u007f]/u.test(input) || input.length > 256) {
    throw new TypeError("runtimeRegistrationToken is invalid");
  }
  return input;
}

const BASE_REQUEST_HEADERS = new Set(["accept", "accept-language", "content-type", "if-match", "if-none-match", "range"]);
const BASE_RESPONSE_HEADERS = new Set(["accept-ranges", "cache-control", "content-disposition", "content-encoding", "content-language", "content-length", "content-range", "content-type", "etag", "expires", "last-modified", "location"]);
function filterHeaders(
  facts: ProxyHeaderFacts,
  base: ReadonlySet<string>,
  extra: ReadonlySet<string>,
): ProxyHeader[] {
  const result: ProxyHeader[] = [];
  let lengthAdded = false;
  for (const entry of facts.fields) {
    const name = entry.name;
    if (facts.connection.has(name) || (!base.has(name) && !extra.has(name)) || FORBIDDEN_HEADERS.has(name)) continue;
    if (name === "content-length") {
      if (lengthAdded) continue;
      lengthAdded = true;
      result.push(Object.freeze({ name, value: String(facts.contentLength) }));
    } else result.push(entry);
  }
  return result;
}


async function writeChunks(stream: ProxyStream, body: Uint8Array, chunkBytes: number, maxBodyBytes: number, signal: AbortSignal): Promise<void> {
  if (body.length > maxBodyBytes) throw new SessionError("resource_exhausted");
  for (let offset = 0; offset < body.length; offset += chunkBytes) {
    const chunk = body.subarray(offset, Math.min(body.length, offset + chunkBytes));
    await writeAll(stream, u32be(chunk.length), { signal });
    await writeAll(stream, chunk, { signal });
  }
  await writeAll(stream, u32be(0), { signal });
  await writeProxyFrame({write: async data => await writeAll(stream,data,{signal})}, "ProxyBodyEnd", {v:PROXY_WIRE_VERSION,trailers:[]});
}

async function* readChunks(reader: ProxyByteReader, maxChunkBytes: number, maxBodyBytes: number, facts: ProxyHeaderFacts, noBody: boolean, maxMetadataBytes: number): AsyncGenerator<Uint8Array> {
  let total = 0;
  let remaining = noBody ? undefined : facts.contentLength;
  while (true) {
    const length = readU32be(await reader.readExactly(4), 0);
    if (length === 0) {
      const terminal = await readProxyFrame(reader, "ProxyBodyEnd", maxMetadataBytes);
      validateProxyTrailers(terminal.trailers, facts.connection);
      if (remaining !== undefined && remaining !== 0n) throw new Error("proxy content length mismatch");
      return;
    }
    if (length > maxChunkBytes || total + length > maxBodyBytes) throw new SessionError("resource_exhausted");
    if (noBody) throw new Error("unexpected proxy response body");
    if (remaining !== undefined) {
      remaining -= BigInt(length);
      if (remaining < 0n) throw new Error("proxy content length mismatch");
    }
    if (Number.isFinite(maxBodyBytes)) total += length;
    yield await reader.readExactly(length);
  }
}

function publicFailure(error: unknown): Readonly<{ status: number; code: string; message: string }> {
  if (error instanceof ProxyPolicyError) return { status: 403, code: "policy_denied", message: "proxy request denied" };
  if (error instanceof InvalidProxyPathError) return { status: 400, code: "invalid_request", message: "invalid proxy request" };
  if (error instanceof SessionError && (error.code === "resource_exhausted" || error.code === "closed" || error.code === "going_away")) {
    return { status: 503, code: error.code, message: "proxy service unavailable" };
  }
  if (error instanceof SessionError && error.code === "canceled") return { status: 499, code: "canceled", message: "proxy request canceled" };
  return { status: 502, code: "operation_failed", message: "proxy request failed" };
}

export function createProxyRuntime(options: ProxyRuntimeOptions): ProxyRuntime {
  const binding = options.sessionBinding;
  const session = binding?.mode === "fixed" ? binding.session : options.session;
  if (session === null || typeof session !== "object" || typeof session.openStream !== "function") throw new TypeError("proxy runtime requires a Session");
  const inputBackingBytes = Math.max(8192,
    positiveLimit("maxBodyBytes", options.maxBodyBytes, SDK_DEFAULTS.proxy.maxBodyBytes),
    positiveLimit("maxMetadataBytes", options.maxMetadataBytes, SDK_DEFAULTS.proxy.maxMetadataBytes) + 4,
    positiveLimit("maxWsFrameBytes", options.maxWsFrameBytes, SDK_DEFAULTS.proxy.maxWsFrameBytes) + 5);
  if (!Number.isSafeInteger(inputBackingBytes) || inputBackingBytes > 0x7fffffff) throw new TypeError("proxy backing exceeds the current Stream capacity");
  const finishTimeoutMS = normalizeTimeout(options.timeoutMs) || SDK_DEFAULTS.proxy.defaultTimeoutMs;
  return createProxyRuntimeWithStreams({ ...options, session: {
    async openStream(kind, wait) {
      const current = binding?.mode === "capture_current" ? binding.controller.captureSession() : session;
      const stream = await current.openStream(kind, wait);
      try {
        return currentProxyStream(stream, { readBytes: 65536, inputBackingBytes,
          finishTimeoutMS, cleanupTimeoutMS: 5000 });
      } catch (error) { await stream.reset().catch(() => undefined); throw error; }
    },
  } });
}

/** @internal Application framing shared with local bridge and policy fixtures. */
export interface ProxyStreamSource {
  openStream(kind: string, options?: OperationOptions & Readonly<{ metadata?: StreamMetadata }>): Promise<ProxyStream>;
}

/** @internal The public entry point always supplies the current Stream owner. */
export function createProxyRuntimeWithStreams(options: Omit<ProxyRuntimeOptions, "session"> & Readonly<{ session: ProxyStreamSource }>): ProxyRuntime {
  if (options.session === null || typeof options.session !== "object" || typeof options.session.openStream !== "function") {
    throw new TypeError("proxy runtime requires a Session");
  }
  const maxMetadataBytes = positiveLimit("maxMetadataBytes", options.maxMetadataBytes, SDK_DEFAULTS.proxy.maxMetadataBytes);
  const maxChunkBytes = positiveLimit("maxChunkBytes", options.maxChunkBytes, SDK_DEFAULTS.proxy.maxChunkBytes);
  const maxBodyBytes = positiveLimit("maxBodyBytes", options.maxBodyBytes, SDK_DEFAULTS.proxy.maxBodyBytes);
  const maxWsFrameBytes = positiveLimit("maxWsFrameBytes", options.maxWsFrameBytes, SDK_DEFAULTS.proxy.maxWsFrameBytes);
  const maxWsBufferedAmountBytes = positiveLimit("maxWsBufferedAmountBytes", options.maxWsBufferedAmountBytes, DEFAULT_MAX_WS_BUFFERED_AMOUNT_BYTES);
  const maxConcurrentHttpStreams = strictlyPositiveLimit("maxConcurrentHttpStreams", options.maxConcurrentHttpStreams, DEFAULT_MAX_CONCURRENT_HTTP_STREAMS);
  const maxQueuedHttpRequests = positiveLimit("maxQueuedHttpRequests", options.maxQueuedHttpRequests, DEFAULT_MAX_QUEUED_HTTP_REQUESTS);
  const maxQueuedHttpBodyBytes = positiveLimit("maxQueuedHttpBodyBytes", options.maxQueuedHttpBodyBytes, DEFAULT_MAX_QUEUED_HTTP_BODY_BYTES);
  const maxConcurrentEventStreams = strictlyPositiveLimit("maxConcurrentEventStreams", options.maxConcurrentEventStreams, Math.max(1, Math.min(16, Math.floor(maxConcurrentHttpStreams * 2 / 3))));
  if (maxConcurrentEventStreams > maxConcurrentHttpStreams) throw new TypeError("event streams exceed HTTP concurrency");
  const eventStreamIdleTimeoutMs = strictlyPositiveLimit("eventStreamIdleTimeoutMs", options.eventStreamIdleTimeoutMs, 45_000);
  const timeoutMs = normalizeTimeout(options.timeoutMs);
  const pathPolicy = normalizePathPolicy(options.pathPolicy);
  const externalOrigin = normalizeOrigin(options.externalOrigin);
  const runtimeRegistrationToken = normalizeToken(options.runtimeRegistrationToken);
  const requestExtra = normalizeHeaderNames(options.extraRequestHeaders);
  const responseExtra = normalizeHeaderNames(options.extraResponseHeaders);
  const webSocketExtra = normalizeHeaderNames(options.extraWebSocketHeaders);
  const admission = new StreamAdmission(maxConcurrentHttpStreams, maxQueuedHttpRequests, maxQueuedHttpBodyBytes);
  let disposed = false;
  let activeEvents = 0;
  const active = new Set<AbortController>();
  const lifetime = new AbortController();

  const register = () => void ensureServiceWorkerRuntimeRegistered({
    timeoutMs: 2_000,
    ...(runtimeRegistrationToken === undefined ? {} : { runtimeRegistrationToken }),
  }).catch(() => undefined);

  const serviceWorker = globalThis.navigator?.serviceWorker;
  if (options.registerServiceWorkerBridge !== false) {
    serviceWorker?.addEventListener("controllerchange", register); register();
  }
  let serviceWorkerBridge: Readonly<{ dispose(): void }> | undefined;

  // One transaction owns admission, framing, cancellation and response backpressure
  // for direct fetch and both browser bridges. It never reconnects a request.
  async function execute(request: ProxyFetchRequest, signal?: AbortSignal, preparedPermit?: StreamPermit, control = false): Promise<Response> {
    let release: StreamPermit | undefined = preparedPermit;
    let adopted = false;
    const prepared = (() => {
      try {
        if (disposed) throw new SessionError("closed");
        const path = normalizePath(request.path);
        if (!control) enforcePathPolicy("http", path, pathPolicy);
        else if (path !== PROXY_CREDENTIAL_CONTROL_PATH || request.method !== "POST") throw new Error("credential_control_invalid");
        const requestFacts = inspectProxyHeaders(request.headers);
        if (requestFacts.transferEncoding) throw new Error("structured request has transfer coding");
        const headers = filterHeaders(requestFacts, BASE_REQUEST_HEADERS, requestExtra);
        const capturedAssociation = proxyRequestAssociation(request);
        if (capturedAssociation?.signal !== undefined) signal = signal === undefined ? capturedAssociation.signal : AbortSignal.any([signal, capturedAssociation.signal]);
        const credentialContext = control ? undefined : capturedAssociation === undefined ? options.credentialContext?.() : capturedAssociation.context;
        const checkAssociation = (): void => {
          if (!control && credentialContext !== options.credentialContext?.()) throw new Error("surface_publication_fenced");
        };
        checkAssociation();
        if (credentialContext !== undefined) {
          if (requestFacts.fields.some(field => ["cookie", "authorization", "x-flowersec-credential-context"].includes(field.name))) throw new Error("credential_conflict");

        }
        const eventRequested = headers.some(({ name, value }) => name === "accept" && acceptsEventStream(value));
        if (eventRequested && activeEvents >= maxConcurrentEventStreams) throw new SessionError("resource_exhausted");
        return { path, requestFacts, headers, credentialContext, checkAssociation, eventRequested };
      } catch (error) {
        if (!adopted) release?.();
        throw error;
      }
    })();
    const { path, requestFacts, headers, credentialContext, checkAssociation, eventRequested } = prepared;
    let eventPermit = eventRequested;
    if (eventPermit) activeEvents++;
    adopted = true;
    const controller = new AbortController();
    active.add(controller);
    let stream: ProxyStream | undefined;
    let senderSettled = false, cleanupSettled = false, listenersRemoved = false;
    let reader: ProxyByteReader | undefined, disposedStream: ProxyStream | undefined;
    const releaseWhenSettled = () => { if (finished && senderSettled && cleanupSettled) release?.(); };
    const removeListeners = () => {
      if (listenersRemoved) return;
      listenersRemoved = true;
      signal?.removeEventListener("abort", cancel);
      controller.signal.removeEventListener("abort", onAbort);
      stream?.signal?.removeEventListener("abort", stopped);
    };
    const disposeStream = () => {
      const completed = () => {
        cleanupSettled = true; active.delete(controller);
        removeListeners();
        releaseWhenSettled();
      };
      if (stream === undefined) { completed(); return; }
      if (disposedStream === stream) return;
      disposedStream = stream; cleanupSettled = false;
      if (stream.dispose !== undefined) stream.dispose(completed); else completed();
    };
    let output: ReadableStreamDefaultController<Uint8Array> | undefined;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const releaseEvent = () => { if (eventPermit) { eventPermit = false; activeEvents--; } };
    let finishing: Promise<unknown> | undefined;
    const stopped = () => controller.abort(new SessionError("stream_reset"));
    const finish = (failure?: unknown): Promise<unknown> => {
      if (finishing !== undefined) return finishing;
      finished = true;
      finishing = Promise.resolve().then(async () => {
        try {
          if (failure !== undefined) throw failure;
          if (stream?.finish !== undefined) {
            if (reader!.bufferedBytes !== 0 || await stream.read({ signal: controller.signal }) !== null) throw new Error("proxy response has trailing bytes");
            await stream.finish({ signal: controller.signal });
          } else await stream?.close();
          output?.close();
          return undefined;
        } catch (error) {
          output?.error(error);
          await stream?.reset().catch(() => undefined);
          return error;
        } finally {
          clearTimeout(timer);
          removeListeners();
          reader?.takeBuffered(); reader = undefined;
          releaseEvent(); disposeStream();
        }
      });
      return finishing;
    };
    const cancel = () => controller.abort(new SessionError("canceled"));
    const onAbort = () => {
      if (finished) void stream?.reset().catch(() => undefined);
      else void finish(controller.signal.reason ?? new SessionError("canceled"));
    };
    const arm = (duration: number) => {
      clearTimeout(timer);
      timer = setTimeout(() => controller.abort(new SessionError("timeout")), duration);
    };
    controller.signal.addEventListener("abort", onAbort, { once: true });
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      if (signal?.aborted) cancel();
      controller.signal.throwIfAborted();
      const body = request.body === undefined ? new Uint8Array() : new Uint8Array(request.body);
      if (body.length > maxBodyBytes) throw new SessionError("resource_exhausted");
      if (requestFacts.contentLength !== undefined && requestFacts.contentLength !== BigInt(body.length)) throw new Error("request content length mismatch");
      // Persistent requests never queue behind an occupied finite-request slot.
      release ??= await admission.acquire(body.length, controller.signal, eventRequested);
      release.resizeBody(body.length);
      controller.signal.throwIfAborted();
      checkAssociation();
      arm(timeoutMs || SDK_DEFAULTS.proxy.defaultTimeoutMs);
      stream = await options.session.openStream(PROXY_HTTP_STREAM_KIND, {
        signal: controller.signal,
        metadata: createStreamMetadata({ protocol: "flowersec.proxy.http", version: 2 }),
      });
      controller.signal.throwIfAborted();
      stream.signal?.addEventListener("abort", stopped, { once: true });
      if (stream.signal?.aborted) stopped();
      reader = new ProxyByteReader(stream, { signal: controller.signal });
      const requestID = request.id.trim() === "" ? randomID() : request.id;
      const requestOrigin = externalOrigin ?? normalizeOrigin(request.externalOrigin);
      checkAssociation();
      await writeProxyFrame({ write: async (data) => await writeAll(stream!, data, { signal: controller.signal }) }, "ProxyHTTPRequest", {
        v: PROXY_WIRE_VERSION, request_id: requestID, method: request.method, path, headers,
        ...(requestOrigin === undefined ? {} : { external_origin: requestOrigin }),
        ...(timeoutMs === 0 ? {} : { timeout_ms: timeoutMs }),
        ...(credentialContext === undefined ? {} : { credential_context: credentialContext,
          credentials: request.credentials ?? "same-origin", request_origin: request.requestOrigin ?? requestOrigin }),
      });
      checkAssociation();
      await writeChunks(stream, body, maxChunkBytes, maxBodyBytes, controller.signal);
      await stream.closeWrite();
      const response = await readProxyFrame(reader, "ProxyHTTPResponse", maxMetadataBytes) as ResponseMeta;
      if (response.v !== PROXY_WIRE_VERSION || response.request_id !== requestID) throw new Error("invalid proxy response");
      if (response.ok !== true) {
        throw new SessionError(response.error?.code === "resource_exhausted" ? "resource_exhausted" : "operation_failed");
      }
      if (!Number.isInteger(response.status)) throw new Error("invalid proxy response");
      const responseFacts = inspectProxyHeaders(response.headers ?? []);
      if (responseFacts.transferEncoding) throw new Error("structured response has transfer coding");
      const headersOut = filterHeaders(responseFacts, BASE_RESPONSE_HEADERS, responseExtra);
      const persistent = eventRequested && headersOut.some(({ name, value }) => name === "content-type" && isEventStream(value));
      if (persistent) arm(eventStreamIdleTimeoutMs);
      else releaseEvent();
      const noBody = request.method === "HEAD" || [204, 205, 304].includes(response.status!);
      const chunks = readChunks(reader, maxChunkBytes, persistent ? Infinity : maxBodyBytes, responseFacts, noBody, maxMetadataBytes)[Symbol.asyncIterator]();
      controller.signal.throwIfAborted();
      const bodyStream = new ReadableStream<Uint8Array>({
        start(value) { output = value; },
        async pull(value) {
          try {
            controller.signal.throwIfAborted();
            const next = await chunks.next();
            if (finished) return;
            if (next.done) await finish();
            else {
              if (persistent) arm(eventStreamIdleTimeoutMs);
              value.enqueue(next.value);
            }
          } catch (error) { await finish(error instanceof SessionError ? error : new SessionError("operation_failed")); }
        },
        cancel() { cancel(); },
      }, { highWaterMark: 0 });
      if (noBody) {
        const next = await chunks.next();
        if (!next.done) throw new Error("unexpected proxy response body");
        const failure = await finish();
        if (failure !== undefined) throw failure;
      }
      return new Response(noBody ? null : bodyStream, {
        status: response.status!, headers: headersOut.map(({ name, value }) => [name, value]),
      });
    } catch (error) {
      // Cancellation owns the local result even when resetting the original
      // stream makes a pending read report a separate transport failure.
      const failure = controller.signal.aborted ? controller.signal.reason : error;
      await finish(failure);
      // An abort may complete admission or openStream in the same microtask.
      if (controller.signal.aborted) { await stream?.reset().catch(() => undefined); disposeStream(); }
      throw failure instanceof SessionError ? failure : new SessionError("operation_failed");
    } finally {
      senderSettled = true;
      releaseWhenSettled();
    }
  }

  async function fetchSession(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const admissionContext = options.credentialContext?.();
    if (disposed) throw new SessionError("closed");
    const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const requestSignal = AbortSignal.any([lifetime.signal, ...(signal ? [signal] : [])]);
    // Reuse the bounded request owner before materializing any upload. Do not
    // queue body producers while all actual request slots are occupied.
    const permit = await admission.acquire(0, requestSignal, true);
    let transferred = false;
    try {
      const prepared = await prepareProxyFetch(input, { ...init, signal: requestSignal }, externalOrigin, maxBodyBytes, permit);
      bindProxyRequestAssociation(prepared.request, { context: admissionContext });
      // execute validates policy before taking ownership of the original permit.
      enforcePathPolicy("http", prepared.request.path, pathPolicy);
      if (disposed || prepared.signal.aborted) throw new SessionError("canceled");
      const response = execute(prepared.request, prepared.signal, permit);
      transferred = true;
      return await response;
    } finally {
      if (!transferred) permit();
    }
  }

  function dispatchFetch(request: ProxyFetchRequest, port: MessagePort): void {
    if (proxyRequestAssociation(request) === undefined) bindProxyRequestAssociation(request, { context: options.credentialContext?.() });
    const controller = new AbortController();
    active.add(controller);
    const flowControlled = usesServiceWorkerResponseFlowControl(request) || request.headers.some(
      ({ name, value }) => name.toLowerCase() === "accept" && acceptsEventStream(value),
    );
    let credit = !flowControlled;
    let creditWake: (() => void) | undefined;
    port.onmessage = (event) => {
      if (event.data?.type === "flowersec-proxy:abort") controller.abort(new SessionError("canceled"));
      else if (event.data?.type === "flowersec-proxy:response_credit") credit = true;
      creditWake?.();
    };
    void (async () => {
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      try {
        const response = await execute(request, controller.signal);
        port.postMessage({ type: "flowersec-proxy:response_meta", status: response.status,
          headers: headersOf(response.headers) });
        reader = response.body?.getReader();
        // Runtime disposal also releases a bridge waiting for consumer credit.
        const wake = () => { controller.abort(new SessionError("canceled")); creditWake?.(); };
        const read = async () => {
          while (!credit) {
            controller.signal.throwIfAborted();
            await new Promise<void>((resolve) => { creditWake = resolve; });
          }
          controller.signal.throwIfAborted();
          credit = !flowControlled;
          return reader!.read();
        };
        const closed = reader?.closed.catch(wake);
        while (reader !== undefined) {
          const next = await read();
          if (next.done) break;
          const data = next.value.slice().buffer as ArrayBuffer;
          port.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
        }
        await closed;
        port.postMessage({ type: "flowersec-proxy:response_end" });
      } catch (error) {
        try { port.postMessage({ type: "flowersec-proxy:response_error", ...publicFailure(error) }); } catch { /* Original publication owner already sealed this port. */ }
      } finally {
        active.delete(controller);
        await reader?.cancel().catch(() => undefined);
        reader?.releaseLock();
        port.close();
      }
    })();
  }

  async function openWebSocketStream(
    input: string,
    openOptions: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {},
  ): Promise<Readonly<{ stream: ProxyStream; protocol: string }>> {
    if (disposed) throw new SessionError("closed");
    const path = normalizePath(input);
    enforcePathPolicy("websocket", path, pathPolicy);
    const credentialContext = options.credentialContext?.();
    const checkAssociation = (): void => { if (credentialContext !== options.credentialContext?.()) throw new Error("surface_publication_fenced"); };
    const controller = new AbortController();
    active.add(controller);
    const cancel = () => controller.abort(openOptions.signal?.reason ?? new SessionError("canceled"));
    const wait = { signal: controller.signal };
    let source: ProxyStream | undefined, buffered: Uint8Array<ArrayBufferLike> = new Uint8Array();
    let closing: Promise<void> | undefined, disposedStream = false, readEOF = false, sendDrained = false;
    const released = () => {
      active.delete(controller); openOptions.signal?.removeEventListener("abort", cancel);
      controller.signal.removeEventListener("abort", abort); source?.signal?.removeEventListener("abort", stopped);
    };
    const disposeStream = (onCleanup?: () => void) => {
      if (disposedStream) {
        if (onCleanup !== undefined) {
          if (source?.dispose !== undefined) source.dispose(onCleanup); else onCleanup();
        }
        return;
      }
      disposedStream = true; buffered = new Uint8Array();
      if (source?.dispose !== undefined) source.dispose(() => { released(); onCleanup?.(); });
      else { released(); onCleanup?.(); }
    };
    const reset = (): Promise<void> => {
      const current = source;
      if (current === undefined) return Promise.resolve();
      closing ??= Promise.resolve().then(async () => { try { await current.reset(); } finally { disposeStream(); } });
      return closing;
    };
    const abort = () => { void reset().catch(() => undefined); };
    const stopped = () => controller.abort(new SessionError("stream_reset"));
    controller.signal.addEventListener("abort", abort, { once: true });
    openOptions.signal?.addEventListener("abort", cancel, { once: true });
    if (openOptions.signal?.aborted) cancel();
    const timer = setTimeout(() => controller.abort(new SessionError("timeout")), timeoutMs || SDK_DEFAULTS.proxy.defaultTimeoutMs);
    let stream: ProxyStream;
    try {
      controller.signal.throwIfAborted();
      checkAssociation();
      source = await options.session.openStream(PROXY_WEBSOCKET_STREAM_KIND, {
        signal: controller.signal, metadata: createStreamMetadata({ protocol: "flowersec.proxy.websocket", version: 2 }),
      });
      if (controller.signal.aborted) { await reset().catch(() => undefined); controller.signal.throwIfAborted(); }
      source.signal?.addEventListener("abort", stopped, { once: true });
      if (source.signal?.aborted) stopped();
      const sourceWait = (options?: OperationOptions) => ({ signal: options?.signal === undefined ? controller.signal : AbortSignal.any([controller.signal, options.signal]) });
      const collectNormal = () => { if (readEOF && sendDrained) disposeStream(); };
      stream = Object.freeze({
        signal: controller.signal,
        async read(options) {
          controller.signal.throwIfAborted(); options?.signal?.throwIfAborted();
          if (buffered.length !== 0) { const bytes = buffered; buffered = new Uint8Array(); return bytes; }
          const bytes = await source!.read(sourceWait(options));
          if (bytes === null) { readEOF = true; collectNormal(); }
          return bytes;
        },
        write: (data, options) => source!.write(data, sourceWait(options)),
        closeWrite: options => source!.closeWrite(sourceWait(options)),
        ...(source.finish === undefined ? {} : { finish: async (options?: OperationOptions) => {
          await source!.finish!(sourceWait(options)); sendDrained = true; collectNormal();
        } }),
        reset,
        close: reset,
        dispose: disposeStream,
      } satisfies ProxyStream);
      const protocols = (openOptions.protocols ?? []).filter((value) => value.trim() !== "" && value === value.trim());
      const headers = filterHeaders(
        inspectProxyHeaders(protocols.length === 0 ? [] : [{ name: "sec-websocket-protocol", value: protocols.join(", ") }]),
        new Set(["sec-websocket-protocol"]),
        webSocketExtra,
      );
      const connectionID = randomID();
      checkAssociation();
      await writeProxyFrame({ write: async (data) => await writeAll(stream, data, wait) }, "ProxyWebSocketOpen", {
        v: PROXY_WIRE_VERSION,
        conn_id: connectionID,
        path,
        headers,
        ...(credentialContext === undefined ? {} : { credential_context: credentialContext,
          credentials: "include", request_origin: externalOrigin }),
      });
      const reader = new ProxyByteReader(stream, wait);
      const response = await readProxyFrame(reader, "ProxyWebSocketResponse", maxMetadataBytes) as WebSocketOpenResponse;
      if (response.v !== PROXY_WIRE_VERSION || response.conn_id !== connectionID || response.ok !== true || (response.protocol !== undefined && typeof response.protocol !== "string")) {
        throw new Error("proxy WebSocket open failed");
      }
      buffered = reader.takeBuffered();
      return Object.freeze({ stream, protocol: response.protocol ?? "" });
    } catch (error) {
      const failure = controller.signal.aborted ? controller.signal.reason : error;
      // A failed open may never assign source, so reset() has no carrier to
      // dispose. Settle the active transaction explicitly after the open
      // attempt has resolved; a late successful open still reaches reset()
      // first and releases only after its real cleanup completes.
      await reset().catch(() => undefined);
      if (source === undefined) disposeStream();
      throw failure instanceof SessionError ? failure : new SessionError("operation_failed");
    } finally { clearTimeout(timer); }
  }

  const runtime: ProxyRuntime = Object.freeze({
    limits: Object.freeze({
      maxMetadataBytes,
      maxChunkBytes,
      maxBodyBytes,
      maxWsFrameBytes,
      maxWsBufferedAmountBytes,
      maxConcurrentHttpStreams,
      maxConcurrentEventStreams,
      maxQueuedHttpRequests,
      maxQueuedHttpBodyBytes,
    }),
    fetch: fetchSession,
    dispatchFetch,
    openWebSocketStream,
    cleanupStatus: () => Object.freeze({ status: active.size === 0 ? "complete" : "pending",
      core_cleanup: active.size === 0 ? "complete" : "pending", pending_callbacks: BigInt(active.size) }),
    dispose: () => {
      if (disposed) return;
      disposed = true;
      lifetime.abort(new SessionError("closed"));
      admission.close();
      for (const controller of active) controller.abort(new SessionError("closed"));
      serviceWorker?.removeEventListener("controllerchange", register);
      serviceWorkerBridge?.dispose();
    },
  });
  registerProxyCredentialControl(runtime, async (body, signal) => execute({ id: randomID(), method: "POST",
    path: PROXY_CREDENTIAL_CONTROL_PATH, headers: [{ name: "content-type", value: "application/cbor" }],
    body: Uint8Array.from(body).buffer }, signal, undefined, true));
  if (serviceWorker !== undefined && options.registerServiceWorkerBridge !== false) {
    serviceWorkerBridge = registerProxyRuntimeServiceWorkerBridge(runtime, serviceWorker);
  }
  return runtime;
}

export type EnsureServiceWorkerRuntimeRegisteredOptions = Readonly<{
  timeoutMs?: number;
  runtimeRegistrationToken?: string;
  publicationOwnerID?: string;
  publicationOwnerEpoch?: number;
}>;

export async function ensureServiceWorkerRuntimeRegistered(
  options: EnsureServiceWorkerRuntimeRegisteredOptions = {},
): Promise<string | undefined> {
  const controller = globalThis.navigator?.serviceWorker?.controller;
  if (controller === null || controller === undefined || typeof controller.postMessage !== "function") return undefined;
  const timeoutMs = options.timeoutMs ?? 2_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 60_000) throw new TypeError("invalid runtime registration timeout");
  const token = normalizeToken(options.runtimeRegistrationToken);
  const publicationOwnerID = options.publicationOwnerID;
  const publicationOwnerEpoch = options.publicationOwnerEpoch;
  if ((publicationOwnerID === undefined) !== (publicationOwnerEpoch === undefined) ||
    publicationOwnerID !== undefined && (publicationOwnerID === "" || publicationOwnerEpoch === undefined || !Number.isSafeInteger(publicationOwnerEpoch) || publicationOwnerEpoch < 1)) {
    throw new TypeError("invalid publication owner registration");
  }
  const channel = new MessageChannel();
  return await new Promise<string | undefined>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, claim?: string): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      channel.port1.close();
      error === undefined ? resolve(claim) : reject(error);
    };
    channel.port1.onmessage = (event) => {
      if (event.data?.type !== "flowersec-proxy:register-runtime-ack") return;
      if (event.data.ok !== true || typeof event.data.owner_claim !== "string" || event.data.owner_claim === "") {
        finish(new Error("service worker runtime registration rejected"));
      } else finish(undefined, event.data.owner_claim);
    };
    channel.port1.onmessageerror = () => finish(new Error("service worker runtime registration failed"));
    const timer = timeoutMs === 0 ? undefined : setTimeout(() => finish(new Error("service worker runtime registration timed out")), timeoutMs);
    try {
      controller.postMessage({
        type: "flowersec-proxy:register-runtime",
        version: 2,
        ...(token === undefined ? {} : { token }),
        ...(publicationOwnerID === undefined ? {} : { owner_id: publicationOwnerID, owner_epoch: publicationOwnerEpoch }),
      }, [channel.port2]);
    } catch {
      finish(new Error("service worker runtime registration failed"));
    }
  });
}

function headersOf(headers: Headers): Array<{ name: string; value: string }> {
  const result: Array<{ name: string; value: string }> = [];
  headers.forEach((value, name) => result.push({ name, value }));
  return result;
}

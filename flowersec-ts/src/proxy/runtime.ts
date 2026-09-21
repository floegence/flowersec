import { prepareProxyFetch } from "./fetch.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
import { SessionError, type ByteStream } from "../public/contract.js";
import { createStreamMetadata } from "../public/streamMetadata.js";

import { InvalidProxyPathError, normalizePath, normalizePrefixes, normalizeHeaderNames, FORBIDDEN_HEADERS } from "./policy.js";
import { ProxyByteReader, writeAll } from "./stream.js";
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
const PROXY_WIRE_VERSION = 1;
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
  const candidate = pathName(path);
  const denied = kind === "websocket"
    ? [...policy.deniedPathPrefixes, ...policy.deniedWebSocketPathPrefixes]
    : policy.deniedPathPrefixes;
  if (denied.some((prefix) => candidate.startsWith(prefix))) throw new ProxyPolicyError("proxy path denied");
  const allowed = kind === "websocket" && policy.allowedWebSocketPathPrefixes.length > 0
    ? policy.allowedWebSocketPathPrefixes
    : policy.allowedPathPrefixes;
  if (allowed.length > 0 && !allowed.some((prefix) => candidate.startsWith(prefix))) {
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
const BASE_RESPONSE_HEADERS = new Set(["accept-ranges", "cache-control", "content-disposition", "content-language", "content-range", "content-type", "etag", "expires", "last-modified", "location"]);
function filterHeaders(
  input: readonly ProxyHeader[],
  base: ReadonlySet<string>,
  extra: ReadonlySet<string>,
): ProxyHeader[] {
  const result: ProxyHeader[] = [];
  for (const entry of input) {
    if (typeof entry?.name !== "string" || typeof entry?.value !== "string") continue;
    const name = entry.name.toLowerCase().trim();
    if ((!base.has(name) && !extra.has(name)) || FORBIDDEN_HEADERS.has(name) || /[\r\n]/u.test(entry.value)) continue;
    result.push(Object.freeze({ name, value: entry.value }));
  }
  return result;
}

class StreamAdmission {
  private active = 0;
  private queuedBytes = 0;
  private closed = false;
  private readonly queue: Array<Readonly<{
    bytes: number;
    signal?: AbortSignal;
    cleanup(): void;
    resolve(release: () => void): void;
    reject(error: Error): void;
  }>> = [];

  constructor(
    private readonly concurrent: number,
    private readonly queued: number,
    private readonly queuedBodyBytes: number,
  ) {}

  acquire(bytes: number, signal?: AbortSignal, noQueue = false): Promise<() => void> {
    if (this.closed) return Promise.reject(new SessionError("closed"));
    if (signal?.aborted === true) return Promise.reject(new SessionError("canceled"));
    if (this.active < this.concurrent && this.queue.length === 0) {
      this.active++;
      return Promise.resolve(this.releaseFunction());
    }
    if (noQueue || this.queue.length >= this.queued || this.queuedBytes + bytes > this.queuedBodyBytes) {
      return Promise.reject(new SessionError("resource_exhausted"));
    }
    return new Promise((resolve, reject) => {
      let cleaned = false;
      const cleanup = () => {
        if (cleaned) return;
        cleaned = true;
        signal?.removeEventListener("abort", onAbort);
      };
      const entry = {
        bytes,
        ...(signal === undefined ? {} : { signal }),
        cleanup,
        resolve: (release: () => void) => { cleanup(); resolve(release); },
        reject: (error: Error) => { cleanup(); reject(error); },
      };
      const onAbort = () => {
        const index = this.queue.indexOf(entry);
        if (index < 0) return;
        this.queue.splice(index, 1);
        this.queuedBytes -= bytes;
        entry.reject(new SessionError("canceled"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.queue.push(entry);
      this.queuedBytes += bytes;
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const entry of this.queue.splice(0)) entry.reject(new SessionError("closed"));
    this.queuedBytes = 0;
  }

  private releaseFunction(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active--;
      this.drain();
    };
  }

  private drain(): void {
    while (!this.closed && this.active < this.concurrent && this.queue.length > 0) {
      const entry = this.queue.shift()!;
      this.queuedBytes -= entry.bytes;
      if (entry.signal?.aborted === true) {
        entry.reject(new SessionError("canceled"));
        continue;
      }
      this.active++;
      entry.resolve(this.releaseFunction());
    }
  }
}

async function writeChunks(stream: ByteStream, body: Uint8Array, chunkBytes: number, maxBodyBytes: number, signal: AbortSignal): Promise<void> {
  if (body.length > maxBodyBytes) throw new SessionError("resource_exhausted");
  for (let offset = 0; offset < body.length; offset += chunkBytes) {
    const chunk = body.subarray(offset, Math.min(body.length, offset + chunkBytes));
    await writeAll(stream, u32be(chunk.length), { signal });
    await writeAll(stream, chunk, { signal });
  }
  await writeAll(stream, u32be(0), { signal });
}

async function* readChunks(reader: ProxyByteReader, maxChunkBytes: number, maxBodyBytes: number): AsyncGenerator<Uint8Array> {
  let total = 0;
  while (true) {
    const length = readU32be(await reader.readExactly(4), 0);
    if (length === 0) return;
    if (length > maxChunkBytes || total + length > maxBodyBytes) throw new SessionError("resource_exhausted");
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
  if (options.session === null || typeof options.session !== "object" || typeof options.session.openStream !== "function") {
    throw new TypeError("proxy runtime requires a Session");
  }
  const maxJsonFrameBytes = positiveLimit("maxJsonFrameBytes", options.maxJsonFrameBytes, SDK_DEFAULTS.proxy.maxJsonFrameBytes);
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
  serviceWorker?.addEventListener("controllerchange", register);
  register();
  let serviceWorkerBridge: Readonly<{ dispose(): void }> | undefined;

  // One transaction owns admission, framing, cancellation and response backpressure
  // for direct fetch and both browser bridges. It never reconnects a request.
  async function execute(request: ProxyFetchRequest, signal?: AbortSignal): Promise<Response> {
    if (disposed) throw new SessionError("closed");
    const path = normalizePath(request.path);
    enforcePathPolicy("http", path, pathPolicy);
    const headers = filterHeaders(request.headers, BASE_REQUEST_HEADERS, requestExtra);
    const eventRequested = headers.some(({ name, value }) => name === "accept" && acceptsEventStream(value));
    if (eventRequested && activeEvents >= maxConcurrentEventStreams) throw new SessionError("resource_exhausted");
    let eventPermit = eventRequested;
    if (eventPermit) activeEvents++;
    const controller = new AbortController();
    active.add(controller);
    let stream: ByteStream | undefined;
    let release: (() => void) | undefined;
    let output: ReadableStreamDefaultController<Uint8Array> | undefined;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const releaseEvent = () => { if (eventPermit) { eventPermit = false; activeEvents--; } };
    const finish = (error?: unknown) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancel);
      controller.signal.removeEventListener("abort", onAbort);
      active.delete(controller);
      releaseEvent();
      release?.();
      if (error !== undefined) {
        output?.error(error);
        void stream?.reset().catch(() => undefined);
      } else {
        output?.close();
        void stream?.close().catch(() => undefined);
      }
    };
    const cancel = () => controller.abort(new SessionError("canceled"));
    const onAbort = () => finish(controller.signal.reason ?? new SessionError("canceled"));
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
      // Persistent requests never queue behind an occupied finite-request slot.
      release = await admission.acquire(body.length, controller.signal, eventRequested);
      controller.signal.throwIfAborted();
      arm(timeoutMs || SDK_DEFAULTS.proxy.defaultTimeoutMs);
      stream = await options.session.openStream(PROXY_HTTP_STREAM_KIND, {
        signal: controller.signal,
        metadata: createStreamMetadata({ protocol: "flowersec.proxy.http", version: 2 }),
      });
      controller.signal.throwIfAborted();
      const reader = new ProxyByteReader(stream, { signal: controller.signal });
      const requestID = request.id.trim() === "" ? randomID() : request.id;
      const requestOrigin = externalOrigin ?? normalizeOrigin(request.externalOrigin);
      await writeJsonFrame({ write: async (data) => await writeAll(stream!, data, { signal: controller.signal }) }, {
        v: PROXY_WIRE_VERSION, request_id: requestID, method: request.method.toUpperCase(), path, headers,
        ...(requestOrigin === undefined ? {} : { external_origin: requestOrigin }),
        ...(timeoutMs === 0 ? {} : { timeout_ms: timeoutMs }),
      });
      await writeChunks(stream, body, maxChunkBytes, maxBodyBytes, controller.signal);
      const response = await readJsonFrame(reader, maxJsonFrameBytes) as ResponseMeta;
      if (response.v !== PROXY_WIRE_VERSION || response.request_id !== requestID) throw new Error("invalid proxy response");
      if (response.ok !== true) {
        throw new SessionError(response.error?.code === "resource_exhausted" ? "resource_exhausted" : "operation_failed");
      }
      if (!Number.isInteger(response.status)) throw new Error("invalid proxy response");
      const headersOut = filterHeaders(response.headers ?? [], BASE_RESPONSE_HEADERS, responseExtra);
      const persistent = eventRequested && headersOut.some(({ name, value }) => name === "content-type" && isEventStream(value));
      if (persistent) arm(eventStreamIdleTimeoutMs);
      else releaseEvent();
      const chunks = readChunks(reader, maxChunkBytes, persistent ? Infinity : maxBodyBytes)[Symbol.asyncIterator]();
      controller.signal.throwIfAborted();
      const bodyStream = new ReadableStream<Uint8Array>({
        start(value) { output = value; },
        async pull(value) {
          try {
            controller.signal.throwIfAborted();
            const next = await chunks.next();
            if (finished) return;
            if (next.done) finish();
            else {
              if (persistent) arm(eventStreamIdleTimeoutMs);
              value.enqueue(next.value);
            }
          } catch (error) { finish(error instanceof SessionError ? error : new SessionError("operation_failed")); }
        },
        cancel() { cancel(); },
      }, { highWaterMark: 0 });
      const noBody = request.method.toUpperCase() === "HEAD" || [204, 205, 304].includes(response.status!);
      if (noBody) {
        const next = await chunks.next();
        if (!next.done) throw new Error("unexpected proxy response body");
        finish();
      }
      return new Response(noBody ? null : bodyStream, {
        status: response.status!, headers: headersOut.map(({ name, value }) => [name, value]),
      });
    } catch (error) {
      finish(error);
      // An abort may complete admission or openStream in the same microtask.
      release?.();
      if (controller.signal.aborted) await stream?.reset().catch(() => undefined);
      throw error instanceof SessionError ? error : new SessionError("operation_failed");
    }
  }

  async function fetchSession(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (disposed) throw new SessionError("closed");
    const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    const prepared = await prepareProxyFetch(input, { ...init,
      signal: AbortSignal.any([lifetime.signal, ...(signal ? [signal] : [])]),
    }, externalOrigin, maxBodyBytes);
    return execute(prepared.request, prepared.signal);
  }

  function dispatchFetch(request: ProxyFetchRequest, port: MessagePort): void {
    const controller = new AbortController();
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
          headers: Array.from(response.headers, ([name, value]) => ({ name, value })) });
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
        port.postMessage({ type: "flowersec-proxy:response_error", ...publicFailure(error) });
      } finally {
        await reader?.cancel().catch(() => undefined);
        reader?.releaseLock();
        port.close();
      }
    })();
  }

  async function openWebSocketStream(
    input: string,
    openOptions: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {},
  ): Promise<Readonly<{ stream: ByteStream; protocol: string }>> {
    if (disposed) throw new SessionError("closed");
    const path = normalizePath(input);
    enforcePathPolicy("websocket", path, pathPolicy);
    const stream = await options.session.openStream(PROXY_WEBSOCKET_STREAM_KIND, {
      ...(openOptions.signal === undefined ? {} : { signal: openOptions.signal }),
      metadata: createStreamMetadata({ protocol: "flowersec.proxy.websocket", version: 2 }),
    });
    try {
      const protocols = (openOptions.protocols ?? []).filter((value) => value.trim() !== "" && value === value.trim());
      const headers = filterHeaders(
        protocols.length === 0 ? [] : [{ name: "sec-websocket-protocol", value: protocols.join(", ") }],
        new Set(["sec-websocket-protocol"]),
        webSocketExtra,
      );
      await writeJsonFrame({ write: async (data) => await writeAll(stream, data, openOptions.signal === undefined ? {} : { signal: openOptions.signal }) }, {
        v: PROXY_WIRE_VERSION,
        conn_id: randomID(),
        path,
        headers,
      });
      const response = await readJsonFrame(new ProxyByteReader(stream, openOptions.signal === undefined ? {} : { signal: openOptions.signal }), maxJsonFrameBytes) as WebSocketOpenResponse;
      if (response.v !== PROXY_WIRE_VERSION || response.ok !== true || (response.protocol !== undefined && typeof response.protocol !== "string")) {
        throw new Error("proxy WebSocket open failed");
      }
      return Object.freeze({ stream, protocol: response.protocol ?? "" });
    } catch (error) {
      await stream.reset().catch(() => undefined);
      throw error instanceof SessionError ? error : new SessionError("operation_failed");
    }
  }

  const runtime: ProxyRuntime = Object.freeze({
    limits: Object.freeze({
      maxJsonFrameBytes,
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
  if (serviceWorker !== undefined) {
    serviceWorkerBridge = registerProxyRuntimeServiceWorkerBridge(runtime, serviceWorker);
  }
  return runtime;
}

export type EnsureServiceWorkerRuntimeRegisteredOptions = Readonly<{
  timeoutMs?: number;
  runtimeRegistrationToken?: string;
}>;

export async function ensureServiceWorkerRuntimeRegistered(
  options: EnsureServiceWorkerRuntimeRegisteredOptions = {},
): Promise<void> {
  const controller = globalThis.navigator?.serviceWorker?.controller;
  if (controller === null || controller === undefined || typeof controller.postMessage !== "function") return;
  const timeoutMs = options.timeoutMs ?? 2_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 60_000) throw new TypeError("invalid runtime registration timeout");
  const token = normalizeToken(options.runtimeRegistrationToken);
  const channel = new MessageChannel();
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      channel.port1.close();
      error === undefined ? resolve() : reject(error);
    };
    channel.port1.onmessage = (event) => {
      if (event.data?.type !== "flowersec-proxy:register-runtime-ack") return;
      finish(event.data.ok === true ? undefined : new Error("service worker runtime registration rejected"));
    };
    channel.port1.onmessageerror = () => finish(new Error("service worker runtime registration failed"));
    const timer = timeoutMs === 0 ? undefined : setTimeout(() => finish(new Error("service worker runtime registration timed out")), timeoutMs);
    try {
      controller.postMessage({
        type: "flowersec-proxy:register-runtime",
        version: 2,
        ...(token === undefined ? {} : { token }),
      }, [channel.port2]);
    } catch {
      finish(new Error("service worker runtime registration failed"));
    }
  });
}

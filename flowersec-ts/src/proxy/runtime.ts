import { SDK_DEFAULTS } from "../defaults.js";
import { readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
import { SessionError, type ByteStream } from "../public/contract.js";
import { createStreamMetadata } from "../public/streamMetadata.js";

import { ProxyByteReader, writeAll } from "./stream.js";
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

type RuntimeFetchMessage = Readonly<{
  type: "flowersec-proxy:fetch";
  req: Readonly<{
    id?: unknown;
    method?: unknown;
    path?: unknown;
    headers?: unknown;
    external_origin?: unknown;
    response_flow_control?: unknown;
    body?: unknown;
  }>;
}>;

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

function normalizePath(input: string): string {
  if (input !== input.trim() || !input.startsWith("/") || input.startsWith("//") || /[\u0000-\u0020]/u.test(input) || input.includes("://")) {
    throw new TypeError("proxy path must be an origin-relative path");
  }
  return input;
}

function pathName(path: string): string {
  const query = path.indexOf("?");
  return query < 0 ? path : path.slice(0, query);
}

function normalizePrefixes(name: string, values: readonly string[] | undefined): readonly string[] {
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = normalizePath(raw);
    if (value.includes("?")) throw new TypeError(`${name} must not include a query`);
    if (!result.includes(value)) result.push(value);
  }
  return Object.freeze(result);
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
const FORBIDDEN_HEADERS = new Set(["authorization", "connection", "cookie", "host", "keep-alive", "proxy-authorization", "set-cookie", "transfer-encoding", "upgrade"]);

function normalizeHeaderNames(values: readonly string[] | undefined): ReadonlySet<string> {
  const result = new Set<string>();
  for (const raw of values ?? []) {
    const value = raw.toLowerCase().trim();
    if (!/^[!#$%&'*+\-.^_`|~0-9a-z]+$/u.test(value) || FORBIDDEN_HEADERS.has(value)) {
      throw new TypeError("proxy header allowlist contains a forbidden name");
    }
    result.add(value);
  }
  return result;
}

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

function parseRuntimeRequest(raw: RuntimeFetchMessage["req"]): ProxyFetchRequest {
  const headers = Array.isArray(raw.headers) ? raw.headers.filter((entry): entry is ProxyHeader =>
    typeof entry === "object" && entry !== null && typeof (entry as ProxyHeader).name === "string" && typeof (entry as ProxyHeader).value === "string") : [];
  const body = raw.body instanceof ArrayBuffer ? raw.body : undefined;
  return {
    id: typeof raw.id === "string" ? raw.id : "",
    method: typeof raw.method === "string" ? raw.method : "GET",
    path: typeof raw.path === "string" ? raw.path : "",
    headers,
    ...(typeof raw.external_origin === "string" ? { externalOrigin: raw.external_origin } : {}),
    ...(raw.response_flow_control === "chunk_credit_v2" ? { responseFlowControl: "chunk_credit_v2" as const } : {}),
    ...(body === undefined ? {} : { body }),
  };
}

class StreamAdmission {
  private active = 0;
  private queuedBytes = 0;
  private closed = false;
  private readonly queue: Array<Readonly<{
    bytes: number;
    signal?: AbortSignal;
    resolve(release: () => void): void;
    reject(error: Error): void;
  }>> = [];

  constructor(
    private readonly concurrent: number,
    private readonly queued: number,
    private readonly queuedBodyBytes: number,
  ) {}

  acquire(bytes: number, signal?: AbortSignal): Promise<() => void> {
    if (this.closed) return Promise.reject(new SessionError("closed"));
    if (signal?.aborted === true) return Promise.reject(new SessionError("canceled"));
    if (this.active < this.concurrent && this.queue.length === 0) {
      this.active++;
      return Promise.resolve(this.releaseFunction());
    }
    if (this.queue.length >= this.queued || this.queuedBytes + bytes > this.queuedBodyBytes) {
      return Promise.reject(new SessionError("resource_exhausted"));
    }
    return new Promise((resolve, reject) => {
      const entry = {
        bytes,
        ...(signal === undefined ? {} : { signal }),
        resolve,
        reject: (error: Error) => reject(error),
      };
      const onAbort = () => {
        const index = this.queue.indexOf(entry);
        if (index < 0) return;
        this.queue.splice(index, 1);
        this.queuedBytes -= bytes;
        reject(new SessionError("canceled"));
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
    total += length;
    yield await reader.readExactly(length);
  }
}

function publicFailure(error: unknown): Readonly<{ status: number; code: string; message: string }> {
  if (error instanceof ProxyPolicyError) return { status: 403, code: "policy_denied", message: "proxy request denied" };
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
  const timeoutMs = normalizeTimeout(options.timeoutMs);
  const pathPolicy = normalizePathPolicy(options.pathPolicy);
  const externalOrigin = normalizeOrigin(options.externalOrigin);
  const runtimeRegistrationToken = normalizeToken(options.runtimeRegistrationToken);
  const requestExtra = normalizeHeaderNames(options.extraRequestHeaders);
  const responseExtra = normalizeHeaderNames(options.extraResponseHeaders);
  const webSocketExtra = normalizeHeaderNames(options.extraWebSocketHeaders);
  const admission = new StreamAdmission(maxConcurrentHttpStreams, maxQueuedHttpRequests, maxQueuedHttpBodyBytes);
  let disposed = false;

  const register = () => void ensureServiceWorkerRuntimeRegistered({
    timeoutMs: 2_000,
    ...(runtimeRegistrationToken === undefined ? {} : { runtimeRegistrationToken }),
  }).catch(() => undefined);

  const serviceWorker = globalThis.navigator?.serviceWorker;
  const onMessage = (event: MessageEvent) => {
    if (event.data === null || typeof event.data !== "object" || (event.data as RuntimeFetchMessage).type !== "flowersec-proxy:fetch") return;
    const port = event.ports?.[0];
    if (port === undefined) return;
    dispatchFetch(parseRuntimeRequest((event.data as RuntimeFetchMessage).req), port);
  };
  serviceWorker?.addEventListener("message", onMessage);
  serviceWorker?.addEventListener("controllerchange", register);
  register();

  function dispatchFetch(request: ProxyFetchRequest, port: MessagePort): void {
    const controller = new AbortController();
    let stream: ByteStream | undefined;
    let release: (() => void) | undefined;
    let credit = request.responseFlowControl !== "chunk_credit_v2";
    let creditWake: (() => void) | undefined;
    port.onmessage = (event) => {
      if (event.data?.type === "flowersec-proxy:abort") {
        controller.abort();
        creditWake?.();
      } else if (event.data?.type === "flowersec-proxy:response_credit") {
        credit = true;
        creditWake?.();
      }
    };
    const waitForCredit = async () => {
      while (!credit) {
        if (controller.signal.aborted) throw new SessionError("canceled");
        await new Promise<void>((resolve) => { creditWake = resolve; });
        creditWake = undefined;
      }
      credit = request.responseFlowControl !== "chunk_credit_v2";
    };

    void (async () => {
      try {
        if (disposed) throw new SessionError("closed");
        const path = normalizePath(request.path);
        enforcePathPolicy("http", path, pathPolicy);
        const body = request.body === undefined ? new Uint8Array() : new Uint8Array(request.body);
        release = await admission.acquire(body.length, controller.signal);
        stream = await options.session.openStream(PROXY_HTTP_STREAM_KIND, {
          signal: controller.signal,
          metadata: createStreamMetadata({ protocol: "flowersec.proxy.http", version: 2 }),
        });
        const reader = new ProxyByteReader(stream, { signal: controller.signal });
        const requestID = request.id.trim() === "" ? randomID() : request.id;
        const headers = filterHeaders(request.headers, BASE_REQUEST_HEADERS, requestExtra);
        const requestOrigin = externalOrigin ?? normalizeOrigin(request.externalOrigin);
        await writeJsonFrame({ write: async (data) => await writeAll(stream!, data, { signal: controller.signal }) }, {
          v: PROXY_WIRE_VERSION,
          request_id: requestID,
          method: request.method.toUpperCase(),
          path,
          headers,
          ...(requestOrigin === undefined ? {} : { external_origin: requestOrigin }),
          ...(timeoutMs === 0 ? {} : { timeout_ms: timeoutMs }),
        });
        await writeChunks(stream, body, maxChunkBytes, maxBodyBytes, controller.signal);
        const response = await readJsonFrame(reader, maxJsonFrameBytes) as ResponseMeta;
        if (response.v !== PROXY_WIRE_VERSION || response.request_id !== requestID || response.ok !== true || !Number.isInteger(response.status)) {
          throw new Error("invalid proxy response");
        }
        const headersOut = filterHeaders(response.headers ?? [], BASE_RESPONSE_HEADERS, responseExtra);
        port.postMessage({ type: "flowersec-proxy:response_meta", status: response.status, headers: headersOut });
        const chunks = readChunks(reader, maxChunkBytes, maxBodyBytes)[Symbol.asyncIterator]();
        for (;;) {
          await waitForCredit();
          const next = await chunks.next();
          if (next.done) break;
          const chunk = next.value;
          const data = chunk.slice().buffer as ArrayBuffer;
          port.postMessage({ type: "flowersec-proxy:response_chunk", data }, [data]);
        }
        port.postMessage({ type: "flowersec-proxy:response_end" });
        await stream.close();
        stream = undefined;
      } catch (error) {
        const failure = publicFailure(error);
        port.postMessage({ type: "flowersec-proxy:response_error", ...failure });
        await stream?.reset().catch(() => undefined);
      } finally {
        release?.();
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

  return Object.freeze({
    limits: Object.freeze({
      maxJsonFrameBytes,
      maxChunkBytes,
      maxBodyBytes,
      maxWsFrameBytes,
      maxWsBufferedAmountBytes,
      maxConcurrentHttpStreams,
      maxQueuedHttpRequests,
      maxQueuedHttpBodyBytes,
    }),
    dispatchFetch,
    openWebSocketStream,
    dispose: () => {
      if (disposed) return;
      disposed = true;
      admission.close();
      serviceWorker?.removeEventListener("message", onMessage);
      serviceWorker?.removeEventListener("controllerchange", register);
    },
  });
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

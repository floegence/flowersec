import type { Client } from "../client.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { createByteReader } from "../streamio/index.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
import { AbortError, FlowersecError, isFlowersecError } from "../utils/errors.js";
import type { YamuxStream } from "../yamux/stream.js";

import { CookieJar } from "./cookieJar.js";
import {
  DEFAULT_MAX_BODY_BYTES,
  DEFAULT_MAX_CHUNK_BYTES,
  DEFAULT_MAX_WS_FRAME_BYTES,
  PROXY_KIND_HTTP1,
  PROXY_KIND_WS,
  PROXY_PROTOCOL_VERSION
} from "./constants.js";
import { filterRequestHeaders, filterResponseHeaders, filterWsOpenHeaders } from "./headerPolicy.js";
import type { Header, HttpResponseMetaV1, WsOpenRespV1 } from "./types.js";

type ProxyFetchReq = Readonly<{
  id: string;
  method: string;
  path: string;
  headers: readonly Header[];
  external_origin?: string;
  response_flow_control?: "chunk_credit_v1";
  body?: ArrayBuffer;
}>;

type ProxyFetchMsg = Readonly<{ type: "flowersec-proxy:fetch"; req: ProxyFetchReq }>;

type ProxyServiceWorkerRegisterMsg = Readonly<{ type: "flowersec-proxy:register-runtime"; token?: string }>;
type ProxyServiceWorkerRegisterAckMsg = Readonly<{ type: "flowersec-proxy:register-runtime-ack"; ok: boolean }>;

type ProxyAbortMsg = Readonly<{ type: "flowersec-proxy:abort" }>;
type ProxyResponseCreditMsg = Readonly<{ type: "flowersec-proxy:response_credit" }>;

type ProxyRespMetaMsg = Readonly<{ type: "flowersec-proxy:response_meta"; status: number; headers: Header[] }>;
type ProxyRespChunkMsg = Readonly<{ type: "flowersec-proxy:response_chunk"; data: ArrayBuffer }>;
type ProxyRespEndMsg = Readonly<{ type: "flowersec-proxy:response_end" }>;
type ProxyRespErrMsg = Readonly<{ type: "flowersec-proxy:response_error"; status: number; message: string }>;

class ProxyRuntimePolicyError extends Error {
  readonly status = 403;
}

export type ProxyRuntimeLimits = Readonly<{
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  maxWsBufferedAmountBytes: number;
  maxConcurrentHttpStreams: number;
  maxQueuedHttpRequests: number;
  maxQueuedHttpBodyBytes: number;
}>;

export type ProxyRuntime = Readonly<{
  limits: ProxyRuntimeLimits;
  dispose: () => void;
  dispatchFetch: (req: ProxyFetchReq, port: MessagePort) => void;
  openWebSocketStream: (
    path: string,
    opts?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>
  ) => Promise<Readonly<{ stream: YamuxStream; protocol: string }>>;
}>;

export type ProxyRuntimePathPolicy = Readonly<{
  allowedPathPrefixes?: readonly string[];
  deniedPathPrefixes?: readonly string[];
  allowedWebSocketPathPrefixes?: readonly string[];
  deniedWebSocketPathPrefixes?: readonly string[];
}>;

export type ProxyRuntimeOptions = Readonly<{
  client: Client;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  maxWsBufferedAmountBytes?: number;
  maxConcurrentHttpStreams?: number;
  maxQueuedHttpRequests?: number;
  maxQueuedHttpBodyBytes?: number;
  // timeoutMs is written into http_request_meta.timeout_ms (0 uses server default).
  timeoutMs?: number;
  extraRequestHeaders?: readonly string[];
  extraResponseHeaders?: readonly string[];
  extraWsHeaders?: readonly string[];
  cookieJar?: CookieJar;
  pathPolicy?: ProxyRuntimePathPolicy;
  externalOrigin?: string;
  runtimeRegistrationToken?: string;
}>;

export type EnsureServiceWorkerRuntimeRegisteredOptions = Readonly<{
  timeoutMs?: number;
  runtimeRegistrationToken?: string;
}>;

function randomB64u(bytes: number): string {
  const b = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(b);
  } else {
    for (let i = 0; i < b.length; i++) b[i] = Math.floor(Math.random() * 256);
  }
  return base64urlEncode(b);
}

function pathOnly(path: string): string {
  const p = path.trim();
  if (!p.startsWith("/")) throw new Error("path must start with /");
  if (p.startsWith("//")) throw new Error("path must not start with //");
  if (/[ \t\r\n]/.test(p)) throw new Error("path contains whitespace");
  if (p.includes("://")) throw new Error("path must not include scheme/host");
  return p;
}

function requestPathname(path: string): string {
  const q = path.indexOf("?");
  return q >= 0 ? path.slice(0, q) : path;
}

function cookiePathFromRequestPath(path: string): string {
  return requestPathname(path);
}

function normalizeTimeoutMs(timeoutMs: number | undefined): number {
  const v = Math.floor(timeoutMs ?? 0);
  if (v < 0) throw new Error("timeout_ms must be >= 0");
  return v;
}

function normalizeExternalOrigin(externalOriginRaw: string | undefined): string | undefined {
  if (typeof externalOriginRaw !== "string") return undefined;
  const externalOrigin = externalOriginRaw.trim();
  if (externalOrigin === "") return undefined;

  let parsed: URL;
  try {
    parsed = new URL(externalOrigin);
  } catch {
    throw new Error("external_origin must be an http(s) origin");
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.host === "") {
    throw new Error("external_origin must be an http(s) origin");
  }
  if (parsed.username !== "" || parsed.password !== "" || (parsed.pathname !== "" && parsed.pathname !== "/") || parsed.search !== "" || parsed.hash !== "") {
    throw new Error("external_origin must be an origin without credentials, path, query, or fragment");
  }
  return parsed.origin;
}

function normalizeOptionalToken(name: string, input: string | undefined): string | undefined {
  if (input == null) return undefined;
  const s = String(input);
  if (s === "") return undefined;
  if (s.trim() !== s || /[\s\u0000-\u001f\u007f]/.test(s)) {
    throw new Error(`${name} must not contain whitespace or control characters`);
  }
  return s;
}

function normalizePathPolicyPrefixes(name: string, input: readonly string[] | undefined): string[] {
  const out: string[] = [];
  if (input == null || input.length === 0) return out;
  for (const raw of input) {
    const s = pathOnly(String(raw ?? ""));
    if (s.includes("?")) throw new Error(`${name} must not include query`);
    if (!out.includes(s)) out.push(s);
  }
  return out;
}

function normalizePathPolicy(policy: ProxyRuntimePathPolicy | undefined): Required<ProxyRuntimePathPolicy> {
  return {
    allowedPathPrefixes: normalizePathPolicyPrefixes("pathPolicy.allowedPathPrefixes", policy?.allowedPathPrefixes),
    deniedPathPrefixes: normalizePathPolicyPrefixes("pathPolicy.deniedPathPrefixes", policy?.deniedPathPrefixes),
    allowedWebSocketPathPrefixes: normalizePathPolicyPrefixes("pathPolicy.allowedWebSocketPathPrefixes", policy?.allowedWebSocketPathPrefixes),
    deniedWebSocketPathPrefixes: normalizePathPolicyPrefixes("pathPolicy.deniedWebSocketPathPrefixes", policy?.deniedWebSocketPathPrefixes),
  };
}

function assertPathPolicyAllows(
  kind: "http" | "websocket",
  path: string,
  policy: Required<ProxyRuntimePathPolicy>
): void {
  const pathname = requestPathname(path);
  const denied = kind === "websocket" ? [...policy.deniedPathPrefixes, ...policy.deniedWebSocketPathPrefixes] : policy.deniedPathPrefixes;
  for (const prefix of denied) {
    if (pathname.startsWith(prefix)) throw new ProxyRuntimePolicyError(`${kind} path is denied by proxy runtime policy`);
  }

  const allowed =
    kind === "websocket" && policy.allowedWebSocketPathPrefixes.length > 0
      ? policy.allowedWebSocketPathPrefixes
      : policy.allowedPathPrefixes;
  if (allowed.length === 0) return;
  for (const prefix of allowed) {
    if (pathname.startsWith(prefix)) return;
  }
  throw new ProxyRuntimePolicyError(`${kind} path is not allowed by proxy runtime policy`);
}

function normalizeMaxBytes(name: string, v: number | undefined, defaultValue: number): number {
  if (v == null) return defaultValue;
  if (!Number.isFinite(v)) throw new Error(`${name} must be a finite number`);
  const n = Math.floor(v);
  if (!Number.isSafeInteger(n)) throw new Error(`${name} must be a safe integer`);
  if (n < 0) throw new Error(`${name} must be >= 0`);
  if (n === 0) return defaultValue;
  return n;
}

const DEFAULT_MAX_CONCURRENT_HTTP_STREAMS = 24;
const DEFAULT_MAX_QUEUED_HTTP_REQUESTS = 128;
const DEFAULT_MAX_QUEUED_HTTP_BODY_BYTES = 64 * (1 << 20);
const DEFAULT_MAX_WS_BUFFERED_AMOUNT_BYTES = 4 * (1 << 20);

function normalizePositiveLimit(name: string, value: number | undefined, defaultValue: number): number {
  if (value == null) return defaultValue;
  if (!Number.isFinite(value) || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function normalizeNonNegativeLimit(name: string, value: number | undefined, defaultValue: number): number {
  if (value == null) return defaultValue;
  if (!Number.isFinite(value) || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return value;
}

type AdmissionRelease = () => void;

type AdmissionWaiter = {
  readonly signal?: AbortSignal;
  readonly bodyBytes: number;
  readonly resolve: (release: AdmissionRelease) => void;
  readonly reject: (error: Error) => void;
  onAbort?: () => void;
};

class HttpStreamAdmission {
  private active = 0;
  private readonly pending: AdmissionWaiter[] = [];
  private pendingBodyBytes = 0;
  private closed = false;

  constructor(
    private readonly path: Client["path"],
    private readonly maxConcurrent: number,
    private readonly maxQueued: number,
    private readonly maxQueuedBodyBytes: number,
  ) {}

  acquire(bodyBytes: number, signal?: AbortSignal): Promise<AdmissionRelease> {
    if (this.closed) return Promise.reject(this.closedError());
    if (signal?.aborted) return Promise.reject(this.abortedError());

    if (this.active < this.maxConcurrent && this.pending.length === 0) {
      this.active++;
      return Promise.resolve(this.createRelease());
    }

    if (this.pending.length >= this.maxQueued) {
      return Promise.reject(
        new FlowersecError({
          path: this.path,
          stage: "yamux",
          code: "resource_exhausted",
          message: "proxy runtime HTTP request queue is full",
        }),
      );
    }
    if (this.pendingBodyBytes + bodyBytes > this.maxQueuedBodyBytes) {
      return Promise.reject(
        new FlowersecError({
          path: this.path,
          stage: "yamux",
          code: "resource_exhausted",
          message: "proxy runtime HTTP request body queue is full",
        }),
      );
    }

    return new Promise<AdmissionRelease>((resolve, reject) => {
      const waiter: AdmissionWaiter = {
        bodyBytes,
        resolve,
        reject,
        ...(signal === undefined ? {} : { signal }),
      };
      waiter.onAbort = () => {
        const index = this.pending.indexOf(waiter);
        if (index < 0) return;
        this.pending.splice(index, 1);
        this.pendingBodyBytes = Math.max(0, this.pendingBodyBytes - waiter.bodyBytes);
        this.cleanupWaiter(waiter);
        reject(this.abortedError());
      };
      signal?.addEventListener("abort", waiter.onAbort, { once: true });
      this.pending.push(waiter);
      this.pendingBodyBytes += bodyBytes;
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const waiter of this.pending.splice(0)) {
      this.pendingBodyBytes = Math.max(0, this.pendingBodyBytes - waiter.bodyBytes);
      this.cleanupWaiter(waiter);
      waiter.reject(this.closedError());
    }
  }

  assertOpen(): void {
    if (this.closed) throw this.closedError();
  }

  private createRelease(): AdmissionRelease {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active = Math.max(0, this.active - 1);
      this.drain();
    };
  }

  private drain(): void {
    while (!this.closed && this.active < this.maxConcurrent && this.pending.length > 0) {
      const waiter = this.pending.shift()!;
      this.pendingBodyBytes = Math.max(0, this.pendingBodyBytes - waiter.bodyBytes);
      this.cleanupWaiter(waiter);
      if (waiter.signal?.aborted) {
        waiter.reject(this.abortedError());
        continue;
      }
      this.active++;
      waiter.resolve(this.createRelease());
    }
  }

  private cleanupWaiter(waiter: AdmissionWaiter): void {
    if (waiter.onAbort != null) {
      waiter.signal?.removeEventListener("abort", waiter.onAbort);
    }
  }

  private abortedError(): AbortError {
    return new AbortError("proxy HTTP request canceled while waiting for stream admission");
  }

  private closedError(): FlowersecError {
    return new FlowersecError({
      path: this.path,
      stage: "close",
      code: "not_connected",
      message: "proxy runtime is disposed",
    });
  }
}

async function writeChunkFrames(
  stream: YamuxStream,
  body: Uint8Array,
  chunkSize: number,
  maxBodyBytes: number
): Promise<void> {
  if (maxBodyBytes > 0 && body.length > maxBodyBytes) throw new Error("request body too large");
  const n = Math.max(1, Math.floor(chunkSize));
  let off = 0;
  while (off < body.length) {
    const end = Math.min(body.length, off + n);
    const chunk = body.subarray(off, end);
    await stream.write(u32be(chunk.length));
    await stream.write(chunk);
    off = end;
  }
  await stream.write(u32be(0));
}

async function readChunkFrames(
  reader: Readonly<{ readExactly: (n: number) => Promise<Uint8Array> }>,
  maxChunkBytes: number,
  maxBodyBytes: number
): Promise<AsyncGenerator<Uint8Array>> {
  async function* gen(): AsyncGenerator<Uint8Array> {
    let total = 0;
    while (true) {
      const lenBuf = await reader.readExactly(4);
      const n = readU32be(lenBuf, 0);
      if (n === 0) return;
      if (maxChunkBytes > 0 && n > maxChunkBytes) throw new Error("response chunk too large");
      total += n;
      if (maxBodyBytes > 0 && total > maxBodyBytes) throw new Error("response body too large");
      const payload = await reader.readExactly(n);
      yield payload;
    }
  }
  return gen();
}

export function createProxyRuntime(opts: ProxyRuntimeOptions): ProxyRuntime {
  const client = opts.client;
  const cookieJar = opts.cookieJar ?? new CookieJar();

  const maxJsonFrameBytes = normalizeMaxBytes("maxJsonFrameBytes", opts.maxJsonFrameBytes, DEFAULT_MAX_JSON_FRAME_BYTES);
  const maxChunkBytes = normalizeMaxBytes("maxChunkBytes", opts.maxChunkBytes, DEFAULT_MAX_CHUNK_BYTES);
  const maxBodyBytes = normalizeMaxBytes("maxBodyBytes", opts.maxBodyBytes, DEFAULT_MAX_BODY_BYTES);
  const maxWsFrameBytes = normalizeMaxBytes("maxWsFrameBytes", opts.maxWsFrameBytes, DEFAULT_MAX_WS_FRAME_BYTES);
  const maxWsBufferedAmountBytes = normalizeMaxBytes(
    "maxWsBufferedAmountBytes",
    opts.maxWsBufferedAmountBytes,
    DEFAULT_MAX_WS_BUFFERED_AMOUNT_BYTES,
  );
  const maxConcurrentHttpStreams = normalizePositiveLimit(
    "maxConcurrentHttpStreams",
    opts.maxConcurrentHttpStreams,
    DEFAULT_MAX_CONCURRENT_HTTP_STREAMS,
  );
  const maxQueuedHttpRequests = normalizeNonNegativeLimit(
    "maxQueuedHttpRequests",
    opts.maxQueuedHttpRequests,
    DEFAULT_MAX_QUEUED_HTTP_REQUESTS,
  );
  const maxQueuedHttpBodyBytes = normalizeNonNegativeLimit(
    "maxQueuedHttpBodyBytes",
    opts.maxQueuedHttpBodyBytes,
    DEFAULT_MAX_QUEUED_HTTP_BODY_BYTES,
  );
  const httpStreamAdmission = new HttpStreamAdmission(
    client.path,
    maxConcurrentHttpStreams,
    maxQueuedHttpRequests,
    maxQueuedHttpBodyBytes,
  );

  const timeoutMs = normalizeTimeoutMs(opts.timeoutMs);

  const extraRequestHeaders = opts.extraRequestHeaders ?? [];
  const extraResponseHeaders = opts.extraResponseHeaders ?? [];
  const extraWsHeaders = opts.extraWsHeaders ?? [];
  const pathPolicy = normalizePathPolicy(opts.pathPolicy);
  const externalOriginOverride = normalizeExternalOrigin(opts.externalOrigin);
  const runtimeRegistrationToken = normalizeOptionalToken("runtimeRegistrationToken", opts.runtimeRegistrationToken);

  const registerRuntime = () => {
    void ensureServiceWorkerRuntimeRegistered({
      timeoutMs: 2_000,
      ...(runtimeRegistrationToken === undefined ? {} : { runtimeRegistrationToken }),
    }).catch(() => {
      // Best-effort: controllerchange will retry once the active Service Worker is ready.
    });
  };

  const onMessage = (ev: MessageEvent) => {
    const data = ev.data as ProxyFetchMsg | unknown;
    if (data == null || typeof data !== "object") return;
    if ((data as ProxyFetchMsg).type !== "flowersec-proxy:fetch") return;

    const msg = data as ProxyFetchMsg;
    const port = ev.ports?.[0];
    if (!port) return;
    dispatchFetch(msg.req, port);
  };

  const sw = globalThis.navigator?.serviceWorker;
  sw?.addEventListener("message", onMessage);
  sw?.addEventListener("controllerchange", registerRuntime);
  registerRuntime();

  const dispatchFetch = (req: ProxyFetchReq, port: MessagePort): void => {
    const ac = new AbortController();
    let stream: YamuxStream | null = null;
    let releaseAdmission: AdmissionRelease | null = null;
    const usesResponseCredits = req.response_flow_control === "chunk_credit_v1";
    let responseCreditAvailable = false;
    let responseCreditResolve: (() => void) | null = null;

    const wakeResponseCreditWaiter = () => {
      const resolve = responseCreditResolve;
      responseCreditResolve = null;
      resolve?.();
    };

    port.onmessage = (ev) => {
      const m = ev.data as ProxyAbortMsg | ProxyResponseCreditMsg | unknown;
      if (!m || typeof m !== "object") return;
      if ((m as ProxyAbortMsg).type === "flowersec-proxy:abort") {
        responseCreditAvailable = false;
        ac.abort("aborted");
        wakeResponseCreditWaiter();
        return;
      }
      if (usesResponseCredits && (m as ProxyResponseCreditMsg).type === "flowersec-proxy:response_credit") {
        responseCreditAvailable = true;
        wakeResponseCreditWaiter();
      }
    };

    const waitForResponseCredit = async (): Promise<void> => {
      if (!usesResponseCredits) return;
      if (ac.signal.aborted) throw new AbortError("aborted");
      while (!responseCreditAvailable) {
        if (ac.signal.aborted) throw new AbortError("aborted");
        await new Promise<void>((resolve) => {
          responseCreditResolve = resolve;
        });
      }
      if (ac.signal.aborted) throw new AbortError("aborted");
      responseCreditAvailable = false;
    };

    void (async () => {
      try {
        const path = pathOnly(req.path);
        assertPathPolicyAllows("http", path, pathPolicy);
        const requestID = req.id.trim() !== "" ? req.id : randomB64u(18);
        const externalOrigin = externalOriginOverride ?? normalizeExternalOrigin(req.external_origin);
        const body = req.body != null ? new Uint8Array(req.body) : new Uint8Array();
        if (maxBodyBytes > 0 && body.length > maxBodyBytes) throw new Error("request body too large");
        releaseAdmission = await httpStreamAdmission.acquire(body.byteLength, ac.signal);
        httpStreamAdmission.assertOpen();
        stream = await client.openStream(PROXY_KIND_HTTP1, { signal: ac.signal });
        const reader = createByteReader(stream, { signal: ac.signal });

        const filteredReqHeaders = filterRequestHeaders(req.headers, { extraAllowed: extraRequestHeaders });
        const cookieHeader = cookieJar.getCookieHeader(cookiePathFromRequestPath(path));
        const reqHeaders: Header[] = cookieHeader === "" ? filteredReqHeaders : [...filteredReqHeaders, { name: "cookie", value: cookieHeader }];

        await writeJsonFrame(stream, {
          v: PROXY_PROTOCOL_VERSION,
          request_id: requestID,
          method: req.method,
          path,
          headers: reqHeaders,
          ...(externalOrigin === undefined ? {} : { external_origin: externalOrigin }),
          timeout_ms: timeoutMs
        });

        await writeChunkFrames(stream, body, Math.min(64 * 1024, maxChunkBytes), maxBodyBytes);

        const respMeta = (await readJsonFrame(reader, maxJsonFrameBytes)) as HttpResponseMetaV1;
        if (respMeta.v !== PROXY_PROTOCOL_VERSION || respMeta.request_id !== requestID) {
          throw new Error("invalid upstream response meta");
        }
        if (!respMeta.ok) {
          const msg = respMeta.error?.message ?? "upstream error";
          port.postMessage({ type: "flowersec-proxy:response_error", status: 502, message: msg } satisfies ProxyRespErrMsg);
          try {
            stream.reset(new Error(msg));
          } catch {
            // Best-effort.
          }
          stream = null;
          return;
        }
        const status = Math.max(0, Math.floor(respMeta.status ?? 502));
        const rawHeaders = Array.isArray(respMeta.headers) ? respMeta.headers : [];
        const { passthrough, setCookie } = filterResponseHeaders(rawHeaders, { extraAllowed: extraResponseHeaders });
        cookieJar.updateFromSetCookieHeaders(setCookie, path);

        port.postMessage({ type: "flowersec-proxy:response_meta", status, headers: passthrough } satisfies ProxyRespMetaMsg);

        const chunks = await readChunkFrames(reader, maxChunkBytes, maxBodyBytes);
        for await (const chunk of chunks) {
          await waitForResponseCredit();
          if (ac.signal.aborted) throw new AbortError("aborted");
          // Always transfer an ArrayBuffer (SharedArrayBuffer is not transferable).
          const ab = chunk.slice().buffer as ArrayBuffer;
          port.postMessage({ type: "flowersec-proxy:response_chunk", data: ab } satisfies ProxyRespChunkMsg, [ab]);
        }
        port.postMessage({ type: "flowersec-proxy:response_end" } satisfies ProxyRespEndMsg);

        await stream.close();
        stream = null;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        const code = isFlowersecError(e) ? e.code : undefined;
        const status =
          e instanceof ProxyRuntimePolicyError
            ? e.status
            : code === "resource_exhausted" || code === "not_connected"
              ? 503
              : 502;
        port.postMessage({
          type: "flowersec-proxy:response_error",
          status,
          message: msg,
        } satisfies ProxyRespErrMsg);
        try {
          stream?.reset(new Error(msg));
        } catch {
          // Best-effort.
        }
      } finally {
        wakeResponseCreditWaiter();
        releaseAdmission?.();
        try {
          port.close();
        } catch {
          // Best-effort.
        }
      }
    })();
  };

  async function openWebSocketStream(
    pathRaw: string,
    wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {}
  ): Promise<Readonly<{ stream: YamuxStream; protocol: string }>> {
    const path = pathOnly(pathRaw);
    assertPathPolicyAllows("websocket", path, pathPolicy);
    const openOpts = wsOpts.signal ? { signal: wsOpts.signal } : undefined;
    const stream = await client.openStream(PROXY_KIND_WS, openOpts);
    const reader = createByteReader(stream, openOpts);

    const cookie = cookieJar.getCookieHeader(cookiePathFromRequestPath(path));
    const headers: Header[] = [];
    const protos = wsOpts.protocols?.filter((p) => p.trim() !== "") ?? [];
    if (protos.length > 0) headers.push({ name: "sec-websocket-protocol", value: protos.join(", ") });
    if (cookie !== "") headers.push({ name: "cookie", value: cookie });

    const filtered = filterWsOpenHeaders(headers, { extraAllowed: extraWsHeaders });
    await writeJsonFrame(stream, { v: PROXY_PROTOCOL_VERSION, conn_id: randomB64u(18), path, headers: filtered });

    const resp = (await readJsonFrame(reader, maxJsonFrameBytes)) as WsOpenRespV1;
    if (resp.v !== PROXY_PROTOCOL_VERSION || resp.ok !== true) {
      const msg = resp.error?.message ?? "upstream ws open failed";
      try {
        stream.reset(new Error(msg));
      } catch {
        // Best-effort.
      }
      throw new Error(msg);
    }
    return { stream, protocol: resp.protocol ?? "" };
  }

  return {
    limits: {
      maxJsonFrameBytes,
      maxChunkBytes,
      maxBodyBytes,
      maxWsFrameBytes,
      maxWsBufferedAmountBytes,
      maxConcurrentHttpStreams,
      maxQueuedHttpRequests,
      maxQueuedHttpBodyBytes,
    },
    dispatchFetch,
    openWebSocketStream,
    dispose: () => {
      httpStreamAdmission.close();
      sw?.removeEventListener("message", onMessage);
      sw?.removeEventListener("controllerchange", registerRuntime);
    }
  };
}

export async function ensureServiceWorkerRuntimeRegistered(
  opts: EnsureServiceWorkerRuntimeRegisteredOptions = {}
): Promise<void> {
  const ctl = globalThis.navigator?.serviceWorker?.controller;
  if (!ctl || typeof ctl.postMessage !== "function") return;

  const timeoutMs = Math.max(0, Math.floor(opts.timeoutMs ?? 2_000));
  const runtimeRegistrationToken = normalizeOptionalToken("runtimeRegistrationToken", opts.runtimeRegistrationToken);
  const ch = new MessageChannel();

  await new Promise<void>((resolve, reject) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const finish = (error?: unknown) => {
      if (done) return;
      done = true;
      if (timer != null) clearTimeout(timer);
      ch.port1.onmessage = null;
      ch.port1.onmessageerror = null;
      try {
        ch.port1.close();
      } catch {
        // Best-effort.
      }
      if (error == null) {
        resolve();
        return;
      }
      reject(error instanceof Error ? error : new Error(String(error)));
    };

    ch.port1.onmessage = (ev: MessageEvent) => {
      const data = ev.data as ProxyServiceWorkerRegisterAckMsg | unknown;
      if (data == null || typeof data !== "object") return;
      if ((data as ProxyServiceWorkerRegisterAckMsg).type !== "flowersec-proxy:register-runtime-ack") return;
      if ((data as ProxyServiceWorkerRegisterAckMsg).ok !== true) {
        finish(new Error("service worker runtime registration was rejected"));
        return;
      }
      finish();
    };
    ch.port1.onmessageerror = () => {
      finish(new Error("service worker runtime registration failed"));
    };

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        finish(new Error("service worker runtime registration timed out"));
      }, timeoutMs);
    }

    try {
      ctl.postMessage({
        type: "flowersec-proxy:register-runtime",
        ...(runtimeRegistrationToken === undefined ? {} : { token: runtimeRegistrationToken }),
      } satisfies ProxyServiceWorkerRegisterMsg, [ch.port2]);
    } catch (error) {
      finish(error);
    }
  });
}

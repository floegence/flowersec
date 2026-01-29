import type { Client } from "../client.js";
import { DEFAULT_MAX_JSON_FRAME_BYTES, readJsonFrame, writeJsonFrame } from "../framing/jsonframe.js";
import { createByteReader } from "../streamio/index.js";
import { base64urlEncode } from "../utils/base64url.js";
import { readU32be, u32be } from "../utils/bin.js";
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
  body?: ArrayBuffer;
}>;

type ProxyFetchMsg = Readonly<{ type: "flowersec-proxy:fetch"; req: ProxyFetchReq }>;

type ProxyServiceWorkerRegisterMsg = Readonly<{ type: "flowersec-proxy:register-runtime" }>;

type ProxyAbortMsg = Readonly<{ type: "flowersec-proxy:abort" }>;

type ProxyRespMetaMsg = Readonly<{ type: "flowersec-proxy:response_meta"; status: number; headers: Header[] }>;
type ProxyRespChunkMsg = Readonly<{ type: "flowersec-proxy:response_chunk"; data: ArrayBuffer }>;
type ProxyRespEndMsg = Readonly<{ type: "flowersec-proxy:response_end" }>;
type ProxyRespErrMsg = Readonly<{ type: "flowersec-proxy:response_error"; status: number; message: string }>;

export type ProxyRuntimeLimits = Readonly<{
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
}>;

export type ProxyRuntime = Readonly<{
  cookieJar: CookieJar;
  limits: ProxyRuntimeLimits;
  dispose: () => void;
  openWebSocketStream: (
    path: string,
    opts?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>
  ) => Promise<Readonly<{ stream: YamuxStream; protocol: string }>>;
}>;

export type ProxyRuntimeOptions = Readonly<{
  client: Client;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  // timeoutMs is written into http_request_meta.timeout_ms (0 uses server default).
  timeoutMs?: number;
  extraRequestHeaders?: readonly string[];
  extraResponseHeaders?: readonly string[];
  extraWsHeaders?: readonly string[];
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

function cookiePathFromRequestPath(path: string): string {
  const q = path.indexOf("?");
  return q >= 0 ? path.slice(0, q) : path;
}

function normalizeTimeoutMs(timeoutMs: number | undefined): number {
  const v = Math.floor(timeoutMs ?? 0);
  if (v < 0) throw new Error("timeout_ms must be >= 0");
  return v;
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
  const cookieJar = new CookieJar();

  const maxJsonFrameBytes = normalizeMaxBytes("maxJsonFrameBytes", opts.maxJsonFrameBytes, DEFAULT_MAX_JSON_FRAME_BYTES);
  const maxChunkBytes = normalizeMaxBytes("maxChunkBytes", opts.maxChunkBytes, DEFAULT_MAX_CHUNK_BYTES);
  const maxBodyBytes = normalizeMaxBytes("maxBodyBytes", opts.maxBodyBytes, DEFAULT_MAX_BODY_BYTES);
  const maxWsFrameBytes = normalizeMaxBytes("maxWsFrameBytes", opts.maxWsFrameBytes, DEFAULT_MAX_WS_FRAME_BYTES);

  const timeoutMs = normalizeTimeoutMs(opts.timeoutMs);

  const extraRequestHeaders = opts.extraRequestHeaders ?? [];
  const extraResponseHeaders = opts.extraResponseHeaders ?? [];
  const extraWsHeaders = opts.extraWsHeaders ?? [];

  const registerRuntime = () => {
    try {
      const ctl = globalThis.navigator?.serviceWorker?.controller;
      ctl?.postMessage({ type: "flowersec-proxy:register-runtime" } satisfies ProxyServiceWorkerRegisterMsg);
    } catch {
      // Best-effort: runtime can still work if SW picks it via matchAll().
    }
  };

  const onMessage = (ev: MessageEvent) => {
    const data = ev.data as ProxyFetchMsg | unknown;
    if (data == null || typeof data !== "object") return;
    if ((data as ProxyFetchMsg).type !== "flowersec-proxy:fetch") return;

    const msg = data as ProxyFetchMsg;
    const port = ev.ports?.[0];
    if (!port) return;
    void handleFetch(msg.req, port);
  };

  const sw = globalThis.navigator?.serviceWorker;
  sw?.addEventListener("message", onMessage);
  sw?.addEventListener("controllerchange", registerRuntime);
  registerRuntime();

  async function handleFetch(req: ProxyFetchReq, port: MessagePort): Promise<void> {
    const ac = new AbortController();
    let stream: YamuxStream | null = null;
    port.onmessage = (ev) => {
      const m = ev.data as ProxyAbortMsg | unknown;
      if (m && typeof m === "object" && (m as ProxyAbortMsg).type === "flowersec-proxy:abort") {
        ac.abort("aborted");
      }
    };

    try {
      const path = pathOnly(req.path);
      const requestID = req.id.trim() !== "" ? req.id : randomB64u(18);
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
        timeout_ms: timeoutMs
      });

      const body = req.body != null ? new Uint8Array(req.body) : new Uint8Array();
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
      cookieJar.updateFromSetCookieHeaders(setCookie);

      port.postMessage({ type: "flowersec-proxy:response_meta", status, headers: passthrough } satisfies ProxyRespMetaMsg);

      const chunks = await readChunkFrames(reader, maxChunkBytes, maxBodyBytes);
      for await (const chunk of chunks) {
        // Always transfer an ArrayBuffer (SharedArrayBuffer is not transferable).
        const ab = chunk.slice().buffer as ArrayBuffer;
        port.postMessage({ type: "flowersec-proxy:response_chunk", data: ab } satisfies ProxyRespChunkMsg, [ab]);
      }
      port.postMessage({ type: "flowersec-proxy:response_end" } satisfies ProxyRespEndMsg);

      await stream.close();
      stream = null;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      port.postMessage({ type: "flowersec-proxy:response_error", status: 502, message: msg } satisfies ProxyRespErrMsg);
      try {
        stream?.reset(new Error(msg));
      } catch {
        // Best-effort.
      }
    } finally {
      try {
        port.close();
      } catch {
        // Best-effort.
      }
    }
  }

  async function openWebSocketStream(
    pathRaw: string,
    wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {}
  ): Promise<Readonly<{ stream: YamuxStream; protocol: string }>> {
    const path = pathOnly(pathRaw);
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
    cookieJar,
    limits: { maxJsonFrameBytes, maxChunkBytes, maxBodyBytes, maxWsFrameBytes },
    openWebSocketStream,
    dispose: () => {
      sw?.removeEventListener("message", onMessage);
      sw?.removeEventListener("controllerchange", registerRuntime);
    }
  };
}

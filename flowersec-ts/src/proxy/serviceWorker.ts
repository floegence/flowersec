import { brotliWorkerSource } from "../generated/brotliWorker.js";
import { decodeBrotliBody, type BrotliDecoder } from "./brotliBody.js";
import { normalizePath } from "./policy.js";

export type ProxyServiceWorkerPassthroughOptions = Readonly<{
  paths?: readonly string[];
  prefixes?: readonly string[];
}>;

export type ProxyServiceWorkerInjectHTMLOptions = Readonly<{
  mode?: "inline_module" | "external_script" | "external_module";
  proxyModuleUrl?: string;
  scriptUrl?: string;
  runtimeGlobal?: string;
  excludePathPrefixes?: readonly string[];
  stripValidatorHeaders?: boolean;
  setNoStore?: boolean;
}>;

export type ProxyServiceWorkerScriptOptions = Readonly<{
  sameOriginOnly?: boolean;
  maxRequestBodyBytes?: number;
  maxEncodedBodyBytes?: number;
  maxResponseChunkBytes?: number;
  maxInjectHTMLBytes?: number;
  maxDecodedBodyBytes?: number;
  responseMetadataTimeoutMs?: number;
  responseBodyInactivityTimeoutMs?: number;
  passthrough?: ProxyServiceWorkerPassthroughOptions;
  proxyPathPrefix?: string;
  stripProxyPathPrefix?: boolean;
  injectHTML?: ProxyServiceWorkerInjectHTMLOptions;
  forwardFetchMessageTypes?: readonly string[];
  windowTarget?: "registered_runtime" | "request_client";
  windowClientMessageType?: string;
  runtimeRegistrationToken?: string;
  runtimeClientPathPrefix?: string;
  conflictHints?: Readonly<{ keepScriptPathSuffixes?: readonly string[] }>;
}>;

type ServiceWorkerConfig = Readonly<{
  sameOriginOnly: boolean;
  maxRequestBodyBytes: number;
  maxEncodedBodyBytes: number;
  maxResponseChunkBytes: number;
  maxInjectHTMLBytes: number;
  maxDecodedBodyBytes: number;
  responseMetadataTimeoutMs: number;
  responseBodyInactivityTimeoutMs: number;
  passthroughPaths: readonly string[];
  passthroughPrefixes: readonly string[];
  proxyPathPrefix: string;
  stripProxyPathPrefix: boolean;
  injectHTML: ProxyServiceWorkerInjectHTMLOptions | null;
  forwardFetchMessageTypes: readonly string[];
  windowTarget: "registered_runtime" | "request_client";
  windowClientMessageType: string;
  runtimeRegistrationToken: string;
  runtimeClientPathPrefix: string;
  conflictHints: readonly string[];
}>;

function strings(name: string, values: readonly string[] | undefined, max = 64): readonly string[] {
  if ((values?.length ?? 0) > max) throw new TypeError(`${name} contains too many entries`);
  const result: string[] = [];
  for (const raw of values ?? []) {
    if (typeof raw !== "string" || raw === "" || raw !== raw.trim() || /[\u0000-\u001f\u007f]/u.test(raw)) {
      throw new TypeError(`${name} contains an invalid entry`);
    }
    if (!result.includes(raw)) result.push(raw);
  }
  return Object.freeze(result);
}

function bounded(name: string, value: number | undefined, fallback: number, maximum: number): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0 || result > maximum) throw new TypeError(`${name} is invalid`);
  return result;
}

function optionalBounded(name: string, value: number | undefined, maximum: number): number {
  const result = value ?? 0;
  if (!Number.isSafeInteger(result) || result < 0 || result > maximum) throw new TypeError(`${name} is invalid`);
  return result;
}

function token(name: string, value: string | undefined, fallback = ""): string {
  const result = value ?? fallback;
  if (result !== result.trim() || /[\u0000-\u0020\u007f]/u.test(result) || result.length > 512) throw new TypeError(`${name} is invalid`);
  return result;
}

function paths(name: string, values: readonly string[] | undefined): readonly string[] {
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = normalizePath(raw);
    if (value.includes("?")) throw new TypeError(`${name} must not include a query`);
    if (!result.includes(value)) result.push(value);
  }
  return Object.freeze(result);
}

function pathPrefix(name: string, value: string | undefined): string {
  if (value === undefined || value === "") return "";
  const normalized = normalizePath(value);
  if (normalized.includes("?")) throw new TypeError(`${name} must not include a query`);
  return normalized;
}

function normalizeOptions(options: ProxyServiceWorkerScriptOptions): ServiceWorkerConfig {
  const proxyPathPrefix = pathPrefix("proxyPathPrefix", options.proxyPathPrefix);
  const inject = options.injectHTML;
  if (inject !== undefined) {
    const mode = inject.mode ?? "inline_module";
    if (mode === "inline_module" && token("injectHTML.proxyModuleUrl", inject.proxyModuleUrl) === "") {
      throw new TypeError("inline HTML injection requires proxyModuleUrl");
    }
    if (mode !== "inline_module" && token("injectHTML.scriptUrl", inject.scriptUrl) === "") {
      throw new TypeError("external HTML injection requires scriptUrl");
    }
  }
  return Object.freeze({
    sameOriginOnly: options.sameOriginOnly ?? true,
    maxRequestBodyBytes: bounded("maxRequestBodyBytes", options.maxRequestBodyBytes, 64 * 1024 * 1024, 256 * 1024 * 1024),
    maxEncodedBodyBytes: bounded("maxEncodedBodyBytes", options.maxEncodedBodyBytes, 64 * 1024 * 1024, 256 * 1024 * 1024),
    maxResponseChunkBytes: bounded("maxResponseChunkBytes", options.maxResponseChunkBytes, 256 * 1024, 4 * 1024 * 1024),
    maxDecodedBodyBytes: bounded("maxDecodedBodyBytes", options.maxDecodedBodyBytes, 64 * 1024 * 1024, 256 * 1024 * 1024),
    maxInjectHTMLBytes: bounded("maxInjectHTMLBytes", options.maxInjectHTMLBytes, 8 * 1024 * 1024, 32 * 1024 * 1024),
    responseMetadataTimeoutMs: bounded("responseMetadataTimeoutMs", options.responseMetadataTimeoutMs, 10_000, 300_000),
    responseBodyInactivityTimeoutMs: optionalBounded("responseBodyInactivityTimeoutMs", options.responseBodyInactivityTimeoutMs, 300_000),
    passthroughPaths: paths("passthrough.paths", options.passthrough?.paths),
    passthroughPrefixes: paths("passthrough.prefixes", options.passthrough?.prefixes),
    proxyPathPrefix,
    stripProxyPathPrefix: options.stripProxyPathPrefix ?? false,
    injectHTML: inject === undefined ? null : Object.freeze({
      ...inject,
      mode: inject.mode ?? "inline_module",
      excludePathPrefixes: paths("injectHTML.excludePathPrefixes", inject.excludePathPrefixes),
    }),
    forwardFetchMessageTypes: strings("forwardFetchMessageTypes", options.forwardFetchMessageTypes),
    windowTarget: options.windowTarget ?? "registered_runtime",
    windowClientMessageType: token("windowClientMessageType", options.windowClientMessageType, "flowersec-proxy:fetch"),
    runtimeRegistrationToken: token("runtimeRegistrationToken", options.runtimeRegistrationToken),
    runtimeClientPathPrefix: pathPrefix("runtimeClientPathPrefix", options.runtimeClientPathPrefix),
    conflictHints: strings("conflictHints.keepScriptPathSuffixes", options.conflictHints?.keepScriptPathSuffixes),
  });
}

function serviceWorkerMain(config: ServiceWorkerConfig, createBrotliDecoder: () => BrotliDecoder, brotliBody: typeof decodeBrotliBody): void {
  const worker = self as any;
  let runtimeClientId = "";

  const pathMatchesPrefix = (path: string, prefix: string) => {
    const pathname = path.split("?", 1)[0] ?? path;
    if (prefix === "/") return pathname.startsWith("/");
    if (prefix.endsWith("/")) return pathname.startsWith(prefix);
    return pathname === prefix || pathname.startsWith(`${prefix}/`);
  };
  const pathMatches = (path: string, values: readonly string[]) => values.some((value) => pathMatchesPrefix(path, value));
  const safeMessage = (error: unknown) => error instanceof Error && error.name === "AbortError"
    ? "proxy request canceled"
    : "proxy request failed";
  const readRequestBody = async (request: Request, limit: number): Promise<ArrayBuffer | undefined> => {
    const source = request.body;
    const declaredHeader = request.headers.get("content-length");
    let declaredLength: number | undefined;
    if (declaredHeader !== null) {
      if (!/^(?:0|[1-9][0-9]*)$/u.test(declaredHeader)) throw new TypeError("invalid proxy request content length");
      try {
        const value = BigInt(declaredHeader);
        if (value > BigInt(limit) || value > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError("proxy request body exceeds limit");
        declaredLength = Number(value);
      } catch (error) {
        if (error instanceof RangeError) throw error;
        throw new TypeError("invalid proxy request content length");
      }
    }
    if (source === null) {
      if (declaredLength !== undefined && declaredLength !== 0) throw new TypeError("proxy request body length mismatch");
      return undefined;
    }
    if (source === undefined) {
      // Do not fall back to Request.arrayBuffer(): that API can allocate an
      // unbounded temporary before the limit check. A body-bearing request
      // must expose a readable stream so this owner can enforce the cap.
      if (declaredLength === 0) return undefined;
      throw new TypeError("proxy request body unavailable");
    }
    const reader = source.getReader();
    // Reserve only the declared size (when available), or one small initial
    // slab. Growing on demand keeps a tiny upload from owning the default
    // 64 MiB budget while retaining a hard upper bound.
    let bytes = new Uint8Array(Math.min(limit, declaredLength ?? 16 * 1024));
    let total = 0;
    let pendingRead: Promise<ReadableStreamReadResult<Uint8Array>> | undefined;
    let released = false;
    let cancelRequested = false;
    let streamDone = false;
    let abortHandler: (() => void) | undefined;
    const abortError = () => new DOMException("proxy request canceled", "AbortError");
    const abort = new Promise<never>((_, reject) => {
      abortHandler = () => {
        // Reject the owner immediately. The underlying reader is canceled
        // cooperatively, and its eventual settlement releases the lock below.
        void reader.cancel().catch(() => undefined);
        reject(abortError());
      };
      request.signal.addEventListener("abort", abortHandler, { once: true });
    });
    const release = () => {
      if (released) return;
      released = true;
      try { reader.releaseLock(); } catch { /* a provider may release it first */ }
    };
    const cancel = () => {
      if (!cancelRequested) {
        cancelRequested = true;
        void reader.cancel().catch(() => undefined);
      }
      if (pendingRead === undefined) release();
      else void pendingRead.then(release, release);
    };
    try {
      for (;;) {
        if (request.signal.aborted) throw abortError();
        pendingRead = reader.read();
        const next = await Promise.race([pendingRead, abort]) as ReadableStreamReadResult<Uint8Array>;
        pendingRead = undefined;
        if (next.done) { streamDone = true; break; }
        const chunk = next.value;
        if (!(chunk instanceof Uint8Array)) throw new TypeError("proxy request body is not bytes");
        if (chunk.byteLength > limit - total) throw new RangeError("proxy request body exceeds limit");
        const required = total + chunk.byteLength;
        if (required > bytes.byteLength) {
          let capacity = Math.max(bytes.byteLength * 2, 16 * 1024, required);
          capacity = Math.min(limit, capacity);
          const grown = new Uint8Array(capacity);
          grown.set(bytes.subarray(0, total));
          bytes = grown;
        }
        bytes.set(chunk, total);
        total = required;
      }
      if (declaredLength !== undefined && total !== declaredLength) throw new TypeError("proxy request body length mismatch");
      return total === 0 ? undefined : bytes.slice(0, total).buffer;
    } finally {
      if (abortHandler !== undefined) request.signal.removeEventListener("abort", abortHandler);
      if (streamDone) release();
      else cancel();
    }
  };

  worker.addEventListener("install", (event: any) => event.waitUntil(worker.skipWaiting()));
  worker.addEventListener("activate", (event: any) => event.waitUntil(worker.clients.claim()));

  worker.addEventListener("message", (event: any) => {
    const data = event.data as Record<string, unknown> | null;
    if (data === null || typeof data !== "object") return;
    if (data.type === "flowersec-proxy:register-runtime") {
      const port = event.ports[0];
      const source = event.source as any;
      let ok = data.version === 2 && source !== null;
      if (config.runtimeRegistrationToken !== "") ok = ok && data.token === config.runtimeRegistrationToken;
      if (ok && config.runtimeClientPathPrefix !== "") {
        try {
          ok = pathMatchesPrefix(new URL(source!.url).pathname, config.runtimeClientPathPrefix);
        } catch {
          ok = false;
        }
      }
      if (ok) runtimeClientId = source!.id;
      port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok });
      port?.close();
      return;
    }
    if (!config.forwardFetchMessageTypes.includes(String(data.type ?? ""))) return;
    event.waitUntil((async () => {
      const target = runtimeClientId === "" ? null : await worker.clients.get(runtimeClientId);
      target?.postMessage(data, event.ports);
    })());
  });

  worker.addEventListener("fetch", (event: any) => {
    event.respondWith((async () => {
      const request = event.request;
      const url = new URL(request.url);
      if (config.sameOriginOnly && url.origin !== worker.location.origin) return await fetch(request);
      if (config.passthroughPaths.includes(url.pathname) || pathMatches(url.pathname, config.passthroughPrefixes)) {
        return await fetch(request);
      }

      const query = url.href.slice(url.origin.length + url.pathname.length);
      let path = url.pathname + query;
      if (config.proxyPathPrefix !== "") {
        if (!pathMatchesPrefix(url.pathname, config.proxyPathPrefix)) return await fetch(request);
        if (config.stripProxyPathPrefix) {
          const stripped = url.pathname.slice(config.proxyPathPrefix.length);
          path = (stripped.startsWith("/") ? stripped : `/${stripped}`) + query;
        }
      }

      const source = event.clientId === "" ? null : await worker.clients.get(event.clientId);
      const target = config.windowTarget === "request_client"
        ? source
        : runtimeClientId === "" ? null : await worker.clients.get(runtimeClientId);
      if (target === null) {
        if (config.windowTarget === "registered_runtime") runtimeClientId = "";
        return new Response("proxy runtime unavailable", { status: 503 });
      }

      let body: ArrayBuffer | undefined;
      if (request.signal.aborted) return new Response("proxy request canceled", { status: 499 });
      if (request.method !== "GET" && request.method !== "HEAD") {
        try {
          body = await readRequestBody(request, config.maxRequestBodyBytes);
        } catch (error) {
          if (error instanceof RangeError) return new Response("proxy request too large", { status: 413 });
          if (request.signal.aborted || error instanceof DOMException && error.name === "AbortError") return new Response("proxy request canceled", { status: 499 });
          return new Response("proxy request body unavailable", { status: 400 });
        }
      }
      const channel = new MessageChannel();
      const response = await new Promise<Response>((resolve) => {
        let metadata: Readonly<{ status: number; headers: Headers }> | null = null;
        let controller: ReadableStreamDefaultController<Uint8Array<ArrayBuffer>> | null = null;
        let finished = false;
        let remoteAbortSent = false;
        let responseCreditOutstanding = false;
        let encodedBodyBytes = 0;
        let bodyInactivityTimer: ReturnType<typeof setTimeout> | undefined;
        const abortRemote = () => {
          if (remoteAbortSent) return;
          remoteAbortSent = true;
          try { channel.port1.postMessage({ type: "flowersec-proxy:abort" }); } catch { /* Port already failed. */ }
        };
        const cleanup = () => {
          clearTimeout(metadataTimer);
          clearTimeout(bodyInactivityTimer);
          clearInterval(runtimeWatchdog);
          request.signal.removeEventListener("abort", requestAborted);
          channel.port1.close();
        };
        const finishError = (status: number, message: string, cancelRemote = false) => {
          if (finished) return;
          finished = true;
          if (cancelRemote) abortRemote();
          if (controller !== null) controller.error(new Error(message));
          else resolve(new Response(message, { status }));
          cleanup();
        };
        const requestAborted = () => finishError(499, "proxy request canceled", true);
        const sendResponseCredit = () => {
          if (finished || controller === null || responseCreditOutstanding) return;
          responseCreditOutstanding = true;
          try {
            channel.port1.postMessage({ type: "flowersec-proxy:response_credit" });
          } catch {
            responseCreditOutstanding = false;
            finishError(502, "proxy response channel failed", true);
          }
        };
        const armBodyInactivityTimer = () => {
          clearTimeout(bodyInactivityTimer);
          if (config.responseBodyInactivityTimeoutMs === 0) return;
          bodyInactivityTimer = setTimeout(
            () => finishError(504, "proxy response body timed out", true),
            config.responseBodyInactivityTimeoutMs,
          );
        };
        const metadataTimer = setTimeout(
          () => finishError(504, "proxy response timed out", true),
          config.responseMetadataTimeoutMs,
        );
        const runtimeWatchdog = setInterval(() => {
          void worker.clients.get(target.id).then((current: any) => {
            if (current !== null || finished) return;
            if (config.windowTarget === "registered_runtime") runtimeClientId = "";
            finishError(503, "proxy runtime unavailable", true);
          }).catch(() => finishError(503, "proxy runtime unavailable", true));
        }, 250);
        request.signal.addEventListener("abort", requestAborted, { once: true });
        channel.port1.onmessage = (message) => {
          const value = message.data as Record<string, unknown> | null;
          if (value === null || typeof value !== "object" || finished) return;
          if (value.type === "flowersec-proxy:response_meta") {
            if (!Number.isInteger(value.status) || (value.status as number) < 200 || (value.status as number) > 599 || metadata !== null) return finishError(502, "invalid proxy response", true);
            const headers = new Headers();
            try {
              if (!Array.isArray(value.headers)) throw new TypeError("invalid response headers");
              for (const entry of value.headers) {
                if (!entry || typeof entry.name !== "string" || typeof entry.value !== "string") throw new TypeError("invalid response header");
                headers.append(entry.name, entry.value);
              }
            } catch { return finishError(502, "invalid proxy response headers", true); }
            const nullBody = request.method === "HEAD" || [204, 205, 304].includes(value.status as number);
            const encodedLength = headers.get("content-length");
            if (encodedLength !== null) {
              if (!/^(?:0|[1-9][0-9]*)$/u.test(encodedLength)) return finishError(502, "invalid proxy content length", true);
              try {
                if (!nullBody && BigInt(encodedLength) > BigInt(config.maxEncodedBodyBytes)) return finishError(502, "proxy encoded body exceeds limit", true);
              } catch { return finishError(502, "invalid proxy content length", true); }
            }
            const decoders: (DecompressionStream | "br")[] = [];
            if (!nullBody) {
              const coding = headers.get("content-encoding");
              const formats = coding === null ? [] : coding.split(",").map(value => value.trim().toLowerCase());
              if (formats.length > 4) return finishError(502, "proxy content coding chain exceeds limit", true);
              try {
                for (const format of formats.reverse()) {
                  if (format === "identity") continue;
                  if (!["gzip", "deflate", "br"].includes(format)) throw new TypeError("unsupported content coding");
                  decoders.push(format === "br" ? "br" : new DecompressionStream(format as CompressionFormat));
                }
              } catch { return finishError(502, "unsupported proxy content coding", true); }
            }
            metadata = { status: value.status as number, headers };
            clearTimeout(metadataTimer);
            if (nullBody) {
              // HEAD/204/205/304 have no body. Do not create a decoder,
              // stream or credit window for an impossible payload.
              finished = true;
              resolve(new Response(null, { status: metadata.status, headers: metadata.headers }));
              abortRemote();
              cleanup();
              return;
            }
            armBodyInactivityTimer();
            const stream = new ReadableStream<Uint8Array<ArrayBuffer>>({
              start(valueController) {
                controller = valueController;
                sendResponseCredit();
              },
              pull() { sendResponseCredit(); },
              cancel() {
                if (finished) return;
                finished = true;
                abortRemote();
                cleanup();
              },
            });
            let decoded: ReadableStream<Uint8Array<ArrayBuffer>> = stream;
            for (const decoder of decoders) {
              if (decoder === "br") {
                decoded = brotliBody(decoded, config.maxDecodedBodyBytes, createBrotliDecoder);
                continue;
              }
              let total = 0;
              decoded = decoded.pipeThrough(decoder).pipeThrough(new TransformStream<Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>>({
                transform(chunk, output) {
                  total += chunk.byteLength;
                  if (total > config.maxDecodedBodyBytes) throw new RangeError("proxy decoded body exceeds limit");
                  output.enqueue(chunk);
                },
              }));
            }
            let presentedBytes = 0;
            decoded = decoded.pipeThrough(new TransformStream<Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>>({
              transform(chunk, output) {
                presentedBytes += chunk.byteLength;
                if (presentedBytes > config.maxDecodedBodyBytes) throw new RangeError("proxy decoded body exceeds limit");
                output.enqueue(chunk);
              },
            }));
            // Synthetic Response does not decode. This is the sole final
            // presentation boundary; origin representation metadata stays intact.
            resolve(new Response(nullBody ? null : decoded, { status: metadata.status, headers: metadata.headers }));
            return;
          }
          if (value.type === "flowersec-proxy:response_chunk") {
            if (controller === null || !(value.data instanceof ArrayBuffer)) return finishError(502, "invalid proxy response", true);
            const chunk = new Uint8Array(value.data);
            if (chunk.byteLength > config.maxResponseChunkBytes) return finishError(502, "proxy response chunk exceeds limit", true);
            if (chunk.byteLength > config.maxEncodedBodyBytes - encodedBodyBytes) return finishError(502, "proxy encoded body exceeds limit", true);
            encodedBodyBytes += chunk.byteLength;
            // A chunk consumes the outstanding credit. A pull after enqueue
            // may immediately issue the next single credit if demand remains.
            responseCreditOutstanding = false;
            try { controller.enqueue(chunk); }
            catch { return finishError(502, "proxy response body failed", true); }
            armBodyInactivityTimer();
            if ((controller.desiredSize ?? 0) > 0) sendResponseCredit();
            return;
          }
          if (value.type === "flowersec-proxy:response_end") {
            if (metadata === null || controller === null) return finishError(502, "proxy response missing metadata", true);
            finished = true;
            controller?.close();
            cleanup();
            return;
          }
          if (value.type === "flowersec-proxy:response_error") {
            const status = Number.isInteger(value.status) && (value.status as number) >= 400 && (value.status as number) <= 599
              ? value.status as number
              : 502;
            finishError(status, typeof value.message === "string" ? value.message : "proxy request failed", true);
          }
        };
        channel.port1.onmessageerror = () => finishError(502, "proxy request failed", true);
        const headers = Array.from(request.headers.entries() as Iterable<[string, string]>).map(([name, value]) => ({ name, value }));
        try {
          target.postMessage({
            type: config.windowClientMessageType,
            req: {
              id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
              method: request.method,
              path,
              headers,
              response_flow_control: "chunk_credit_v2",
              ...(body === undefined ? {} : { body }),
            },
          }, [channel.port2, ...(body === undefined ? [] : [body])]);
        } catch {
          if (config.windowTarget === "registered_runtime") runtimeClientId = "";
          finishError(503, "proxy runtime unavailable");
        }
      });

      const injection = config.injectHTML;
      if (injection === null || pathMatches(url.pathname, injection.excludePathPrefixes ?? [])) return response;
      if (request.method !== "GET" || response.status !== 200 || [...request.headers.keys()].some(name => name === "range" || name.startsWith("if-")) || (response.headers.get("cache-control") ?? "").split(",").some(value => value.trim().toLowerCase() === "no-transform")) return response;
      if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) return response;
      const htmlReader = response.body!.getReader();
      const htmlBytes = new Uint8Array(config.maxInjectHTMLBytes);
      let size = 0;
      try {
        for (;;) {
          const next = await htmlReader.read();
          if (next.done) break;
          if (next.value.byteLength > config.maxInjectHTMLBytes - size) {
            await htmlReader.cancel();
            return new Response("proxy HTML response too large", { status: 502 });
          }
          htmlBytes.set(next.value, size);
          size += next.value.byteLength;
        }
      } finally { htmlReader.releaseLock(); }
      const decoder = new TextDecoder();
      let html = decoder.decode(htmlBytes.subarray(0, size));
      const runtimeGlobal = injection.runtimeGlobal ?? "__flowersecProxyRuntime";
      let markup: string;
      if ((injection.mode ?? "inline_module") === "inline_module") {
        markup = `<script type="module">import { installWebSocketPatch, disableUpstreamServiceWorkerRegister } from ${JSON.stringify(injection.proxyModuleUrl)};const rt=globalThis[${JSON.stringify(runtimeGlobal)}];if(rt){disableUpstreamServiceWorkerRegister();installWebSocketPatch({runtime:rt});}</script>`;
      } else {
        const module = injection.mode === "external_module" ? " type=\"module\"" : "";
        markup = `<script${module} src=${JSON.stringify(injection.scriptUrl)} data-flowersec-runtime-global=${JSON.stringify(runtimeGlobal)}></script>`;
      }
      const location = html.search(/<\/head\s*>/iu);
      html = location >= 0 ? `${html.slice(0, location)}${markup}${html.slice(location)}` : `${markup}${html}`;
      const headers = new Headers(response.headers);
      for (const name of ["content-encoding", "content-length", "etag", "last-modified", "content-digest", "repr-digest", "digest", "content-md5", "content-range", "accept-ranges"]) headers.delete(name);
      if (injection.setNoStore !== false) headers.set("cache-control", "no-store");
      return new Response(html, { status: response.status, statusText: response.statusText, headers });
    })().catch((error) => new Response(safeMessage(error), { status: 502 })));
  });
}

export function createProxyServiceWorkerScript(options: ProxyServiceWorkerScriptOptions = {}): string {
  const config = normalizeOptions(options);
  return `// Generated by @floegence/flowersec-core/proxy v2\n(${serviceWorkerMain.toString()})(${JSON.stringify(config)}, ${brotliWorkerSource}, ${decodeBrotliBody.toString()});\n`;
}

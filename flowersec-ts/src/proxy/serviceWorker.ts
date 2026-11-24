import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { BodyIntake } from "./bodyIntake.js";

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
  maxInjectHTMLBytes?: number;
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
  maxInjectHTMLBytes: number;
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
  runtimeRegistrationDigest: string;
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

function normalizeOptions(options: ProxyServiceWorkerScriptOptions): ServiceWorkerConfig {
  const registrationToken = token("runtimeRegistrationToken", options.runtimeRegistrationToken);
  const proxyPathPrefix = token("proxyPathPrefix", options.proxyPathPrefix, "");
  if (proxyPathPrefix !== "" && (!proxyPathPrefix.startsWith("/") || proxyPathPrefix.startsWith("//"))) {
    throw new TypeError("proxyPathPrefix must be an origin-relative prefix");
  }
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
    maxInjectHTMLBytes: bounded("maxInjectHTMLBytes", options.maxInjectHTMLBytes, 8 * 1024 * 1024, 32 * 1024 * 1024),
    responseMetadataTimeoutMs: bounded("responseMetadataTimeoutMs", options.responseMetadataTimeoutMs, 10_000, 300_000),
    responseBodyInactivityTimeoutMs: optionalBounded("responseBodyInactivityTimeoutMs", options.responseBodyInactivityTimeoutMs, 300_000),
    passthroughPaths: strings("passthrough.paths", options.passthrough?.paths),
    passthroughPrefixes: strings("passthrough.prefixes", options.passthrough?.prefixes),
    proxyPathPrefix,
    stripProxyPathPrefix: options.stripProxyPathPrefix ?? false,
    injectHTML: inject === undefined ? null : Object.freeze({
      ...inject,
      mode: inject.mode ?? "inline_module",
      excludePathPrefixes: strings("injectHTML.excludePathPrefixes", inject.excludePathPrefixes),
    }),
    forwardFetchMessageTypes: strings("forwardFetchMessageTypes", options.forwardFetchMessageTypes),
    windowTarget: options.windowTarget ?? "request_client",
    windowClientMessageType: token("windowClientMessageType", options.windowClientMessageType, "flowersec-proxy:fetch"),
    runtimeRegistrationDigest: registrationToken && bytesToHex(sha256(new TextEncoder().encode(registrationToken))),
    runtimeClientPathPrefix: token("runtimeClientPathPrefix", options.runtimeClientPathPrefix),
    conflictHints: strings("conflictHints.keepScriptPathSuffixes", options.conflictHints?.keepScriptPathSuffixes),
  });
}

function serviceWorkerMain(config: ServiceWorkerConfig, Intake: typeof BodyIntake): void {
  const worker = self as any;
  let runtimeClientId = "";
  const registrations = new Set<string>();
  const restricted = !!(config.runtimeRegistrationDigest || config.runtimeClientPathPrefix);
  const matchesToken = async (value: unknown): Promise<boolean> => {
    if (!config.runtimeRegistrationDigest) return true;
    if (typeof value !== "string" || !value.length || value.length > 512) return false;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("") === config.runtimeRegistrationDigest;
  };
  const intake = new Intake(24, Math.max(config.maxRequestBodyBytes, 64 * 1024 * 1024));
  const shared = config.windowTarget === "registered_runtime";
  const cacheName = `flowersec-proxy-owner-v2:${worker.registration?.scope ?? worker.location.href}`;
  const ownerKey = worker.location.href;
  const ownerCache = (): Promise<Cache> => worker.caches.open(cacheName);
  let mutation: Promise<void> = Promise.resolve();
  const serialize = (operation: () => Promise<void>) => {
    const result = mutation.then(operation);
    mutation = result.catch(() => undefined);
    return result;
  };
  const storedOwner = async () => (await (await ownerCache()).match(ownerKey))?.text();
  const eligible = (client: any) => !!client?.id && (!config.runtimeClientPathPrefix || new URL(client.url).pathname.startsWith(config.runtimeClientPathPrefix));
  const confirmations = new Map<string, Promise<boolean>>();
  const confirm = (client: any): Promise<boolean> => {
    if (!eligible(client)) return Promise.resolve(false);
    const existing = confirmations.get(client.id);
    if (existing) return existing;
    if (confirmations.size >= 256) return Promise.resolve(false);
    const confirmation = new Promise<boolean>(resolve => {
      const channel = new MessageChannel();
      const finish = (ok: boolean) => { clearTimeout(timer); channel.port1.close(); resolve(ok); };
      const timer = setTimeout(() => finish(false), 2_000);
      channel.port1.onmessage = event => {
        if (event.data?.registered !== true) return finish(false);
        void matchesToken(event.data.token).then(finish, () => finish(false));
      };
      channel.port1.onmessageerror = () => finish(false);
      try { client.postMessage({ type: "flowersec-proxy:confirm-registration" }, [channel.port2]); }
      catch { finish(false); }
    }).finally(() => confirmations.delete(client.id));
    confirmations.set(client.id, confirmation);
    return confirmation;
  };
  const resolveTarget = async (source: any) => {
    await mutation;
    if (!shared) {
      if (!restricted || registrations.has(source?.id)) return source;
      const before = mutation;
      if (!await confirm(source) || before !== mutation || registrations.size >= 256) return null;
      registrations.add(source.id);
      return source;
    }
    const id = runtimeClientId || await storedOwner();
    if (!id) return null;
    const client = await worker.clients.get(id);
    if (client && (runtimeClientId === id || await confirm(client)) && (runtimeClientId || await storedOwner()) === id) {
      runtimeClientId = id;
      return client;
    }
    return null;
  };

  const boundedBody = async (body: ReadableStream<Uint8Array> | null, limit: number, reserve?: (bytes: number) => boolean): Promise<ArrayBuffer | null> => {
    let buffer = new Uint8Array(0);
    let used = 0;
    if (body === null) return buffer.buffer;
    const reader = body.getReader();
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) return used === buffer.length ? buffer.buffer : buffer.buffer.slice(0, used);
        const required = used + next.value.byteLength;
        if (required > limit) {
          void reader.cancel().catch(() => undefined);
          return null;
        }
        if (required > buffer.length) {
          const capacity = Math.min(limit, Math.max(required, buffer.length * 2));
          if (reserve && !reserve(capacity - buffer.length)) {
            void reader.cancel().catch(() => undefined);
            return null;
          }
          const grown = new Uint8Array(capacity);
          grown.set(buffer);
          buffer = grown;
        }
        buffer.set(next.value, used);
        used = required;
      }
    } finally { reader.releaseLock(); }
  };

  const pathMatches = (path: string, values: readonly string[]) => values.some((value) => path.startsWith(value));
  const safeMessage = (error: unknown) => error instanceof Error && error.name === "AbortError"
    ? "proxy request canceled"
    : "proxy request failed";

  worker.addEventListener("install", (event: any) => event.waitUntil(worker.skipWaiting()));
  worker.addEventListener("activate", (event: any) => event.waitUntil(worker.clients.claim()));

  worker.addEventListener("message", (event: any) => {
    const data = event.data as Record<string, unknown> | null;
    if (data === null || typeof data !== "object") return;
    if (data.type === "flowersec-proxy:release-runtime" && data.version === 2) {
      event.waitUntil(serialize(async () => {
        if (shared && event.source?.id === (runtimeClientId || await storedOwner())) {
          await (await ownerCache()).delete(ownerKey);
          runtimeClientId = "";
        }
        registrations.delete(event.source?.id);
      }));
      return;
    }
    if (data.type === "flowersec-proxy:register-runtime") {
      const port = event.ports[0];
      const source = event.source as any;
      let ok = data.version === 2 && typeof source?.id === "string" && source.id !== "";
      if (ok && config.runtimeClientPathPrefix !== "") {
        try {
          ok = new URL(source!.url).pathname.startsWith(config.runtimeClientPathPrefix);
        } catch {
          ok = false;
        }
      }
      event.waitUntil(serialize(async () => {
        ok = ok && await matchesToken(data.token);
        if (ok && restricted && config.windowTarget === "request_client") {
          if (registrations.size >= 256 && !registrations.has(source.id)) {
            await Promise.all(Array.from(registrations, async id => {
              if (!await worker.clients.get(id)) registrations.delete(id);
            }));
          }
          ok = registrations.has(source.id) || registrations.size < 256;
          if (ok) registrations.add(source.id);
        }
        if (ok && config.windowTarget === "registered_runtime") {
          const previous = runtimeClientId || await storedOwner();
          if (previous && previous !== source.id) {
            ok = !(await worker.clients.get(previous));
          }
          if (ok) {
            await (await ownerCache()).put(ownerKey, new Response(source.id));
            runtimeClientId = source.id;
          }
        }
        port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok });
        port?.close();
      }).catch(() => { port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: false }); port?.close(); }));
      return;
    }
    if (!config.forwardFetchMessageTypes.includes(String(data.type ?? ""))) return;
    event.waitUntil((async () => {
      const target = await resolveTarget(event.source);
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

      let path = url.pathname + url.search;
      if (config.proxyPathPrefix !== "") {
        if (!url.pathname.startsWith(config.proxyPathPrefix)) return await fetch(request);
        if (config.stripProxyPathPrefix) {
          const stripped = url.pathname.slice(config.proxyPathPrefix.length);
          path = (stripped.startsWith("/") ? stripped : `/${stripped}`) + url.search;
        }
      }

      const source = event.clientId === "" ? null : await worker.clients.get(event.clientId);
      const target = await resolveTarget(source);
      const registered = runtimeClientId;
      const forgetTarget = () => {
        if (config.windowTarget === "registered_runtime" && runtimeClientId === registered) runtimeClientId = "";
      };
      if (target == null) {
        return new Response("proxy runtime unavailable", { status: 503 });
      }

      let body: ArrayBuffer | undefined;
      if (request.signal.aborted) return new Response("proxy request canceled", { status: 499 });
      if (request.method !== "GET" && request.method !== "HEAD") {
        const reservation = intake.begin();
        if (!reservation) return new Response("proxy service unavailable", { status: 503 });
        try {
          let busy = false;
          let requestBody: ArrayBuffer | null;
          if (request.body === undefined) {
            if (!reservation.grow(config.maxRequestBodyBytes)) return new Response("proxy service unavailable", { status: 503 });
            const blob = await request.blob();
            requestBody = blob.size > config.maxRequestBodyBytes ? null : await blob.arrayBuffer();
          } else requestBody = await boundedBody(request.body, config.maxRequestBodyBytes, bytes => {
            busy = !reservation.grow(bytes);
            return !busy;
          });
          if (request.signal.aborted) return new Response("proxy request canceled", { status: 499 });
          if (busy) return new Response("proxy service unavailable", { status: 503 });
          if (requestBody === null) return new Response("proxy request too large", { status: 413 });
          body = requestBody;
        } finally { reservation.release(); }
      }
      const channel = new MessageChannel();
      const response = await new Promise<Response>((resolve) => {
        let metadata: Readonly<{ status: number; headers: Headers }> | null = null;
        let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
        let finished = false;
        let remoteAbortSent = false;
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
            if (current != null || finished) return;
            forgetTarget();
            finishError(503, "proxy runtime unavailable", true);
          }).catch(() => finishError(503, "proxy runtime unavailable", true));
        }, 250);
        request.signal.addEventListener("abort", requestAborted, { once: true });
        const handleMessage = (message: MessageEvent) => {
          const value = message.data as Record<string, unknown> | null;
          if (value === null || typeof value !== "object" || finished) return;
          if (value.type === "flowersec-proxy:response_meta") {
            if (typeof value.status !== "number" || !Number.isInteger(value.status) || value.status < 200 || value.status > 599 || metadata !== null) return finishError(502, "invalid proxy response");
            const headers = new Headers();
            if (Array.isArray(value.headers)) for (const entry of value.headers) {
              if (entry && typeof entry.name === "string" && typeof entry.value === "string") headers.append(entry.name, entry.value);
            }
            metadata = { status: value.status as number, headers };
            clearTimeout(metadataTimer);
            armBodyInactivityTimer();
            if (request.method === "HEAD" || [204, 205, 304].includes(metadata.status)) return;
            const stream = new ReadableStream<Uint8Array>({
              start(valueController) {
                controller = valueController;
                channel.port1.postMessage({ type: "flowersec-proxy:response_credit" });
              },
              pull() { channel.port1.postMessage({ type: "flowersec-proxy:response_credit" }); },
              cancel() {
                if (finished) return;
                finished = true;
                abortRemote();
                cleanup();
              },
            });
            resolve(new Response(stream, { status: metadata.status, headers: metadata.headers }));
            return;
          }
          if (value.type === "flowersec-proxy:response_chunk") {
            if (controller === null || !(value.data instanceof ArrayBuffer)) return finishError(502, "invalid proxy response");
            controller.enqueue(new Uint8Array(value.data));
            armBodyInactivityTimer();
            return;
          }
          if (value.type === "flowersec-proxy:response_end") {
            if (metadata === null) return finishError(502, "invalid proxy response");
            if (controller === null) resolve(new Response(null, metadata));
            finished = true;
            controller?.close();
            cleanup();
            return;
          }
          if (value.type === "flowersec-proxy:response_error") {
            finishError(Number.isInteger(value.status) ? value.status as number : 502, typeof value.message === "string" ? value.message : "proxy request failed");
          }
        };
        channel.port1.onmessage = (message) => {
          try { handleMessage(message); } catch { finishError(502, "invalid proxy response", true); }
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
          forgetTarget();
          finishError(503, "proxy runtime unavailable");
        }
      });

      const injection = config.injectHTML;
      if (response.body === null || injection === null || pathMatches(url.pathname, injection.excludePathPrefixes ?? [])) return response;
      if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) return response;
      const bytes = await boundedBody(response.body, config.maxInjectHTMLBytes);
      if (bytes === null) return new Response("proxy HTML response too large", { status: 502 });
      const decoder = new TextDecoder();
      let html = decoder.decode(bytes);
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
      headers.delete("content-length");
      if (injection.stripValidatorHeaders !== false) { headers.delete("etag"); headers.delete("last-modified"); }
      if (injection.setNoStore !== false) headers.set("cache-control", "no-store");
      return new Response(html, { status: response.status, statusText: response.statusText, headers });
    })().catch((error) => new Response(safeMessage(error), { status: 502 })));
  });
}

export function createProxyServiceWorkerScript(options: ProxyServiceWorkerScriptOptions = {}): string {
  const config = normalizeOptions(options);
  return `// Generated by @floegence/flowersec-core/proxy v2\n(${serviceWorkerMain.toString()})(${JSON.stringify(config)}, ${BodyIntake.toString()});\n`;
}

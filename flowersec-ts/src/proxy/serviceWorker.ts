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

function normalizeOptions(options: ProxyServiceWorkerScriptOptions): ServiceWorkerConfig {
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
    windowTarget: options.windowTarget ?? "registered_runtime",
    windowClientMessageType: token("windowClientMessageType", options.windowClientMessageType, "flowersec-proxy:fetch"),
    runtimeRegistrationToken: token("runtimeRegistrationToken", options.runtimeRegistrationToken),
    runtimeClientPathPrefix: token("runtimeClientPathPrefix", options.runtimeClientPathPrefix),
    conflictHints: strings("conflictHints.keepScriptPathSuffixes", options.conflictHints?.keepScriptPathSuffixes),
  });
}

function serviceWorkerMain(config: ServiceWorkerConfig): void {
  const worker = self as any;
  let runtimeClientId = "";

  const pathMatches = (path: string, values: readonly string[]) => values.some((value) => path.startsWith(value));
  const safeMessage = (error: unknown) => error instanceof Error && error.name === "AbortError"
    ? "proxy request canceled"
    : "proxy request failed";

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
          ok = new URL(source!.url).pathname.startsWith(config.runtimeClientPathPrefix);
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

      let path = url.pathname + url.search;
      if (config.proxyPathPrefix !== "") {
        if (!url.pathname.startsWith(config.proxyPathPrefix)) return await fetch(request);
        if (config.stripProxyPathPrefix) {
          const stripped = url.pathname.slice(config.proxyPathPrefix.length);
          path = (stripped.startsWith("/") ? stripped : `/${stripped}`) + url.search;
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
        const requestBody = await request.clone().arrayBuffer() as ArrayBuffer;
        if (requestBody.byteLength > config.maxRequestBodyBytes) return new Response("proxy request too large", { status: 413 });
        body = requestBody;
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
            if (!Number.isInteger(value.status) || metadata !== null) return finishError(502, "invalid proxy response");
            const headers = new Headers();
            if (Array.isArray(value.headers)) for (const entry of value.headers) {
              if (entry && typeof entry.name === "string" && typeof entry.value === "string") headers.append(entry.name, entry.value);
            }
            metadata = { status: value.status as number, headers };
            clearTimeout(metadataTimer);
            armBodyInactivityTimer();
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
            finished = true;
            controller?.close();
            cleanup();
            return;
          }
          if (value.type === "flowersec-proxy:response_error") {
            finishError(Number.isInteger(value.status) ? value.status as number : 502, typeof value.message === "string" ? value.message : "proxy request failed");
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
      if (!(response.headers.get("content-type") ?? "").toLowerCase().includes("text/html")) return response;
      const bytes = await response.arrayBuffer();
      if (bytes.byteLength > config.maxInjectHTMLBytes) return new Response("proxy HTML response too large", { status: 502 });
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
  return `// Generated by @floegence/flowersec-core/proxy v2\n(${serviceWorkerMain.toString()})(${JSON.stringify(config)});\n`;
}

export type ProxyServiceWorkerPassthroughOptions = Readonly<{
  // Exact pathname matches that should never be proxied.
  // Example: ["/_redeven_sw.js", "/v1/channel/init/entry"]
  paths?: readonly string[];
  // Pathname prefixes that should never be proxied.
  // Example: ["/assets/", "/api/"]
  prefixes?: readonly string[];
}>;

export type ProxyServiceWorkerInjectHTMLInlineModule = Readonly<{
  // Default mode when injectHTML is provided and mode is omitted.
  mode?: "inline_module";
  // A same-origin module URL that exports installWebSocketPatch and disableUpstreamServiceWorkerRegister.
  proxyModuleUrl: string;
  // The runtime is looked up from window.top[runtimeGlobal] (runtime mode with same-origin iframe).
  runtimeGlobal?: string;
}>;

export type ProxyServiceWorkerInjectHTMLExternalScript = Readonly<{
  mode: "external_script";
  // A same-origin script URL injected into <head>. It should patch WebSocket and disable upstream SW registration.
  scriptUrl: string;
  // Optional data attribute value for the injected script.
  runtimeGlobal?: string;
}>;

export type ProxyServiceWorkerInjectHTMLExternalModule = Readonly<{
  mode: "external_module";
  // A same-origin module script URL injected into <head>.
  scriptUrl: string;
  // Optional data attribute value for the injected script.
  runtimeGlobal?: string;
}>;

export type ProxyServiceWorkerInjectHTMLOptions = (ProxyServiceWorkerInjectHTMLInlineModule | ProxyServiceWorkerInjectHTMLExternalScript | ProxyServiceWorkerInjectHTMLExternalModule) &
  Readonly<{
    // If set, skip HTML injection for requests whose pathname starts with any of these prefixes.
    // This helps avoid injection recursion (for example, when serving the injected script itself).
    excludePathPrefixes?: readonly string[];
    // When injecting HTML, strip validator headers that would no longer match the modified body.
    // Default: true.
    stripValidatorHeaders?: boolean;
    // When injecting HTML, set Cache-Control: no-store if the response does not already specify Cache-Control.
    // Default: true.
    setNoStore?: boolean;
  }>;

export type ProxyServiceWorkerScriptOptions = Readonly<{
  // If true, only proxy same-origin requests (recommended).
  //
  // Proxying cross-origin requests is unsafe because the runtime proxy protocol only forwards a path+query,
  // which would drop scheme/host and can route requests to the wrong upstream.
  //
  // Default: true.
  sameOriginOnly?: boolean;

  // If set, matching requests fall through to the default network fetch and are never proxied.
  passthrough?: ProxyServiceWorkerPassthroughOptions;

  // If set, only requests whose pathname starts with this prefix are proxied.
  // Other requests fall through to the default network fetch.
  proxyPathPrefix?: string;
  // If true, the forwarded upstream path strips proxyPathPrefix (mapping the local mount prefix to upstream root).
  //
  // Example:
  // - proxyPathPrefix: "/apps/code/"
  // - request:        "/apps/code/static/app.js"
  // - forwarded:      "/static/app.js"
  stripProxyPathPrefix?: boolean;

  // If set, HTML responses are buffered and a small bootstrap script is injected into <head>.
  //
  // The injected script disables upstream SW registration and patches WebSocket to route via flowersec-proxy/ws.
  injectHTML?: ProxyServiceWorkerInjectHTMLOptions;
}>;

function normalizePathPrefix(name: string, v: unknown): string {
  const s = typeof v === "string" ? v.trim() : "";
  if (s === "") return "";
  if (!s.startsWith("/")) throw new Error(`${name} must start with "/"`);
  if (s.startsWith("//")) throw new Error(`${name} must not start with "//"`);
  if (/[ \t\r\n]/.test(s)) throw new Error(`${name} must not contain whitespace`);
  if (s.includes("://")) throw new Error(`${name} must not include scheme/host`);
  return s;
}

function normalizePathList(name: string, input: readonly string[] | undefined): string[] {
  const out: string[] = [];
  if (input == null || input.length === 0) return out;
  for (const raw of input) {
    const s = normalizePathPrefix(name, raw);
    if (s === "") continue;
    out.push(s);
  }
  return Array.from(new Set(out));
}

// createProxyServiceWorkerScript returns a Service Worker script that forwards fetches to a runtime
// in a controlled window via postMessage + MessageChannel.
//
// The runtime side is implemented by createProxyRuntime(...) in this package.
export function createProxyServiceWorkerScript(opts: ProxyServiceWorkerScriptOptions = {}): string {
  const sameOriginOnly = opts.sameOriginOnly ?? true;
  if (typeof sameOriginOnly !== "boolean") {
    throw new Error("sameOriginOnly must be a boolean");
  }

  const proxyPathPrefix = normalizePathPrefix("proxyPathPrefix", opts.proxyPathPrefix);
  const stripProxyPathPrefix = opts.stripProxyPathPrefix ?? false;
  if (typeof stripProxyPathPrefix !== "boolean") {
    throw new Error("stripProxyPathPrefix must be a boolean");
  }

  const passthroughPaths = normalizePathList("passthrough.paths", opts.passthrough?.paths);
  const passthroughPrefixes = normalizePathList("passthrough.prefixes", opts.passthrough?.prefixes);

  const injectHTML = opts.injectHTML ?? null;

  // Injection mode defaults to inline_module when injectHTML is provided.
  const injectMode = injectHTML?.mode ?? "inline_module";
  const runtimeGlobal = injectHTML != null ? (injectHTML.runtimeGlobal?.trim() ?? "__flowersecProxyRuntime") : "__flowersecProxyRuntime";
  if (injectHTML != null && runtimeGlobal === "") {
    throw new Error("injectHTML.runtimeGlobal must be non-empty");
  }

  const excludeInjectPrefixes = normalizePathList("injectHTML.excludePathPrefixes", injectHTML?.excludePathPrefixes);
  const stripValidatorHeaders = injectHTML?.stripValidatorHeaders ?? true;
  if (typeof stripValidatorHeaders !== "boolean") {
    throw new Error("injectHTML.stripValidatorHeaders must be a boolean");
  }
  const setNoStore = injectHTML?.setNoStore ?? true;
  if (typeof setNoStore !== "boolean") {
    throw new Error("injectHTML.setNoStore must be a boolean");
  }

  let proxyModuleUrl = "";
  let injectScriptUrl = "";
  if (injectHTML != null) {
    if (injectMode === "inline_module") {
      // Note: union type guarantees proxyModuleUrl exists, but keep a runtime check for JS callers.
      proxyModuleUrl =
        "proxyModuleUrl" in injectHTML && typeof injectHTML.proxyModuleUrl === "string"
          ? injectHTML.proxyModuleUrl.trim()
          : "";
      if (proxyModuleUrl === "") {
        throw new Error("injectHTML.proxyModuleUrl must be non-empty");
      }
    } else {
      injectScriptUrl =
        "scriptUrl" in injectHTML && typeof injectHTML.scriptUrl === "string"
          ? injectHTML.scriptUrl.trim()
          : "";
      if (injectScriptUrl === "") {
        throw new Error("injectHTML.scriptUrl must be non-empty");
      }
    }
  }

  return `// Generated by @floegence/flowersec-core/proxy
const SAME_ORIGIN_ONLY = ${JSON.stringify(sameOriginOnly)};
const PROXY_PATH_PREFIX = ${JSON.stringify(proxyPathPrefix)};
const STRIP_PROXY_PATH_PREFIX = ${JSON.stringify(stripProxyPathPrefix)};

const PASSTHROUGH_PATHS = new Set(${JSON.stringify(passthroughPaths)});
const PASSTHROUGH_PREFIXES = ${JSON.stringify(passthroughPrefixes)};

const INJECT_HTML = ${JSON.stringify(injectHTML != null)};
const INJECT_MODE = ${JSON.stringify(injectMode)};
const PROXY_MODULE_URL = ${JSON.stringify(proxyModuleUrl)};
const INJECT_SCRIPT_URL = ${JSON.stringify(injectScriptUrl)};
const RUNTIME_GLOBAL = ${JSON.stringify(runtimeGlobal)};
const INJECT_EXCLUDE_PREFIXES = ${JSON.stringify(excludeInjectPrefixes)};
const INJECT_STRIP_VALIDATOR_HEADERS = ${JSON.stringify(stripValidatorHeaders)};
const INJECT_SET_NO_STORE = ${JSON.stringify(setNoStore)};

const INJECT_STRIP_HEADER_NAMES = new Set(["content-length", "etag", "last-modified", "content-md5"]);

let runtimeClientId = null;

self.addEventListener("install", (event) => {
  // Take over as soon as possible.
  event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return;
  if (data.type !== "flowersec-proxy:register-runtime") return;
  if (event.source && typeof event.source.id === "string") runtimeClientId = event.source.id;
});

async function getRuntimeClient() {
  if (runtimeClientId) {
    const c = await self.clients.get(runtimeClientId);
    if (c) return c;
    runtimeClientId = null;
  }
  const cs = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  if (cs.length > 0) {
    runtimeClientId = cs[0].id;
    return cs[0];
  }
  return null;
}

function shouldPassthrough(pathname) {
  if (PASSTHROUGH_PATHS.has(pathname)) return true;
  for (const p of PASSTHROUGH_PREFIXES) {
    if (pathname.startsWith(p)) return true;
  }
  return false;
}

function shouldSkipInject(pathname) {
  for (const p of INJECT_EXCLUDE_PREFIXES) {
    if (pathname.startsWith(p)) return true;
  }
  return false;
}

function headersToPairs(headers) {
  const out = [];
  headers.forEach((value, name) => out.push({ name, value }));
  return out;
}

function concatChunks(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function injectBootstrap(html) {
  let snippet = "";

  if (INJECT_MODE === "inline_module") {
    snippet =
      '<script type="module">' +
      'import { installWebSocketPatch, disableUpstreamServiceWorkerRegister } from ' + JSON.stringify(PROXY_MODULE_URL) + ';' +
      'const rt = window.top && window.top[' + JSON.stringify(RUNTIME_GLOBAL) + '];' +
      'if (rt) { disableUpstreamServiceWorkerRegister(); installWebSocketPatch({ runtime: rt }); }' +
      '</script>';
  } else if (INJECT_MODE === "external_module") {
    snippet =
      '<script type="module" src="' +
      INJECT_SCRIPT_URL +
      '"' +
      (RUNTIME_GLOBAL ? ' data-flowersec-runtime-global="' + RUNTIME_GLOBAL + '"' : "") +
      "></script>";
  } else if (INJECT_MODE === "external_script") {
    snippet =
      '<script src="' +
      INJECT_SCRIPT_URL +
      '"' +
      (RUNTIME_GLOBAL ? ' data-flowersec-runtime-global="' + RUNTIME_GLOBAL + '"' : "") +
      "></script>";
  }

  const lower = html.toLowerCase();
  const closeHead = lower.indexOf("</head>");
  if (closeHead >= 0) {
    return html.slice(0, closeHead) + snippet + html.slice(closeHead);
  }
  const idx = lower.indexOf("<head");
  if (idx >= 0) {
    const end = html.indexOf(">", idx);
    if (end >= 0) return html.slice(0, end + 1) + snippet + html.slice(end + 1);
  }
  return snippet + html;
}

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Only proxy same-origin requests by default. The runtime proxy protocol forwards path+query only.
  if (SAME_ORIGIN_ONLY && url.origin !== self.location.origin) return;

  if (PROXY_PATH_PREFIX && !url.pathname.startsWith(PROXY_PATH_PREFIX)) return;
  if (shouldPassthrough(url.pathname)) return;

  event.respondWith(handleFetch(event));
});

async function handleFetch(event) {
  const runtime = await getRuntimeClient();
  if (!runtime) return new Response("flowersec-proxy runtime not available", { status: 503 });

  const req = event.request;
  const url = new URL(req.url);
  const id = Math.random().toString(16).slice(2) + Date.now().toString(16);
  const body = (req.method === "GET" || req.method === "HEAD") ? undefined : await req.arrayBuffer();

  const ch = new MessageChannel();
  const port = ch.port1;
  const port2 = ch.port2;

  let metaResolve;
  let metaReject;
  const metaPromise = new Promise((resolve, reject) => { metaResolve = resolve; metaReject = reject; });

  const queued = [];
  const htmlChunks = [];
  let shouldInjectHTML = false;
  const injectAllowed = INJECT_HTML && !shouldSkipInject(url.pathname);

  let doneResolve;
  let doneReject;
  const donePromise = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });

  let controller = null;

  const stream = new ReadableStream({
    start(c) { controller = c; },
    cancel() {
      try { port.postMessage({ type: "flowersec-proxy:abort" }); } catch {}
      try { port.close(); } catch {}
    }
  });

  port.onmessage = (ev) => {
    const m = ev.data;
    if (!m || typeof m.type !== "string") return;
    if (m.type === "flowersec-proxy:response_meta") {
      if (injectAllowed) {
        const ct = String((m.headers || []).find((h) => (h.name || "").toLowerCase() === "content-type")?.value || "");
        shouldInjectHTML = ct.toLowerCase().includes("text/html");
      }
      metaResolve(m);
      if (controller && !shouldInjectHTML) for (const q of queued) controller.enqueue(q);
      if (shouldInjectHTML) for (const q of queued) htmlChunks.push(q);
      queued.length = 0;
      return;
    }
    if (m.type === "flowersec-proxy:response_chunk") {
      const b = new Uint8Array(m.data);
      if (shouldInjectHTML) {
        htmlChunks.push(b);
        return;
      }
      if (controller) controller.enqueue(b); else queued.push(b);
      return;
    }
    if (m.type === "flowersec-proxy:response_end") {
      if (shouldInjectHTML) {
        doneResolve(htmlChunks);
        return;
      }
      controller?.close();
      return;
    }
    if (m.type === "flowersec-proxy:response_error") {
      const err = new Error(m.message || "proxy error");
      metaReject(err);
      doneReject(err);
      controller?.error(err);
      try { port.close(); } catch {}
      return;
    }
  };

  let path = url.pathname + url.search;
  if (PROXY_PATH_PREFIX && STRIP_PROXY_PATH_PREFIX) {
    let rest = url.pathname.slice(PROXY_PATH_PREFIX.length);
    if (rest.startsWith("/")) rest = rest.slice(1);
    path = "/" + rest + url.search;
  }

  runtime.postMessage({
    type: "flowersec-proxy:fetch",
    req: { id, method: req.method, path, headers: headersToPairs(req.headers), body }
  }, [port2]);

  const meta = await metaPromise;
  const headers = new Headers();
  for (const h of (meta.headers || [])) {
    const name = String(h.name || "");
    const lower = name.toLowerCase();
    if (shouldInjectHTML && INJECT_STRIP_VALIDATOR_HEADERS && INJECT_STRIP_HEADER_NAMES.has(lower)) continue;
    headers.append(name, String(h.value || ""));
  }

  if (shouldInjectHTML && INJECT_SET_NO_STORE && !headers.has("Cache-Control")) {
    headers.set("Cache-Control", "no-store");
  }

  if (shouldInjectHTML) {
    const chunks = await donePromise;
    const raw = concatChunks(chunks);
    const html = new TextDecoder().decode(raw);
    const injected = injectBootstrap(html);
    return new Response(new TextEncoder().encode(injected), { status: meta.status || 502, headers });
  }

  return new Response(stream, { status: meta.status || 502, headers });
}
`;
}

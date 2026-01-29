// Proxy service worker for examples/ts/proxy-sandbox.
//
// It forwards fetches under PROXY_PATH_PREFIX to a runtime in a controlled window via postMessage.
// For HTML responses, it buffers and injects a small bootstrap <script> that:
// - disables upstream SW registration (conflict avoidance)
// - patches WebSocket to flowersec-proxy/ws (delegates to the top-level runtime)
const PROXY_PATH_PREFIX = "/examples/ts/proxy-sandbox/app/";
let runtimeClientId = null;

self.addEventListener("install", () => void self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

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
  const snippet =
    `<script type="module">` +
    `import { installWebSocketPatch, disableUpstreamServiceWorkerRegister } from "/flowersec-ts/dist/proxy/index.js";` +
    `const rt = window.top && window.top.__flowersecProxyRuntime;` +
    `if (rt) { disableUpstreamServiceWorkerRegister(); installWebSocketPatch({ runtime: rt }); }` +
    `</script>`;
  const lower = html.toLowerCase();
  const idx = lower.indexOf("<head");
  if (idx >= 0) {
    const end = html.indexOf(">", idx);
    if (end >= 0) return html.slice(0, end + 1) + snippet + html.slice(end + 1);
  }
  return snippet + html;
}

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (!url.pathname.startsWith(PROXY_PATH_PREFIX)) return;
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

  let controller = null;
  const queued = [];
  const htmlChunks = [];
  let shouldInjectHTML = false;

  let doneResolve;
  let doneReject;
  const donePromise = new Promise((resolve, reject) => { doneResolve = resolve; doneReject = reject; });

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
      const ct = String((m.headers || []).find((h) => (h.name || "").toLowerCase() === "content-type")?.value || "");
      shouldInjectHTML = ct.toLowerCase().includes("text/html");
      metaResolve(m);
      if (controller) for (const q of queued) controller.enqueue(q);
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

  // Map the local mount path (/examples/ts/proxy-sandbox/app/*) to the upstream root (/*).
  const upstreamPath = "/" + url.pathname.slice(PROXY_PATH_PREFIX.length) + url.search;
  runtime.postMessage({
    type: "flowersec-proxy:fetch",
    req: { id, method: req.method, path: upstreamPath, headers: headersToPairs(req.headers), body }
  }, [port2]);

  const meta = await metaPromise;
  const headers = new Headers();
  for (const h of (meta.headers || [])) headers.append(h.name, h.value);

  if (shouldInjectHTML) {
    const chunks = await donePromise;
    const raw = concatChunks(chunks);
    const html = new TextDecoder().decode(raw);
    const injected = injectBootstrap(html);
    return new Response(new TextEncoder().encode(injected), { status: meta.status || 502, headers });
  }

  return new Response(stream, { status: meta.status || 502, headers });
}

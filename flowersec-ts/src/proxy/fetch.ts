import { enableResponseFlowControl } from "./serviceWorkerRuntime.js";
import { SessionError } from "../public/contract.js";
import { InvalidProxyPathError, normalizePath } from "./policy.js";
import type { ProxyFetchRequest, ProxyRuntime } from "./types.js";

export async function prepareProxyFetch(input: RequestInfo | URL, init?: RequestInit, externalOrigin?: string, maxBodyBytes = 64 * 1024 * 1024): Promise<{
  request: ProxyFetchRequest; signal: AbortSignal;
}> {
  const raw = input instanceof Request ? input.url : String(input);
  let path = raw;
  if (!raw.startsWith("/")) {
    const url = new URL(raw);
    if (externalOrigin === undefined || url.origin !== externalOrigin || url.username || url.password || url.hash) {
      throw new InvalidProxyPathError("proxy fetch requires a path or the configured external origin");
    }
    path = url.pathname + url.search;
  }
  path = normalizePath(path);
  const request = new Request(input instanceof Request ? input : `https://flowersec.invalid${path}`, init);
  request.signal.throwIfAborted();
  let body: ArrayBuffer | undefined;
  if (request.body !== null) {
    const reader = request.body.getReader();
    const abort = () => { void reader.cancel().catch(() => undefined); };
    request.signal.addEventListener("abort", abort, { once: true });
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        request.signal.throwIfAborted();
        const next = await reader.read();
        request.signal.throwIfAborted();
        if (next.done) break;
        total += next.value.byteLength;
        if (total > maxBodyBytes) throw new SessionError("resource_exhausted");
        chunks.push(next.value);
      }
      const bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      body = bytes.buffer;
    } finally {
      request.signal.removeEventListener("abort", abort);
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  }
  return { request: enableResponseFlowControl({ id: crypto.randomUUID(), method: request.method, path,
    headers: Array.from(request.headers, ([name, value]) => ({ name, value })),
    ...(body === undefined ? {} : { body }),
  }), signal: request.signal };
}

// Window applications use the same controller-owned transaction through a
// credited port. At most one body chunk may be in flight across the bridge.
export function fetchProxyPort(dispatch: ProxyRuntime["dispatchFetch"], request: ProxyFetchRequest, signal: AbortSignal, maxChunkBytes = 256 * 1024): Promise<Response> {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const port = channel.port1;
    let output: ReadableStreamDefaultController<Uint8Array> | undefined;
    let finished = false;
    let receivedMetadata = false;
    let pending: (() => void) | undefined;
    const finish = (error?: Error) => {
      if (finished) return;
      finished = true;
      signal.removeEventListener("abort", abort);
      port.close();
      pending?.();
      if (error) { output?.error(error); reject(error); }
      else output?.close();
    };
    const abort = () => {
      port.postMessage({ type: "flowersec-proxy:abort" });
      finish(new SessionError("canceled"));
    };
    signal.addEventListener("abort", abort, { once: true });
    port.onmessage = (event) => {
      if (finished) return;
      const message = event.data;
      switch (message?.type) {
        case "flowersec-proxy:response_meta": {
          if (receivedMetadata || !Number.isInteger(message.status) || message.status < 200 || message.status > 599 || !Array.isArray(message.headers)) { abort(); return; }
          receivedMetadata = true;
          const noBody = request.method === "HEAD" || [204, 205, 304].includes(message.status);
          const body = noBody ? null : new ReadableStream<Uint8Array>({
            start(controller) { output = controller; },
            pull() {
              return new Promise<void>((done) => {
                pending = done;
                port.postMessage({ type: "flowersec-proxy:response_credit" });
              });
            },
            cancel() { abort(); },
          }, { highWaterMark: 0 });
          try {
            resolve(new Response(body, { status: message.status,
              headers: message.headers.map(({ name, value }: { name: string; value: string }) => [name, value]),
            }));
          } catch { abort(); }
          break;
        }
        case "flowersec-proxy:response_chunk":
          if (!output || !pending || !(message.data instanceof ArrayBuffer) || message.data.byteLength > maxChunkBytes) { abort(); return; }
          output.enqueue(new Uint8Array(message.data)); pending?.(); pending = undefined; break;
        case "flowersec-proxy:response_end": if (!receivedMetadata) abort(); else finish(); break;
        case "flowersec-proxy:response_error":
          finish(new SessionError(message.code === "resource_exhausted" ? "resource_exhausted" : "operation_failed")); break;
      }
    };
    try { dispatch(request, channel.port2); } catch { abort(); }
    if (signal.aborted) abort();
  });
}

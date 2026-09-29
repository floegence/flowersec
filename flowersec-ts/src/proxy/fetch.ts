import type { StreamPermit } from "./admission.js";
import { enableResponseFlowControl } from "./serviceWorkerRuntime.js";
import { SessionError } from "../public/contract.js";
import { InvalidProxyPathError, normalizePath } from "./policy.js";
import type { ProxyFetchRequest, ProxyRuntime } from "./types.js";

export async function prepareProxyFetch(input: RequestInfo | URL, init?: RequestInit, externalOrigin?: string, maxBodyBytes = 64 * 1024 * 1024, permit?: StreamPermit): Promise<{
  request: ProxyFetchRequest; signal: AbortSignal;
}> {
  const raw = input instanceof Request ? input.url : String(input);
  let path = raw;
  if (!raw.startsWith("/")) {
    const url = new URL(raw);
    if (externalOrigin === undefined || url.origin !== externalOrigin || url.username || url.password || url.hash) {
      throw new InvalidProxyPathError("proxy fetch requires a path or the configured external origin");
    }
    path = url.href.slice(url.origin.length);
  }
  path = normalizePath(path);
  const request = new Request(input instanceof Request ? input : `https://flowersec.invalid${path}`, init);
  request.signal.throwIfAborted();
  // Request applies the browser URL algorithm. Use its final observable target,
  // including an empty query, for the later subtree authorization decision.
  const requestURL = new URL(request.url);
  path = normalizePath(requestURL.href.slice(requestURL.origin.length));
  let body: ArrayBuffer | undefined;
  let source = request.body as ReadableStream<Uint8Array> | null | undefined;
  if (source === undefined) {
    // Some browsers expose Body.blob() without Request.body. The Blob is a
    // host-owned representation; inspect its size before creating SDK bytes.
    // This bounds our copy, not the browser's native Body materialization.
    if (request.method !== "GET" && request.method !== "HEAD") {
      const blob = await observeBody(request.blob(), request.signal, permit);
      if (blob.size > maxBodyBytes) throw new SessionError("resource_exhausted");
      permit?.resizeBody(blob.size);
      body = await observeBody(blob.arrayBuffer(), request.signal, permit);
    }
    source = null;
  }
  if (source !== null) {
    const reader = source.getReader();
    let bytes = new Uint8Array(0);
    let total = 0;
    let ended = false;
    try {
      for (;;) {
        request.signal.throwIfAborted();
        const next = await observeBody(reader.read(), request.signal, permit);
        request.signal.throwIfAborted();
        if (next.done) { ended = true; break; }
        const chunk = next.value;
        if (!(chunk instanceof Uint8Array) || chunk.byteLength > maxBodyBytes - total) throw new SessionError("resource_exhausted");
        const needed = total + chunk.byteLength;
        if (needed > bytes.length) {
          const capacity = Math.min(maxBodyBytes, Math.max(needed, bytes.length * 2));
          // Charge both the old slab and the replacement while copying. The
          // workspace envelope is shared across this admission owner.
          const releaseWorkspace = permit?.workspace(bytes.length);
          try {
            permit?.resizeBody(capacity);
            const nextBytes = new Uint8Array(capacity);
            nextBytes.set(bytes.subarray(0, total));
            bytes = nextBytes;
          } finally { releaseWorkspace?.(); }
        }
        bytes.set(chunk, total);
        total = needed;
      }
      if (total === bytes.length) body = bytes.buffer;
      else {
        const releaseWorkspace = permit?.workspace(bytes.length);
        try {
          permit?.resizeBody(total);
          body = bytes.slice(0, total).buffer;
        } finally { releaseWorkspace?.(); }
      }
    } finally {
      if (ended) reader.releaseLock();
      else {
        // Logical cancellation may finish immediately, but the actual reader
        // cancellation retains its original admission until the host settles.
        const releaseTail = permit?.retain();
        void reader.cancel().catch(() => undefined).finally(() => {
          reader.releaseLock();
          releaseTail?.();
        });
      }
    }
  }

  return { request: enableResponseFlowControl({ id: "", method: request.method, path,
    headers: headersOf(request.headers),
    ...(body === undefined ? {} : { body }),
  }), signal: request.signal };
}

// Cancel only the observer; native Body work owns any remaining host tail.
async function observeBody<T>(work: Promise<T>, signal: AbortSignal, permit?: StreamPermit): Promise<T> {
  const releaseTail = permit?.retain();
  if (releaseTail !== undefined) void work.then(releaseTail, releaseTail);
  signal.throwIfAborted();
  let abort: (() => void) | undefined;
  try {
    const result = await Promise.race([work, new Promise<never>((_, reject) => {
      abort = () => reject(new SessionError("canceled"));
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    })]);
    signal.throwIfAborted();
    return result;
  } finally {
    if (abort !== undefined) signal.removeEventListener("abort", abort);
  }
}

// Window applications use the same controller-owned transaction through a
// credited port. At most one body chunk may be in flight across the bridge.
export function fetchProxyPort(dispatch: ProxyRuntime["dispatchFetch"], request: ProxyFetchRequest, signal: AbortSignal, maxChunkBytes = 256 * 1024, releaseRequest?: () => void): Promise<Response> {
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
      releaseRequest?.();
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

function headersOf(headers: Headers): Array<{ name: string; value: string }> {
  const result: Array<{ name: string; value: string }> = [];
  headers.forEach((value, name) => result.push({ name, value }));
  return result;
}

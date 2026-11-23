import { enableResponseFlowControl } from "./serviceWorkerRuntime.js";
import type { BodyIntake } from "./bodyIntake.js";
import { SessionError } from "../public/contract.js";
import { InvalidProxyPathError, normalizePath } from "./policy.js";
import type { ProxyFetchRequest, ProxyRuntime } from "./types.js";

export async function prepareProxyFetch(input: RequestInfo | URL, init?: RequestInit, externalOrigin?: string, maxBodyBytes = 64 * 1024 * 1024, intake?: BodyIntake): Promise<{
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
  const body = await readRequestBody(request, maxBodyBytes, intake);
  return { request: enableResponseFlowControl({ id: "", method: request.method, path,
    headers: Array.from(request.headers, ([name, value]) => ({ name, value })),
    ...(body === undefined ? {} : { body }),
  }), signal: request.signal };
}

async function readRequestBody(request: Request, maxBodyBytes: number, intake?: BodyIntake): Promise<ArrayBuffer | undefined> {
  const source = request.body as ReadableStream<Uint8Array> | null | undefined;
  if (source === null || ["GET", "HEAD"].includes(request.method)) return undefined;
  const reservation = intake?.begin();
  if (intake && !reservation) throw new SessionError("resource_exhausted");
  if (source === undefined) {
    // Some current browser engines implement Body consumption without exposing
    // Request.body. Blob size is checked before copying bytes into the carrier;
    // the ordinary streaming path retains its incremental budget enforcement.
    try {
      if (reservation && !reservation.grow(maxBodyBytes)) throw new SessionError("resource_exhausted");
      const blob = await request.blob();
      request.signal.throwIfAborted();
      if (blob.size > maxBodyBytes) throw new SessionError("resource_exhausted");
      const body = blob.size ? await blob.arrayBuffer() : undefined;
      request.signal.throwIfAborted();
      return body;
    } finally { reservation?.release(); }
  }
  try {
    const reader = source.getReader();
    const abort = () => { void reader.cancel().catch(() => undefined); };
    request.signal.addEventListener("abort", abort, { once: true });
    let bytes = new Uint8Array(0);
    let total = 0;
    try {
      for (;;) {
        request.signal.throwIfAborted();
        const next = await reader.read();
        request.signal.throwIfAborted();
        if (next.done) break;
        const required = total + next.value.byteLength;
        if (required > maxBodyBytes) throw new SessionError("resource_exhausted");
        if (required > bytes.length) {
          const capacity = Math.min(maxBodyBytes, Math.max(required, bytes.length * 2));
          if (reservation && !reservation.grow(capacity - bytes.length)) throw new SessionError("resource_exhausted");
          const grown = new Uint8Array(capacity);
          grown.set(bytes);
          bytes = grown;
        }
        bytes.set(next.value, total);
        total = required;
      }
      return total === bytes.length ? bytes.buffer : bytes.buffer.slice(0, total);
    } finally {
      request.signal.removeEventListener("abort", abort);
      await reader.cancel().catch(() => undefined);
      reader.releaseLock();
    }
  } finally { reservation?.release(); }
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
    const metadataTimer = setTimeout(() => cancel(new SessionError("timeout")), 10_000);
    const finish = (error?: Error) => {
      if (finished) return;
      finished = true;
      clearTimeout(metadataTimer);
      signal.removeEventListener("abort", abort);
      port.close();
      pending?.();
      if (error) { output?.error(error); reject(error); }
      else output?.close();
    };
    const cancel = (error: SessionError) => {
      try { port.postMessage({ type: "flowersec-proxy:abort" }); } finally { finish(error); }
    };
    const abort = () => cancel(new SessionError("canceled"));
    port.onmessageerror = () => cancel(new SessionError("operation_failed"));
    signal.addEventListener("abort", abort, { once: true });
    port.onmessage = (event) => {
      if (finished) return;
      const message = event.data;
      switch (message?.type) {
        case "flowersec-proxy:response_meta": {
          if (receivedMetadata || !Number.isInteger(message.status) || message.status < 200 || message.status > 599 || !Array.isArray(message.headers)) { abort(); return; }
          receivedMetadata = true;
          clearTimeout(metadataTimer);
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

import type { ProxyFetchRequest, ProxyHeader, ProxyRuntime } from "./types.js";

type RuntimeFetchMessage = Readonly<{
  type: "flowersec-proxy:fetch";
  req: unknown;
}>;

type RuntimeRequestRecord = Readonly<{
  id?: unknown;
  method?: unknown;
  path?: unknown;
  headers?: unknown;
  external_origin?: unknown;
  response_flow_control?: unknown;
  body?: unknown;
}>;

type ProxyRuntimeServiceWorkerBridgeHandle = Readonly<{ dispose(): void }>;
const responseFlowControl = new WeakSet<ProxyFetchRequest>();

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function parseRuntimeRequest(value: unknown): ProxyFetchRequest {
  const raw = record(value) as RuntimeRequestRecord | undefined;
  if (raw === undefined || typeof raw.id !== "string" || typeof raw.method !== "string" ||
      typeof raw.path !== "string" || !Array.isArray(raw.headers)) {
    throw new TypeError("invalid proxy service worker request");
  }
  const headers = raw.headers.map((value): ProxyHeader => {
    const header = record(value);
    if (header === undefined || typeof header.name !== "string" || typeof header.value !== "string") {
      throw new TypeError("invalid proxy service worker request headers");
    }
    return Object.freeze({ name: header.name, value: header.value });
  });
  if (raw.body !== undefined && !(raw.body instanceof ArrayBuffer)) {
    throw new TypeError("invalid proxy service worker request body");
  }
  if (raw.external_origin !== undefined && typeof raw.external_origin !== "string") {
    throw new TypeError("invalid proxy service worker request origin");
  }
  if (raw.response_flow_control !== undefined && raw.response_flow_control !== "chunk_credit_v2") {
    throw new TypeError("invalid proxy service worker response flow control");
  }
  const request: ProxyFetchRequest = Object.freeze({
    id: raw.id,
    method: raw.method,
    path: raw.path,
    headers: Object.freeze(headers),
    ...(typeof raw.external_origin === "string" ? { externalOrigin: raw.external_origin } : {}),
    ...(raw.body instanceof ArrayBuffer ? { body: raw.body } : {}),
  });
  if (raw.response_flow_control === "chunk_credit_v2") responseFlowControl.add(request);
  return request;
}

export function usesServiceWorkerResponseFlowControl(request: ProxyFetchRequest): boolean {
  return responseFlowControl.has(request);
}

export function registerProxyRuntimeServiceWorkerBridge(
  runtime: ProxyRuntime,
  serviceWorker: ServiceWorkerContainer,
): ProxyRuntimeServiceWorkerBridgeHandle {
  let disposed = false;
  const onMessage = (event: MessageEvent<unknown>): void => {
    const message = record(event.data) as RuntimeFetchMessage | undefined;
    if (message?.type !== "flowersec-proxy:fetch") return;
    const port = event.ports?.[0];
    if (port === undefined) return;
    try {
      runtime.dispatchFetch(parseRuntimeRequest(message.req), port);
    } catch {
      port.postMessage({
        type: "flowersec-proxy:response_error",
        status: 400,
        code: "invalid_request",
        message: "invalid proxy request",
      });
      port.close();
    }
  };
  serviceWorker.addEventListener("message", onMessage);
  return Object.freeze({
    dispose: () => {
      if (disposed) return;
      disposed = true;
      serviceWorker.removeEventListener("message", onMessage);
    },
  });
}

import { bindProxyRequestAssociation } from "./requestAssociation.js";
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
  request_origin?: unknown;
  credentials?: unknown;
  association_context?: unknown;
  association_generation?: unknown;
  response_flow_control?: unknown;
  body?: unknown;
}>;

const responseFlowControl = new WeakSet<ProxyFetchRequest>();

export function enableResponseFlowControl(request: ProxyFetchRequest): ProxyFetchRequest {
  responseFlowControl.add(request);
  return request;
}

type ProxyRuntimeServiceWorkerBridgeHandle = Readonly<{ dispose(): void }>;

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
  if (raw.credentials !== undefined && (typeof raw.credentials !== "string" || !["omit", "same-origin", "include"].includes(raw.credentials)) ||
      raw.request_origin !== undefined && typeof raw.request_origin !== "string") throw new TypeError("invalid proxy credentials selection");
  const request: ProxyFetchRequest = Object.freeze({
    id: raw.id,
    method: raw.method,
    path: raw.path,
    headers: Object.freeze(headers),
    ...(raw.credentials === undefined ? {} : { credentials: raw.credentials as RequestCredentials }),
    ...(raw.request_origin === undefined ? {} : { requestOrigin: raw.request_origin as string }),
    ...(typeof raw.external_origin === "string" ? { externalOrigin: raw.external_origin } : {}),
    ...(raw.body instanceof ArrayBuffer ? { body: raw.body } : {}),
  });
  let requestOrigin: string | undefined;
  if (typeof raw.request_origin === "string") {
    const url = new URL(raw.request_origin);
    if (url.origin !== raw.request_origin || !["https:", "http:"].includes(url.protocol)) throw new TypeError("invalid original request origin");
    requestOrigin = url.origin;
  }
  if (raw.association_context !== undefined || raw.association_generation !== undefined) {
    if (typeof raw.association_context !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(raw.association_context) ||
        !Number.isSafeInteger(raw.association_generation) || Number(raw.association_generation) < 1) throw new TypeError("invalid original request association");
    bindProxyRequestAssociation(request, { context: raw.association_context, generation: Number(raw.association_generation), ...(requestOrigin === undefined ? {} : { requestOrigin }) });
  } else {
    bindProxyRequestAssociation(request, { context: undefined, ...(requestOrigin === undefined ? {} : { requestOrigin }) });
  }
  if (raw.response_flow_control === "chunk_credit_v2") enableResponseFlowControl(request);
  return request;
}

export function usesServiceWorkerResponseFlowControl(request: ProxyFetchRequest): boolean {
  return responseFlowControl.has(request);
}

export function registerProxyRuntimeServiceWorkerBridge(
  runtime: ProxyRuntime,
  serviceWorker: ServiceWorkerContainer,
): ProxyRuntimeServiceWorkerBridgeHandle {
  const originalWorker = serviceWorker.controller;
  if (originalWorker === null) throw new Error("publication_owner_unavailable");
  let disposed = false;
  const onMessage = (event: MessageEvent<unknown>): void => {
    const message = record(event.data) as RuntimeFetchMessage | undefined;
    if (disposed || serviceWorker.controller !== originalWorker || event.source !== originalWorker || message?.type !== "flowersec-proxy:fetch") return;
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

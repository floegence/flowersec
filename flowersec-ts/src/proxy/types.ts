import type { ByteStream, Session } from "../public/contract.js";

export type ProxyHeader = Readonly<{ name: string; value: string }>;

export type ProxyRuntimeLimits = Readonly<{
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  maxWsBufferedAmountBytes: number;
  maxConcurrentHttpStreams: number;
  maxQueuedHttpRequests: number;
  maxQueuedHttpBodyBytes: number;
}>;

export type ProxyRuntimePathPolicy = Readonly<{
  allowedPathPrefixes?: readonly string[];
  deniedPathPrefixes?: readonly string[];
  allowedWebSocketPathPrefixes?: readonly string[];
  deniedWebSocketPathPrefixes?: readonly string[];
}>;

export type ProxyRuntimeOptions = Readonly<{
  session: Session;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  maxWsBufferedAmountBytes?: number;
  maxConcurrentHttpStreams?: number;
  maxQueuedHttpRequests?: number;
  maxQueuedHttpBodyBytes?: number;
  timeoutMs?: number;
  extraRequestHeaders?: readonly string[];
  extraResponseHeaders?: readonly string[];
  extraWebSocketHeaders?: readonly string[];
  pathPolicy?: ProxyRuntimePathPolicy;
  externalOrigin?: string;
  runtimeRegistrationToken?: string;
}>;

export type ProxyFetchRequest = Readonly<{
  id: string;
  method: string;
  path: string;
  headers: readonly ProxyHeader[];
  externalOrigin?: string;
  body?: ArrayBuffer;
}>;

export type ProxyRuntime = Readonly<{
  limits: ProxyRuntimeLimits;
  dispatchFetch(request: ProxyFetchRequest, port: MessagePort): void;
  openWebSocketStream(
    path: string,
    options?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>,
  ): Promise<Readonly<{ stream: ByteStream; protocol: string }>>;
  dispose(): void;
}>;

export type ProxyRuntimeScopeLimits = Readonly<{
  timeoutMs?: number;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
}>;

type ProxyRuntimeScopeBase = Readonly<{
  appBasePath?: string;
  limits?: ProxyRuntimeScopeLimits;
}>;

export type ProxyRuntimeServiceWorkerScope = ProxyRuntimeScopeBase & Readonly<{
  mode: "service_worker";
  serviceWorker: Readonly<{ scriptUrl: string; scope: string }>;
}>;

export type ProxyRuntimeControllerBridgeScope = ProxyRuntimeScopeBase & Readonly<{
  mode: "controller_bridge";
  controllerBridge: Readonly<{ allowedOrigins: readonly string[] }>;
}>;

export type ProxyRuntimeScope = ProxyRuntimeServiceWorkerScope | ProxyRuntimeControllerBridgeScope;

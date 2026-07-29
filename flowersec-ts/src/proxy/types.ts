import type { ByteStreamV2, SessionV2 } from "../v2/contract.js";

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
  session: SessionV2;
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

export type ProxyFetchRequestV2 = Readonly<{
  id: string;
  method: string;
  path: string;
  headers: readonly ProxyHeader[];
  externalOrigin?: string;
  responseFlowControl?: "chunk_credit_v2";
  body?: ArrayBuffer;
}>;

export type ProxyRuntime = Readonly<{
  limits: ProxyRuntimeLimits;
  dispatchFetch(request: ProxyFetchRequestV2, port: MessagePort): void;
  openWebSocketStream(
    path: string,
    options?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>,
  ): Promise<Readonly<{ stream: ByteStreamV2; protocol: string }>>;
  dispose(): void;
}>;

export type ProxyRuntimeScopeLimitsV2 = Readonly<{
  timeoutMs?: number;
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
}>;

type ProxyRuntimeScopeBaseV2 = Readonly<{
  appBasePath?: string;
  limits?: ProxyRuntimeScopeLimitsV2;
}>;

export type ProxyRuntimeServiceWorkerScopeV2 = ProxyRuntimeScopeBaseV2 & Readonly<{
  mode: "service_worker";
  serviceWorker: Readonly<{ scriptUrl: string; scope: string }>;
}>;

export type ProxyRuntimeControllerBridgeScopeV2 = ProxyRuntimeScopeBaseV2 & Readonly<{
  mode: "controller_bridge";
  controllerBridge: Readonly<{ allowedOrigins: readonly string[] }>;
}>;

export type ProxyRuntimeScopeV2 = ProxyRuntimeServiceWorkerScopeV2 | ProxyRuntimeControllerBridgeScopeV2;

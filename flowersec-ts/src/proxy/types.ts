import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ConnectionController } from "../v4/controller.js";
import type { V4Session } from "../v4/public.js";
import type { ProxyStream } from "./stream.js";

export type ProxyHeader = Readonly<{ name: string; value: string }>;

export type ProxyRuntimeLimits = Readonly<{
  maxMetadataBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  maxWsBufferedAmountBytes: number;
  maxConcurrentHttpStreams: number;
  maxConcurrentEventStreams: number;
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
  session: V4Session;
  sessionBinding?: ProxySessionBinding;
  /** Captured privately before request admission; never supplied by content. */
  credentialContext?: () => string | undefined;
  /** Surface installs its guarded bridge after all owners are registered. */
  registerServiceWorkerBridge?: boolean;
  maxMetadataBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  maxWsBufferedAmountBytes?: number;
  maxConcurrentHttpStreams?: number;
  maxConcurrentEventStreams?: number;
  eventStreamIdleTimeoutMs?: number;
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
  requestOrigin?: string;
  credentials?: RequestCredentials;
  body?: ArrayBuffer;
}>;

export type ProxyRuntime = Readonly<{
  limits: ProxyRuntimeLimits;
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  dispatchFetch(request: ProxyFetchRequest, port: MessagePort): void;
  openWebSocketStream(
    path: string,
    options?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>,
  ): Promise<Readonly<{ stream: ProxyStream; protocol: string }>>;
  dispose(): void;
  cleanupStatus?(): V4CleanupStatus;
}>;

export type ProxyRuntimeScopeLimits = Readonly<{
  timeoutMs?: number;
  maxMetadataBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
}>;

export type ProxyRuntimeHTTPScope = Readonly<{
  additionalPathPrefixes?: readonly string[];
  extraRequestHeaders?: readonly string[];
}>;

type ProxyRuntimeScopeBase = Readonly<{
  appBasePath?: string;
  http?: ProxyRuntimeHTTPScope;
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

/** A request captures one original Session and never migrates after OPEN. */
export type ProxySessionBinding = Readonly<{ mode: "fixed"; session: V4Session }> |
  Readonly<{ mode: "capture_current"; controller: V4ConnectionController }>;
export type ProxySurfaceMode = "trusted" | "isolated";
export interface ProxySurfaceRequestPolicy {
  readonly methods: readonly string[];
  readonly paths: ProxyRuntimePathPolicy;
  readonly allowWebSocket: boolean;
}
export interface ProxyClearResult {
  readonly serverInvalidation: "not_attempted" | "confirmed" | "unknown";
  readonly ownedDeliveryFence: "confirmed" | "unconfirmed";
  readonly associationInstallation: "installed" | "not_installed";
  readonly clearedForThisSurface: boolean;
  readonly readyForReuse: boolean;
  readonly callError?: "operation_conflict" | "source_unavailable" | "canceled" | "deadline_exceeded" | "credential_clear_failed" | "association_install_failed";
  readonly cleanupStatus: V4CleanupStatus;
  readonly deliveryScope: "current_surface_composition";
}
/** The SDK registers an actual trusted publication boundary during initialization. */
export interface ProxyPublicationOwner {
  readonly ownerID: string;
  fence(context: string, signal: AbortSignal): Promise<void>;
  install(context: string, signal: AbortSignal): Promise<void>;
  cleanupStatus(): V4CleanupStatus;
  close(): void;
}

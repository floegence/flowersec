import type { Session } from "../public/contract.js";
import { SDK_DEFAULTS } from "../defaults.js";
import type { ArtifactLeaseV3 } from "../v3/artifactLease.js";
import {
  createConnectionControllerV3 as createCoreControllerV3,
  type ArtifactSourceV3,
  type ConnectionControllerOptionsV3 as CoreControllerOptionsV3,
  type ConnectionControllerV3,
} from "../v3/connectionController.js";
import {
  BrowserRuntimeCapabilityRegistryV3,
  createBrowserWebTransportCarrierV3,
} from "../v3/browserRuntime.js";
import { attemptClaimedArtifactLeaseV3, connectArtifactLeaseV3, type SessionConnectorRuntimeV3 } from "../v3/sessionConnector.js";
import { readyNativeAdmissionV3, readyWebSocketAdmissionV3, type WebSocketLikeV3 } from "../v3/runtimeAdapters.js";
import { TransportFailureV3, ConnectErrorV3 } from "../v3/security.js";
import { browserSessionRuntimeV3 } from "../v3/browserSessionRuntime.js";
import {
  unwrapPrivateLoopbackArtifactLeaseV1,
  validatePrivateLoopbackOriginV1,
  type PrivateLoopbackArtifactLeaseV1,
  type PrivateLoopbackArtifactSourceV1,
} from "./privateLoopbackV1.js";

export type SessionOptionsV3 = Readonly<{
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

export type ConnectionControllerOptionsV3 = Readonly<{
  maximumAttempts?: number;
  connectTimeoutMs?: number;
}>;

export type PrivateLoopbackSessionOptionsV1 = Readonly<{
  origin: string;
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

export type PrivateLoopbackConnectionControllerOptionsV1 = Readonly<{
  origin: string;
  maximumAttempts?: number;
  connectTimeoutMs?: number;
}>;

export async function connectV3(
  lease: ArtifactLeaseV3,
  options: SessionOptionsV3 = {},
): Promise<Session> {
  const registry = await BrowserRuntimeCapabilityRegistryV3.create();
  return await connectArtifactLeaseV3(
    lease,
    browserRuntime(registry, options.connectTimeoutMs),
    options.signal,
  );
}

export async function createConnectionControllerV3(
  source: ArtifactSourceV3,
  options: ConnectionControllerOptionsV3 = {},
): Promise<ConnectionControllerV3<Session>> {
  const registry = await BrowserRuntimeCapabilityRegistryV3.create();
  const runtime = browserRuntime(registry, options.connectTimeoutMs);
  const coreOptions: CoreControllerOptionsV3 = {
    capabilitySnapshot: runtime.capabilitySnapshot,
    projectSessionFailure,
    ...(options.maximumAttempts === undefined ? {} : { maximumAttempts: options.maximumAttempts }),
  };
  return createCoreControllerV3(
    source,
    async (context) => await attemptClaimedArtifactLeaseV3(context, runtime),
    coreOptions,
  );
}

export async function connectPrivateLoopbackV1(
  lease: PrivateLoopbackArtifactLeaseV1,
  options: PrivateLoopbackSessionOptionsV1,
): Promise<Session> {
  const privateOrigin = validatePrivateLoopbackOriginV1(options.origin);
  const unwrapped = unwrapPrivateLoopbackLease(lease);
  if (new URL(unwrapped.endpoint).origin.replace(/^ws:/, "http:") !== privateOrigin) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  const registry = await BrowserRuntimeCapabilityRegistryV3.create();
  return await connectArtifactLeaseV3(
    unwrapped.innerLease,
    privateLoopbackBrowserRuntime(registry, options.connectTimeoutMs, privateOrigin),
    options.signal,
  );
}

export async function createPrivateLoopbackConnectionControllerV1(
  source: PrivateLoopbackArtifactSourceV1,
  options: PrivateLoopbackConnectionControllerOptionsV1,
): Promise<ConnectionControllerV3<Session>> {
  const privateOrigin = validatePrivateLoopbackOriginV1(options.origin);
  const registry = await BrowserRuntimeCapabilityRegistryV3.create();
  const runtime = privateLoopbackBrowserRuntime(registry, options.connectTimeoutMs, privateOrigin);
  const mappedSource: ArtifactSourceV3 = {
    acquire: async ({ signal }) => {
      const result = await source.acquire({ signal });
      if (result.kind === "failure") return result;
      let unwrapped: ReturnType<typeof unwrapPrivateLoopbackArtifactLeaseV1>;
      try {
        unwrapped = unwrapPrivateLoopbackArtifactLeaseV1(result.lease);
      } catch {
        return { kind: "failure", code: "artifact_invalid", disposition: { kind: "terminal" } };
      }
      if (new URL(unwrapped.endpoint).origin.replace(/^ws:/, "http:") !== privateOrigin) {
        return { kind: "failure", code: "artifact_invalid", disposition: { kind: "terminal" } };
      }
      return { kind: "lease", lease: unwrapped.innerLease };
    },
  };
  return createCoreControllerV3(
    mappedSource,
    async (context) => await attemptClaimedArtifactLeaseV3(context, runtime),
    {
      capabilitySnapshot: runtime.capabilitySnapshot,
      projectSessionFailure,
      ...(options.maximumAttempts === undefined ? {} : { maximumAttempts: options.maximumAttempts }),
    },
  );
}

function unwrapPrivateLoopbackLease(
  lease: PrivateLoopbackArtifactLeaseV1,
): ReturnType<typeof unwrapPrivateLoopbackArtifactLeaseV1> {
  try {
    return unwrapPrivateLoopbackArtifactLeaseV1(lease);
  } catch {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
}

function browserRuntime(
  registry: BrowserRuntimeCapabilityRegistryV3,
  connectTimeoutMs: number | undefined,
): SessionConnectorRuntimeV3 {
  const connectTimeoutMilliseconds = connectTimeoutMs ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isSafeInteger(connectTimeoutMilliseconds) || connectTimeoutMilliseconds < 1) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return {
    capabilitySnapshot: () => registry.snapshot(),
    connectTimeoutMilliseconds,
    protocolRuntime: browserSessionRuntimeV3,
    dial: async (candidate, artifact, attemptNow, capability, signal) => {
      if (candidate.carrier === "webtransport") {
        const carrier = await createBrowserWebTransportCarrierV3(
          candidate,
          attemptNow,
          capability,
          registry,
          artifact.session.max_inbound_streams + 2,
          signal,
        );
        return readyNativeAdmissionV3(candidate, carrier);
      }
      if (candidate.carrier !== "websocket" || candidate.tls.mode !== "ca") {
        throw new TransportFailureV3("tls_unsupported");
      }
      validateBrowserWebSocketURL(candidate.normalized_url, artifact.path.kind);
      return await dialBrowserWebSocket(candidate, artifact, candidate.normalized_url, signal);
    },
  };
}

function privateLoopbackBrowserRuntime(
  registry: BrowserRuntimeCapabilityRegistryV3,
  connectTimeoutMs: number | undefined,
  privateOrigin: string,
): SessionConnectorRuntimeV3 {
  const connectTimeoutMilliseconds = connectTimeoutMs ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isSafeInteger(connectTimeoutMilliseconds) || connectTimeoutMilliseconds < 1) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return {
    capabilitySnapshot: () => registry.snapshot(),
    connectTimeoutMilliseconds,
    protocolRuntime: browserSessionRuntimeV3,
    dial: async (candidate, artifact, _attemptNow, _capability, signal) => {
      const targetURL = artifact.path.kind === "direct" && candidate.carrier === "websocket" &&
        candidate.tls.mode === "ca"
        ? privateWebSocketURL(candidate.normalized_url, privateOrigin)
        : undefined;
      if (targetURL === undefined) throw new TransportFailureV3("tls_unsupported");
      return await dialBrowserWebSocket(candidate, artifact, targetURL, signal);
    },
  };
}

async function dialBrowserWebSocket(
  candidate: Parameters<SessionConnectorRuntimeV3["dial"]>[0],
  artifact: Parameters<SessionConnectorRuntimeV3["dial"]>[1],
  targetURL: string,
  signal: AbortSignal,
): Promise<Awaited<ReturnType<SessionConnectorRuntimeV3["dial"]>>> {
  const Constructor = (globalThis as unknown as {
    WebSocket?: new (url: string, protocols?: string | string[]) => WebSocketLikeV3;
  }).WebSocket;
  if (Constructor === undefined) throw new TransportFailureV3("tls_unsupported");
  const protocol = artifact.path.kind === "direct" ? "flowersec.direct.v3" : "flowersec.tunnel.v3";
  let socket: WebSocketLikeV3;
  try { socket = new Constructor(targetURL, protocol); } catch (error) {
    throw new TransportFailureV3("connection_failed", undefined, error);
  }
  return await readyWebSocketAdmissionV3(candidate, artifact, socket, signal);
}

function privateWebSocketURL(candidateURL: string, privateOrigin: string): string | undefined {
  try {
    const candidate = new URL(candidateURL);
    const origin = new URL(privateOrigin);
    if (candidate.protocol !== "wss:" || candidate.host !== origin.host ||
        candidate.pathname !== "/flowersec/v3/direct" || candidate.search !== "" || candidate.hash !== "") return undefined;
    candidate.protocol = "ws:";
    return candidate.href;
  } catch {
    return undefined;
  }
}

function validateBrowserWebSocketURL(raw: string, path: "direct" | "tunnel"): void {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new TransportFailureV3("invalid_artifact"); }
  const expectedPath = path === "direct" ? "/flowersec/v3/direct" : "/flowersec/v3/tunnel";
  if (parsed.href !== raw || parsed.protocol !== "wss:" || parsed.username !== "" || parsed.password !== "" ||
      parsed.pathname !== expectedPath || parsed.search !== "" || parsed.hash !== "") {
    throw new TransportFailureV3("invalid_artifact");
  }
}

function projectSessionFailure(error: Error): ConnectErrorV3 {
  const code = (error as { code?: unknown }).code;
  const retryable = new Set([
    "closed", "going_away", "timeout", "resource_exhausted", "stream_reset", "rekey_failed", "liveness_failed",
  ]).has(String(code));
  return new ConnectErrorV3("connection_failed", { kind: retryable ? "retryable" : "terminal" });
}

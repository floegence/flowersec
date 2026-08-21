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

export type SessionOptionsV3 = Readonly<{
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

export type ConnectionControllerOptionsV3 = Readonly<{
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
      const Constructor = (globalThis as unknown as {
        WebSocket?: new (url: string, protocols?: string | string[]) => WebSocketLikeV3;
      }).WebSocket;
      if (Constructor === undefined) throw new TransportFailureV3("tls_unsupported");
      const protocol = artifact.path.kind === "direct" ? "flowersec.direct.v3" : "flowersec.tunnel.v3";
      let socket: WebSocketLikeV3;
      try { socket = new Constructor(candidate.normalized_url, protocol); } catch (error) {
        throw new TransportFailureV3("connection_failed", undefined, error);
      }
      return await readyWebSocketAdmissionV3(candidate, artifact, socket, signal);
    },
  };
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

import type { NodeConnectionPath } from "./connectionPath.js";
import type { Session } from "../public/contract.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { rpcFrameLimit } from "../framing/jsonframe.js";
import { rpcConcurrency } from "../rpc/server.js";
import type { ArtifactLeaseV3 } from "../v3/artifactLease.js";
import {
  createConnectionControllerV3 as createCoreControllerV3,
  type ArtifactSourceV3,
  type ConnectionControllerOptionsV3 as CoreControllerOptionsV3,
  type ConnectionControllerV3,
} from "../v3/connectionController.js";
import {
  connectNodeWebSocketV3,
  detectNodeRuntimeCapabilityV3,
} from "../v3/nodeRuntime.js";
import {
  attemptClaimedArtifactLeaseV3,
  connectArtifactLeaseWithRuntimeV3,
  type SessionConnectorRuntimeV3,
} from "../v3/sessionConnector.js";
import { readyNativeAdmissionV3, readyWebSocketAdmissionV3 } from "../v3/runtimeAdapters.js";
import { ConnectErrorV3, TransportFailureV3 } from "../v3/security.js";
import { nodeSessionRuntimeV3 } from "../v3/nodeSessionRuntime.js";
import {
  createNativeRawQuicDriver,
  createNativeWebTransportDriver,
  tryLoadNativeTransportAddon,
} from "./nativeTransportAddon.js";
import { createNodeRawQuicClientV3 } from "./rawQuicAdapterV3.js";
import {
  createRPCRouter,
  freezeRPCHandlers,
  type FrozenRPCHandlers,
  RPCHandlers,
  type SessionHandlerBinding,
} from "./acceptor.js";

export type NodeTLSRootsV3 = string | Uint8Array | readonly (string | Uint8Array)[];

export type SessionOptionsV3 = Readonly<{
  webTransportProfile?: "draft02" | "native_h3";
  origin?: string;
  roots?: NodeTLSRootsV3;
  connectionPath?: NodeConnectionPath;
  signal?: AbortSignal;
  connectTimeoutMs?: number;
  rpcHandlers?: RPCHandlers | SessionHandlerBinding<RPCHandlers>;
  maxRpcFrameBytes?: number;
  maxConcurrentRpcRequests?: number;
  /** Select this endpoint's authorized Tunnel URL without changing its TLS policy. */
  tunnelIngressURL?: string;
}>;

export type ConnectionControllerOptionsV3 = Readonly<{
  webTransportProfile?: "draft02" | "native_h3";
  origin?: string;
  roots?: NodeTLSRootsV3;
  connectionPath?: NodeConnectionPath;
  connectTimeoutMs?: number;
  maximumAttempts?: number;
  rpcHandlers?: RPCHandlers;
  maxRpcFrameBytes?: number;
  maxConcurrentRpcRequests?: number;
  tunnelIngressURL?: string;
}>;

export async function connectV3(lease: ArtifactLeaseV3, options: SessionOptionsV3): Promise<Session> {
  return await connectArtifactLeaseWithRuntimeV3(
    lease, options, () => nodeRuntime(options),
  );
}

export function createConnectionControllerV3(
  source: ArtifactSourceV3,
  options: ConnectionControllerOptionsV3,
): ConnectionControllerV3<Session> {
  if (options.rpcHandlers !== undefined && !(options.rpcHandlers instanceof RPCHandlers)) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  const runtime = nodeRuntime(options);
  const coreOptions: CoreControllerOptionsV3 = {
    ...(runtime.tunnelIngressURL === undefined ? {} : { tunnelIngressURL: runtime.tunnelIngressURL }),
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

function nodeRuntime(options: Readonly<{
  webTransportProfile?: "draft02" | "native_h3";
  origin?: string;
  roots?: NodeTLSRootsV3;
  connectionPath?: NodeConnectionPath;
  connectTimeoutMs?: number;
  rpcHandlers?: RPCHandlers | SessionHandlerBinding<RPCHandlers>;
  maxRpcFrameBytes?: number;
  maxConcurrentRpcRequests?: number;
  tunnelIngressURL?: string;
}>): SessionConnectorRuntimeV3 {
  const connectTimeoutMilliseconds = options.connectTimeoutMs ?? SDK_DEFAULTS.transport.connectTimeoutMs;
  if (!Number.isSafeInteger(connectTimeoutMilliseconds) || connectTimeoutMilliseconds < 1) {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  if (options.connectionPath !== undefined && typeof options.connectionPath.connect !== "function") {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  const addon = options.connectionPath === undefined ? tryLoadNativeTransportAddon() : undefined;
  const rawQuic = addon === undefined ? undefined : createNativeRawQuicDriver(addon);
  if (options.webTransportProfile !== undefined && options.webTransportProfile !== "draft02" && options.webTransportProfile !== "native_h3") throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  const webTransport = addon !== undefined && options.webTransportProfile !== undefined ? createNativeWebTransportDriver(addon, options.webTransportProfile) : undefined;
  const capability = detectNodeRuntimeCapabilityV3(rawQuic !== undefined, options.origin !== undefined, webTransport !== undefined);
  let rpcSnapshot: FrozenRPCHandlers | undefined;
  try {
    rpcSnapshot = options.rpcHandlers === undefined ? undefined : freezeRPCHandlers(options.rpcHandlers);
  } catch {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return {
    capabilitySnapshot: () => capability,
    candidateEligible: (candidate) =>
      (options.connectionPath === undefined || candidate.carrier === "websocket") &&
      (candidate.carrier === "raw_quic" || options.origin !== undefined),
    connectTimeoutMilliseconds,
    protocolRuntime: nodeSessionRuntimeV3,
    maxRpcFrameBytes: rpcFrameLimit(options.maxRpcFrameBytes),
    maxConcurrentRpcRequests: rpcConcurrency(options.maxConcurrentRpcRequests),
    ...(options.tunnelIngressURL === undefined ? {} : { tunnelIngressURL: options.tunnelIngressURL }),
    ...(rpcSnapshot === undefined ? {} : { createRPCRouter: () => createRPCRouter(rpcSnapshot) }),
    dial: async (candidate, artifact, attemptNow, _capability, signal) => {
      if (candidate.carrier === "websocket") {
        if (options.origin === undefined) throw new TransportFailureV3("tls_unsupported");
        const socket = await connectNodeWebSocketV3(candidate, attemptNow, {
          origin: options.origin,
          signal,
          ...(options.connectionPath === undefined ? {} : { connectionPath: options.connectionPath }),
          ...(options.roots === undefined ? {} : { roots: options.roots }),
          timeoutMilliseconds: connectTimeoutMilliseconds,
        });
        return await readyWebSocketAdmissionV3(candidate, artifact, socket, signal);
      }
      const native = candidate.carrier === "raw_quic" ? rawQuic : webTransport;
      if (native !== undefined) {
        const carrier = await createNodeRawQuicClientV3(native, candidate, artifact, attemptNow, {
          signal,
          ...(options.origin === undefined ? {} : { origin: options.origin }),
          ...(options.roots === undefined ? {} : { roots: options.roots }),
          handshakeTimeoutMs: connectTimeoutMilliseconds,
        });
        return readyNativeAdmissionV3(candidate, carrier);
      }
      throw new TransportFailureV3("tls_unsupported");
    },
  };
}

function projectSessionFailure(error: Error): ConnectErrorV3 {
  const code = (error as { code?: unknown }).code;
  const retryable = new Set([
    "closed", "going_away", "timeout", "resource_exhausted", "stream_reset", "rekey_failed", "liveness_failed",
  ]).has(String(code));
  return new ConnectErrorV3("connection_failed", { kind: retryable ? "retryable" : "terminal" });
}

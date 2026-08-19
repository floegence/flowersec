import type { Session } from "../public/contract.js";
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
import { attemptClaimedArtifactLeaseV3, connectArtifactLeaseV3, type SessionConnectorRuntimeV3 } from "../v3/sessionConnector.js";
import { readyNativeAdmissionV3, readyWebSocketAdmissionV3 } from "../v3/runtimeAdapters.js";
import { ConnectErrorV3, TransportFailureV3 } from "../v3/security.js";
import { nodeSessionRuntimeV3 } from "../v3/nodeSessionRuntime.js";
import {
  createNativeRawQuicDriverV3,
  tryLoadNativeTransportAddon,
} from "./nativeTransportAddon.js";
import { createNodeRawQuicClientV3 } from "./rawQuicAdapterV3.js";
import {
  createRPCRouter,
  freezeRPCHandlers,
  type FrozenRPCHandlers,
  type RPCHandlers,
} from "./acceptor.js";

export type NodeTLSRootsV3 = string | Uint8Array | readonly (string | Uint8Array)[];

export type SessionOptionsV3 = Readonly<{
  origin?: string;
  roots?: NodeTLSRootsV3;
  signal?: AbortSignal;
  connectTimeoutMs?: number;
  rpcHandlers?: RPCHandlers;
}>;

export type ConnectionControllerOptionsV3 = Readonly<{
  origin?: string;
  roots?: NodeTLSRootsV3;
  connectTimeoutMs?: number;
  maximumAttempts?: number;
  rpcHandlers?: RPCHandlers;
}>;

export async function connectV3(lease: ArtifactLeaseV3, options: SessionOptionsV3): Promise<Session> {
  return await connectArtifactLeaseV3(lease, nodeRuntime(options), options.signal);
}

export function createConnectionControllerV3(
  source: ArtifactSourceV3,
  options: ConnectionControllerOptionsV3,
): ConnectionControllerV3<Session> {
  const runtime = nodeRuntime(options);
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

function nodeRuntime(options: Readonly<{
  origin?: string;
  roots?: NodeTLSRootsV3;
  connectTimeoutMs?: number;
  rpcHandlers?: RPCHandlers;
}>): SessionConnectorRuntimeV3 {
  const addon = tryLoadNativeTransportAddon();
  const rawQuic = addon === undefined ? undefined : createNativeRawQuicDriverV3(addon);
  const capability = detectNodeRuntimeCapabilityV3(rawQuic !== undefined, options.origin !== undefined);
  let rpcSnapshot: FrozenRPCHandlers | undefined;
  try {
    rpcSnapshot = options.rpcHandlers === undefined ? undefined : freezeRPCHandlers(options.rpcHandlers);
  } catch {
    throw new ConnectErrorV3("artifact_invalid", { kind: "terminal" });
  }
  return {
    capabilitySnapshot: () => capability,
    protocolRuntime: nodeSessionRuntimeV3,
    ...(rpcSnapshot === undefined ? {} : { createRPCRouter: () => createRPCRouter(rpcSnapshot) }),
    dial: async (candidate, artifact, attemptNow, _capability, signal) => {
      if (candidate.carrier === "websocket") {
        if (options.origin === undefined) throw new TransportFailureV3("tls_unsupported");
        const socket = await connectNodeWebSocketV3(candidate, attemptNow, {
          origin: options.origin,
          signal,
          ...(options.roots === undefined ? {} : { roots: options.roots }),
          ...(options.connectTimeoutMs === undefined ? {} : { timeoutMilliseconds: options.connectTimeoutMs }),
        });
        return await readyWebSocketAdmissionV3(candidate, artifact, socket, signal);
      }
      if (candidate.carrier === "raw_quic" && rawQuic !== undefined) {
        const carrier = await createNodeRawQuicClientV3(rawQuic, candidate, artifact, attemptNow, {
          signal,
          ...(options.roots === undefined ? {} : { roots: options.roots }),
          ...(options.connectTimeoutMs === undefined ? {} : { handshakeTimeoutMs: options.connectTimeoutMs }),
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

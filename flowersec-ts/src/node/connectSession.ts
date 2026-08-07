import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { NODE_RUNTIME_CAPABILITY_V2 } from "./runtimeCapability.js";
import type { SessionV2 } from "../v2/contract.js";
import {
  composeCandidateAttemptFactoryV2,
  SessionConnectorV2,
} from "../connector/sessionConnector.js";
import { createWebSocketCandidateFactoryV2 } from "../connector/adapters/webSocketCandidate.js";
import { createWebTransportCandidateFactoryV2 } from "../connector/adapters/webTransportCandidate.js";
import { createNodeWsFactory } from "./wsFactory.js";
import { createNodeWebTransportClientV2 } from "./webTransportClient.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import { ConnectError } from "../utils/errors.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  createConnectionControllerV2,
  type ArtifactSource,
  type ConnectionController,
  type ConnectionControllerOptions,
} from "../connectionController.js";

export type NodeSessionTLSOptions = Readonly<{
  ca?: string | Uint8Array;
  serverCertificateHash?: Uint8Array;
}>;

export type NodeSessionOptions = Readonly<{
  origin: string;
  signal?: AbortSignal;
  connectTimeoutMs?: number;
  tls?: NodeSessionTLSOptions;
}>;

export type NodeConnectionControllerOptions = Readonly<{
  origin: string;
  connectTimeoutMs?: number;
  tls?: NodeSessionTLSOptions;
  maxAttempts?: number;
}>;

export function createNodeConnectionController(
  source: ArtifactSource,
  options: NodeConnectionControllerOptions,
): ConnectionController {
  const controllerOptions: ConnectionControllerOptions = options.maxAttempts === undefined
    ? {}
    : { maxAttempts: options.maxAttempts };
  return createConnectionControllerV2(
    source,
    async (lease, signal) => await connectNodeSession(lease, {
      origin: options.origin,
      signal,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
      ...(options.tls === undefined ? {} : { tls: options.tls }),
    }),
    controllerOptions,
  );
}

export async function connectNodeSession(
  lease: ArtifactLeaseV2,
  options: NodeSessionOptions,
): Promise<SessionV2> {
  let origin: string;
  let wsFactory: ReturnType<typeof createNodeWsFactory>;
  try {
    origin = normalizeOrigin(options.origin);
    wsFactory = createNodeWsFactory(options.tls);
  } catch {
    throw new ConnectError("invalid_options");
  }
  const connector = new SessionConnectorV2(
    lease,
    composeCandidateAttemptFactoryV2({
      websocket: createWebSocketCandidateFactoryV2((url, subprotocol) => wsFactory(url, origin, subprotocol)),
      webtransport: createWebTransportCandidateFactoryV2(async (candidate, artifact, signal) =>
        await createNodeWebTransportClientV2(candidate.normalized_url, {
          path: artifact.path.kind,
          inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
          signal,
          ...(options.tls?.serverCertificateHash === undefined
            ? {}
            : { serverCertificateHash: options.tls.serverCertificateHash }),
        })),
    }),
    {
      capability: NODE_RUNTIME_CAPABILITY_V2,
      runtime: nodeSessionRuntimeV2,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
    },
  );
  const result = await connector.connect(options.signal === undefined ? {} : { signal: options.signal });
  return projectSessionV2(result.session);
}

function normalizeOrigin(input: string): string {
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new TypeError("origin must be an absolute HTTP(S) origin"); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== input || parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("origin must be an absolute HTTP(S) origin without path, query, or credentials");
  }
  return parsed.origin;
}

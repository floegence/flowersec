import {
  composeCandidateAttemptFactoryV2,
  SessionConnectorV2,
} from "../connector/sessionConnector.js";
import type { ArtifactLease } from "../public/artifactLease.js";
import { createWebSocketCandidateFactoryV2 } from "../connector/adapters/webSocketCandidate.js";
import { createWebTransportCandidateFactoryV2 } from "../connector/adapters/webTransportCandidate.js";
import { detectBrowserRuntimeCapabilityV2 } from "./runtimeCapability.js";
import type { Session } from "../public/contract.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import { createBrowserWebTransportClientV2 } from "./webTransportClient.js";
import type { WebSocketLike } from "../ws-client/binaryTransport.js";
import { browserSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  createConnectionControllerV2,
  type ArtifactSource,
  type ConnectionController,
  type ConnectionControllerOptions as CoreConnectionControllerOptions,
} from "../connectionController.js";

export type SessionOptions = Readonly<{
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

export type ConnectionControllerOptions = Readonly<{
  connectTimeoutMs?: number;
  maximumAttempts?: number;
}>;

export function createConnectionController(
  source: ArtifactSource,
  options: ConnectionControllerOptions = {},
): ConnectionController {
  const controllerOptions: CoreConnectionControllerOptions = options.maximumAttempts === undefined
    ? {}
    : { maximumAttempts: options.maximumAttempts };
  return createConnectionControllerV2(
    source,
    async (lease, signal) => await connect(lease, {
      signal,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
    }),
    controllerOptions,
  );
}

export async function connect(
  lease: ArtifactLease,
  options: SessionOptions = {},
): Promise<Session> {
  const { signal, ...connectorOptions } = options;
  const connector = new SessionConnectorV2(
    lease,
    composeCandidateAttemptFactoryV2({
      websocket: createWebSocketCandidateFactoryV2(defaultWebSocketFactory),
      webtransport: createWebTransportCandidateFactoryV2(async (candidate, artifact, signal) =>
        await createBrowserWebTransportClientV2(candidate.normalized_url, {
          path: artifact.path.kind,
          inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
          signal,
        })),
    }),
    {
      ...connectorOptions,
      capability: detectBrowserRuntimeCapabilityV2(),
      runtime: browserSessionRuntimeV2,
    },
  );
  const result = await connector.connect(signal === undefined ? {} : { signal });
  return projectSessionV2(result.session);
}

type BrowserWebSocketLike = WebSocketLike & Readonly<{ protocol?: string }>;

function defaultWebSocketFactory(url: string, subprotocol: string): BrowserWebSocketLike {
  const Constructor = (globalThis as unknown as {
    WebSocket?: new (url: string, protocols?: string | string[]) => BrowserWebSocketLike;
  }).WebSocket;
  if (Constructor === undefined) throw new Error("WebSocket is unavailable in this browser runtime");
  return new Constructor(url, subprotocol);
}

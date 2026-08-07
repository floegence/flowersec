import {
  composeCandidateAttemptFactoryV2,
  SessionConnectorV2,
  type ConnectorArtifactLeaseV2,
} from "../connector/sessionConnector.js";
import { createWebSocketCandidateFactoryV2 } from "../connector/adapters/webSocketCandidate.js";
import { createWebTransportCandidateFactoryV2 } from "../connector/adapters/webTransportCandidate.js";
import { detectBrowserRuntimeCapabilityV2 } from "./runtimeCapability.js";
import type { SessionV2 } from "../v2/contract.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import { createBrowserWebTransportClientV2 } from "./webTransportClient.js";
import type { WebSocketLike } from "../ws-client/binaryTransport.js";
import { browserSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  createConnectionControllerV2,
  type ArtifactSource,
  type ConnectionController,
  type ConnectionControllerOptions,
} from "../connectionController.js";

export type BrowserSessionOptions = Readonly<{
  signal?: AbortSignal;
  connectTimeoutMs?: number;
}>;

export type BrowserConnectionControllerOptions = Readonly<{
  connectTimeoutMs?: number;
  maxAttempts?: number;
}>;

export function createBrowserConnectionController(
  source: ArtifactSource,
  options: BrowserConnectionControllerOptions = {},
): ConnectionController {
  const controllerOptions: ConnectionControllerOptions = options.maxAttempts === undefined
    ? {}
    : { maxAttempts: options.maxAttempts };
  return createConnectionControllerV2(
    source,
    async (lease, signal) => await connectBrowserSession(lease, {
      signal,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
    }),
    controllerOptions,
  );
}

export async function connectBrowserSession(
  lease: ConnectorArtifactLeaseV2,
  options: BrowserSessionOptions = {},
): Promise<SessionV2> {
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

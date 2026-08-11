import type { ArtifactLease } from "../public/artifactLease.js";
import { detectNodeRuntimeCapabilityV2 } from "./runtimeCapability.js";
import type { Session } from "../public/contract.js";
import {
  composeCandidateAttemptFactoryV2,
  SessionConnectorV2,
} from "../connector/sessionConnector.js";
import { createWebSocketCandidateFactoryV2 } from "../connector/adapters/webSocketCandidate.js";
import { createRawQuicCandidateFactoryV2 } from "../connector/adapters/rawQuicCandidate.js";
import { createNodeWsFactory } from "./wsFactory.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import { ConnectError } from "../public/connectError.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  createConnectionControllerV2,
  type ArtifactSource,
  type ConnectionController,
  type ConnectionControllerOptions as CoreConnectionControllerOptions,
} from "../connectionController.js";
import {
  freezeSessionHandlersForConnector,
  type SessionHandlers,
} from "./acceptor.js";
import {
  createNativeRawQuicDriver,
  loadNativeTransportAddon,
} from "./nativeTransportAddon.js";
import { createNodeRawQuicClientV2 } from "./rawQuicAdapter.js";

export type SessionTLSOptions = Readonly<{
  ca?: string | Uint8Array;
}>;

export type SessionOptions = Readonly<{
  origin: string;
  signal?: AbortSignal;
  connectTimeoutMs?: number;
  tls?: SessionTLSOptions;
  handlers?: SessionHandlers;
}>;

export type ConnectionControllerOptions = Readonly<{
  origin: string;
  connectTimeoutMs?: number;
  tls?: SessionTLSOptions;
  maximumAttempts?: number;
}>;

export function createConnectionController(
  source: ArtifactSource,
  options: ConnectionControllerOptions,
): ConnectionController {
  const controllerOptions: CoreConnectionControllerOptions = options.maximumAttempts === undefined
    ? {}
    : { maximumAttempts: options.maximumAttempts };
  return createConnectionControllerV2(
    source,
    async (lease, signal) => await connect(lease, {
      origin: options.origin,
      signal,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
      ...(options.tls === undefined ? {} : { tls: options.tls }),
    }),
    controllerOptions,
  );
}

export async function connect(
  lease: ArtifactLease,
  options: SessionOptions,
): Promise<Session> {
  let origin: string;
  let wsFactory: ReturnType<typeof createNodeWsFactory>;
  try {
    origin = normalizeOrigin(options.origin);
    wsFactory = createNodeWsFactory(options.tls);
  } catch {
    throw new ConnectError("invalid_options");
  }
  const rpcRouter = options.handlers === undefined
    ? undefined
    : freezeSessionHandlersForConnector(options.handlers);
  const nativeAddon = loadNativeTransportAddon();
  const rawQuicFactory = createRawQuicCandidateFactoryV2(async (candidate, artifact, signal) => {
    if (options.tls?.ca === undefined) {
      throw new TypeError("raw QUIC requires explicit trust roots");
    }
    return await createNodeRawQuicClientV2(
      createNativeRawQuicDriver(nativeAddon),
      candidate,
      artifact,
      { ca: options.tls.ca },
      signal,
      options.connectTimeoutMs,
    );
  });
  const connector = new SessionConnectorV2(
    lease,
    composeCandidateAttemptFactoryV2({
      websocket: createWebSocketCandidateFactoryV2((url, subprotocol) => wsFactory(url, origin, subprotocol)),
      raw_quic: rawQuicFactory,
    }),
    {
      capability: detectNodeRuntimeCapabilityV2(nativeAddon !== undefined),
      runtime: nodeSessionRuntimeV2,
      ...(rpcRouter === undefined ? {} : { rpcRouter }),
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

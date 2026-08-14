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
  createRPCRouter,
  freezeRPCHandlers,
  type FrozenRPCHandlers,
  type RPCHandlers,
} from "./acceptor.js";
import {
  createNativeRawQuicDriver,
  NativeTransportUnavailableError,
  tryLoadNativeTransportAddon,
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
  rpcHandlers?: RPCHandlers;
}>;

export type ConnectionControllerOptions = Readonly<{
  origin: string;
  connectTimeoutMs?: number;
  tls?: SessionTLSOptions;
  maximumAttempts?: number;
  rpcHandlers?: RPCHandlers;
}>;

export function createConnectionController(
  source: ArtifactSource,
  options: ConnectionControllerOptions,
): ConnectionController {
  validateSessionOptions(options);
  const controllerOptions: CoreConnectionControllerOptions = options.maximumAttempts === undefined
    ? {}
    : { maximumAttempts: options.maximumAttempts };
  let rpcSnapshot: FrozenRPCHandlers | undefined;
  const controller = createConnectionControllerV2(
    source,
    async (lease, signal) => await connectWithRPCSnapshot(lease, {
      origin: options.origin,
      signal,
      ...(options.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: options.connectTimeoutMs }),
      ...(options.tls === undefined ? {} : { tls: options.tls }),
    }, rpcSnapshot),
    controllerOptions,
  );
  rpcSnapshot = options.rpcHandlers === undefined
    ? undefined
    : freezeRPCHandlers(options.rpcHandlers);
  return controller;
}

export async function connect(
  lease: ArtifactLease,
  options: SessionOptions,
): Promise<Session> {
  validateSessionOptions(options);
  const rpcSnapshot = options.rpcHandlers === undefined
    ? undefined
    : freezeRPCHandlers(options.rpcHandlers);
  return await connectWithRPCSnapshot(lease, options, rpcSnapshot);
}

async function connectWithRPCSnapshot(
  lease: ArtifactLease,
  options: SessionOptions,
  rpcSnapshot: FrozenRPCHandlers | undefined,
): Promise<Session> {
  let origin: string;
  let wsFactory: ReturnType<typeof createNodeWsFactory>;
  try {
    origin = normalizeOrigin(options.origin);
    wsFactory = createNodeWsFactory(options.tls);
  } catch {
    throw new ConnectError("invalid_options");
  }
  const rpcRouter = rpcSnapshot === undefined
    ? undefined
    : createRPCRouter(rpcSnapshot);
  // WebSocket sessions do not require the optional native raw QUIC addon. Load
  // it only when a raw QUIC candidate is actually selected by the connector.
  const nativeAddon = tryLoadNativeTransportAddon();
  const rawQuicFactory = createRawQuicCandidateFactoryV2(async (candidate, artifact, signal) => {
    if (nativeAddon === undefined) throw new NativeTransportUnavailableError();
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

function validateSessionOptions(options: Readonly<{
  origin: string;
  tls?: SessionTLSOptions;
}>): void {
  try {
    normalizeOrigin(options.origin);
    createNodeWsFactory(options.tls);
  } catch {
    throw new ConnectError("invalid_options");
  }
}

function normalizeOrigin(input: string): string {
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new TypeError("origin must be an absolute HTTP(S) origin"); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== input || parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("origin must be an absolute HTTP(S) origin without path, query, or credentials");
  }
  return parsed.origin;
}

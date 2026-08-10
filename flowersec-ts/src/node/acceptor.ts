import { RpcRouter } from "../rpc/server.js";
import type { RpcError as WireRpcError } from "../rpc/wire.js";
import {
  acceptReceivedSessionV2,
  receiveSessionAdmissionV2,
  rejectSessionAdmissionV2,
  type ReceivedSessionAdmissionV2,
} from "../connector/sessionAcceptor.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  startNodeWebTransportServerV2,
  type NodeWebTransportServerV2,
} from "./webTransportServer.js";
import type { CarrierSessionV2 } from "../v2/carrier.js";
import { admissionBindingV2, type ArtifactV2, type DecodedFSB2RequestV2 } from "../v2/artifact.js";
import { startNodeWebSocketServer, type NodeWebSocketServer } from "./webSocketServer.js";
import { configureServerWebSocketCarrierRoleV2 } from "../transport/webSocketAdapter.js";
import { unwrapArtifact, type Artifact } from "../public/artifact.js";
import {
  SessionError,
  type IncomingStream,
  type JsonValue,
  type OperationOptions,
  type Session,
} from "../public/contract.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import {
  runtimeAuthorizationRequestFromDecoded,
  type RuntimeAuthorizationRequest,
} from "./controlplane.js";

export type { RuntimeAuthorizationRequest } from "./controlplane.js";

const DEFAULT_MAX_CONCURRENT_STREAMS = 64;
const MAX_CONCURRENT_STREAMS = 128;
const encoder = new TextEncoder();

export type AuthorizationDecision =
  | Readonly<{ decision: "allow"; artifact: Artifact }>
  | Readonly<{ decision: "reject" | "retry"; reason: string }>;

export type RPCHandlerResult =
  | Readonly<{ payload: JsonValue }>
  | Readonly<{ error: Readonly<{ code: number; message?: string }> }>;

export type RPCHandler = (
  payload: JsonValue,
  request: Readonly<{ typeId: number }>,
) => Promise<RPCHandlerResult>;

export type NotificationHandler = (
  payload: JsonValue,
  request: Readonly<{ typeId: number }>,
) => Promise<void> | void;

export type StreamHandler = (
  incoming: IncomingStream,
  options: OperationOptions,
) => Promise<void>;

export type SessionHandlerOptions = Readonly<{
  maxConcurrentStreams?: number;
}>;

export class SessionHandlersError extends Error {
  constructor(readonly code: "invalid_handler" | "already_registered" | "frozen") {
    super(`Flowersec session handler registration failed (code=${code})`);
    this.name = "SessionHandlersError";
  }
}

export class SessionHandlers {
  constructor(options: SessionHandlerOptions = {}) {
    const maximum = options.maxConcurrentStreams ?? DEFAULT_MAX_CONCURRENT_STREAMS;
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_CONCURRENT_STREAMS) {
      throw new SessionHandlersError("invalid_handler");
    }
    sessionHandlerStates.set(this, {
      maxConcurrentStreams: maximum,
      rpc: new Map(),
      notifications: new Map(),
      streams: new Map(),
      frozen: false,
    });
  }

  handleRPC(typeId: number, handler: RPCHandler): void {
    const state = mutableHandlerState(this);
    if (!Number.isSafeInteger(typeId) || typeId < 1 || typeId > 0xffff_ffff || typeof handler !== "function") {
      throw new SessionHandlersError("invalid_handler");
    }
    if (state.rpc.has(typeId)) throw new SessionHandlersError("already_registered");
    if (state.notifications.has(typeId)) throw new SessionHandlersError("already_registered");
    state.rpc.set(typeId, handler);
  }

  handleNotification(typeId: number, handler: NotificationHandler): void {
    const state = mutableHandlerState(this);
    if (!Number.isSafeInteger(typeId) || typeId < 1 || typeId > 0xffff_ffff || typeof handler !== "function") {
      throw new SessionHandlersError("invalid_handler");
    }
    if (state.rpc.has(typeId) || state.notifications.has(typeId)) throw new SessionHandlersError("already_registered");
    state.notifications.set(typeId, handler);
  }

  handleStream(kind: string, handler: StreamHandler): void {
    const state = mutableHandlerState(this);
    if (kind.length < 1 || encoder.encode(kind).length > 255 || kind === "flowersec.rpc.v2" || typeof handler !== "function") {
      throw new SessionHandlersError("invalid_handler");
    }
    if (state.streams.has(kind)) throw new SessionHandlersError("already_registered");
    state.streams.set(kind, handler);
  }
}

type SessionHandlerState = {
  maxConcurrentStreams: number;
  rpc: Map<number, RPCHandler>;
  notifications: Map<number, NotificationHandler>;
  streams: Map<string, StreamHandler>;
  frozen: boolean;
};

const sessionHandlerStates = new WeakMap<SessionHandlers, SessionHandlerState>();

function mutableHandlerState(handlers: SessionHandlers): SessionHandlerState {
  const state = sessionHandlerStates.get(handlers);
  if (state === undefined) throw new SessionHandlersError("invalid_handler");
  if (state.frozen) throw new SessionHandlersError("frozen");
  return state;
}

function freezeHandlers(handlers: SessionHandlers, router: RpcRouter): FrozenHandlers {
  const state = mutableHandlerState(handlers);
  state.frozen = true;
  for (const [typeId, handler] of state.rpc) {
    router.register(typeId, async (payload) => {
      const result = await handler(payload as JsonValue, Object.freeze({ typeId }));
      if ("error" in result) return { payload: null, error: validRPCError(result.error) };
      return { payload: result.payload };
    });
  }
  for (const [typeId, handler] of state.notifications) {
    router.onNotify(typeId, (payload) => {
      void Promise.resolve(handler(payload as JsonValue, Object.freeze({ typeId }))).catch(() => undefined);
    });
  }
  return Object.freeze({
    maxConcurrentStreams: state.maxConcurrentStreams,
    streams: new Map(state.streams),
  });
}

type FrozenHandlers = Readonly<{
  maxConcurrentStreams: number;
  streams: ReadonlyMap<string, StreamHandler>;
}>;

export type AcceptorListener = Readonly<{
  carrier: "websocket";
  path: "direct" | "tunnel";
  host: string;
  port: number;
  tls?: Readonly<{ certificate: string; privateKey: string }>;
  allowedOrigins: readonly string[];
}> | Readonly<{
  carrier: "webtransport";
  path: "direct" | "tunnel";
  host: string;
  port: number;
  route: string;
  certificate: string;
  privateKey: string;
}>;

export type AcceptorOptions = Readonly<{
  listeners: readonly AcceptorListener[];
  maxInboundStreams: number;
  authorize(
    request: RuntimeAuthorizationRequest,
    options: OperationOptions,
  ): Promise<AuthorizationDecision>;
  resolveHandlers?(
    request: RuntimeAuthorizationRequest,
    options: OperationOptions,
  ): Promise<SessionHandlers> | SessionHandlers;
}>;

export class AcceptedSession {
  private constructor() {}

  get session(): Session {
    return acceptedSessionState(this).session;
  }

  async serve(options: OperationOptions = {}): Promise<void> {
    const active = new Set<Promise<void>>();
    const state = acceptedSessionState(this);
    try {
      while (true) {
        if (options.signal?.aborted) throw new SessionError("canceled");
        const incoming = await this.session.acceptStream(options);
        const handler = state.handlers.streams.get(incoming.kind);
        if (handler === undefined || active.size >= state.handlers.maxConcurrentStreams) {
          await incoming.stream.reset();
          continue;
        }
        const task = (async () => {
          try {
            await handler(incoming, options);
          } catch {
            await incoming.stream.reset().catch(() => undefined);
          } finally {
            await incoming.stream.close().catch(() => undefined);
          }
        })()
          .finally(() => active.delete(task));
        active.add(task);
      }
    } finally {
      await this.session.close().catch(() => undefined);
      await Promise.allSettled(active);
    }
  }

  async close(): Promise<void> {
    await this.session.close();
  }
}

type AcceptedSessionState = Readonly<{ session: Session; handlers: FrozenHandlers }>;
const acceptedSessionStates = new WeakMap<AcceptedSession, AcceptedSessionState>();

function acceptedSessionState(accepted: AcceptedSession): AcceptedSessionState {
  const state = acceptedSessionStates.get(accepted);
  if (state === undefined) throw new SessionError("operation_failed");
  return state;
}

function createAcceptedSession(session: Session, handlers: FrozenHandlers): AcceptedSession {
  const accepted = new (AcceptedSession as unknown as { new(): AcceptedSession })();
  acceptedSessionStates.set(accepted, { session, handlers });
  return Object.freeze(accepted);
}

export class Acceptor {
  private constructor() {}

  addresses(): readonly Readonly<{ host: string; port: number }>[] {
    return acceptorState(this).listeners.map((listener) => listener.address());
  }

  async accept(operation: OperationOptions = {}): Promise<AcceptedSession> {
    const state = acceptorState(this);
    state.start();
    return await state.accepted.shift(operation.signal);
  }

  async close(): Promise<void> {
    const state = acceptorState(this);
    state.abort.abort();
    state.accepted.close();
    await Promise.all(state.pending.splice(0).map(async (leg) => await leg.received.carrier.close().catch(() => undefined)));
    await Promise.all(state.listeners.map(async (listener) => await listener.close()));
  }
}

type AuthorizedLeg = Readonly<{
  received: ReceivedSessionAdmissionV2;
  decoded: DecodedFSB2RequestV2;
  artifact: ArtifactV2;
  handlers: FrozenHandlers;
  router: RpcRouter;
}>;

async function authorizeCarrier(state: AcceptorState, carrier: CarrierSessionV2): Promise<AuthorizedLeg | undefined> {
  const received = await receiveSessionAdmissionV2(carrier, state.abort.signal);
  const decoded = received.decoded;
  const request = runtimeAuthorizationRequestFromDecoded(decoded);
  const decision = await state.options.authorize(request, { signal: state.abort.signal });
  if (decision.decision !== "allow") {
    return await rejectSessionAdmissionV2(received, {
      accepted: false,
      status: decision.decision === "retry" ? 2 : 1,
      reason: decision.reason,
    }, state.abort.signal);
  }
  const router = new RpcRouter();
  const registry = state.options.resolveHandlers === undefined
    ? new SessionHandlers()
    : await state.options.resolveHandlers(request, { signal: state.abort.signal });
  return { received, decoded, artifact: unwrapArtifact(decision.artifact), handlers: freezeHandlers(registry, router), router };
}

async function establishDirect(leg: AuthorizedLeg, signal: AbortSignal): Promise<AcceptedSession> {
  const internal = await acceptReceivedSessionV2(leg.received, leg.artifact, {
    runtime: nodeSessionRuntimeV2,
    rpcRouter: leg.router,
    role: "server",
    signal,
  });
  return createAcceptedSession(projectSessionV2(internal), leg.handlers);
}

function tunnelLegsMatch(first: AuthorizedLeg, second: AuthorizedLeg): boolean {
  const a = first.artifact.path;
  const b = second.artifact.path;
  if (a.kind !== "tunnel" || b.kind !== "tunnel") return false;
  return a.role !== b.role &&
    a.rendezvous_group_id === b.rendezvous_group_id &&
    first.artifact.session.channel_id === second.artifact.session.channel_id &&
    first.artifact.session.contract_hash_b64u === second.artifact.session.contract_hash_b64u &&
    first.decoded.request.listener_audience === second.decoded.request.listener_audience &&
    first.decoded.request.candidate_set_hash_b64u === second.decoded.request.candidate_set_hash_b64u &&
    a.local_endpoint_instance_id === b.expected_peer_endpoint_instance_id &&
    a.expected_peer_endpoint_instance_id === b.local_endpoint_instance_id;
}

async function establishTunnelPair(first: AuthorizedLeg, second: AuthorizedLeg, signal: AbortSignal): Promise<readonly AcceptedSession[]> {
  const establish = async (leg: AuthorizedLeg, peer: AuthorizedLeg): Promise<AcceptedSession> => {
    const path = leg.artifact.path;
    if (path.kind !== "tunnel") throw new SessionError("operation_failed");
    if (leg.received.carrier.kind === "websocket") {
      configureServerWebSocketCarrierRoleV2(leg.received.carrier, path.role === 2);
    }
    const internal = await acceptReceivedSessionV2(leg.received, leg.artifact, {
      runtime: nodeSessionRuntimeV2,
      rpcRouter: leg.router,
      role: path.role === 1 ? "server" : "client",
      localAdmissionBinding: admissionBindingV2(peer.received.rawFSB2),
      peerAdmissionBinding: admissionBindingV2(leg.received.rawFSB2),
      localEndpointInstanceID: path.expected_peer_endpoint_instance_id,
      expectedPeerEndpointInstanceID: path.local_endpoint_instance_id,
      signal,
    });
    return createAcceptedSession(projectSessionV2(internal), leg.handlers);
  };
  return await Promise.all([establish(first, second), establish(second, first)]);
}

async function processCarrier(state: AcceptorState, carrier: CarrierSessionV2): Promise<void> {
  const leg = await authorizeCarrier(state, carrier);
  if (leg === undefined) return;
  if (leg.artifact.path.kind === "direct") {
    state.accepted.push(await establishDirect(leg, state.abort.signal));
    return;
  }
  const peerIndex = state.pending.findIndex((candidate) => tunnelLegsMatch(candidate, leg));
  if (peerIndex < 0) {
    state.pending.push(leg);
    return;
  }
  const peer = state.pending.splice(peerIndex, 1)[0]!;
  for (const accepted of await establishTunnelPair(peer, leg, state.abort.signal)) state.accepted.push(accepted);
}

async function runAcceptLoop(state: AcceptorState): Promise<void> {
  while (!state.abort.signal.aborted) {
    try {
      const carrier = await state.accept({ signal: state.abort.signal });
      void processCarrier(state, carrier).catch(async () => {
        await carrier.close().catch(() => undefined);
      });
    } catch (error) {
      if (!state.abort.signal.aborted) state.accepted.fail(error instanceof Error ? error : new Error(String(error)));
      return;
    }
  }
}

class AcceptedQueue {
  private readonly values: AcceptedSession[] = [];
  private readonly waiters = new Set<Readonly<{ resolve(value: AcceptedSession): void; reject(error: Error): void }>>();
  private failure: Error | undefined;

  push(value: AcceptedSession): void {
    if (this.failure !== undefined) { void value.close(); return; }
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(value);
    else { this.waiters.delete(waiter); waiter.resolve(value); }
  }

  async shift(signal?: AbortSignal): Promise<AcceptedSession> {
    if (signal?.aborted === true) throw new SessionError("canceled");
    const value = this.values.shift();
    if (value !== undefined) return value;
    if (this.failure !== undefined) throw this.failure;
    return await new Promise<AcceptedSession>((resolve, reject) => {
      const waiter = { resolve: (session: AcceptedSession) => { cleanup(); resolve(session); }, reject: (error: Error) => { cleanup(); reject(error); } };
      const abort = () => { this.waiters.delete(waiter); reject(new SessionError("canceled")); };
      const cleanup = () => signal?.removeEventListener("abort", abort);
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }

  fail(error: Error): void {
    if (this.failure !== undefined) return;
    this.failure = error;
    for (const waiter of this.waiters) waiter.reject(error);
    this.waiters.clear();
  }

  close(): void { this.fail(new SessionError("closed")); }
}

type Listener = NodeWebTransportServerV2 | NodeWebSocketServer;
type AcceptorState = Readonly<{
  listeners: readonly Listener[];
  options: AcceptorOptions;
  accept(operation: OperationOptions): Promise<Awaited<ReturnType<Listener["accept"]>>>;
  accepted: AcceptedQueue;
  pending: AuthorizedLeg[];
  abort: AbortController;
  start(): void;
}>;
const acceptorStates = new WeakMap<Acceptor, AcceptorState>();

function acceptorState(acceptor: Acceptor): AcceptorState {
  const state = acceptorStates.get(acceptor);
  if (state === undefined) throw new SessionError("operation_failed");
  return state;
}

export async function createAcceptor(options: AcceptorOptions): Promise<Acceptor> {
  if (!Number.isSafeInteger(options.maxInboundStreams) || options.maxInboundStreams < 1 || options.maxInboundStreams > 128 || options.listeners.length === 0) {
    throw new TypeError("invalid Flowersec Acceptor options");
  }
  const listeners: Listener[] = [];
  try {
    for (const listener of options.listeners) {
      listeners.push(listener.carrier === "websocket"
        ? await startNodeWebSocketServer({ ...listener, inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2 })
        : await startNodeWebTransportServerV2({
          host: listener.host, port: listener.port, path: listener.route,
          certificate: listener.certificate, privateKey: listener.privateKey,
          carrierPath: listener.path,
          inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
        }));
    }
  } catch (error) {
    await Promise.allSettled(listeners.map(async (listener) => await listener.close()));
    throw error;
  }
  let cursor = 0;
  const accept = async (operation: OperationOptions) => {
    if (listeners.length === 1) return await listeners[0]!.accept(operation);
    const controller = new AbortController();
    const abort = () => controller.abort(operation.signal?.reason);
    operation.signal?.addEventListener("abort", abort, { once: true });
    try {
      return await Promise.any(listeners.map(async (listener, index) => {
        const selected = listeners[(index + cursor) % listeners.length]!;
        return await selected.accept({ signal: controller.signal });
      })).finally(() => { cursor = (cursor + 1) % listeners.length; controller.abort(); });
    } finally {
      operation.signal?.removeEventListener("abort", abort);
    }
  };
  const acceptor = new (Acceptor as unknown as { new(): Acceptor })();
  const accepted = new AcceptedQueue();
  const abort = new AbortController();
  let started = false;
  const state: AcceptorState = {
    listeners, options, accept, accepted, pending: [], abort,
    start() {
      if (started) return;
      started = true;
      void runAcceptLoop(state);
    },
  };
  acceptorStates.set(acceptor, state);
  return Object.freeze(acceptor);
}

function validRPCError(error: Readonly<{ code: number; message?: string }>): WireRpcError {
  if (!Number.isSafeInteger(error.code) || error.code < 1 || error.code > 0xffff_ffff) {
    return { code: 500, message: "handler failed" };
  }
  if (error.message !== undefined && encoder.encode(error.message).length > 1024) {
    return { code: 500, message: "handler failed" };
  }
  return error.message === undefined ? { code: error.code } : { code: error.code, message: error.message };
}

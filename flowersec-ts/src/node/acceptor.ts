import { RpcRouter } from "../rpc/server.js";
import type { RpcError as WireRpcError } from "../rpc/wire.js";
import { assertRpcError, assertRpcTypeId } from "../rpc/validate.js";
import {
  acceptReceivedSessionV2,
  receiveSessionAdmissionV2,
  rejectSessionAdmissionV2,
  type ReceivedSessionAdmissionV2,
} from "../connector/sessionAcceptor.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import type { CarrierSessionV2 } from "../v2/carrier.js";
import type { ArtifactV2 } from "../v2/artifact.js";
import {
  startNodeWebSocketServer,
  type NodeWebSocketServer,
} from "./webSocketServer.js";
import { createNativeRawQuicDriver } from "./nativeTransportAddon.js";
import {
  startNodeRawQuicServer,
  type NodeRawQuicServer,
} from "./rawQuicServer.js";
import { unwrapArtifact } from "../public/artifact.js";
import {
  SessionError,
  type JsonValue,
  type OperationOptions,
  type Session,
} from "../public/contract.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import {
  runtimeAuthorizationRequestFromDecoded,
  type DirectAuthorizationDecision,
  type RuntimeAuthorizationRequest,
} from "./controlplane.js";
import {
  HandlerRegistrationError,
  StreamHandlers,
  freezeStreamHandlers,
  registerStreamHandlersAtomically,
  serveFrozenStreamHandlers,
  type FrozenStreamHandlers,
  type StreamHandler,
  type StreamHandlerOptions,
} from "../public/streamHandlers.js";

export type { RuntimeAuthorizationRequest } from "./controlplane.js";
export { HandlerRegistrationError } from "../public/streamHandlers.js";
export type { StreamHandler } from "../public/streamHandlers.js";

const DEFAULT_CLEANUP_TIMEOUT_MS = 2_000;

export type AuthorizationDecision = DirectAuthorizationDecision;

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

export type SessionHandlerOptions = StreamHandlerOptions;

export class RPCHandlers {
  constructor() {
    rpcHandlerStates.set(this, createRPCHandlerState());
  }

  handleRPC(typeId: number, handler: RPCHandler): void {
    registerRPC(mutableRPCHandlerState(this), typeId, handler);
  }

  handleNotification(typeId: number, handler: NotificationHandler): void {
    registerNotification(mutableRPCHandlerState(this), typeId, handler);
  }
}

export class SessionHandlers {
  declare private readonly streamHandlerRegistrarBrand: void;

  constructor(options: SessionHandlerOptions = {}) {
    sessionHandlerStates.set(this, {
      rpc: createRPCHandlerState(),
      streams: new StreamHandlers(options),
      frozen: false,
    });
  }

  handleRPC(typeId: number, handler: RPCHandler): void {
    const state = mutableSessionHandlerState(this);
    registerRPC(state.rpc, typeId, handler);
  }

  handleNotification(typeId: number, handler: NotificationHandler): void {
    const state = mutableSessionHandlerState(this);
    registerNotification(state.rpc, typeId, handler);
  }

  handleStream(kind: string, handler: StreamHandler): void {
    const state = mutableSessionHandlerState(this);
    state.streams.handleStream(kind, handler);
  }
}

type RPCHandlerState = {
  requests: Map<number, RPCHandler>;
  notifications: Map<number, NotificationHandler>;
  frozen: boolean;
  snapshot?: FrozenRPCHandlers;
};

type SessionHandlerState = {
  rpc: RPCHandlerState;
  streams: StreamHandlers;
  frozen: boolean;
  snapshot?: FrozenSessionHandlers;
};

const rpcHandlerStates = new WeakMap<RPCHandlers, RPCHandlerState>();
const sessionHandlerStates = new WeakMap<
  SessionHandlers,
  SessionHandlerState
>();

function createRPCHandlerState(): RPCHandlerState {
  return { requests: new Map(), notifications: new Map(), frozen: false };
}

function mutableRPCHandlerState(handlers: RPCHandlers): RPCHandlerState {
  const state = rpcHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.frozen) throw new HandlerRegistrationError("frozen");
  return state;
}

function mutableSessionHandlerState(handlers: SessionHandlers): SessionHandlerState {
  const state = sessionHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.frozen) throw new HandlerRegistrationError("frozen");
  return state;
}

/** @internal */
export function registerSessionStreamHandlersAtomically(
  handlers: SessionHandlers,
  entries: readonly (readonly [string, StreamHandler])[],
): void {
  const state = mutableSessionHandlerState(handlers);
  registerStreamHandlersAtomically(state.streams, entries);
}

function registerRPC(state: RPCHandlerState, typeId: number, handler: RPCHandler): void {
  validateRPCRegistration(typeId, handler);
  if (state.requests.has(typeId) || state.notifications.has(typeId)) {
    throw new HandlerRegistrationError("already_registered");
  }
  state.requests.set(typeId, handler);
}

function registerNotification(
  state: RPCHandlerState,
  typeId: number,
  handler: NotificationHandler,
): void {
  validateRPCRegistration(typeId, handler);
  if (state.requests.has(typeId) || state.notifications.has(typeId)) {
    throw new HandlerRegistrationError("already_registered");
  }
  state.notifications.set(typeId, handler);
}

function validateRPCRegistration(typeId: number, handler: unknown): void {
  try {
    assertRpcTypeId(typeId);
  } catch {
    throw new HandlerRegistrationError("invalid_handler");
  }
  if (typeof handler !== "function") {
    throw new HandlerRegistrationError("invalid_handler");
  }
}

export type FrozenRPCHandlers = Readonly<{
  requests: ReadonlyMap<number, RPCHandler>;
  notifications: ReadonlyMap<number, NotificationHandler>;
}>;

/** @internal */
export function freezeRPCHandlers(handlers: RPCHandlers): FrozenRPCHandlers {
  const state = rpcHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    requests: new Map(state.requests),
    notifications: new Map(state.notifications),
  });
  return state.snapshot;
}

function freezeRPCHandlerState(state: RPCHandlerState): FrozenRPCHandlers {
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    requests: new Map(state.requests),
    notifications: new Map(state.notifications),
  });
  return state.snapshot;
}

/** @internal */
export function createRPCRouter(snapshot: FrozenRPCHandlers): RpcRouter {
  const router = new RpcRouter();
  for (const [typeId, handler] of snapshot.requests) {
    router.register(typeId, async (payload) => {
      const result = await handler(
        payload as JsonValue,
        Object.freeze({ typeId }),
      );
      if ("error" in result)
        return { payload: null, error: validRPCError(result.error) };
      return { payload: result.payload };
    });
  }
  for (const [typeId, handler] of snapshot.notifications) {
    router.onNotify(typeId, (payload) => {
      void Promise.resolve(
        handler(payload as JsonValue, Object.freeze({ typeId })),
      ).catch(() => undefined);
    });
  }
  return router;
}

function freezeSessionHandlers(handlers: SessionHandlers): FrozenSessionHandlers {
  const state = sessionHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    rpc: freezeRPCHandlerState(state.rpc),
    streams: freezeStreamHandlers(state.streams),
  });
  return state.snapshot;
}

type FrozenSessionHandlers = Readonly<{
  rpc: FrozenRPCHandlers;
  streams: FrozenStreamHandlers;
}>;

export type AcceptorListener =
  | Readonly<{
      carrier: "websocket";
      path: "direct";
      host: string;
      port: number;
      tls?: Readonly<{ certificate: string; privateKey: string }>;
      allowedOrigins: readonly string[];
    }>
  | Readonly<{
      carrier: "raw_quic";
      path: "direct";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string; privateKey: string }>;
    }>;

export type AcceptorOptions = Readonly<{
  listeners: readonly AcceptorListener[];
  maxInboundStreams: number;
  cleanupTimeoutMs?: number;
  authorize(
    request: RuntimeAuthorizationRequest,
    options: OperationOptions,
  ): Promise<AuthorizationDecision>;
  release?(leaseId: string): Promise<void> | void;
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
    const state = acceptedSessionState(this);
    await serveFrozenStreamHandlers(
      state.handlers.streams,
      this.session,
      options,
      async () => await this.close(),
    );
  }

  async close(): Promise<void> {
    const state = acceptedSessionState(this) as AcceptedSessionState & {
      closePromise?: Promise<void>;
      releasePromise?: Promise<void>;
    };
    if (state.closePromise === undefined) {
      state.closePromise = (async () => {
        try {
          await state.session.close();
        } finally {
          if (state.release !== undefined && state.releasePromise === undefined) {
            state.releasePromise = Promise.resolve().then(() => state.release!());
          }
          await state.releasePromise;
        }
      })();
    }
    await state.closePromise;
  }
}

type AcceptedSessionState = {
  session: Session;
  handlers: FrozenSessionHandlers;
  release?: () => Promise<void> | void;
  closePromise?: Promise<void>;
  releasePromise?: Promise<void>;
};
const acceptedSessionStates = new WeakMap<
  AcceptedSession,
  AcceptedSessionState
>();

function acceptedSessionState(accepted: AcceptedSession): AcceptedSessionState {
  const state = acceptedSessionStates.get(accepted);
  if (state === undefined) throw new SessionError("operation_failed");
  return state;
}

function createAcceptedSession(
  session: Session,
  handlers: FrozenSessionHandlers,
  release?: () => Promise<void> | void,
): AcceptedSession {
  const accepted = new (
    AcceptedSession as unknown as { new (): AcceptedSession }
  )();
  const state: AcceptedSessionState = { session, handlers };
  if (release !== undefined) state.release = release;
  acceptedSessionStates.set(accepted, state);
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
    if (state.lifecycle.completion === undefined) {
      state.lifecycle.completion = closeAcceptor(state);
    }
    await withCleanupTimeout(state.lifecycle.completion, state.cleanupTimeoutMs);
  }
}

const MAX_CONCURRENT_ADMISSIONS = 64;
const MAX_PENDING_ACCEPTED_SESSIONS = 64;

async function closeAcceptor(state: AcceptorState): Promise<void> {
  state.abort.abort();
  const queued = state.accepted.close();
  const cleanup = await Promise.allSettled([
    ...state.listeners.map(async (listener) => await listener.close()),
    ...queued.map(async (accepted) => await accepted.close()),
  ]);
  while (state.tasks.size > 0) {
    await Promise.allSettled([...state.tasks]);
  }
  if (
    cleanup.some((result) => result.status === "rejected") ||
    state.lifecycle.cleanupFailed
  ) {
    throw new SessionError("operation_failed");
  }
}

type AuthorizedLeg = Readonly<{
  received: ReceivedSessionAdmissionV2;
  artifact: ArtifactV2;
  handlers: FrozenSessionHandlers;
  router: RpcRouter;
  leaseId?: string;
}>;

async function releaseLease(state: AcceptorState, leaseId: string | undefined): Promise<void> {
  if (leaseId === undefined || state.options.release === undefined) return;
  await state.options.release(leaseId);
}

async function authorizeCarrier(
  state: AcceptorState,
  carrier: CarrierSessionV2,
): Promise<AuthorizedLeg | undefined> {
  const received = await receiveSessionAdmissionV2(carrier, state.abort.signal);
  const decoded = received.decoded;
  const request = runtimeAuthorizationRequestFromDecoded(decoded);
  const decision = await state.options.authorize(request, { signal: state.abort.signal });
  if (decision.decision !== "allow") {
    return await rejectSessionAdmissionV2(
      received,
      {
        accepted: false,
        status: decision.decision === "retry" ? 2 : 1,
        reason: decision.reason,
      },
      state.abort.signal,
    );
  }
  const leaseId = "leaseId" in decision && typeof decision.leaseId === "string"
    ? decision.leaseId
    : undefined;
  try {
    const registry =
      state.options.resolveHandlers === undefined
        ? new SessionHandlers()
        : await state.options.resolveHandlers(request, { signal: state.abort.signal });
    const handlers = freezeSessionHandlers(registry);
    const leg: {
      received: ReceivedSessionAdmissionV2;
      artifact: ArtifactV2;
      handlers: FrozenSessionHandlers;
      router: RpcRouter;
      leaseId?: string;
    } = {
      received,
      artifact: unwrapArtifact(decision.artifact),
      handlers,
      router: createRPCRouter(handlers.rpc),
    };
    if (leaseId !== undefined) leg.leaseId = leaseId;
    return leg;
  } catch (error) {
    await releaseLease(state, leaseId).catch(() => undefined);
    throw error;
  }
}

async function establishDirect(
  leg: AuthorizedLeg,
  signal: AbortSignal,
  release?: () => Promise<void> | void,
): Promise<AcceptedSession> {
  const internal = await acceptReceivedSessionV2(leg.received, leg.artifact, {
    runtime: nodeSessionRuntimeV2,
    rpcRouter: leg.router,
    role: "server",
    signal,
  });
  return createAcceptedSession(projectSessionV2(internal), leg.handlers, release);
}

async function processCarrier(
  state: AcceptorState,
  carrier: CarrierSessionV2,
): Promise<void> {
  const leg = await authorizeCarrier(state, carrier);
  if (leg === undefined) return;
  let releaseOwnedByAcceptedSession = false;
  try {
    if (
      leg.received.decoded.request.pathKind !== "direct" ||
      leg.artifact.path.kind !== "direct"
    ) {
      await leg.received.carrier.close().catch(() => undefined);
      throw new SessionError("operation_failed");
    }
    const accepted = await establishDirect(
      leg,
      state.abort.signal,
      leg.leaseId === undefined ? undefined : () => releaseLease(state, leg.leaseId),
    );
    releaseOwnedByAcceptedSession = true;
    if (state.accepted.push(accepted) === "rejected") {
      try {
        await accepted.close();
      } catch {
        state.lifecycle.cleanupFailed = true;
        throw new SessionError("operation_failed");
      }
    }
  } catch (error) {
    if (!releaseOwnedByAcceptedSession) {
      await releaseLease(state, leg.leaseId).catch(() => undefined);
    }
    throw error;
  }
}

async function runAcceptLoop(state: AcceptorState): Promise<void> {
  while (!state.abort.signal.aborted) {
    try {
      while (state.admissions.size >= MAX_CONCURRENT_ADMISSIONS) {
        await Promise.race(state.admissions);
        if (state.abort.signal.aborted) return;
      }
      const carrier = await state.accept({ signal: state.abort.signal });
      const task = processCarrier(state, carrier)
        .catch(async () => {
          await carrier.close().catch(() => undefined);
        })
        .finally(() => {
          state.admissions.delete(task);
          state.tasks.delete(task);
        });
      state.admissions.add(task);
      state.tasks.add(task);
    } catch (error) {
      if (!state.abort.signal.aborted)
        state.accepted.fail(
          error instanceof Error ? error : new Error(String(error)),
        );
      return;
    }
  }
}

class AcceptedQueue {
  private readonly values: AcceptedSession[] = [];
  private readonly waiters = new Set<
    Readonly<{
      resolve(value: AcceptedSession): void;
      reject(error: Error): void;
    }>
  >();
  private failure: Error | undefined;

  push(value: AcceptedSession): "delivered" | "queued" | "rejected" {
    if (this.failure !== undefined) return "rejected";
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) {
      if (this.values.length >= MAX_PENDING_ACCEPTED_SESSIONS) return "rejected";
      this.values.push(value);
      return "queued";
    }
    else {
      this.waiters.delete(waiter);
      waiter.resolve(value);
      return "delivered";
    }
  }

  async shift(signal?: AbortSignal): Promise<AcceptedSession> {
    if (signal?.aborted === true) throw new SessionError("canceled");
    const value = this.values.shift();
    if (value !== undefined) return value;
    if (this.failure !== undefined) throw this.failure;
    return await new Promise<AcceptedSession>((resolve, reject) => {
      const waiter = {
        resolve: (session: AcceptedSession) => {
          cleanup();
          resolve(session);
        },
        reject: (error: Error) => {
          cleanup();
          reject(error);
        },
      };
      const abort = () => {
        this.waiters.delete(waiter);
        reject(new SessionError("canceled"));
      };
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

  close(): readonly AcceptedSession[] {
    this.fail(new SessionError("closed"));
    return this.values.splice(0);
  }
}

type Listener = NodeWebSocketServer | NodeRawQuicServer;
type AcceptorState = Readonly<{
  listeners: readonly Listener[];
  options: AcceptorOptions;
  accept(
    operation: OperationOptions,
  ): Promise<Awaited<ReturnType<Listener["accept"]>>>;
  accepted: AcceptedQueue;
  abort: AbortController;
  tasks: Set<Promise<void>>;
  admissions: Set<Promise<void>>;
  cleanupTimeoutMs: number;
  lifecycle: { completion?: Promise<void>; cleanupFailed: boolean };
  start(): void;
}>;
const acceptorStates = new WeakMap<Acceptor, AcceptorState>();

function acceptorState(acceptor: Acceptor): AcceptorState {
  const state = acceptorStates.get(acceptor);
  if (state === undefined) throw new SessionError("operation_failed");
  return state;
}

export async function createAcceptor(
  options: AcceptorOptions,
): Promise<Acceptor> {
  if (
    !Number.isSafeInteger(options.maxInboundStreams) ||
    options.maxInboundStreams < 1 ||
    options.maxInboundStreams > 128 ||
    options.listeners.length === 0
  ) {
    throw new TypeError("invalid Flowersec Acceptor options");
  }
  const cleanupTimeoutMs = options.cleanupTimeoutMs ?? DEFAULT_CLEANUP_TIMEOUT_MS;
  if (!Number.isSafeInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1 || cleanupTimeoutMs > 60_000) {
    throw new TypeError("invalid Flowersec Acceptor cleanup timeout");
  }
  if (options.listeners.some((listener) => listener.path !== "direct")) {
    throw new TypeError(
      "Flowersec Acceptor listeners must use the direct path",
    );
  }
  const listeners: Listener[] = [];
  let rawQuicDriver: ReturnType<typeof createNativeRawQuicDriver> | undefined;
  try {
    for (const listener of options.listeners) {
      if (listener.carrier === "websocket") {
        listeners.push(await startNodeWebSocketServer({
          ...listener,
          inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
        }));
      } else {
        rawQuicDriver ??= createNativeRawQuicDriver();
        listeners.push(await startNodeRawQuicServer(rawQuicDriver, {
          ...listener,
          inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
        }));
      }
    }
  } catch (error) {
    await Promise.allSettled(
      listeners.map(async (listener) => await listener.close()),
    );
    throw error;
  }
  let cursor = 0;
  const accept = async (operation: OperationOptions) => {
    if (listeners.length === 1) return await listeners[0]!.accept(operation);
    const controller = new AbortController();
    const abort = () => controller.abort(operation.signal?.reason);
    operation.signal?.addEventListener("abort", abort, { once: true });
    try {
      return await new Promise<CarrierSessionV2>((resolve, reject) => {
        let settled = false;
        let remaining = listeners.length;
        const errors: unknown[] = [];
        listeners.forEach((listener, index) => {
          const selected = listeners[(index + cursor) % listeners.length]!;
          void selected.accept({ signal: controller.signal }).then((carrier) => {
            if (!settled) {
              settled = true;
              cursor = (cursor + 1) % listeners.length;
              controller.abort();
              resolve(carrier);
            } else {
              carrier.abort({ code: 1000, reason: "accept race lost" });
            }
          }, (error: unknown) => {
            errors.push(error);
            remaining -= 1;
            if (!settled && remaining === 0) {
              settled = true;
              reject(new AggregateError(errors, "all listeners failed to accept"));
            }
          });
        });
      });
    } finally {
      operation.signal?.removeEventListener("abort", abort);
    }
  };
  const acceptor = new (Acceptor as unknown as { new (): Acceptor })();
  const accepted = new AcceptedQueue();
  const abort = new AbortController();
  const tasks = new Set<Promise<void>>();
  const admissions = new Set<Promise<void>>();
  let started = false;
  const state: AcceptorState = {
    listeners,
    options,
    accept,
    accepted,
    abort,
    tasks,
    admissions,
    cleanupTimeoutMs,
    lifecycle: { cleanupFailed: false },
    start() {
      if (started) return;
      started = true;
      const task = runAcceptLoop(state).finally(() => tasks.delete(task));
      tasks.add(task);
    },
  };
  acceptorStates.set(acceptor, state);
  return Object.freeze(acceptor);
}

async function withCleanupTimeout(completion: Promise<void>, timeoutMs: number): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      completion,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new SessionError("timeout")), timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function validRPCError(
  error: Readonly<{ code: number; message?: string }>,
): WireRpcError {
  try {
    return assertRpcError(error);
  } catch {
    return { code: 500, message: "handler failed" };
  }
}

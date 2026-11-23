import type { OperationOptions, Session } from "../public/contract.js";
import { projectSessionV3 } from "../v3/publicSession.js";
import { rpcFrameLimit } from "../framing/jsonframe.js";
import { rpcConcurrency } from "../rpc/server.js";
import { boundIngressURL } from "./listenerIngress.js";
import {
  acceptCarrierSessionV3,
  createAdmissionReasonRegistryV3,
  type AdmissionAuthorizerV3,
} from "../v3/serverAdmission.js";
import { nodeSessionRuntimeV3 } from "../v3/nodeSessionRuntime.js";
import type { CarrierSessionV3 } from "../v3/carrier.js";
import { AdmissionStatusV3 } from "../v3/artifact.js";
import {
  unwrapArtifactHandleV3,
  type ArtifactHandleV3,
} from "../v3/publicApi.js";
import {
  SessionHandlersV3,
  createRPCRouter,
  freezeSessionHandlersV3,
  type FrozenSessionHandlers,
  type SessionHandlerBinding,
} from "./acceptor.js";
import { serveFrozenStreamHandlers } from "../public/streamHandlers.js";
import {
  createNativeRawQuicDriver,
  loadNativeTransportAddon,
} from "./nativeTransportAddon.js";
import {
  startNodeRawQuicListenerV3,
  startNodeWebTransportListener, type NodeWebTransportListenerConfig,
  type NodeRawQuicListenerV3,
} from "./rawQuicServerV3.js";
import {
  startNodeWebSocketListenerV3,
  type NodeWebSocketListenerV3,
} from "./webSocketServerV3.js";
import {
  runtimeAuthorizationRequestV3FromDecoded,
  type RuntimeAuthorizationRequestV3,
} from "./runtimeAuthorizationV3.js";

const DEFAULT_ADMISSION_TIMEOUT_MS = 10_000;
const emptyHandlers = new SessionHandlersV3();
type ResolvedHandlers = SessionHandlersV3 | SessionHandlerBinding<SessionHandlersV3>;

export type AcceptorListenerV3 =
  | (NodeWebTransportListenerConfig & Readonly<{ path: "direct" }>)
  | Readonly<{
      carrier: "websocket";
      publicURL?: string;
      path: "direct";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string; privateKey: string }>;
      allowedOrigins: readonly string[];
    }>
  | Readonly<{
      carrier: "raw_quic";
      publicURL?: string;
      path: "direct";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string | Uint8Array; privateKey: string | Uint8Array }>;
    }>;

export type AcceptorOptionsV3 = Readonly<{
  listeners: readonly AcceptorListenerV3[];
  maxInboundStreams: number;
  /** Bounds admissions in progress and authenticated sessions awaiting accept. */
  maxPendingSessions?: number;
  maxRpcFrameBytes?: number;
  maxConcurrentRpcRequests?: number;
  admissionTimeoutMs?: number;
  admissionReasons?: readonly string[];
  authorize: AcceptorAuthorizerV3;
  resolveHandlers?(
    request: RuntimeAuthorizationRequestV3,
    options: OperationOptions,
  ): Promise<ResolvedHandlers> | ResolvedHandlers;
}>;

export type AcceptorAuthorizationDecisionV3 =
  | Readonly<{ accepted: true; artifact: ArtifactHandleV3 }>
  | Readonly<{ accepted: false; retryable: boolean; reason: string }>;

export type AcceptorAuthorizerV3 = (
  request: RuntimeAuthorizationRequestV3,
  options: OperationOptions,
) => Promise<AcceptorAuthorizationDecisionV3> | AcceptorAuthorizationDecisionV3;

export class AcceptedSessionV3 {
  private constructor() {}

  get session(): Session {
    return acceptedSessionStateV3(this).session;
  }

  /** Non-secret lookup key of the authorization that established this session. */
  get authorizationKey(): string { return acceptedSessionStateV3(this).authorizationKey; }

  async serve(options: OperationOptions = {}): Promise<void> {
    const state = acceptedSessionStateV3(this);
    await serveFrozenStreamHandlers(
      state.handlers.streams,
      state.session,
      options,
      async () => await this.close(),
    );
  }

  async close(): Promise<void> {
    const state = acceptedSessionStateV3(this);
    state.closePromise ??= state.session.close();
    await state.closePromise;
  }
}

export class AcceptorV3 {
  private constructor() {}

  addresses(): readonly Readonly<{ host: string; port: number }>[] {
    return acceptorState(this).listeners.map((listener) => listener.address());
  }

  async accept(options: OperationOptions = {}): Promise<AcceptedSessionV3> {
    const state = acceptorState(this);
    if (state.closed) throw new Error("Flowersec v5 acceptor is closed");
    const { signal } = options;
    signal?.throwIfAborted();
    const next = state.ready.values().next();
    if (!next.done) { state.ready.delete(next.value); return next.value; }
    if (state.listenerCount === 0) throw state.listenerError;
    if (state.waiters.size >= state.maxPendingSessions) throw new Error("Flowersec v5 accept capacity exceeded");
    return await new Promise((resolve, reject) => {
      const abort = () => { state.waiters.delete(waiter); reject(signal?.reason); };
      const waiter: AcceptWaiter = {
        resolve(value) { signal?.removeEventListener("abort", abort); resolve(value); },
        reject(error) { signal?.removeEventListener("abort", abort); reject(error); },
      };
      state.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
    });
  }

  async close(): Promise<void> {
    const state = acceptorState(this);
    const existing = closes.get(state);
    if (existing !== undefined) return await existing;
    state.closed = true;
    const closing = Promise.resolve().then(async () => {
      const error = new Error("Flowersec v5 acceptor closed");
      state.abort.abort(error);
      for (const waiter of state.waiters) waiter.reject(error);
      state.waiters.clear();
      const results = await Promise.allSettled([
        ...Array.from(state.ready, value => value.close()),
        ...state.listeners.map(listener => listener.close()), ...state.pumps, ...state.admissions,
      ]);
      state.ready.clear();
      if (results.some(({ status }) => status === "rejected")) throw new Error("Flowersec v5 acceptor cleanup failed");
    });
    closes.set(state, closing);
    await closing;
  }
}

async function admit(state: AcceptorStateV3, carrier: CarrierSessionV3, ingress: string, providers: Set<Promise<unknown>>): Promise<AcceptedSessionV3> {
      const admission = new AbortController();
      const unlinkAdmission = linkAbort(state.abort.signal, admission);
      const deadline = setTimeout(() => {
        admission.abort(new Error("Flowersec v5 admission timed out"));
      }, state.admissionTimeoutMs);
      try {
        let handlers: FrozenSessionHandlers | undefined, authorizationKey: string | undefined;
        const authorize: AdmissionAuthorizerV3 = async (request, signal) => {
          const selected = request.request.candidates.find(entry => entry.id === request.request.chosen_candidate_id);
          if (selected?.normalized_url !== ingress) throw new Error("authorized candidate does not match the bound listener");
          const authorizationRequest = runtimeAuthorizationRequestV3FromDecoded(request);
          signal?.throwIfAborted();
          const decision = await ownProvider(providers, state.authorize(
            authorizationRequest, signal === undefined ? {} : { signal },
          ));
          if (decision.accepted === true) {
            return { accepted: true, artifact: unwrapArtifactHandleV3(decision.artifact) };
          }
          if (decision.accepted !== false || typeof decision.retryable !== "boolean") {
            throw new Error("invalid Direct authorization decision");
          }
          return {
            accepted: false,
            status: decision.retryable
              ? AdmissionStatusV3.Retryable
              : AdmissionStatusV3.Reject,
            reason: decision.reason,
          };
        };
        const internal = await acceptCarrierSessionV3(carrier, authorize, {
          runtime: nodeSessionRuntimeV3,
          maxRpcFrameBytes: state.maxRpcFrameBytes,
          maxConcurrentRpcRequests: state.maxConcurrentRpcRequests,
          admissionReasons: state.admissionReasons,
          resolveRPCRouter: async (request, signal) => {
            signal?.throwIfAborted();
            const authorizationRequest = runtimeAuthorizationRequestV3FromDecoded(request);
            authorizationKey = authorizationRequest.lookupKey();
            const registry = state.resolveHandlers === undefined
              ? emptyHandlers
              : await ownProvider(providers, state.resolveHandlers(authorizationRequest, signal === undefined ? {} : { signal }));
            if (signal?.aborted === true) {
              throw signal.reason instanceof Error ? signal.reason : new Error("Flowersec v5 admission canceled");
            }
            handlers = freezeSessionHandlersV3(registry);
            return createRPCRouter(handlers.rpc);
          },
          signal: admission.signal,
        });
        if (handlers === undefined || authorizationKey === undefined) throw new Error("Flowersec v5 handlers were not resolved");
        return createAcceptedSessionV3(projectSessionV3(internal), handlers, authorizationKey);
      } catch (error) {
        carrier.abort({ code: 6, reason: "admission failed" });
        throw error;
      } finally {
        clearTimeout(deadline);
        unlinkAdmission();
      }
}

function ownProvider<T>(providers: Set<Promise<unknown>>, value: T | Promise<T>): Promise<T> {
  const task = Promise.resolve(value);
  providers.add(task);
  const finish = () => { providers.delete(task); };
  void task.then(finish, finish);
  return task;
}

type ListenerV3 = NodeWebSocketListenerV3 | NodeRawQuicListenerV3;
type AcceptWaiter = { resolve(value: AcceptedSessionV3): void; reject(error: unknown): void };
type AcceptorStateV3 = {
  listeners: readonly ListenerV3[];
  authorize: AcceptorAuthorizerV3;
  resolveHandlers?: AcceptorOptionsV3["resolveHandlers"];
  admissionReasons: ReadonlySet<string>;
  admissionTimeoutMs: number;
  abort: AbortController;
  closed: boolean;
  maxPendingSessions: number;
  maxRpcFrameBytes: number;
  maxConcurrentRpcRequests: number;
  listenerCount: number;
  listenerError?: unknown;
  admissions: Set<Promise<void>>;
  pumps: Promise<void>[];
  ready: Set<AcceptedSessionV3>;
  waiters: Set<AcceptWaiter>;
};
const acceptorStatesV3 = new WeakMap<AcceptorV3, AcceptorStateV3>();
const closes = new WeakMap<AcceptorStateV3, Promise<void>>();
type AcceptedSessionStateV3 = {
  session: Session;
  authorizationKey: string;
  handlers: FrozenSessionHandlers;
  closePromise?: Promise<void>;
};
const acceptedSessionStatesV3 = new WeakMap<AcceptedSessionV3, AcceptedSessionStateV3>();

export async function createAcceptorV3(options: AcceptorOptionsV3): Promise<AcceptorV3> {
  validateOptions(options);
  const maxRpcFrameBytes = rpcFrameLimit(options.maxRpcFrameBytes);
  const maxConcurrentRpcRequests = rpcConcurrency(options.maxConcurrentRpcRequests);
  const admissionReasons = createAdmissionReasonRegistryV3(
    ["expired_artifact"],
    options.admissionReasons,
  );
  const listeners: ListenerV3[] = [];
  const ingress: string[] = [];
  let rawDriver: ReturnType<typeof createNativeRawQuicDriver> | undefined;
  try {
    for (const listener of options.listeners) {
      const running = listener.carrier === "websocket"
        ? await startNodeWebSocketListenerV3({
            ...listener,
            inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
          })
        : listener.carrier === "webtransport" ? await startNodeWebTransportListener({ ...listener, inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2 })
        : await startNodeRawQuicListenerV3(
            rawDriver ??= createNativeRawQuicDriver(loadNativeTransportAddon()),
            {
              ...listener,
              inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
            },
          );
      listeners.push(running);
      ingress.push(boundIngressURL("direct", listener.carrier, running.address(), listener.publicURL));
    }
  } catch (error) {
    await Promise.allSettled(listeners.map(async (listener) => await listener.close()));
    throw error;
  }
  const acceptor = new (AcceptorV3 as unknown as { new(): AcceptorV3 })();
  const state: AcceptorStateV3 = {
    listeners: Object.freeze(listeners),
    authorize: options.authorize,
    ...(options.resolveHandlers === undefined ? {} : { resolveHandlers: options.resolveHandlers }),
    admissionReasons,
    admissionTimeoutMs: options.admissionTimeoutMs ?? DEFAULT_ADMISSION_TIMEOUT_MS,
    abort: new AbortController(),
    closed: false,
    listenerCount: listeners.length, maxPendingSessions: options.maxPendingSessions ?? 1024, maxRpcFrameBytes, maxConcurrentRpcRequests,
    admissions: new Set(), pumps: [], ready: new Set(), waiters: new Set(),
  };
  acceptorStatesV3.set(acceptor, state);
  state.pumps = listeners.map((listener, i) => listen(state, listener, ingress[i]!));
  return Object.freeze(acceptor);
}

function createAcceptedSessionV3(
  session: Session,
  handlers: FrozenSessionHandlers,
  authorizationKey: string,
): AcceptedSessionV3 {
  const accepted = new (AcceptedSessionV3 as unknown as { new(): AcceptedSessionV3 })();
  acceptedSessionStatesV3.set(accepted, { session, handlers, authorizationKey });
  return Object.freeze(accepted);
}

function acceptedSessionStateV3(accepted: AcceptedSessionV3): AcceptedSessionStateV3 {
  const state = acceptedSessionStatesV3.get(accepted);
  if (state === undefined) throw new Error("invalid Flowersec v5 accepted session");
  return state;
}

function acceptorState(value: AcceptorV3): AcceptorStateV3 {
  const state = acceptorStatesV3.get(value);
  if (state === undefined) throw new Error("invalid Flowersec v5 acceptor");
  return state;
}

async function listen(state: AcceptorStateV3, listener: ListenerV3, ingress: string): Promise<void> {
  try {
    while (!state.closed) {
      const carrier = await listener.accept({ signal: state.abort.signal });
      if (state.closed || state.ready.size + state.admissions.size >= state.maxPendingSessions) {
        carrier.abort({ code: 6, reason: "admission unavailable" });
        continue;
      }
      const providers = new Set<Promise<unknown>>();
      const work = admit(state, carrier, ingress, providers).then(async value => {
        if (state.closed) { await value.close(); return; }
        const waiter = state.waiters.values().next().value;
        if (waiter !== undefined) { state.waiters.delete(waiter); waiter.resolve(value); return; }
        state.ready.add(value);
        const remove = () => {
          if (!state.ready.delete(value)) return;
          const cleanup = value.close();
          state.admissions.add(cleanup);
          const finish = () => { state.admissions.delete(cleanup); };
          void cleanup.then(finish, finish);
        };
        void value.session.waitTermination().then(remove, remove);
      }, error => {
        const waiter = state.waiters.values().next().value;
        if (waiter !== undefined) { state.waiters.delete(waiter); waiter.reject(error); }
      }).finally(async () => { await Promise.allSettled(providers); });
      state.admissions.add(work);
      const finished = () => { state.admissions.delete(work); };
      void work.then(finished, finished);
    }
  } catch (error) {
    state.listenerError = error;
  } finally {
    if (--state.listenerCount === 0 && !state.closed) {
      for (const waiter of state.waiters) waiter.reject(state.listenerError);
      state.waiters.clear();
    }
  }
}

function validateOptions(options: AcceptorOptionsV3): void {
  if (options.listeners.length === 0 ||
      (options.maxPendingSessions !== undefined && (!Number.isSafeInteger(options.maxPendingSessions) || options.maxPendingSessions < 1 || options.maxPendingSessions > 65536)) ||
      !Number.isSafeInteger(options.maxInboundStreams) || options.maxInboundStreams < 1 ||
      options.maxInboundStreams > 128 || typeof options.authorize !== "function" ||
      (options.admissionTimeoutMs !== undefined &&
        (!Number.isSafeInteger(options.admissionTimeoutMs) ||
          options.admissionTimeoutMs < 1 || options.admissionTimeoutMs > 600_000)) ||
      (options.resolveHandlers !== undefined && typeof options.resolveHandlers !== "function") ||
      options.listeners.some(({ path, carrier }) => path !== "direct" || !["websocket", "raw_quic", "webtransport"].includes(carrier))) {
    throw new TypeError("invalid Flowersec v5 Acceptor options");
  }
}

function linkAbort(source: AbortSignal | undefined, target: AbortController): () => void {
  if (source === undefined) return () => undefined;
  const abort = () => target.abort(source.reason);
  source.addEventListener("abort", abort, { once: true });
  if (source.aborted) abort();
  return () => source.removeEventListener("abort", abort);
}

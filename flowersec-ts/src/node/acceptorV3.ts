import type { OperationOptions, Session } from "../public/contract.js";
import { projectSessionV3 } from "../v3/publicSession.js";
import {
  acceptCarrierSessionV3,
  createAdmissionReasonRegistryV3,
  type AdmissionAuthorizerV3,
} from "../v3/serverAdmission.js";
import { nodeSessionRuntimeV3 } from "../v3/nodeSessionRuntime.js";
import type { CarrierSessionV3 } from "../v3/carrier.js";
import { AdmissionStatusV3, type DecodedFSB3RequestV3 } from "../v3/artifact.js";
import {
  unwrapArtifactHandleV3,
  type ArtifactHandleV3,
} from "../v3/publicApi.js";
import {
  SessionHandlersV3,
  createRPCRouter,
  freezeSessionHandlersV3,
  type FrozenSessionHandlers,
} from "./acceptor.js";
import { serveFrozenStreamHandlers } from "../public/streamHandlers.js";
import {
  createNativeRawQuicDriverV3,
  loadNativeTransportAddon,
} from "./nativeTransportAddon.js";
import {
  startNodeRawQuicListenerV3,
  type NodeRawQuicListenerV3,
} from "./rawQuicServerV3.js";
import {
  startNodeWebSocketListenerV3,
  type NodeWebSocketListenerV3,
} from "./webSocketServerV3.js";

export type AcceptorListenerV3 =
  | Readonly<{
      carrier: "websocket";
      path: "direct";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string; privateKey: string }>;
      allowedOrigins: readonly string[];
    }>
  | Readonly<{
      carrier: "raw_quic";
      path: "direct";
      host: string;
      port: number;
      tls: Readonly<{ certificate: string | Uint8Array; privateKey: string | Uint8Array }>;
    }>;

export type AcceptorOptionsV3 = Readonly<{
  listeners: readonly AcceptorListenerV3[];
  maxInboundStreams: number;
  admissionReasons?: readonly string[];
  authorize: AcceptorAuthorizerV3;
  resolveHandlers?(
    request: DecodedFSB3RequestV3,
    options: OperationOptions,
  ): Promise<SessionHandlersV3> | SessionHandlersV3;
  nowUnixSeconds?: () => number;
}>;

export type AcceptorAuthorizationDecisionV3 =
  | Readonly<{ accepted: true; artifact: ArtifactHandleV3 }>
  | Readonly<{ accepted: false; retryable: boolean; reason: string }>;

export type AcceptorAuthorizerV3 = (
  request: DecodedFSB3RequestV3,
  options: OperationOptions,
) => Promise<AcceptorAuthorizationDecisionV3> | AcceptorAuthorizationDecisionV3;

export class AcceptedSessionV3 {
  private constructor() {}

  get session(): Session {
    return acceptedSessionStateV3(this).session;
  }

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
    if (state.closed) throw new Error("Flowersec v3 acceptor is closed");
    const controller = new AbortController();
    const unlinkExternal = linkAbort(options.signal, controller);
    const unlinkClose = linkAbort(state.abort.signal, controller);
    try {
      const carrier = await acceptAny(state, controller.signal);
      try {
        let handlers: FrozenSessionHandlers | undefined;
        const authorize: AdmissionAuthorizerV3 = async (request, signal) => {
          const decision = await state.authorize(
            request,
            signal === undefined ? {} : { signal },
          );
          if (decision.accepted) {
            return { accepted: true, artifact: unwrapArtifactHandleV3(decision.artifact) };
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
          admissionReasons: state.admissionReasons,
          resolveRPCRouter: async (request, signal) => {
            const registry = state.resolveHandlers === undefined
              ? new SessionHandlersV3()
              : await state.resolveHandlers(request, signal === undefined ? {} : { signal });
            handlers = freezeSessionHandlersV3(registry);
            return createRPCRouter(handlers.rpc);
          },
          ...(state.nowUnixSeconds === undefined ? {} : { nowUnixSeconds: state.nowUnixSeconds }),
          signal: controller.signal,
        });
        if (handlers === undefined) throw new Error("Flowersec v3 handlers were not resolved");
        return createAcceptedSessionV3(projectSessionV3(internal), handlers);
      } catch (error) {
        await carrier.close().catch(() => undefined);
        throw error;
      }
    } finally {
      unlinkExternal();
      unlinkClose();
    }
  }

  async close(): Promise<void> {
    const state = acceptorState(this);
    const existing = closes.get(state);
    if (existing !== undefined) return await existing;
    const closing = (async () => {
      await Promise.resolve();
      state.closed = true;
      state.abort.abort(new Error("Flowersec v3 acceptor closed"));
      const results = await Promise.allSettled(state.listeners.map(async (listener) => await listener.close()));
      if (results.some(({ status }) => status === "rejected")) throw new Error("Flowersec v3 acceptor cleanup failed");
    })();
    closes.set(state, closing);
    return await closing;
  }
}

type ListenerV3 = NodeWebSocketListenerV3 | NodeRawQuicListenerV3;
type AcceptorStateV3 = {
  listeners: readonly ListenerV3[];
  authorize: AcceptorAuthorizerV3;
  resolveHandlers?: AcceptorOptionsV3["resolveHandlers"];
  admissionReasons: ReadonlySet<string>;
  nowUnixSeconds?: () => number;
  abort: AbortController;
  closed: boolean;
  cursor: number;
};
const acceptorStatesV3 = new WeakMap<AcceptorV3, AcceptorStateV3>();
const closes = new WeakMap<AcceptorStateV3, Promise<void>>();
type AcceptedSessionStateV3 = {
  session: Session;
  handlers: FrozenSessionHandlers;
  closePromise?: Promise<void>;
};
const acceptedSessionStatesV3 = new WeakMap<AcceptedSessionV3, AcceptedSessionStateV3>();

export async function createAcceptorV3(options: AcceptorOptionsV3): Promise<AcceptorV3> {
  validateOptions(options);
  const admissionReasons = createAdmissionReasonRegistryV3(
    ["expired_artifact"],
    options.admissionReasons,
  );
  const listeners: ListenerV3[] = [];
  let rawDriver: ReturnType<typeof createNativeRawQuicDriverV3> | undefined;
  try {
    for (const listener of options.listeners) {
      const running = listener.carrier === "websocket"
        ? await startNodeWebSocketListenerV3({
            ...listener,
            inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
          })
        : await startNodeRawQuicListenerV3(
            rawDriver ??= createNativeRawQuicDriverV3(loadNativeTransportAddon()),
            {
              ...listener,
              inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
            },
          );
      listeners.push(running);
    }
  } catch (error) {
    await Promise.allSettled(listeners.map(async (listener) => await listener.close()));
    throw error;
  }
  const acceptor = new (AcceptorV3 as unknown as { new(): AcceptorV3 })();
  acceptorStatesV3.set(acceptor, {
    listeners: Object.freeze(listeners),
    authorize: options.authorize,
    ...(options.resolveHandlers === undefined ? {} : { resolveHandlers: options.resolveHandlers }),
    admissionReasons,
    ...(options.nowUnixSeconds === undefined ? {} : { nowUnixSeconds: options.nowUnixSeconds }),
    abort: new AbortController(),
    closed: false,
    cursor: 0,
  });
  return Object.freeze(acceptor);
}

function createAcceptedSessionV3(
  session: Session,
  handlers: FrozenSessionHandlers,
): AcceptedSessionV3 {
  const accepted = new (AcceptedSessionV3 as unknown as { new(): AcceptedSessionV3 })();
  acceptedSessionStatesV3.set(accepted, { session, handlers });
  return Object.freeze(accepted);
}

function acceptedSessionStateV3(accepted: AcceptedSessionV3): AcceptedSessionStateV3 {
  const state = acceptedSessionStatesV3.get(accepted);
  if (state === undefined) throw new Error("invalid Flowersec v3 accepted session");
  return state;
}

function acceptorState(value: AcceptorV3): AcceptorStateV3 {
  const state = acceptorStatesV3.get(value);
  if (state === undefined) throw new Error("invalid Flowersec v3 acceptor");
  return state;
}

async function acceptAny(state: AcceptorStateV3, signal: AbortSignal): Promise<CarrierSessionV3> {
  if (state.listeners.length === 1) return await state.listeners[0]!.accept({ signal });
  const controller = new AbortController();
  const unlink = linkAbort(signal, controller);
  try {
    return await new Promise<CarrierSessionV3>((resolve, reject) => {
      let settled = false;
      let remaining = state.listeners.length;
      const errors: unknown[] = [];
      state.listeners.forEach((_, index) => {
        const selected = state.listeners[(index + state.cursor) % state.listeners.length]!;
        void selected.accept({ signal: controller.signal }).then((carrier) => {
          if (!settled) {
            settled = true;
            state.cursor = (state.cursor + 1) % state.listeners.length;
            controller.abort(new Error("listener race complete"));
            resolve(carrier);
          } else {
            carrier.abort({ code: 6, reason: "listener race lost" });
          }
        }, (error: unknown) => {
          errors.push(error);
          remaining -= 1;
          if (!settled && remaining === 0) {
            settled = true;
            reject(new AggregateError(errors, "all Flowersec v3 listeners failed"));
          }
        });
      });
    });
  } finally {
    unlink();
  }
}

function validateOptions(options: AcceptorOptionsV3): void {
  if (options.listeners.length === 0 ||
      !Number.isSafeInteger(options.maxInboundStreams) || options.maxInboundStreams < 1 ||
      options.maxInboundStreams > 128 || typeof options.authorize !== "function" ||
      (options.resolveHandlers !== undefined && typeof options.resolveHandlers !== "function") ||
      options.listeners.some(({ path }) => path !== "direct")) {
    throw new TypeError("invalid Flowersec v3 Acceptor options");
  }
}

function linkAbort(source: AbortSignal | undefined, target: AbortController): () => void {
  if (source === undefined) return () => undefined;
  const abort = () => target.abort(source.reason);
  source.addEventListener("abort", abort, { once: true });
  if (source.aborted) abort();
  return () => source.removeEventListener("abort", abort);
}

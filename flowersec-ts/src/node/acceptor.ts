import { sha256 } from "@noble/hashes/sha256";

import { RpcRouter } from "../rpc/server.js";
import type { RpcError as WireRpcError } from "../rpc/wire.js";
import { acceptNativeSessionV2 } from "../connector/sessionAcceptor.js";
import { nodeSessionRuntimeV2 } from "./sessionRuntime.js";
import {
  startNodeWebTransportServerV2,
  type NodeWebTransportServerV2,
} from "./webTransportServer.js";
import { unwrapArtifact, type Artifact } from "../public/artifact.js";
import {
  SessionError,
  type IncomingStream,
  type JsonValue,
  type OperationOptions,
  type Session,
} from "../public/contract.js";
import { projectSessionV2 } from "../v2/publicSession.js";
import type { DecodedFSB2RequestV2 } from "../v2/artifact.js";
import { base64urlEncode } from "../utils/base64url.js";

const DEFAULT_MAX_CONCURRENT_STREAMS = 64;
const MAX_CONCURRENT_STREAMS = 128;
const encoder = new TextEncoder();

export class RuntimeAuthorizationRequest {
  declare private readonly requestBrand: void;
  private constructor(readonly lookupKey: string) {}
}

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
    state.rpc.set(typeId, handler);
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
  return Object.freeze({
    maxConcurrentStreams: state.maxConcurrentStreams,
    streams: new Map(state.streams),
  });
}

type FrozenHandlers = Readonly<{
  maxConcurrentStreams: number;
  streams: ReadonlyMap<string, StreamHandler>;
}>;

export type AcceptorOptions = Readonly<{
  host: string;
  port: number;
  path: string;
  certificate: string;
  privateKey: string;
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
        const task = handler(incoming, options)
          .finally(() => incoming.stream.close())
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

  address(): Readonly<{ host: string; port: number }> {
    return acceptorState(this).server.address();
  }

  async accept(operation: OperationOptions = {}): Promise<AcceptedSession> {
    const state = acceptorState(this);
    const carrier = await state.server.accept(operation);
    const router = new RpcRouter();
    let handlers: FrozenHandlers | undefined;
    const internal = await acceptNativeSessionV2(
      carrier,
      async (decoded, signal) => {
        const request = runtimeAuthorizationRequest(decoded);
        const decision = await state.options.authorize(request, signal === undefined ? {} : { signal });
        if (decision.decision !== "allow") {
          return {
            accepted: false,
            status: decision.decision === "retry" ? 2 : 1,
            reason: decision.reason,
          };
        }
        const registry = state.options.resolveHandlers === undefined
          ? new SessionHandlers()
          : await state.options.resolveHandlers(request, signal === undefined ? {} : { signal });
        handlers = freezeHandlers(registry, router);
        return { accepted: true, artifact: unwrapArtifact(decision.artifact) };
      },
      {
        runtime: nodeSessionRuntimeV2,
        rpcRouter: router,
        ...(operation.signal === undefined ? {} : { signal: operation.signal }),
      },
    );
    if (handlers === undefined) {
      await internal.close().catch(() => undefined);
      throw new SessionError("operation_failed");
    }
    return createAcceptedSession(projectSessionV2(internal), handlers);
  }

  async close(): Promise<void> {
    await acceptorState(this).server.close();
  }
}

type AcceptorState = Readonly<{ server: NodeWebTransportServerV2; options: AcceptorOptions }>;
const acceptorStates = new WeakMap<Acceptor, AcceptorState>();

function acceptorState(acceptor: Acceptor): AcceptorState {
  const state = acceptorStates.get(acceptor);
  if (state === undefined) throw new SessionError("operation_failed");
  return state;
}

export async function createAcceptor(options: AcceptorOptions): Promise<Acceptor> {
  if (!Number.isSafeInteger(options.maxInboundStreams) || options.maxInboundStreams < 1 || options.maxInboundStreams > 128) {
    throw new TypeError("invalid Flowersec Acceptor options");
  }
  const server = await startNodeWebTransportServerV2({
    host: options.host,
    port: options.port,
    path: options.path,
    certificate: options.certificate,
    privateKey: options.privateKey,
    carrierPath: "direct",
    inboundBidirectionalStreamCapacity: options.maxInboundStreams + 2,
  });
  const acceptor = new (Acceptor as unknown as { new(): Acceptor })();
  acceptorStates.set(acceptor, { server, options });
  return Object.freeze(acceptor);
}

function runtimeAuthorizationRequest(decoded: DecodedFSB2RequestV2): RuntimeAuthorizationRequest {
  const credential = decoded.request.pathKind === "direct"
    ? decoded.request.routing_token
    : decoded.request.attach_token;
  const lookupKey = base64urlEncode(sha256(encoder.encode(credential)));
  return new (RuntimeAuthorizationRequest as unknown as { new(lookupKey: string): RuntimeAuthorizationRequest })(lookupKey);
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

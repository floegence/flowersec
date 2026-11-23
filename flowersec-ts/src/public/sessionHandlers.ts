import { RpcRouter, type RpcHandler as WireHandler } from "../rpc/server.js";
import type { RpcError as WireRpcError } from "../rpc/wire.js";
import { assertRpcError, assertRpcTypeId } from "../rpc/validate.js";
import type { JsonValue } from "./contract.js";
import {
  HandlerRegistrationError,
  StreamHandlers,
  freezeStreamHandlers,
  registerStreamHandlersAtomically,
  type FrozenStreamHandlers,
  type StreamHandler,
  type StreamHandlerOptions,
} from "../public/streamHandlers.js";

export { HandlerRegistrationError } from "../public/streamHandlers.js";
export type { StreamHandler } from "../public/streamHandlers.js";

export type RPCHandlerResult =
  | Readonly<{ payload: JsonValue }>
  | Readonly<{ error: Readonly<{ code: number; message?: string }> }>;

type HandlerRequest = Readonly<{ typeId: number; signal?: AbortSignal; context?: object }>;

export type RPCHandler = (payload: JsonValue, request: HandlerRequest) => Promise<RPCHandlerResult>;

export type NotificationHandler = (
  payload: JsonValue,
  request: HandlerRequest,
) => Promise<void> | void;

export type SessionHandlerOptions = StreamHandlerOptions;
const bindingKey = Symbol("session handler binding");
export type SessionHandlerBinding<T> = Readonly<{ [bindingKey]: Readonly<{ handlers: T; context: object }> }>;

export class RPCHandlers {
  constructor() {
    rpcHandlerStates.set(this, createRPCHandlerState());
  }

  /** Bind local state for one connect or accepted session. Reuse the registry across sessions. */
  forSession(context: object): SessionHandlerBinding<this> {
    if (typeof context !== "object" || context === null) throw new HandlerRegistrationError("invalid_handler");
    return Object.freeze({ [bindingKey]: Object.freeze({ handlers: this, context }) });
  }

  handleRPC(typeId: number, handler: RPCHandler): void {
    registerRPC(mutableRPCHandlerState(this), typeId, handler);
  }

  handleNotification(typeId: number, handler: NotificationHandler): void {
    registerNotification(mutableRPCHandlerState(this), typeId, handler);
  }
}

export class SessionHandlersV3 extends RPCHandlers {
  declare private readonly streamHandlerRegistrarBrand: void;
  declare private readonly sessionHandlersV3Brand: void;

  constructor(options: SessionHandlerOptions = {}) {
    super();
    sessionHandlerStates.set(this, {
      streams: new StreamHandlers(options),
      frozen: false,
    });
  }

  handleStream(kind: string, handler: StreamHandler): void {
    const state = mutableSessionHandlerState(this);
    state.streams.handleStream(kind, handler);
  }
}

type RPCHandlerState = {
  requests: Map<number, WireHandler>;
  notifications: Map<number, WireNotification>;
  frozen: boolean;
  snapshot?: FrozenRPCHandlers;
};

type SessionHandlerState = {
  streams: StreamHandlers;
  frozen: boolean;
  snapshot?: FrozenSessionHandlers;
};

const rpcHandlerStates = new WeakMap<RPCHandlers, RPCHandlerState>();
const sessionHandlerStates = new WeakMap<SessionHandlersV3, SessionHandlerState>();

function createRPCHandlerState(): RPCHandlerState {
  return { requests: new Map(), notifications: new Map(), frozen: false };
}

function mutableRPCHandlerState(handlers: RPCHandlers): RPCHandlerState {
  const state = rpcHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.frozen) throw new HandlerRegistrationError("frozen");
  return state;
}

function mutableSessionHandlerState(
  handlers: SessionHandlersV3,
): SessionHandlerState {
  const state = sessionHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.frozen) throw new HandlerRegistrationError("frozen");
  return state;
}

/** @internal */
export function registerSessionStreamHandlersAtomically(
  handlers: SessionHandlersV3,
  entries: readonly (readonly [string, StreamHandler])[],
): void {
  const state = mutableSessionHandlerState(handlers);
  registerStreamHandlersAtomically(state.streams, entries);
}

function registerRPC(
  state: RPCHandlerState,
  typeId: number,
  handler: RPCHandler,
): void {
  validateRPCRegistration(typeId, handler);
  if (state.requests.has(typeId) || state.notifications.has(typeId)) {
    throw new HandlerRegistrationError("already_registered");
  }
  state.requests.set(typeId, async (payload, signal, context) => {
    const result = await handler(payload as JsonValue, handlerRequest(typeId, signal, context));
    return "error" in result ? { payload: null, error: validRPCError(result.error) } : { payload: result.payload };
  });
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
  state.notifications.set(typeId, (payload, signal, context) => handler(payload as JsonValue, handlerRequest(typeId, signal, context)));
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

type WireNotification = (payload: unknown, signal?: AbortSignal, context?: object) => void | Promise<void>;
export type FrozenRPCHandlers = Readonly<{
  requests: ReadonlyMap<number, WireHandler>;
  notifications: ReadonlyMap<number, WireNotification>;
  context?: object;
}>;

function handlerRequest(typeId: number, signal?: AbortSignal, context?: object): HandlerRequest {
  return Object.freeze({ typeId, ...(signal && { signal }), ...(context && { context }) });
}

/** @internal */
export function freezeRPCHandlers(handlers: RPCHandlers | SessionHandlerBinding<RPCHandlers>): FrozenRPCHandlers {
  if (!(handlers instanceof RPCHandlers)) {
    const bound = readBinding(handlers, RPCHandlers);
    return Object.freeze({ ...freezeRPCHandlers(bound.handlers), context: bound.context });
  }
  const state = rpcHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  return freezeRPCHandlerState(state);
}

function freezeRPCHandlerState(state: RPCHandlerState): FrozenRPCHandlers {
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    requests: state.requests,
    notifications: state.notifications,
  });
  return state.snapshot;
}

/** @internal */
export function createRPCRouter(snapshot: FrozenRPCHandlers): RpcRouter {
  return new RpcRouter(snapshot);
}

/** @internal */
export function freezeSessionHandlersV3(
  handlers: SessionHandlersV3 | SessionHandlerBinding<SessionHandlersV3>,
): FrozenSessionHandlers {
  if (!(handlers instanceof SessionHandlersV3)) {
    const bound = readBinding(handlers, SessionHandlersV3);
    const shared = freezeSessionHandlersV3(bound.handlers);
    return Object.freeze({ streams: shared.streams, rpc: Object.freeze({ ...shared.rpc, context: bound.context }) });
  }
  const state = sessionHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    rpc: freezeRPCHandlers(handlers),
    streams: freezeStreamHandlers(state.streams),
  });
  return state.snapshot;
}

function readBinding<T>(binding: SessionHandlerBinding<T>, registry: abstract new (...args: never[]) => T) {
  const bound = binding?.[bindingKey];
  if (!(bound?.handlers instanceof registry)) {
    throw new HandlerRegistrationError("invalid_handler");
  }
  return bound;
}

/** @internal */
export type FrozenSessionHandlers = Readonly<{
  rpc: FrozenRPCHandlers;
  streams: FrozenStreamHandlers;
}>;

function validRPCError(
  error: Readonly<{ code: number; message?: string }>,
): WireRpcError {
  try {
    return assertRpcError(error);
  } catch {
    return { code: 500, message: "handler failed" };
  }
}

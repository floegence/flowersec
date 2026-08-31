import { RpcRouter } from "../rpc/server.js";
import type { RpcError as WireRpcError } from "../rpc/wire.js";
import { assertRpcError, assertRpcTypeId } from "../rpc/validate.js";
import type { JsonValue } from "../public/contract.js";
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

export class SessionHandlersV3 {
  declare private readonly streamHandlerRegistrarBrand: void;
  declare private readonly sessionHandlersV3Brand: void;

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
      const result = await handler(payload as JsonValue, Object.freeze({ typeId }));
      if ("error" in result) {
        return { payload: null, error: validRPCError(result.error) };
      }
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

/** @internal */
export function freezeSessionHandlersV3(
  handlers: SessionHandlersV3,
): FrozenSessionHandlers {
  if (!(handlers instanceof SessionHandlersV3)) {
    throw new HandlerRegistrationError("invalid_handler");
  }
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

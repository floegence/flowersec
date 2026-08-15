import {
  SessionError,
  type IncomingStream,
  type OperationOptions,
  type Session,
} from "./contract.js";
import { validApplicationStreamKind } from "../v2/protocol.js";

const DEFAULT_MAX_CONCURRENT_STREAMS = 64;
const MAX_CONCURRENT_STREAMS = 128;

export type StreamHandler = (
  incoming: IncomingStream,
  options: OperationOptions,
) => Promise<void>;

export type StreamHandlerOptions = Readonly<{
  maxConcurrentStreams?: number;
}>;

export class HandlerRegistrationError extends Error {
  constructor(
    readonly code: "invalid_handler" | "already_registered" | "frozen",
  ) {
    super(`Flowersec handler registration failed (code=${code})`);
    this.name = "HandlerRegistrationError";
  }
}

type StreamHandlerState = {
  maxConcurrentStreams: number;
  streams: Map<string, StreamHandler>;
  frozen: boolean;
  snapshot?: FrozenStreamHandlers;
};

export type FrozenStreamHandlers = Readonly<{
  maxConcurrentStreams: number;
  streams: ReadonlyMap<string, StreamHandler>;
}>;

const streamHandlerStates = new WeakMap<StreamHandlers, StreamHandlerState>();

/** Carrier-neutral application-stream handlers for any established Session. */
export class StreamHandlers {
  declare private readonly streamHandlerRegistrarBrand: void;

  constructor(options: StreamHandlerOptions = {}) {
    const maximum =
      options.maxConcurrentStreams ?? DEFAULT_MAX_CONCURRENT_STREAMS;
    if (
      !Number.isSafeInteger(maximum) ||
      maximum < 1 ||
      maximum > MAX_CONCURRENT_STREAMS
    ) {
      throw new HandlerRegistrationError("invalid_handler");
    }
    streamHandlerStates.set(this, {
      maxConcurrentStreams: maximum,
      streams: new Map(),
      frozen: false,
    });
  }

  handleStream(kind: string, handler: StreamHandler): void {
    registerStreamHandlersAtomically(this, [[kind, handler]]);
  }

  async serve(session: Session, options: OperationOptions = {}): Promise<void> {
    if (session === null || typeof session !== "object") {
      throw new HandlerRegistrationError("invalid_handler");
    }
    await serveFrozenStreamHandlers(
      freezeStreamHandlers(this),
      session,
      options,
      async () => await session.close(),
    );
  }
}

function mutableStreamHandlerState(handlers: StreamHandlers): StreamHandlerState {
  const state = streamHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.frozen) throw new HandlerRegistrationError("frozen");
  return state;
}

function registerIntoState(
  state: StreamHandlerState,
  entries: readonly (readonly [string, StreamHandler])[],
): void {
  if (entries.length === 0) throw new HandlerRegistrationError("invalid_handler");
  const pending = new Set<string>();
  for (const [kind, handler] of entries) {
    if (
      !validApplicationStreamKind(kind) ||
      kind === "flowersec.rpc.v2" ||
      typeof handler !== "function"
    ) {
      throw new HandlerRegistrationError("invalid_handler");
    }
    if (state.streams.has(kind) || pending.has(kind)) {
      throw new HandlerRegistrationError("already_registered");
    }
    pending.add(kind);
  }
  for (const [kind, handler] of entries) state.streams.set(kind, handler);
}

/** @internal */
export function registerStreamHandlersAtomically(
  handlers: StreamHandlers,
  entries: readonly (readonly [string, StreamHandler])[],
): void {
  registerIntoState(mutableStreamHandlerState(handlers), entries);
}

/** @internal */
export function freezeStreamHandlers(
  handlers: StreamHandlers,
): FrozenStreamHandlers {
  const state = streamHandlerStates.get(handlers);
  if (state === undefined) throw new HandlerRegistrationError("invalid_handler");
  if (state.snapshot !== undefined) return state.snapshot;
  state.frozen = true;
  state.snapshot = Object.freeze({
    maxConcurrentStreams: state.maxConcurrentStreams,
    streams: new Map(state.streams),
  });
  return state.snapshot;
}

/** @internal */
export async function serveFrozenStreamHandlers(
  snapshot: FrozenStreamHandlers,
  session: Session,
  options: OperationOptions,
  close: () => Promise<void>,
): Promise<void> {
  const active = new Set<Promise<void>>();
  const controller = new AbortController();
  const abortFromCaller = (): void => controller.abort(options.signal?.reason);
  if (options.signal?.aborted === true) abortFromCaller();
  else options.signal?.addEventListener("abort", abortFromCaller, { once: true });
  const handlerOptions: OperationOptions = Object.freeze({
    signal: controller.signal,
  });
  try {
    while (true) {
      if (controller.signal.aborted) throw new SessionError("canceled");
      const incoming = await session.acceptStream(handlerOptions);
      const handler = snapshot.streams.get(incoming.kind);
      if (
        handler === undefined ||
        active.size >= snapshot.maxConcurrentStreams
      ) {
        await incoming.stream.reset();
        continue;
      }
      const task = (async () => {
        try {
          await handler(incoming, handlerOptions);
          await incoming.stream.closeWrite();
        } catch {
          await incoming.stream.reset().catch(() => undefined);
        }
      })().finally(() => active.delete(task));
      active.add(task);
    }
  } finally {
    options.signal?.removeEventListener("abort", abortFromCaller);
    controller.abort(new SessionError("closed"));
    await close().catch(() => undefined);
    await Promise.allSettled(active);
  }
}

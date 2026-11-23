import type {
  ByteStreamV3,
  IncomingStreamV3,
  InternalByteStreamV3,
  InternalSessionV3,
  JsonValueV3,
  OperationOptionsV3,
  RpcPeerV3,
  RpcResultV3,
  SessionErrorCode,
  SessionV3,
  StreamOpenOptionsV3,
} from "./contract.js";
import { SessionError } from "./contract.js";
import { createStreamMetadataV3, streamMetadataValuesV3 } from "./streamMetadata.js";
import { assertRpcTypeId } from "../rpc/validate.js";

const internals = new WeakMap<SessionV3, InternalSessionV3>();
/** @internal Read the actual session and stream owners for the capacity inventory. */
export function sessionInventory(session: SessionV3) {
  const value = internals.get(session)?.runtimeInventory?.();
  if (!value) throw new Error("session inventory unavailable");
  return value;
}

/** @internal */
export function projectSessionV3(session: InternalSessionV3): SessionV3 {
  const notificationOwner: NotificationSubscriptionOwner = {
    lifetime: new AbortController(),
    subscriptions: new Set(),
    closed: false,
  };
  const clearNotificationSubscriptions = () => {
    notificationOwner.closed = true;
    notificationOwner.lifetime.abort();
    for (const unsubscribe of [...notificationOwner.subscriptions]) unsubscribe();
  };
  const rpc = projectRpcPeerV3(session.rpc, notificationOwner);
  const unreliable = session.unreliableMessages;
  let terminationWaiters: Set<() => void> | undefined;
  let terminated = false;
  const finishTermination = () => {
    terminated = true;
    clearNotificationSubscriptions();
    terminationWaiters?.forEach(wake => wake());
    terminationWaiters = undefined;
  };
  void session.termination.then(finishTermination, finishTermination);
  const projected: SessionV3 = Object.freeze({
    rpc,
    ...(unreliable === undefined ? {} : { unreliableMessages: unreliable }),
    async openStream(kind: string, options?: StreamOpenOptionsV3): Promise<ByteStreamV3> {
      try {
        const internalOptions = options === undefined ? undefined : {
          ...(options.signal === undefined ? {} : { signal: options.signal }),
          ...(options.metadata === undefined ? {} : { metadata: streamMetadataValuesV3(options.metadata) }),
        };
        return projectByteStreamV3(await session.openStream(kind, internalOptions));
      } catch (error) {
        throw redactSessionError(error, options?.signal);
      }
    },
    async acceptStream(options?: OperationOptionsV3): Promise<IncomingStreamV3> {
      try {
        const incoming = await session.acceptStream(options);
        return Object.freeze({
          kind: incoming.kind,
          metadata: createStreamMetadataV3(incoming.metadata),
          stream: projectByteStreamV3(incoming.stream),
        });
      } catch (error) {
        throw redactSessionError(error, options?.signal);
      }
    },
    async rekey(options?: OperationOptionsV3): Promise<void> {
      try { await session.rekey(options); } catch (error) { throw redactSessionError(error, options?.signal); }
    },
    async probeLiveness(options?: OperationOptionsV3): Promise<number> {
      try { return await session.probeLiveness(options); } catch (error) { throw redactSessionError(error, options?.signal); }
    },
    async waitTermination(options?: OperationOptionsV3) {
      const signal = options?.signal;
      try {
        signal?.throwIfAborted();
        // A canceled observer must not stay attached to a long-lived session promise.
        if (signal && !terminated) await new Promise<void>((resolve, reject) => {
          const wake = () => { signal.removeEventListener("abort", abort); resolve(); };
          const abort = () => { terminationWaiters?.delete(wake); reject(signal.reason); };
          (terminationWaiters ??= new Set()).add(wake);
          signal.addEventListener("abort", abort, { once: true });
        });
        const end = await session.termination;
        return Object.freeze({ error: redactSessionError(end.error), ...(end.peerCloseReceived && { peerCloseReceived: true as const }) });
      } catch (error) {
        throw redactSessionError(error, signal);
      }
    },
    async close(): Promise<void> {
      clearNotificationSubscriptions();
      try { await session.close(); } catch (error) { throw redactSessionError(error); }
    },
  });
  internals.set(projected, session);
  return projected;
}

function projectByteStreamV3(stream: InternalByteStreamV3): ByteStreamV3 {
  return Object.freeze({
    kind: stream.kind,
    get terminalError() {
      return stream.terminalError === undefined ? undefined : redactSessionError(stream.terminalError);
    },
    async read(options?: OperationOptionsV3) {
      try { return await stream.read(options); } catch (error) { throw redactSessionError(error, options?.signal); }
    },
    async write(data: Uint8Array, options?: OperationOptionsV3) {
      try { return await stream.write(data, options); } catch (error) { throw redactSessionError(error, options?.signal); }
    },
    async closeWrite() {
      try { await stream.closeWrite(); } catch (error) { throw redactSessionError(error); }
    },
    async reset() {
      try { await stream.reset(); } catch (error) { throw redactSessionError(error); }
    },
    async close() {
      try { await stream.close(); } catch (error) { throw redactSessionError(error); }
    },
  });
}

function projectRpcPeerV3(
  peer: InternalSessionV3["rpc"],
  notificationOwner: NotificationSubscriptionOwner,
): RpcPeerV3 {
  return Object.freeze({
    async call<Request extends JsonValueV3 = JsonValueV3, Response = unknown>(
      typeId: number,
      payload: Request,
      decodeResponse: (payload: JsonValueV3) => Response,
      options?: OperationOptionsV3,
    ): Promise<RpcResultV3<Response>> {
      try {
        options?.signal?.throwIfAborted();
        assertRpcTypeId(typeId);
        assertJsonValue(payload);
        const result = await peer.call(typeId, payload, options?.signal);
        if (result.error !== undefined) {
          return Object.freeze({ ok: false as const, error: Object.freeze({ ...result.error }) });
        }
        assertJsonValue(result.payload);
        return Object.freeze({ ok: true as const, payload: decodeResponse(result.payload) });
      } catch (error) {
        throw redactSessionError(error, options?.signal);
      }
    },
    async notify<Payload extends JsonValueV3 = JsonValueV3>(
      typeId: number,
      payload: Payload,
      options?: OperationOptionsV3,
    ) {
      try {
        options?.signal?.throwIfAborted();
        assertRpcTypeId(typeId);
        assertJsonValue(payload);
        await raceWithSignal(peer.notify(typeId, payload, options?.signal), options?.signal);
      } catch (error) { throw redactSessionError(error, options?.signal); }
    },
    onNotify<Payload>(
      typeId: number,
      decodePayload: (payload: JsonValueV3) => Payload,
      handler: (payload: Payload) => void | Promise<void>,
    ) {
      assertRpcTypeId(typeId);
      if (notificationOwner.closed) return () => undefined;
      let subscribed = true;
      const unsubscribe = peer.onNotify(typeId, async (payload) => {
        if (!subscribed) return;
        let decoded: Payload;
        try {
          assertJsonValue(payload);
          decoded = decodePayload(payload);
        } catch {
          return;
        }
        if (!subscribed) return;
        try {
          await raceWithSignal(Promise.resolve(handler(decoded)), notificationOwner.lifetime.signal);
        } catch {
          // Notification handlers are isolated from RPC serving.
        }
      });
      const cancel = () => {
        if (!subscribed) return;
        subscribed = false;
        notificationOwner.subscriptions.delete(cancel);
        unsubscribe();
      };
      notificationOwner.subscriptions.add(cancel);
      return cancel;
    },
  });
}

type NotificationSubscriptionOwner = {
  lifetime: AbortController;
  subscriptions: Set<() => void>;
  closed: boolean;
};

function assertJsonValue(value: unknown): asserts value is JsonValueV3 {
  validateJsonValue(value, new Set<object>());
}

function validateJsonValue(value: unknown, ancestors: Set<object>): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (Number.isFinite(value)) return;
    throw new TypeError("RPC payload contains a non-finite number");
  }
  if (typeof value !== "object") throw new TypeError("RPC payload is not a JSON value");
  if (ancestors.has(value)) throw new TypeError("RPC payload contains a cycle");

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) throw new TypeError("RPC payload contains a sparse array");
        validateJsonValue(value[index], ancestors);
      }
      return;
    }
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("RPC payload contains a non-JSON object");
    }
    for (const key of Object.keys(value)) {
      validateJsonValue((value as Record<string, unknown>)[key], ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

async function raceWithSignal<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await operation;
  if (signal.aborted) {
    void operation.catch(() => undefined);
    throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
  }
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason ?? new DOMException("The operation was aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    void operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

function redactSessionError(error: unknown, signal?: AbortSignal): SessionError {
  if (signal?.aborted && error === signal.reason) {
    return new SessionError(error instanceof Error && error.name === "TimeoutError" ? "timeout" : "canceled");
  }
  if (error instanceof SessionError) return error;
  return new SessionError(sessionErrorCode(error));
}

function sessionErrorCode(error: unknown): SessionErrorCode {
  if (error instanceof DOMException && error.name === "AbortError") return "canceled";
  if (error instanceof Error) {
    if (error.name === "AbortError") return "canceled";
    if (error.name === "TimeoutError") return "timeout";
    const code = (error as Error & { code?: unknown }).code;
    if (error.name === "CarrierError" || typeof code === "string") {
      if (code === "closed" || code === "carrier_closed") return "closed";
      if (code === "aborted" || code === "operation_aborted") return "canceled";
      if (code === "reset" || code === "stream_reset") return "stream_reset";
    }
    if (error.name === "SessionV3Error") {
      const code = (error as Error & { code?: unknown }).code;
      switch (code) {
        case "aborted": return "canceled";
        case "timeout": return "timeout";
        case "closed": return "closed";
        case "going_away": return "going_away";
        case "open_rejected": return "stream_rejected";
        case "stream_reset": return "stream_reset";
        case "resource_exhausted": return "resource_exhausted";
        case "rekey_failed": return "rekey_failed";
        case "liveness_failed": return "liveness_failed";
        default: return "operation_failed";
      }
    }
  }
  return "operation_failed";
}

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

/** @internal */
export function projectSessionV3(session: InternalSessionV3): SessionV3 {
  const notificationOwner: NotificationSubscriptionOwner = {
    subscriptions: new Set(),
    closed: false,
  };
  const clearNotificationSubscriptions = () => {
    notificationOwner.closed = true;
    for (const unsubscribe of [...notificationOwner.subscriptions]) unsubscribe();
  };
  const rpc = projectRpcPeerV3(session.rpc, notificationOwner);
  const unreliable = session.unreliableMessages;
  void session.termination.then(
    clearNotificationSubscriptions,
    clearNotificationSubscriptions,
  );
  return Object.freeze({
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
        throw redactSessionError(error);
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
        throw redactSessionError(error);
      }
    },
    async rekey(options?: OperationOptionsV3): Promise<void> {
      try { await session.rekey(options); } catch (error) { throw redactSessionError(error); }
    },
    async probeLiveness(options?: OperationOptionsV3): Promise<number> {
      try { return await session.probeLiveness(options); } catch (error) { throw redactSessionError(error); }
    },
    async waitTermination(options?: OperationOptionsV3) {
      try {
        const { error } = await raceWithSignal(session.waitTermination(), options?.signal);
        return Object.freeze({ error: redactSessionError(error) });
      } catch (error) {
        throw redactSessionError(error);
      }
    },
    async close(): Promise<void> {
      try { await session.close(); } catch (error) { throw redactSessionError(error); }
      finally { clearNotificationSubscriptions(); }
    },
  });
}

function projectByteStreamV3(stream: InternalByteStreamV3): ByteStreamV3 {
  return Object.freeze({
    kind: stream.kind,
    get terminalError() {
      return stream.terminalError === undefined ? undefined : redactSessionError(stream.terminalError);
    },
    async read(options?: OperationOptionsV3) {
      try { return await stream.read(options); } catch (error) { throw redactSessionError(error); }
    },
    async write(data: Uint8Array, options?: OperationOptionsV3) {
      try { return await stream.write(data, options); } catch (error) { throw redactSessionError(error); }
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
        assertRpcTypeId(typeId);
        assertJsonValue(payload);
        const result = await peer.call(typeId, payload, options?.signal);
        if (result.error !== undefined) {
          return Object.freeze({ ok: false as const, error: Object.freeze({ ...result.error }) });
        }
        assertJsonValue(result.payload);
        return Object.freeze({ ok: true as const, payload: decodeResponse(result.payload) });
      } catch (error) {
        throw redactSessionError(error);
      }
    },
    async notify<Payload extends JsonValueV3 = JsonValueV3>(
      typeId: number,
      payload: Payload,
      options?: OperationOptionsV3,
    ) {
      try {
        assertRpcTypeId(typeId);
        assertJsonValue(payload);
        if (options?.signal?.aborted) throw options.signal.reason ?? new DOMException("The operation was aborted", "AbortError");
        await raceWithSignal(peer.notify(typeId, payload, options?.signal), options?.signal);
      } catch (error) { throw redactSessionError(error); }
    },
    onNotify<Payload>(
      typeId: number,
      decodePayload: (payload: JsonValueV3) => Payload,
      handler: (payload: Payload) => void | Promise<void>,
    ) {
      assertRpcTypeId(typeId);
      if (notificationOwner.closed) return () => undefined;
      const unsubscribe = peer.onNotify(typeId, (payload) => {
        let decoded: Payload;
        try {
          assertJsonValue(payload);
          decoded = decodePayload(payload);
        } catch {
          return;
        }
        try {
          void Promise.resolve(handler(decoded)).catch(() => undefined);
        } catch {
          // Notification handlers are isolated from RPC serving.
        }
      });
      let subscribed = true;
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
  if (signal.aborted) throw signal.reason ?? new DOMException("The operation was aborted", "AbortError");
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason ?? new DOMException("The operation was aborted", "AbortError"));
    signal.addEventListener("abort", abort, { once: true });
    void operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

function redactSessionError(error: unknown): SessionError {
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

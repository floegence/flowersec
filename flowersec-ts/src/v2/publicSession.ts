import type {
  ByteStreamV2,
  IncomingStreamV2,
  InternalByteStreamV2,
  InternalSessionV2,
  OperationOptionsV2,
  RpcPeerV2,
  SessionErrorCode,
  SessionV2,
  StreamOpenOptionsV2,
} from "./contract.js";
import { SessionError } from "./contract.js";

/** @internal */
export function projectSessionV2(session: InternalSessionV2): SessionV2 {
  const rpc = projectRpcPeerV2(session.rpc);
  const termination = session.termination.then(({ error }) => ({ error: redactSessionError(error) }));
  return Object.freeze({
    rpc,
    termination,
    async openStream(kind: string, options?: StreamOpenOptionsV2): Promise<ByteStreamV2> {
      try {
        return projectByteStreamV2(await session.openStream(kind, options));
      } catch (error) {
        throw redactSessionError(error);
      }
    },
    async acceptStream(options?: OperationOptionsV2): Promise<IncomingStreamV2> {
      try {
        const incoming = await session.acceptStream(options);
        return Object.freeze({
          kind: incoming.kind,
          metadata: incoming.metadata,
          stream: projectByteStreamV2(incoming.stream),
        });
      } catch (error) {
        throw redactSessionError(error);
      }
    },
    async rekey(options?: OperationOptionsV2): Promise<void> {
      try { await session.rekey(options); } catch (error) { throw redactSessionError(error); }
    },
    async probeLiveness(options?: OperationOptionsV2): Promise<number> {
      try { return await session.probeLiveness(options); } catch (error) { throw redactSessionError(error); }
    },
    async waitClosed() {
      const { error } = await session.waitClosed();
      return Object.freeze({ error: redactSessionError(error) });
    },
    async close(): Promise<void> {
      try { await session.close(); } catch (error) { throw redactSessionError(error); }
    },
  });
}

function projectByteStreamV2(stream: InternalByteStreamV2): ByteStreamV2 {
  return Object.freeze({
    kind: stream.kind,
    get terminalError() {
      return stream.terminalError === undefined ? undefined : redactSessionError(stream.terminalError);
    },
    async read(options?: OperationOptionsV2) {
      try { return await stream.read(options); } catch (error) { throw redactSessionError(error); }
    },
    async write(data: Uint8Array, options?: OperationOptionsV2) {
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

function projectRpcPeerV2(peer: InternalSessionV2["rpc"]): RpcPeerV2 {
  return Object.freeze({
    async call(typeId: number, payload: unknown, signal?: AbortSignal) {
      try { return await peer.call(typeId, payload, signal); } catch (error) { throw redactSessionError(error); }
    },
    async notify(typeId: number, payload: unknown) {
      try { await peer.notify(typeId, payload); } catch (error) { throw redactSessionError(error); }
    },
    onNotify(typeId: number, handler: (payload: unknown) => void) {
      return peer.onNotify(typeId, handler);
    },
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
    if (error.name === "SessionV2Error") {
      const code = (error as Error & { code?: unknown }).code;
      switch (code) {
        case "aborted": return "canceled";
        case "timeout": return "timeout";
        case "closed": return "closed";
        case "going_away": return "going_away";
        case "open_rejected": return "stream_rejected";
        case "resource_exhausted": return "resource_exhausted";
        default: return "operation_failed";
      }
    }
  }
  return "operation_failed";
}

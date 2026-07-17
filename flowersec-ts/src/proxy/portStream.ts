import type { YamuxStream } from "../yamux/stream.js";

import {
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_END_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
  type ProxyWindowStreamChunkMsg,
  type ProxyWindowStreamCloseMsg,
  type ProxyWindowStreamResetMsg,
  type ProxyWindowStreamWriteAckMsg,
} from "./windowBridgeProtocol.js";

function cloneChunk(chunk: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(chunk.byteLength);
  out.set(chunk);
  return out.buffer;
}

function validWriteId(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

type QueuedRead = Readonly<{
  chunk: Uint8Array;
  writeId: number;
}>;

type ReadResult = QueuedRead | null | Error;

type PendingAcknowledgement = Readonly<{
  writeId: number;
  resolve: () => void;
  reject: (error: Error) => void;
}>;

export function createMessagePortBackedStream(
  port: MessagePort,
  opts: Readonly<{ maxBufferedBytes?: number; onTerminal?: () => void }> = {},
): YamuxStream {
  let closed = false;
  let acceptingWrites = true;
  let error: Error | null = null;
  const queue: QueuedRead[] = [];
  const waiters: Array<(value: ReadResult) => void> = [];
  let pendingInboundWriteId: number | null = null;
  let pendingOutboundAcknowledgement: PendingAcknowledgement | null = null;
  let nextWriteId = 1;
  let writeTail: Promise<void> = Promise.resolve();
  let queuedWriteBytes = 0;
  const maxBufferedBytes = opts.maxBufferedBytes ?? 4 * (1 << 20);
  let terminalNotified = false;

  const notifyTerminal = () => {
    if (terminalNotified) return;
    terminalNotified = true;
    opts.onTerminal?.();
  };

  const closePort = () => {
    try {
      port.close();
    } catch {
      // Best-effort.
    }
  };

  const drainWaiters = (value: ReadResult) => {
    for (const waiter of waiters.splice(0)) waiter(value);
  };

  const terminateWithError = (err: Error, notifyPeer: boolean) => {
    if (error != null) return;
    error = err;
    closed = true;
    acceptingWrites = false;
    queue.length = 0;
    pendingInboundWriteId = null;
    drainWaiters(err);
    pendingOutboundAcknowledgement?.reject(err);
    pendingOutboundAcknowledgement = null;
    if (notifyPeer) {
      try {
        port.postMessage({
          type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
          message: err.message,
        } satisfies ProxyWindowStreamResetMsg);
      } catch {
        // The local error remains authoritative.
      }
    }
    closePort();
    notifyTerminal();
  };

  const failProtocol = (message: string) => {
    terminateWithError(new Error(`proxy Window stream protocol error: ${message}`), true);
  };

  const finishClosed = () => {
    if (closed) return;
    if (pendingInboundWriteId != null) {
      failProtocol("stream ended before the pending chunk was acknowledged");
      return;
    }
    closed = true;
    acceptingWrites = false;
    const closeError = new Error("stream is closed");
    pendingOutboundAcknowledgement?.reject(closeError);
    pendingOutboundAcknowledgement = null;
    drainWaiters(null);
    closePort();
    notifyTerminal();
  };

  const acknowledgeRead = (item: QueuedRead) => {
    if (closed) return;
    if (pendingInboundWriteId !== item.writeId) {
      failProtocol("read acknowledgement does not match the pending chunk");
      throw error;
    }
    pendingInboundWriteId = null;
    try {
      port.postMessage({
        type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
        writeId: item.writeId,
      } satisfies ProxyWindowStreamWriteAckMsg);
    } catch (cause) {
      const err = cause instanceof Error ? cause : new Error(String(cause));
      terminateWithError(err, false);
      throw err;
    }
  };

  port.onmessage = (ev) => {
    if (closed) return;
    const data = ev.data as
      | ProxyWindowStreamChunkMsg
      | ProxyWindowStreamCloseMsg
      | ProxyWindowStreamResetMsg
      | ProxyWindowStreamWriteAckMsg
      | unknown;
    if (data == null || typeof data !== "object") return;
    const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
    switch (type) {
      case PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE: {
        const msg = data as ProxyWindowStreamChunkMsg;
        if (!(msg.data instanceof ArrayBuffer) || !validWriteId(msg.writeId)) {
          failProtocol("invalid stream chunk");
          return;
        }
        if (pendingInboundWriteId != null || queue.length > 0) {
          failProtocol("received more than one unacknowledged chunk");
          return;
        }
        pendingInboundWriteId = msg.writeId;
        const item = { chunk: new Uint8Array(msg.data), writeId: msg.writeId };
        const waiter = waiters.shift();
        if (waiter == null) {
          queue.push(item);
        } else {
          waiter(item);
        }
        return;
      }
      case PROXY_WINDOW_STREAM_END_MSG_TYPE:
      case PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE:
        finishClosed();
        return;
      case PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE: {
        const writeId = (data as ProxyWindowStreamWriteAckMsg).writeId;
        const pending = pendingOutboundAcknowledgement;
        if (!validWriteId(writeId) || pending == null || pending.writeId !== writeId) {
          failProtocol("unexpected stream write acknowledgement");
          return;
        }
        pendingOutboundAcknowledgement = null;
        pending.resolve();
        return;
      }
      case PROXY_WINDOW_STREAM_RESET_MSG_TYPE: {
        const message = String((data as ProxyWindowStreamResetMsg).message ?? "stream reset");
        terminateWithError(new Error(message), false);
        return;
      }
      default:
        return;
    }
  };
  port.start?.();

  return {
    async read(): Promise<Uint8Array | null> {
      if (error != null) throw error;
      const queued = queue.shift();
      if (queued != null) {
        acknowledgeRead(queued);
        return queued.chunk;
      }
      if (closed) return null;

      const value = await new Promise<ReadResult>((resolve) => {
        waiters.push(resolve);
      });
      if (value instanceof Error) throw value;
      if (value == null) return null;
      acknowledgeRead(value);
      return value.chunk;
    },

    async write(chunk: Uint8Array): Promise<void> {
      if (error != null) throw error;
      if (!acceptingWrites || closed) throw new Error("stream is closed");
      const nextQueuedWriteBytes = queuedWriteBytes + chunk.byteLength;
      if (!Number.isSafeInteger(nextQueuedWriteBytes) || nextQueuedWriteBytes > maxBufferedBytes) {
        throw new Error("proxy WebSocket outbound buffer exceeded");
      }
      queuedWriteBytes = nextQueuedWriteBytes;
      const ab = cloneChunk(chunk);
      const operation = writeTail.then(async () => {
        if (error != null) throw error;
        if (closed) throw new Error("stream is closed");
        if (!Number.isSafeInteger(nextWriteId)) {
          failProtocol("stream write identifier space exhausted");
          throw error;
        }
        if (pendingOutboundAcknowledgement != null) {
          failProtocol("multiple outbound chunks are awaiting acknowledgement");
          throw error;
        }
        const writeId = nextWriteId++;
        await new Promise<void>((resolve, reject) => {
          pendingOutboundAcknowledgement = { writeId, resolve, reject };
          try {
            port.postMessage({
              type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
              data: ab,
              writeId,
            } satisfies ProxyWindowStreamChunkMsg, [ab]);
          } catch (cause) {
            pendingOutboundAcknowledgement = null;
            const postError = cause instanceof Error ? cause : new Error(String(cause));
            terminateWithError(postError, false);
            reject(postError);
          }
        });
      });
      writeTail = operation.catch(() => {});
      try {
        await operation;
      } finally {
        queuedWriteBytes = Math.max(0, queuedWriteBytes - chunk.byteLength);
      }
    },

    async close(): Promise<void> {
      if (closed) return;
      acceptingWrites = false;
      await writeTail;
      if (error != null) throw error;
      if (closed) return;
      closed = true;
      queue.length = 0;
      pendingInboundWriteId = null;
      drainWaiters(null);
      try {
        port.postMessage({ type: PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE } satisfies ProxyWindowStreamCloseMsg);
      } finally {
        closePort();
        notifyTerminal();
      }
    },

    reset(err: Error): void {
      const resetError = err instanceof Error ? err : new Error(String(err));
      terminateWithError(resetError, true);
    },
  } as YamuxStream;
}

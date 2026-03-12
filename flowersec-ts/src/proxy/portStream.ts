import type { YamuxStream } from "../yamux/stream.js";

import {
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_END_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  type ProxyWindowStreamChunkMsg,
  type ProxyWindowStreamCloseMsg,
  type ProxyWindowStreamResetMsg,
} from "./windowBridgeProtocol.js";

function cloneChunk(chunk: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(chunk.byteLength);
  out.set(chunk);
  return out.buffer;
}

type ReadQueueItem = Uint8Array | null;

export function createMessagePortBackedStream(port: MessagePort): YamuxStream {
  let closed = false;
  let error: Error | null = null;
  const queue: ReadQueueItem[] = [];
  const waiters: Array<(value: ReadQueueItem | Error) => void> = [];

  const resolveWaiter = (value: ReadQueueItem | Error) => {
    const waiter = waiters.shift();
    if (waiter) {
      waiter(value);
      return true;
    }
    return false;
  };

  const pushValue = (value: ReadQueueItem) => {
    if (resolveWaiter(value)) return;
    queue.push(value);
  };

  const fail = (err: Error) => {
    if (error != null) return;
    error = err;
    while (resolveWaiter(err)) {
      // Drain waiters.
    }
  };

  port.onmessage = (ev) => {
    const data = ev.data as ProxyWindowStreamChunkMsg | ProxyWindowStreamCloseMsg | ProxyWindowStreamResetMsg | unknown;
    if (data == null || typeof data !== "object") return;
    const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
    switch (type) {
      case PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE: {
        const raw = (data as ProxyWindowStreamChunkMsg).data;
        if (!(raw instanceof ArrayBuffer)) return;
        pushValue(new Uint8Array(raw));
        return;
      }
      case PROXY_WINDOW_STREAM_END_MSG_TYPE:
      case PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE:
        closed = true;
        pushValue(null);
        return;
      case PROXY_WINDOW_STREAM_RESET_MSG_TYPE: {
        closed = true;
        const message = String((data as ProxyWindowStreamResetMsg).message ?? "stream reset");
        fail(new Error(message));
        try {
          port.close();
        } catch {
          // Best-effort.
        }
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
      const next = queue.shift();
      if (next !== undefined) return next;
      if (closed) return null;

      const value = await new Promise<ReadQueueItem | Error>((resolve) => {
        waiters.push(resolve);
      });
      if (value instanceof Error) throw value;
      return value;
    },

    async write(chunk: Uint8Array): Promise<void> {
      if (error != null) throw error;
      if (closed) throw new Error("stream is closed");
      const ab = cloneChunk(chunk);
      port.postMessage({ type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE, data: ab } satisfies ProxyWindowStreamChunkMsg, [ab]);
    },

    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      try {
        port.postMessage({ type: PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE } satisfies ProxyWindowStreamCloseMsg);
      } finally {
        pushValue(null);
      }
    },

    reset(err: Error): void {
      const message = err instanceof Error ? err.message : String(err);
      closed = true;
      fail(err instanceof Error ? err : new Error(message));
      try {
        port.postMessage({ type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE, message } satisfies ProxyWindowStreamResetMsg);
      } finally {
        try {
          port.close();
        } catch {
          // Best-effort.
        }
      }
    },
  } as YamuxStream;
}

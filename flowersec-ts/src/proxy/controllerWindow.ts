import type { ProxyRuntime } from "./runtime.js";
import {
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_END_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_WS_ERROR_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_MSG_TYPE,
  type ProxyWindowFetchMsg,
  type ProxyWindowStreamChunkMsg,
  type ProxyWindowStreamCloseMsg,
  type ProxyWindowStreamResetMsg,
  type ProxyWindowWsOpenAckMsg,
  type ProxyWindowWsErrorMsg,
  type ProxyWindowWsOpenMsg,
} from "./windowBridgeProtocol.js";

export type RegisterProxyControllerWindowOptions = Readonly<{
  runtime: ProxyRuntime;
  allowedOrigins: readonly string[];
  targetWindow?: Window;
  expectedSource?: Window | null;
}>;

export type ProxyControllerWindowHandle = Readonly<{
  dispose: () => void;
}>;

function normalizeOrigins(origins: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const origin of origins) {
    const normalized = String(origin ?? "").trim();
    if (normalized === "" || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function cloneChunk(chunk: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(chunk.byteLength);
  out.set(chunk);
  return out.buffer;
}

function bridgeWebSocket(runtime: ProxyRuntime, msg: ProxyWindowWsOpenMsg, port: MessagePort): void {
  const ac = new AbortController();
  let streamClosed = false;

  const closePort = () => {
    try {
      port.close();
    } catch {
      // Best-effort.
    }
  };

  void (async () => {
    try {
      const wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {
        signal: ac.signal,
        ...(msg.protocols === undefined ? {} : { protocols: msg.protocols }),
      };
      const { stream, protocol } = await runtime.openWebSocketStream(msg.path, wsOpts);

      port.onmessage = (ev) => {
        const data = ev.data as
          | ProxyWindowStreamChunkMsg
          | ProxyWindowStreamCloseMsg
          | ProxyWindowStreamResetMsg
          | unknown;
        if (data == null || typeof data !== "object") return;
        const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
        switch (type) {
          case PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE: {
            const raw = (data as ProxyWindowStreamChunkMsg).data;
            if (!(raw instanceof ArrayBuffer)) return;
            void stream.write(new Uint8Array(raw));
            return;
          }
          case PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE:
            void stream.close();
            return;
          case PROXY_WINDOW_STREAM_RESET_MSG_TYPE: {
            const message = String((data as ProxyWindowStreamResetMsg).message ?? "stream reset");
            stream.reset(new Error(message));
            streamClosed = true;
            ac.abort(message);
            closePort();
            return;
          }
          default:
            return;
        }
      };
      port.start?.();
      port.postMessage({ type: PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE, protocol } satisfies ProxyWindowWsOpenAckMsg);

      while (!streamClosed) {
        const chunk = await stream.read();
        if (chunk == null) {
          streamClosed = true;
          port.postMessage({ type: PROXY_WINDOW_STREAM_END_MSG_TYPE });
          closePort();
          return;
        }
        const ab = cloneChunk(chunk);
        port.postMessage({ type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE, data: ab } satisfies ProxyWindowStreamChunkMsg, [ab]);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      port.postMessage({ type: PROXY_WINDOW_WS_ERROR_MSG_TYPE, message } satisfies ProxyWindowWsErrorMsg);
      closePort();
    }
  })();
}

export function registerProxyControllerWindow(opts: RegisterProxyControllerWindowOptions): ProxyControllerWindowHandle {
  const allowedOrigins = normalizeOrigins(opts.allowedOrigins);
  if (allowedOrigins.length === 0) {
    throw new Error("allowedOrigins is required");
  }

  const targetWindow = opts.targetWindow ?? globalThis.window;
  if (targetWindow == null) {
    throw new Error("targetWindow is not available");
  }

  const onMessage = (ev: MessageEvent) => {
    if (!allowedOrigins.includes(String(ev.origin ?? "").trim())) return;
    if (opts.expectedSource != null && ev.source !== opts.expectedSource) return;

    const data = ev.data as ProxyWindowFetchMsg | ProxyWindowWsOpenMsg | unknown;
    if (data == null || typeof data !== "object") return;

    const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
    const port = ev.ports?.[0];
    if (!port) return;

    switch (type) {
      case PROXY_WINDOW_FETCH_MSG_TYPE:
        opts.runtime.dispatchFetch((data as ProxyWindowFetchMsg).req, port);
        return;
      case PROXY_WINDOW_WS_OPEN_MSG_TYPE:
        bridgeWebSocket(opts.runtime, data as ProxyWindowWsOpenMsg, port);
        return;
      default:
        return;
    }
  };

  targetWindow.addEventListener("message", onMessage);
  return {
    dispose: () => {
      targetWindow.removeEventListener("message", onMessage);
    },
  };
}

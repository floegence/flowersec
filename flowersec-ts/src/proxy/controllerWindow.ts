import type { ProxyRuntime } from "./runtime.js";
import {
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_END_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_ERROR_MSG_TYPE,
  PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY,
  PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_MSG_TYPE,
  type ProxyWindowFetchRequest,
  type ProxyWindowFetchMsg,
  type ProxyWindowStreamChunkMsg,
  type ProxyWindowStreamCloseMsg,
  type ProxyWindowStreamResetMsg,
  type ProxyWindowStreamWriteAckMsg,
  type ProxyWindowWsOpenAckMsg,
  type ProxyWindowWsErrorMsg,
  type ProxyWindowWsOpenMsg,
} from "./windowBridgeProtocol.js";

export type RegisterProxyControllerWindowOptions = Readonly<{
  runtime: ProxyRuntime;
  allowedOrigins: readonly string[];
  targetWindow?: Window;
  expectedSource?: Window | null;
  capabilityNonce?: string;
}>;

export type ProxyControllerWindowHandle = Readonly<{
  dispose: () => void;
}>;

type ActiveControllerWebSocketBridge = Readonly<{
  dispose: (error: Error) => void;
  isTerminal: () => boolean;
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

function normalizeCapabilityNonce(value: string | undefined): string {
  if (value == null) return "";
  const s = String(value);
  if (s === "") return "";
  if (s.trim() !== s || /[\s\u0000-\u001f\u007f]/.test(s)) {
    throw new Error("capabilityNonce must not contain whitespace or control characters");
  }
  return s;
}

function requireBridgeCapability(expectedSource: Window | null | undefined, capabilityNonce: string): void {
  if (expectedSource == null && capabilityNonce === "") {
    throw new Error("expectedSource or capabilityNonce is required");
  }
}

function hasExpectedCapability(data: unknown, capabilityNonce: string): boolean {
  if (capabilityNonce === "") return true;
  if (data == null || typeof data !== "object") return false;
  return (data as { capabilityNonce?: unknown }).capabilityNonce === capabilityNonce;
}

function withTrustedExternalOrigin(
  req: ProxyWindowFetchRequest,
  rawOrigin: string,
): ProxyWindowFetchRequest {
  let externalOrigin: string | undefined;
  try {
    const url = new URL(rawOrigin);
    if (url.protocol === "http:" || url.protocol === "https:") {
      externalOrigin = url.origin;
    }
  } catch {
    // Opaque and invalid origins must not become upstream authority metadata.
  }

  const sanitized: { -readonly [K in keyof ProxyWindowFetchRequest]: ProxyWindowFetchRequest[K] } = { ...req };
  delete sanitized.external_origin;
  return externalOrigin === undefined
    ? sanitized
    : { ...sanitized, external_origin: externalOrigin };
}

function validWriteId(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function bridgeWebSocket(
  runtime: ProxyRuntime,
  msg: ProxyWindowWsOpenMsg,
  port: MessagePort,
  onTerminal: () => void,
): ActiveControllerWebSocketBridge {
  const capabilities = Array.isArray(msg.capabilities)
    ? msg.capabilities.filter((value): value is string => typeof value === "string")
    : [];
  if (!capabilities.includes(PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY)) {
    try {
      port.postMessage({
        type: PROXY_WINDOW_WS_ERROR_MSG_TYPE,
        message: "proxy Window bridge requires bidirectional stream acknowledgements",
      } satisfies ProxyWindowWsErrorMsg);
    } catch {
      // Best-effort.
    } finally {
      port.close();
    }
    onTerminal();
    return { dispose: () => {}, isTerminal: () => true };
  }

  const ac = new AbortController();
  let terminal = false;
  let terminalError: Error | null = null;
  let acceptingWrites = true;
  let stream: Awaited<ReturnType<ProxyRuntime["openWebSocketStream"]>>["stream"] | null = null;
  let pendingInboundWriteId: number | null = null;
  let pendingOutboundAcknowledgement: Readonly<{
    writeId: number;
    resolve: () => void;
    reject: (error: Error) => void;
  }> | null = null;
  let nextWriteId = 1;
  const maxBufferedBytes = runtime.limits.maxWsBufferedAmountBytes ?? 4 * (1 << 20);
  let terminalNotified = false;

  const notifyTerminal = () => {
    if (terminalNotified) return;
    terminalNotified = true;
    onTerminal();
  };

  const closePort = () => {
    try {
      port.close();
    } catch {
      // Best-effort.
    }
  };

  const failBridge = (error: unknown, notifyPeer = true) => {
    if (terminal) return;
    terminal = true;
    acceptingWrites = false;
    const err = error instanceof Error ? error : new Error(String(error));
    terminalError = err;
    pendingInboundWriteId = null;
    pendingOutboundAcknowledgement?.reject(err);
    pendingOutboundAcknowledgement = null;
    if (stream != null) {
      void Promise.resolve(stream.reset(err)).catch(() => {
        // The bridge error is already delivered through the terminal response.
      });
    }
    try {
      ac.abort(err.message);
    } catch {
      // Best-effort.
    }
    if (notifyPeer) {
      try {
        port.postMessage({
          type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
          message: err.message,
        } satisfies ProxyWindowStreamResetMsg);
      } catch {
        // Best-effort.
      }
    }
    closePort();
    notifyTerminal();
  };

  const failProtocol = (message: string) => {
    failBridge(new Error(`proxy Window stream protocol error: ${message}`));
  };

  const postChunkAndWait = async (chunk: Uint8Array): Promise<void> => {
    if (chunk.byteLength > maxBufferedBytes) {
      throw new Error("proxy WebSocket inbound chunk exceeded the buffer limit");
    }
    if (!Number.isSafeInteger(nextWriteId)) {
      throw new Error("proxy Window stream write identifier space exhausted");
    }
    if (pendingOutboundAcknowledgement != null) {
      throw new Error("proxy Window stream already has an unacknowledged outbound chunk");
    }
    const writeId = nextWriteId++;
    const ab = cloneChunk(chunk);
    await new Promise<void>((resolve, reject) => {
      pendingOutboundAcknowledgement = { writeId, resolve, reject };
      try {
        port.postMessage({
          type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
          data: ab,
          writeId,
        } satisfies ProxyWindowStreamChunkMsg, [ab]);
      } catch (error) {
        pendingOutboundAcknowledgement = null;
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  };

  port.onmessage = (ev) => {
    const data = ev.data as
      | ProxyWindowStreamChunkMsg
      | ProxyWindowStreamCloseMsg
      | ProxyWindowStreamResetMsg
      | ProxyWindowStreamWriteAckMsg
      | unknown;
    if (data == null || typeof data !== "object") return;
    const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
    if (stream == null) {
      if (type === PROXY_WINDOW_STREAM_RESET_MSG_TYPE) {
        const message = String((data as ProxyWindowStreamResetMsg).message ?? "stream reset");
        failBridge(new Error(message), false);
      } else if (type === PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE
        || type === PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE
        || type === PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE) {
        failProtocol("received stream traffic before the websocket opened");
      }
      return;
    }
    switch (type) {
      case PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE: {
        if (!acceptingWrites) return;
        const chunkMessage = data as ProxyWindowStreamChunkMsg;
        const raw = chunkMessage.data;
        if (!(raw instanceof ArrayBuffer) || !validWriteId(chunkMessage.writeId)) {
          failProtocol("invalid stream chunk");
          return;
        }
        if (pendingInboundWriteId != null) {
          failProtocol("received more than one unacknowledged chunk");
          return;
        }
        if (raw.byteLength > maxBufferedBytes) {
          failBridge(new Error("proxy WebSocket outbound buffer exceeded"));
          return;
        }
        const writeId = chunkMessage.writeId;
        const chunk = new Uint8Array(raw);
        pendingInboundWriteId = writeId;
        void stream.write(chunk)
          .then(() => {
            if (terminal) return;
            if (pendingInboundWriteId !== writeId) {
              failProtocol("completed write does not match the pending chunk");
              return;
            }
            pendingInboundWriteId = null;
            port.postMessage({
              type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
              writeId,
            } satisfies ProxyWindowStreamWriteAckMsg);
          })
          .catch((error) => failBridge(error));
        return;
      }
      case PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE: {
        if (!acceptingWrites) return;
        if (pendingInboundWriteId != null) {
          failProtocol("stream closed before the pending chunk was acknowledged");
          return;
        }
        acceptingWrites = false;
        terminal = true;
        const closeError = new Error("stream is closed");
        pendingInboundWriteId = null;
        pendingOutboundAcknowledgement?.reject(closeError);
        pendingOutboundAcknowledgement = null;
        void Promise.resolve(stream.close()).catch(() => {
          // The peer already closed its bridge endpoint.
        });
        closePort();
        notifyTerminal();
        return;
      }
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
        failBridge(new Error(message), false);
        return;
      }
      default:
        return;
    }
  };
  port.start?.();

  void (async () => {
    try {
      const wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {
        signal: ac.signal,
        ...(msg.protocols === undefined ? {} : { protocols: msg.protocols }),
      };
      const opened = await runtime.openWebSocketStream(msg.path, wsOpts);
      if (terminal) {
        await Promise.resolve(opened.stream.reset(terminalError ?? new Error("proxy controller Window bridge is closed")));
        return;
      }
      stream = opened.stream;
      port.postMessage({
        type: PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
        protocol: opened.protocol,
        capabilities: [PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY],
      } satisfies ProxyWindowWsOpenAckMsg);

      while (!terminal) {
        const chunk = await stream.read();
        if (chunk == null) {
          terminal = true;
          acceptingWrites = false;
          port.postMessage({ type: PROXY_WINDOW_STREAM_END_MSG_TYPE });
          closePort();
          notifyTerminal();
          return;
        }
        await postChunkAndWait(chunk);
      }
    } catch (error) {
      if (terminal) return;
      const message = error instanceof Error ? error.message : String(error);
      if (stream == null) {
        terminal = true;
        acceptingWrites = false;
        terminalError = error instanceof Error ? error : new Error(message);
        try {
          port.postMessage({ type: PROXY_WINDOW_WS_ERROR_MSG_TYPE, message } satisfies ProxyWindowWsErrorMsg);
        } finally {
          closePort();
          notifyTerminal();
        }
        return;
      }
      failBridge(error);
    }
  })();

  return {
    dispose: (error: Error) => failBridge(error),
    isTerminal: () => terminal,
  };
}

export function registerProxyControllerWindow(opts: RegisterProxyControllerWindowOptions): ProxyControllerWindowHandle {
  const allowedOrigins = normalizeOrigins(opts.allowedOrigins);
  if (allowedOrigins.length === 0) {
    throw new Error("allowedOrigins is required");
  }
  const capabilityNonce = normalizeCapabilityNonce(opts.capabilityNonce);
  requireBridgeCapability(opts.expectedSource, capabilityNonce);
  const activeWebSocketBridges = new Set<ActiveControllerWebSocketBridge>();
  let disposed = false;

  const targetWindow = opts.targetWindow ?? globalThis.window;
  if (targetWindow == null) {
    throw new Error("targetWindow is not available");
  }

  const onMessage = (ev: MessageEvent) => {
    const eventOrigin = String(ev.origin ?? "").trim();
    if (!allowedOrigins.includes(eventOrigin)) return;
    if (opts.expectedSource != null && ev.source !== opts.expectedSource) return;

    const data = ev.data as ProxyWindowFetchMsg | ProxyWindowWsOpenMsg | unknown;
    if (data == null || typeof data !== "object") return;
    if (!hasExpectedCapability(data, capabilityNonce)) return;

    const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
    const port = ev.ports?.[0];
    if (!port) return;

    switch (type) {
      case PROXY_WINDOW_FETCH_MSG_TYPE: {
        const msg = data as ProxyWindowFetchMsg;
        opts.runtime.dispatchFetch(withTrustedExternalOrigin(msg.req, eventOrigin), port);
        return;
      }
      case PROXY_WINDOW_WS_OPEN_MSG_TYPE: {
        if (disposed) return;
        let bridge: ActiveControllerWebSocketBridge | null = null;
        bridge = bridgeWebSocket(opts.runtime, data as ProxyWindowWsOpenMsg, port, () => {
          if (bridge != null) activeWebSocketBridges.delete(bridge);
        });
        if (!bridge.isTerminal()) activeWebSocketBridges.add(bridge);
        return;
      }
      default:
        return;
    }
  };

  targetWindow.addEventListener("message", onMessage);
  return {
    dispose: () => {
      if (disposed) return;
      disposed = true;
      targetWindow.removeEventListener("message", onMessage);
      const error = new Error("proxy controller Window bridge is disposed");
      for (const bridge of [...activeWebSocketBridges]) bridge.dispose(error);
    },
  };
}

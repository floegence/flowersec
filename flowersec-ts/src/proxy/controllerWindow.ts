import type { ProxyRuntime } from "./runtime.js";
import {
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE,
  PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE,
  PROXY_WINDOW_STREAM_END_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_ERROR_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_MSG_TYPE,
  PROXY_WINDOW_WS_WRITE_ACK_CAPABILITY,
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

function bridgeWebSocket(runtime: ProxyRuntime, msg: ProxyWindowWsOpenMsg, port: MessagePort): void {
  const ac = new AbortController();
  let terminal = false;
  let acceptingWrites = true;
  let stream: Awaited<ReturnType<ProxyRuntime["openWebSocketStream"]>>["stream"] | null = null;
  let pendingWriteBytes = 0;
  let writeChain: Promise<void> = Promise.resolve();
  const maxBufferedBytes = runtime.limits.maxWsBufferedAmountBytes ?? 4 * (1 << 20);

  const closePort = () => {
    try {
      port.close();
    } catch {
      // Best-effort.
    }
  };

  const failBridge = (error: unknown) => {
    if (terminal) return;
    terminal = true;
    acceptingWrites = false;
    const err = error instanceof Error ? error : new Error(String(error));
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
    try {
      port.postMessage({
        type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
        message: err.message,
      } satisfies ProxyWindowStreamResetMsg);
    } catch {
      // Best-effort.
    }
    closePort();
  };

  void (async () => {
    try {
      const wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {
        signal: ac.signal,
        ...(msg.protocols === undefined ? {} : { protocols: msg.protocols }),
      };
      const opened = await runtime.openWebSocketStream(msg.path, wsOpts);
      stream = opened.stream;

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
            if (!acceptingWrites || stream == null) return;
            const raw = (data as ProxyWindowStreamChunkMsg).data;
            if (!(raw instanceof ArrayBuffer)) return;
            if (pendingWriteBytes + raw.byteLength > maxBufferedBytes) {
              failBridge(new Error("proxy WebSocket outbound buffer exceeded"));
              return;
            }
            const rawWriteId = (data as ProxyWindowStreamChunkMsg).writeId;
            const writeId = Number.isSafeInteger(rawWriteId) && Number(rawWriteId) > 0
              ? Number(rawWriteId)
              : undefined;
            const chunk = new Uint8Array(raw);
            pendingWriteBytes += chunk.byteLength;
            writeChain = writeChain
              .then(async () => {
                if (terminal || stream == null) throw new Error("stream is closed");
                await stream.write(chunk);
                if (terminal || writeId === undefined) return;
                port.postMessage({
                  type: PROXY_WINDOW_STREAM_WRITE_ACK_MSG_TYPE,
                  writeId,
                } satisfies ProxyWindowStreamWriteAckMsg);
              })
              .catch((error) => failBridge(error))
              .finally(() => {
                pendingWriteBytes = Math.max(0, pendingWriteBytes - chunk.byteLength);
              });
            return;
          }
          case PROXY_WINDOW_STREAM_CLOSE_MSG_TYPE:
            if (!acceptingWrites || stream == null) return;
            acceptingWrites = false;
            writeChain = writeChain
              .then(() => stream?.close())
              .catch((error) => failBridge(error)) as Promise<void>;
            return;
          case PROXY_WINDOW_STREAM_RESET_MSG_TYPE: {
            const message = String((data as ProxyWindowStreamResetMsg).message ?? "stream reset");
            failBridge(new Error(message));
            return;
          }
          default:
            return;
        }
      };
      port.start?.();
      port.postMessage({
        type: PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
        protocol: opened.protocol,
        capabilities: [PROXY_WINDOW_WS_WRITE_ACK_CAPABILITY],
      } satisfies ProxyWindowWsOpenAckMsg);

      while (!terminal) {
        const chunk = await stream.read();
        if (chunk == null) {
          terminal = true;
          acceptingWrites = false;
          port.postMessage({ type: PROXY_WINDOW_STREAM_END_MSG_TYPE });
          closePort();
          return;
        }
        const ab = cloneChunk(chunk);
        port.postMessage({ type: PROXY_WINDOW_STREAM_CHUNK_MSG_TYPE, data: ab } satisfies ProxyWindowStreamChunkMsg, [ab]);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (stream == null) {
        port.postMessage({ type: PROXY_WINDOW_WS_ERROR_MSG_TYPE, message } satisfies ProxyWindowWsErrorMsg);
        closePort();
        return;
      }
      failBridge(error);
    }
  })();
}

export function registerProxyControllerWindow(opts: RegisterProxyControllerWindowOptions): ProxyControllerWindowHandle {
  const allowedOrigins = normalizeOrigins(opts.allowedOrigins);
  if (allowedOrigins.length === 0) {
    throw new Error("allowedOrigins is required");
  }
  const capabilityNonce = normalizeCapabilityNonce(opts.capabilityNonce);
  requireBridgeCapability(opts.expectedSource, capabilityNonce);

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

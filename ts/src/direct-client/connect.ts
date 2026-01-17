import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { assertDirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { normalizeObserver, nowSeconds, type ClientObserverLike } from "../observability/observer.js";
import { base64urlDecode } from "../utils/base64url.js";
import { AbortError, TimeoutError, isAbortError, isTimeoutError, throwIfAborted } from "../utils/errors.js";
import { WebSocketBinaryTransport, type WebSocketLike } from "../ws-client/binaryTransport.js";
import { clientHandshake } from "../e2ee/handshake.js";
import { YamuxSession } from "../yamux/session.js";
import { ByteReader } from "../yamux/byteReader.js";
import { RpcClient } from "../rpc/client.js";
import { writeStreamHello } from "../rpc/streamHello.js";
import { RpcProxy } from "../rpc-proxy/rpcProxy.js";

// DirectConnectOptions controls transport and handshake limits.
export type DirectConnectOptions = Readonly<{
  /** Explicit Origin value (required). In browsers this must match window.location.origin. */
  origin: string;
  /** Optional AbortSignal to cancel connect/handshake. */
  signal?: AbortSignal;
  /** Optional websocket connect timeout in milliseconds (0 disables). */
  connectTimeoutMs?: number;
  /** Optional total E2EE handshake timeout in milliseconds (0 disables). */
  handshakeTimeoutMs?: number;
  /** Maximum allowed bytes for handshake payloads. */
  maxHandshakePayload?: number;
  /** Maximum encrypted record size on the wire. */
  maxRecordBytes?: number;
  /** Maximum buffered plaintext bytes in the secure channel. */
  maxBufferedBytes?: number;
  /** Maximum queued websocket bytes before backpressure. */
  maxWsQueuedBytes?: number;
  /** Optional factory for creating the WebSocket instance. */
  wsFactory?: (url: string, origin: string) => WebSocketLike;
  /** Optional observer for client metrics. */
  observer?: ClientObserverLike;
}>;

// connectDirectClientRpc connects to a direct websocket endpoint and returns an RPC-ready client.
export async function connectDirectClientRpc(info: DirectConnectInfo, opts: DirectConnectOptions) {
  const ready = assertDirectConnectInfo(info);
  const observer = normalizeObserver(opts.observer);
  const signal = opts.signal;
  const connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  const handshakeTimeoutMs = opts.handshakeTimeoutMs ?? 10_000;

  const connectStart = nowSeconds();
  const origin = opts.origin;
  if (origin == null || origin === "") throw new Error("missing origin");
  const ws = createWebSocket(ready.ws_url, origin, opts.wsFactory);
  try {
    await waitOpen(ws, {
      timeoutMs: connectTimeoutMs,
      ...(signal !== undefined ? { signal } : {})
    });
    observer.onTunnelConnect("ok", undefined, nowSeconds() - connectStart);
  } catch (err) {
    const reason = classifyConnectError(err);
    observer.onTunnelConnect("fail", reason, nowSeconds() - connectStart);
    throw err;
  }

  throwIfAborted(signal, "connect aborted");

  const transport = new WebSocketBinaryTransport(ws, {
    ...(opts.maxWsQueuedBytes !== undefined ? { maxQueuedBytes: opts.maxWsQueuedBytes } : {}),
    observer
  });
  const psk = base64urlDecode(ready.e2ee_psk_b64u);
  const suite = ready.default_suite as unknown as 1 | 2;

  const handshakeStart = nowSeconds();
  let secure: Awaited<ReturnType<typeof clientHandshake>>;
  try {
    secure = await withAbortAndTimeout(
      clientHandshake(transport, {
        channelId: ready.channel_id,
        suite,
        psk,
        clientFeatures: 0,
        maxHandshakePayload: opts.maxHandshakePayload ?? 8 * 1024,
        maxRecordBytes: opts.maxRecordBytes ?? (1 << 20),
        ...(opts.maxBufferedBytes !== undefined ? { maxBufferedBytes: opts.maxBufferedBytes } : {}),
        timeoutMs: handshakeTimeoutMs,
        ...(signal !== undefined ? { signal } : {})
      }),
      {
        timeoutMs: handshakeTimeoutMs,
        ...(signal !== undefined ? { signal } : {}),
        onCancel: () => transport.close()
      }
    );
    observer.onTunnelHandshake("ok", undefined, nowSeconds() - handshakeStart);
  } catch (err) {
    observer.onTunnelHandshake("fail", classifyHandshakeError(err), nowSeconds() - handshakeStart);
    transport.close();
    throw err;
  }

  const conn = {
    read: () => secure.read(),
    write: (b: Uint8Array) => secure.write(b),
    close: () => secure.close()
  };
  const mux = new YamuxSession(conn, { client: true });
  const rpcStream = await mux.openStream();

  const reader = new ByteReader(async () => {
    try {
      return await rpcStream.read();
    } catch {
      return null;
    }
  });
  const readExactly = (n: number) => reader.readExactly(n);
  const write = (b: Uint8Array) => rpcStream.write(b);

  await writeStreamHello(write, "rpc");
  const rpc = new RpcClient(readExactly, write, { observer });
  const rpcProxy = new RpcProxy();
  rpcProxy.attach(rpc);

  return {
    secure,
    mux,
    rpc,
    rpcProxy,
    close: () => {
      rpcProxy.detach();
      rpc.close();
      mux.close();
      secure.close();
    }
  };
}

// defaultWebSocketFactory constructs a browser WebSocket.
function defaultWebSocketFactory(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike;
}

function isBrowserEnv(): boolean {
  return typeof window !== "undefined" && typeof window.location !== "undefined" && typeof window.location.origin === "string";
}

function createWebSocket(url: string, origin: string, wsFactory: ((url: string, origin: string) => WebSocketLike) | undefined): WebSocketLike {
  if (wsFactory != null) return wsFactory(url, origin);
  if (isBrowserEnv()) {
    if (window.location.origin !== origin) throw new Error(`origin mismatch: expected ${origin}, got ${window.location.origin}`);
    return defaultWebSocketFactory(url);
  }
  throw new Error("wsFactory is required outside the browser to set the Origin header");
}

// waitOpen resolves when the websocket opens or rejects on error/close.
function waitOpen(ws: WebSocketLike, opts: Readonly<{ signal?: AbortSignal; timeoutMs?: number }> = {}): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new AbortError("connect aborted"));
      return;
    }
    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onErr = () => {
      cleanup();
      reject(new Error("websocket error"));
    };
    const onClose = () => {
      cleanup();
      reject(new Error("websocket closed"));
    };
    const onAbort = () => {
      cleanup();
      try {
        ws.close();
      } catch {
        // ignore
      }
      reject(new AbortError("connect aborted"));
    };
    const timeoutMs = Math.max(0, opts.timeoutMs ?? 0);
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            cleanup();
            try {
              ws.close();
            } catch {
              // ignore
            }
            reject(new TimeoutError("connect timeout"));
          }, timeoutMs)
        : undefined;
    const cleanup = () => {
      if (timer != null) clearTimeout(timer);
      ws.removeEventListener("open", onOpen);
      ws.removeEventListener("error", onErr);
      ws.removeEventListener("close", onClose);
      opts.signal?.removeEventListener("abort", onAbort);
    };
    ws.addEventListener("open", onOpen);
    ws.addEventListener("error", onErr);
    ws.addEventListener("close", onClose);
    opts.signal?.addEventListener("abort", onAbort);
  });
}

function classifyConnectError(err: unknown): "websocket_error" | "websocket_closed" | "timeout" | "canceled" {
  if (isTimeoutError(err)) return "timeout";
  if (isAbortError(err)) return "canceled";
  if (err instanceof Error && err.message === "websocket closed") return "websocket_closed";
  return "websocket_error";
}

function classifyHandshakeError(err: unknown): "handshake_error" | "timeout" | "canceled" {
  if (isTimeoutError(err)) return "timeout";
  if (isAbortError(err)) return "canceled";
  return "handshake_error";
}

async function withAbortAndTimeout<T>(
  p: Promise<T>,
  opts: Readonly<{ signal?: AbortSignal; timeoutMs?: number; onCancel?: () => void }>
): Promise<T> {
  if (opts.signal?.aborted) {
    opts.onCancel?.();
    throw new AbortError("canceled");
  }
  const timeoutMs = Math.max(0, opts.timeoutMs ?? 0);
  if (timeoutMs <= 0 && opts.signal == null) return await p;
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      settled = true;
      if (timer != null) clearTimeout(timer);
      opts.signal?.removeEventListener("abort", onAbort);
    };
    const finish = (fn: () => void) => {
      if (settled) return;
      cleanup();
      fn();
    };
    const onAbort = () => {
      opts.onCancel?.();
      finish(() => reject(new AbortError("canceled")));
    };
    const timer =
      timeoutMs > 0
        ? setTimeout(() => {
            opts.onCancel?.();
            finish(() => reject(new TimeoutError("timeout")));
          }, timeoutMs)
        : undefined;
    opts.signal?.addEventListener("abort", onAbort);
    void p.then(
      (v) => finish(() => resolve(v)),
      (e) => finish(() => reject(e))
    );
  });
}

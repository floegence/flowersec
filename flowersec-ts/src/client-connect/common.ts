import { AbortError, TimeoutError, isAbortError, isTimeoutError, throwIfAborted } from "../utils/errors.js";
import { E2EEHandshakeError } from "../e2ee/errors.js";
import type { WebSocketLike } from "../ws-client/binaryTransport.js";

class WebSocketClosedError extends Error {
  constructor() {
    super("websocket closed");
    this.name = "WebSocketClosedError";
  }
}

class WebSocketOpenError extends Error {
  constructor() {
    super("websocket error");
    this.name = "WebSocketOpenError";
  }
}

export class OriginMismatchError extends Error {
  readonly expected: string;
  readonly got: string;

  constructor(expected: string, got: string) {
    super(`origin mismatch: expected ${expected}, got ${got}`);
    this.name = "OriginMismatchError";
    this.expected = expected;
    this.got = got;
  }
}

export class WsFactoryRequiredError extends Error {
  constructor() {
    super(
      "wsFactory is required outside the browser to set the Origin header (use connectTunnelNode/connectDirectNode or createNodeWsFactory from @floegence/flowersec-core/node)"
    );
    this.name = "WsFactoryRequiredError";
  }
}

function defaultWebSocketFactory(url: string): WebSocketLike {
  return new WebSocket(url) as unknown as WebSocketLike;
}

function isBrowserEnv(): boolean {
  return typeof window !== "undefined" && typeof window.location !== "undefined" && typeof window.location.origin === "string";
}

export function createWebSocket(
  url: string,
  origin: string,
  wsFactory: ((url: string, origin: string) => WebSocketLike) | undefined
): WebSocketLike {
  if (wsFactory != null) return wsFactory(url, origin);
  if (isBrowserEnv()) {
    if (window.location.origin !== origin) throw new OriginMismatchError(origin, window.location.origin);
    return defaultWebSocketFactory(url);
  }
  throw new WsFactoryRequiredError();
}

export function classifyConnectError(err: unknown): "websocket_error" | "websocket_closed" | "timeout" | "canceled" {
  if (isTimeoutError(err)) return "timeout";
  if (isAbortError(err)) return "canceled";
  if (err instanceof WebSocketClosedError) return "websocket_closed";
  return "websocket_error";
}

export function classifyHandshakeError(
  err: unknown
): "auth_tag_mismatch" | "handshake_failed" | "invalid_suite" | "invalid_version" | "timestamp_after_init_exp" | "timestamp_out_of_skew" | "timeout" | "canceled" {
  if (isTimeoutError(err)) return "timeout";
  if (isAbortError(err)) return "canceled";
  if (err instanceof E2EEHandshakeError) return err.code;
  return "handshake_failed";
}

export async function withAbortAndTimeout<T>(
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
    p.then(
      (v) => finish(() => resolve(v)),
      (e) => finish(() => reject(e))
    );
  });
}

// waitOpen resolves when the websocket opens or rejects on error/close.
export function waitOpen(ws: WebSocketLike, opts: Readonly<{ signal?: AbortSignal; timeoutMs?: number }> = {}): Promise<void> {
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
      reject(new WebSocketOpenError());
    };
    const onClose = () => {
      cleanup();
      reject(new WebSocketClosedError());
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

// randomBytes uses the Web Crypto API for nonces and IDs.
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function ioReadOpts(signal: AbortSignal | undefined, timeoutMs: number | undefined): { signal?: AbortSignal; timeoutMs?: number } {
  throwIfAborted(signal, "operation aborted");
  const ms = timeoutMs == null ? undefined : Math.max(0, timeoutMs);
  return signal != null ? { signal, ...(ms !== undefined ? { timeoutMs: ms } : {}) } : ms !== undefined ? { timeoutMs: ms } : {};
}

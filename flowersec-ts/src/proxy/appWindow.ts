import type { YamuxStream } from "../yamux/stream.js";

import type { ProxyRuntimeLimits } from "./runtime.js";
import { createMessagePortBackedStream } from "./portStream.js";
import {
  PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE,
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_WS_ERROR_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE,
  PROXY_WINDOW_WS_OPEN_MSG_TYPE,
  type ProxyWindowFetchForwardMsg,
  type ProxyWindowFetchMsg,
  type ProxyWindowWsErrorMsg,
  type ProxyWindowWsOpenAckMsg,
  type ProxyWindowWsOpenMsg,
} from "./windowBridgeProtocol.js";

export type RegisterProxyAppWindowOptions = Readonly<{
  controllerOrigin: string;
  controllerWindow?: Window | null;
  targetWindow?: Window;
  maxWsFrameBytes?: number;
}>;

export type ProxyAppWindowHandle = Readonly<{
  runtime: Readonly<{
    limits: Partial<ProxyRuntimeLimits>;
    openWebSocketStream: (
      path: string,
      opts?: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }>
    ) => Promise<Readonly<{ stream: YamuxStream; protocol: string }>>;
  }>;
  dispose: () => void;
}>;

function resolveTargetWindow(raw: Window | undefined): Window {
  const target = raw ?? globalThis.window;
  if (target == null) throw new Error("targetWindow is not available");
  return target;
}

function resolveControllerWindow(targetWindow: Window, raw: Window | null | undefined): Window {
  if (raw != null) return raw;
  try {
    if (targetWindow.top && targetWindow.top !== targetWindow) return targetWindow.top;
  } catch {
    // ignore
  }
  try {
    if (targetWindow.parent && targetWindow.parent !== targetWindow) return targetWindow.parent;
  } catch {
    // ignore
  }
  throw new Error("controllerWindow is not available");
}

function postFetchError(port: MessagePort, message: string): void {
  try {
    port.postMessage({ type: "flowersec-proxy:response_error", status: 502, message });
  } catch {
    // Best-effort.
  }
  try {
    port.close();
  } catch {
    // Best-effort.
  }
}

export function registerProxyAppWindow(opts: RegisterProxyAppWindowOptions): ProxyAppWindowHandle {
  const controllerOrigin = String(opts.controllerOrigin ?? "").trim();
  if (controllerOrigin === "") {
    throw new Error("controllerOrigin is required");
  }

  const targetWindow = resolveTargetWindow(opts.targetWindow);
  const controllerWindow = resolveControllerWindow(targetWindow, opts.controllerWindow);

  const sw = targetWindow.navigator?.serviceWorker;
  const onServiceWorkerMessage = (ev: MessageEvent) => {
    const data = ev.data as ProxyWindowFetchForwardMsg | unknown;
    if (data == null || typeof data !== "object") return;
    if ((data as ProxyWindowFetchForwardMsg).type !== PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE) return;

    const port = ev.ports?.[0];
    if (!port) return;

    try {
      controllerWindow.postMessage(
        { type: PROXY_WINDOW_FETCH_MSG_TYPE, req: (data as ProxyWindowFetchForwardMsg).req } satisfies ProxyWindowFetchMsg,
        controllerOrigin,
        [port],
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      postFetchError(port, message);
    }
  };

  sw?.addEventListener("message", onServiceWorkerMessage);

  const runtime = {
    limits: opts.maxWsFrameBytes === undefined ? {} : { maxWsFrameBytes: opts.maxWsFrameBytes },
    openWebSocketStream: async (
      path: string,
      wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {},
    ): Promise<Readonly<{ stream: YamuxStream; protocol: string }>> => {
      const channel = new MessageChannel();
      const port = channel.port1;
      port.start?.();

      return await new Promise<Readonly<{ stream: YamuxStream; protocol: string }>>((resolve, reject) => {
        let settled = false;

        const finishReject = (error: unknown) => {
          if (settled) return;
          settled = true;
          try {
            port.close();
          } catch {
            // Best-effort.
          }
          reject(error instanceof Error ? error : new Error(String(error)));
        };

        const finishResolve = (protocol: string) => {
          if (settled) return;
          settled = true;
          resolve({ stream: createMessagePortBackedStream(port), protocol });
        };

        port.onmessage = (ev) => {
          const data = ev.data as ProxyWindowWsOpenAckMsg | ProxyWindowWsErrorMsg | unknown;
          if (data == null || typeof data !== "object") return;
          const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
          if (type === PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE) {
            finishResolve(String((data as ProxyWindowWsOpenAckMsg).protocol ?? ""));
            return;
          }
          if (type === PROXY_WINDOW_WS_ERROR_MSG_TYPE) {
            finishReject(new Error(String((data as ProxyWindowWsErrorMsg).message ?? "upstream ws open failed")));
          }
        };

        if (wsOpts.signal != null) {
          if (wsOpts.signal.aborted) {
            finishReject(wsOpts.signal.reason ?? new Error("aborted"));
            return;
          }
          wsOpts.signal.addEventListener("abort", () => finishReject(wsOpts.signal?.reason ?? new Error("aborted")), { once: true });
        }

        try {
          controllerWindow.postMessage(
            {
              type: PROXY_WINDOW_WS_OPEN_MSG_TYPE,
              path,
              ...(wsOpts.protocols === undefined ? {} : { protocols: wsOpts.protocols }),
            } satisfies ProxyWindowWsOpenMsg,
            controllerOrigin,
            [channel.port2],
          );
        } catch (error) {
          finishReject(error);
        }
      });
    },
  };

  return {
    runtime,
    dispose: () => {
      sw?.removeEventListener("message", onServiceWorkerMessage);
    },
  };
}

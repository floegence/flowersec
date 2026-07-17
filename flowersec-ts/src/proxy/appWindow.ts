import type { YamuxStream } from "../yamux/stream.js";

import type { ProxyRuntimeLimits } from "./runtime.js";
import {
  createServiceWorkerControllerGuard,
  type ServiceWorkerControllerGuardConflictPolicy,
  type ServiceWorkerControllerGuardMonitorOptions,
  type ServiceWorkerControllerGuardRepairOptions,
} from "./controllerGuard.js";
import { createMessagePortBackedStream } from "./portStream.js";
import {
  PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE,
  PROXY_WINDOW_FETCH_MSG_TYPE,
  PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
  PROXY_WINDOW_WS_ERROR_MSG_TYPE,
  PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY,
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
  maxWsBufferedAmountBytes?: number;
  capabilityNonce?: string;
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

export type ProxyAppServiceWorkerControlOptions = Readonly<{
  scriptUrl: string;
  scope?: string;
  expectedScriptPathSuffix: string;
  repair?: ServiceWorkerControllerGuardRepairOptions;
  monitor?: ServiceWorkerControllerGuardMonitorOptions;
  conflicts?: ServiceWorkerControllerGuardConflictPolicy;
}>;

export type RegisterProxyAppWindowWithServiceWorkerControlOptions = RegisterProxyAppWindowOptions & Readonly<{
  serviceWorker: ProxyAppServiceWorkerControlOptions;
}>;

type ActiveAppWebSocketBridge = Readonly<{
  dispose: (error: Error) => void;
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

function normalizeCapabilityNonce(value: string | undefined): string {
  if (value == null) return "";
  const s = String(value);
  if (s === "") return "";
  if (s.trim() !== s || /[\s\u0000-\u001f\u007f]/.test(s)) {
    throw new Error("capabilityNonce must not contain whitespace or control characters");
  }
  return s;
}

export function registerProxyAppWindow(opts: RegisterProxyAppWindowOptions): ProxyAppWindowHandle {
  const controllerOrigin = String(opts.controllerOrigin ?? "").trim();
  if (controllerOrigin === "") {
    throw new Error("controllerOrigin is required");
  }

  const targetWindow = resolveTargetWindow(opts.targetWindow);
  const controllerWindow = resolveControllerWindow(targetWindow, opts.controllerWindow);
  const capabilityNonce = normalizeCapabilityNonce(opts.capabilityNonce);
  const activeWebSocketBridges = new Set<ActiveAppWebSocketBridge>();
  let disposed = false;

  const sw = targetWindow.navigator?.serviceWorker;
  const onServiceWorkerMessage = (ev: MessageEvent) => {
    const data = ev.data as ProxyWindowFetchForwardMsg | unknown;
    if (data == null || typeof data !== "object") return;
    if ((data as ProxyWindowFetchForwardMsg).type !== PROXY_WINDOW_FETCH_FORWARD_MSG_TYPE) return;

    const port = ev.ports?.[0];
    if (!port) return;

    try {
      controllerWindow.postMessage(
        {
          type: PROXY_WINDOW_FETCH_MSG_TYPE,
          req: (data as ProxyWindowFetchForwardMsg).req,
          ...(capabilityNonce === "" ? {} : { capabilityNonce }),
        } satisfies ProxyWindowFetchMsg,
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
    limits: {
      ...(opts.maxWsFrameBytes === undefined ? {} : { maxWsFrameBytes: opts.maxWsFrameBytes }),
      ...(opts.maxWsBufferedAmountBytes === undefined
        ? {}
        : { maxWsBufferedAmountBytes: opts.maxWsBufferedAmountBytes }),
    },
    openWebSocketStream: async (
      path: string,
      wsOpts: Readonly<{ protocols?: readonly string[]; signal?: AbortSignal }> = {},
    ): Promise<Readonly<{ stream: YamuxStream; protocol: string }>> => {
      if (disposed) throw new Error("proxy app Window bridge is disposed");
      const channel = new MessageChannel();
      const port = channel.port1;
      port.start?.();

      return await new Promise<Readonly<{ stream: YamuxStream; protocol: string }>>((resolve, reject) => {
        let settled = false;
        let terminal = false;
        let stream: YamuxStream | null = null;

        const cleanup = () => {
          activeWebSocketBridges.delete(bridge);
          if (wsOpts.signal != null) wsOpts.signal.removeEventListener("abort", onAbort);
        };

        const finishTerminal = () => {
          if (terminal) return false;
          terminal = true;
          cleanup();
          return true;
        };

        const finishReject = (error: unknown) => {
          if (settled) return;
          settled = true;
          finishTerminal();
          try {
            port.close();
          } catch {
            // Best-effort.
          }
          reject(error instanceof Error ? error : new Error(String(error)));
        };

        const disposeBridge = (error: Error) => {
          if (!finishTerminal()) return;
          if (stream != null) {
            try {
              void Promise.resolve(stream.reset(error)).catch(() => {
                // The bridge is already terminal.
              });
            } catch {
              // The bridge is already terminal.
            }
            return;
          }
          try {
            port.postMessage({
              type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
              message: error.message,
            });
          } catch {
            // Best-effort.
          }
          if (!settled) {
            settled = true;
            reject(error);
          }
          try {
            port.close();
          } catch {
            // Best-effort.
          }
        };

        const bridge: ActiveAppWebSocketBridge = { dispose: disposeBridge };

        const onAbort = () => {
          const reason = wsOpts.signal?.reason;
          disposeBridge(reason instanceof Error ? reason : new Error(String(reason ?? "aborted")));
        };

        activeWebSocketBridges.add(bridge);

        const finishResolve = (ack: ProxyWindowWsOpenAckMsg) => {
          if (settled || terminal) return;
          const capabilities = Array.isArray(ack.capabilities)
            ? ack.capabilities.filter((value): value is string => typeof value === "string")
            : [];
          if (!capabilities.includes(PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY)) {
            try {
              port.postMessage({
                type: PROXY_WINDOW_STREAM_RESET_MSG_TYPE,
                message: "proxy Window bridge capability mismatch",
              });
            } catch {
              // The capability error remains authoritative.
            }
            finishReject(new Error("proxy Window bridge does not support bidirectional stream acknowledgements"));
            return;
          }
          if (disposed) {
            disposeBridge(new Error("proxy app Window bridge is disposed"));
            return;
          }
          settled = true;
          stream = createMessagePortBackedStream(port, {
            maxBufferedBytes: opts.maxWsBufferedAmountBytes ?? 4 * (1 << 20),
            onTerminal: finishTerminal,
          });
          resolve({
            stream,
            protocol: String(ack.protocol ?? ""),
          });
        };

        port.onmessage = (ev) => {
          const data = ev.data as ProxyWindowWsOpenAckMsg | ProxyWindowWsErrorMsg | unknown;
          if (data == null || typeof data !== "object") return;
          const type = typeof (data as { type?: unknown }).type === "string" ? (data as { type: string }).type : "";
          if (type === PROXY_WINDOW_WS_OPEN_ACK_MSG_TYPE) {
            finishResolve(data as ProxyWindowWsOpenAckMsg);
            return;
          }
          if (type === PROXY_WINDOW_WS_ERROR_MSG_TYPE) {
            finishReject(new Error(String((data as ProxyWindowWsErrorMsg).message ?? "upstream ws open failed")));
          }
        };

        if (wsOpts.signal != null) {
          if (wsOpts.signal.aborted) {
            onAbort();
            return;
          }
          wsOpts.signal.addEventListener("abort", onAbort, { once: true });
        }

        try {
          controllerWindow.postMessage(
            {
              type: PROXY_WINDOW_WS_OPEN_MSG_TYPE,
              path,
              capabilities: [PROXY_WINDOW_WS_BIDIRECTIONAL_ACK_CAPABILITY],
              ...(wsOpts.protocols === undefined ? {} : { protocols: wsOpts.protocols }),
              ...(capabilityNonce === "" ? {} : { capabilityNonce }),
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
      if (disposed) return;
      disposed = true;
      sw?.removeEventListener("message", onServiceWorkerMessage);
      const error = new Error("proxy app Window bridge is disposed");
      for (const bridge of [...activeWebSocketBridges]) bridge.dispose(error);
    },
  };
}

export async function registerProxyAppWindowWithServiceWorkerControl(
  opts: RegisterProxyAppWindowWithServiceWorkerControlOptions
): Promise<ProxyAppWindowHandle> {
  const targetWindow = resolveTargetWindow(opts.targetWindow);
  const sw = targetWindow.navigator?.serviceWorker;
  if (sw == null || typeof sw.register !== "function") {
    throw new Error("serviceWorker is not available");
  }

  await sw.register(opts.serviceWorker.scriptUrl, {
    ...(opts.serviceWorker.scope === undefined ? {} : { scope: opts.serviceWorker.scope }),
  });

  const guard = createServiceWorkerControllerGuard({
    targetWindow,
    expectedScriptPathSuffix: opts.serviceWorker.expectedScriptPathSuffix,
    ...(opts.serviceWorker.repair === undefined ? {} : { repair: opts.serviceWorker.repair }),
    ...(opts.serviceWorker.monitor === undefined ? {} : { monitor: opts.serviceWorker.monitor }),
    ...(opts.serviceWorker.conflicts === undefined ? {} : { conflicts: opts.serviceWorker.conflicts }),
  });

  try {
    await guard.ensure();
  } finally {
    guard.dispose();
  }

  return registerProxyAppWindow(opts);
}

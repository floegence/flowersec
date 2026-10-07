import type { OperationOptions } from "../public/contract.js";
import type { V4ConnectionMaterialSource, V4Session, V4TransportEnvironment } from "../v4/public.js";
import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";

import { createProxySurface, type ProxySurface, type ProxySurfaceOptions } from "./surface.js";
import type { ProxyRuntime, ProxyRuntimeOptions } from "./types.js";
import {
  registerProxyControllerWindow,
  type ProxyControllerWindowHandle,
  type RegisterProxyControllerWindowOptions,
} from "./windowBridge.js";

export type ProxyBrowserConnectOptions = Readonly<{
  connect?: OperationOptions;
  requirements?: Partial<V4ConnectionRequirements>;
  runtime?: Omit<ProxyRuntimeOptions, "session" | "sessionBinding" | "credentialContext" | "registerServiceWorkerBridge">;
  surface?: Omit<ProxySurfaceOptions, "binding" | "runtime" | "serviceWorker">;
  serviceWorker?: Readonly<{
    scriptUrl: string;
    scope?: string;
    repairQueryKey?: string;
    maxRepairAttempts?: number;
    controllerTimeoutMs?: number;
  }>;
}>;

export type ProxyBrowserHandle = Readonly<{
  session: V4Session;
  runtime: ProxyRuntime;
  surface: ProxySurface;
  dispose(): Promise<void>;
}>;

export async function connectProxyBrowser(
  environment: V4TransportEnvironment,
  source: V4ConnectionMaterialSource,
  options: ProxyBrowserConnectOptions = {},
): Promise<ProxyBrowserHandle> {
  const session = await environment.connect(source, options.requirements, options.connect);
  let surface: ProxySurface | undefined;
  try {
    const contentOrigin = options.surface?.contentOrigin ?? options.runtime?.externalOrigin ?? globalThis.location?.origin;
    if (contentOrigin === undefined) throw new TypeError("proxy browser requires an explicit Surface origin");
    surface = await createProxySurface({ mode: "trusted", hostOrigin: contentOrigin, contentOrigin,
      requestPolicy: { methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        paths: options.runtime?.pathPolicy ?? {}, allowWebSocket: true }, ...options.surface,
      binding: { mode: "fixed", session }, ...(options.runtime === undefined ? {} : { runtime: options.runtime }),
      ...(options.serviceWorker === undefined ? {} : { serviceWorker: options.serviceWorker }), });
    return Object.freeze({
      session,
      runtime: surface.runtime, surface,
      dispose: async () => {
        try { await surface!.dispose(); } finally { await session.close(); }
      },
    });
  } catch (error) {
    await surface?.dispose().catch(() => undefined);
    await session.close().catch(() => undefined);
    throw error;
  }
}
export type ProxyControllerBrowserConnectOptions = ProxyBrowserConnectOptions & Readonly<{
  controller: Omit<RegisterProxyControllerWindowOptions, "runtime">;
}>;

export type ProxyControllerBrowserHandle = ProxyBrowserHandle & Readonly<{
  controller: ProxyControllerWindowHandle;
}>;

export async function connectProxyControllerBrowser(
  environment: V4TransportEnvironment,
  source: V4ConnectionMaterialSource,
  options: ProxyControllerBrowserConnectOptions,
): Promise<ProxyControllerBrowserHandle> {
  const base = await connectProxyBrowser(environment, source, options);
  let controller: ProxyControllerWindowHandle | undefined;
  try {
    controller = registerProxyControllerWindow({ runtime: base.runtime, ...options.controller });
    return Object.freeze({
      session: base.session,
      runtime: base.runtime, surface: base.surface,
      controller,
      dispose: async () => {
        controller!.dispose();
        await base.dispose();
      },
    });
  } catch (error) {
    controller?.dispose();
    await base.dispose();
    throw error;
  }
}

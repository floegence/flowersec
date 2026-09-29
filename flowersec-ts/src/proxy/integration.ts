import type { OperationOptions } from "../public/contract.js";
import type { V4ConnectionMaterialSource, V4Session, V4TransportEnvironment } from "../v4/public.js";
import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";

import { createProxyRuntime } from "./runtime.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";
import type { ProxyRuntime, ProxyRuntimeOptions } from "./types.js";
import {
  registerProxyControllerWindow,
  type ProxyControllerWindowHandle,
  type RegisterProxyControllerWindowOptions,
} from "./windowBridge.js";

export type ProxyBrowserConnectOptions = Readonly<{
  connect?: OperationOptions;
  requirements?: Partial<V4ConnectionRequirements>;
  runtime?: Omit<ProxyRuntimeOptions, "session">;
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
  dispose(): Promise<void>;
}>;

export async function connectProxyBrowser(
  environment: V4TransportEnvironment,
  source: V4ConnectionMaterialSource,
  options: ProxyBrowserConnectOptions = {},
): Promise<ProxyBrowserHandle> {
  const session = await environment.connect(source, options.requirements, options.connect);
  let runtime: ProxyRuntime | undefined;
  try {
    if (options.serviceWorker !== undefined) await registerServiceWorkerAndEnsureControl(options.serviceWorker);
    runtime = createProxyRuntime({ ...options.runtime, session });
    return Object.freeze({
      session,
      runtime,
      dispose: async () => {
        runtime!.dispose();
        await session.close();
      },
    });
  } catch (error) {
    runtime?.dispose();
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
      runtime: base.runtime,
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

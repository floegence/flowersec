import { connectV3, type SessionOptionsV3 } from "../browser/connectSessionV3.js";
import type { ArtifactLeaseV3 } from "../v3/artifactLease.js";
import type { Session } from "../public/contract.js";

import { createProxyRuntime } from "./runtime.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";
import type { ProxyRuntime, ProxyRuntimeOptions } from "./types.js";
import {
  registerProxyControllerWindow,
  type ProxyControllerWindowHandle,
  type RegisterProxyControllerWindowOptions,
} from "./windowBridge.js";

export type ProxyBrowserConnectOptions = Readonly<{
  connect?: SessionOptionsV3;
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
  session: Session;
  runtime: ProxyRuntime;
  dispose(): Promise<void>;
}>;

export async function connectProxyBrowser(
  lease: ArtifactLeaseV3,
  options: ProxyBrowserConnectOptions = {},
): Promise<ProxyBrowserHandle> {
  const session = await connectV3(lease, options.connect);
  let runtime: ProxyRuntime | undefined;
  try {
    if (options.serviceWorker !== undefined) await registerServiceWorkerAndEnsureControl(options.serviceWorker);
    runtime = createProxyRuntime({ session, ...options.runtime });
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
  lease: ArtifactLeaseV3,
  options: ProxyControllerBrowserConnectOptions,
): Promise<ProxyControllerBrowserHandle> {
  const base = await connectProxyBrowser(lease, options);
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

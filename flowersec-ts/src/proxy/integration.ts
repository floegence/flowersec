import { connect, type SessionOptions } from "../browser/connectSession.js";
import type { ArtifactLease } from "../public/artifactLease.js";
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
  connect?: SessionOptions;
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
  lease: ArtifactLease,
  options: ProxyBrowserConnectOptions = {},
): Promise<ProxyBrowserHandle> {
  const session = await connect(lease, options.connect);
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
  lease: ArtifactLease,
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

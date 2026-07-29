import {
  connectBrowserSessionV2,
  type BrowserSessionConnectorV2Options,
} from "../browser/connectV2.js";
import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import type { SessionV2 } from "../v2/contract.js";

import { createProxyRuntime } from "./runtime.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";
import type { ProxyRuntime, ProxyRuntimeOptions } from "./types.js";
import {
  registerProxyControllerWindow,
  type ProxyControllerWindowHandle,
  type RegisterProxyControllerWindowOptions,
} from "./windowBridge.js";

export type ProxyBrowserConnectV2Options = Readonly<{
  connect?: BrowserSessionConnectorV2Options;
  runtime?: Omit<ProxyRuntimeOptions, "session">;
  serviceWorker?: Readonly<{
    scriptUrl: string;
    scope?: string;
    repairQueryKey?: string;
    maxRepairAttempts?: number;
    controllerTimeoutMs?: number;
  }>;
}>;

export type ProxyBrowserHandleV2 = Readonly<{
  session: SessionV2;
  runtime: ProxyRuntime;
  dispose(): Promise<void>;
}>;

export async function connectProxyBrowserV2(
  lease: ArtifactLeaseV2,
  options: ProxyBrowserConnectV2Options = {},
): Promise<ProxyBrowserHandleV2> {
  const session = await connectBrowserSessionV2(lease, options.connect);
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
export type ProxyControllerBrowserConnectV2Options = ProxyBrowserConnectV2Options & Readonly<{
  controller: Omit<RegisterProxyControllerWindowOptions, "runtime">;
}>;

export type ProxyControllerBrowserHandleV2 = ProxyBrowserHandleV2 & Readonly<{
  controller: ProxyControllerWindowHandle;
}>;

export async function connectProxyControllerBrowserV2(
  lease: ArtifactLeaseV2,
  options: ProxyControllerBrowserConnectV2Options,
): Promise<ProxyControllerBrowserHandleV2> {
  const base = await connectProxyBrowserV2(lease, options);
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

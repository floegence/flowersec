import { connectV3, type SessionOptionsV3 } from "../browser/connectSessionV3.js";
import { leaseScopeV3, type ArtifactLeaseV3 } from "../v3/artifactLease.js";
import type { Session } from "../public/contract.js";

import { createScopedProxyRuntime } from "./runtime.js";
import { assertProxyRuntimeScope, PROXY_RUNTIME_SCOPE } from "./scope.js";
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

function proxyAuthority(lease: ArtifactLeaseV3) {
  const entry = leaseScopeV3(lease, PROXY_RUNTIME_SCOPE.name);
  if (!entry) return undefined;
  if (entry.scope_version !== PROXY_RUNTIME_SCOPE.version) throw new TypeError("unsupported proxy scope version");
  return assertProxyRuntimeScope(entry.payload);
}

export async function connectProxyBrowser(
  lease: ArtifactLeaseV3,
  options: ProxyBrowserConnectOptions = {},
): Promise<ProxyBrowserHandle> {
  const authority = proxyAuthority(lease);
  if (authority && options.serviceWorker && (authority.mode !== "service_worker" ||
      options.serviceWorker.scriptUrl !== authority.serviceWorker.scriptUrl || options.serviceWorker.scope !== authority.serviceWorker.scope)) {
    throw new TypeError("service worker does not match the proxy scope");
  }
  const session = await connectV3(lease, options.connect);
  let runtime: ProxyRuntime | undefined;
  try {
    if (options.serviceWorker !== undefined) await registerServiceWorkerAndEnsureControl(options.serviceWorker);
    runtime = createScopedProxyRuntime({ ...options.runtime, session }, authority);
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
  const authority = proxyAuthority(lease);
  const allowedOrigins = Object.freeze([...options.controller.allowedOrigins]);
  if (authority && (authority.mode !== "controller_bridge" || allowedOrigins.some(origin => !authority.controllerBridge.allowedOrigins.includes(origin)))) {
    throw new TypeError("controller origins do not match the proxy scope");
  }
  const base = await connectProxyBrowser(lease, options);
  let controller: ProxyControllerWindowHandle | undefined;
  try {
    controller = registerProxyControllerWindow({ ...options.controller, allowedOrigins, runtime: base.runtime });
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

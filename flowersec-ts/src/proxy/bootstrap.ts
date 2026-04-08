import type { Client } from "../client.js";
import type { ConnectArtifact } from "../connect/artifact.js";
import type { ConnectBrowserOptions, TunnelConnectBrowserOptions } from "../browser/connect.js";
import { connectBrowser, connectTunnelBrowser } from "../browser/connect.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";

import {
  registerProxyIntegration,
  type ProxyIntegrationPlugin,
  type RegisterProxyIntegrationOptions,
  type ProxyIntegrationServiceWorkerOptions,
} from "./integration.js";
import { registerProxyControllerWindow, type RegisterProxyControllerWindowOptions } from "./controllerWindow.js";
import type { ProxyPresetInput } from "./preset.js";
import type { ProxyProfile, ProxyProfileName } from "./profiles.js";
import {
  extractProxyRuntimeScopeV1,
  resolvePresetInputFromScope,
  resolveRuntimeLimitsFromScope,
  resolveRuntimePresetLimits,
  type ProxyRuntimeScopeV1,
} from "./runtimeScope.js";
import { createProxyRuntime, type ProxyRuntime } from "./runtime.js";

export type ConnectTunnelProxyBrowserOptions = Readonly<{
  connect?: TunnelConnectBrowserOptions;
  preset?: ProxyPresetInput;
  runtimeGlobalKey?: string;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  serviceWorker: ProxyIntegrationServiceWorkerOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

type ConnectTunnelProxyBrowserCompatOptions = ConnectTunnelProxyBrowserOptions &
  Readonly<{
    /** @deprecated Runtime-only compatibility alias. Not part of the stable TS surface. */
    profile?: ProxyProfileName | Partial<ProxyProfile>;
  }>;

type _AssertFalse<T extends false> = T;

// Type-level regression guard: deprecated profile must stay out of the stable TS surface.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _ConnectTunnelProxyBrowserOptionsExcludeProfile = _AssertFalse<"profile" extends keyof ConnectTunnelProxyBrowserOptions ? true : false>;

export type ConnectTunnelProxyBrowserHandle = Readonly<{
  client: Client;
  runtime: ProxyRuntime;
  dispose: () => Promise<void>;
}>;

export type ConnectArtifactProxyBrowserOptions = Readonly<{
  connect?: ConnectBrowserOptions;
  preset?: ProxyPresetInput;
  runtimeGlobalKey?: string;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  serviceWorker?: ProxyIntegrationServiceWorkerOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

export type ConnectTunnelProxyControllerBrowserOptions = Readonly<{
  connect?: TunnelConnectBrowserOptions;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  allowedOrigins: RegisterProxyControllerWindowOptions["allowedOrigins"];
  targetWindow?: RegisterProxyControllerWindowOptions["targetWindow"];
  expectedSource?: RegisterProxyControllerWindowOptions["expectedSource"];
}>;

export type ConnectTunnelProxyControllerBrowserHandle = Readonly<{
  client: Client;
  runtime: ProxyRuntime;
  dispose: () => void;
}>;

export type ConnectArtifactProxyControllerBrowserOptions = Readonly<{
  connect?: ConnectBrowserOptions;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  allowedOrigins?: RegisterProxyControllerWindowOptions["allowedOrigins"];
  targetWindow?: RegisterProxyControllerWindowOptions["targetWindow"];
  expectedSource?: RegisterProxyControllerWindowOptions["expectedSource"];
}>;

function scopeRuntimeToIntegrationOptions(
  scope: Extract<ProxyRuntimeScopeV1, { mode: "service_worker" }>,
  opts: ConnectArtifactProxyBrowserOptions
): Omit<RegisterProxyIntegrationOptions, "client"> {
  const runtimeLimits = resolveRuntimeLimitsFromScope(scope, opts.runtime);
  const presetFromScope = resolvePresetInputFromScope(scope, opts.preset);
  const presetFromLimits = presetFromScope ?? resolveRuntimePresetLimits(scope);
  const serviceWorker = opts.serviceWorker ?? (scope.mode === "service_worker" ? {
    scriptUrl: scope.serviceWorker.scriptUrl,
    scope: scope.serviceWorker.scope,
  } : undefined);
  if (!serviceWorker) {
    throw new Error("service worker config is required for proxy runtime mode");
  }
  return {
    ...(presetFromLimits === undefined ? {} : { preset: presetFromLimits }),
    ...(opts.runtimeGlobalKey === undefined ? {} : { runtimeGlobalKey: opts.runtimeGlobalKey }),
    ...(runtimeLimits === undefined ? {} : { runtime: runtimeLimits }),
    serviceWorker,
    ...(opts.plugins === undefined ? {} : { plugins: opts.plugins }),
  };
}

async function connectProxyBrowserClient(
  client: Client,
  opts: ConnectTunnelProxyBrowserOptions
): Promise<ConnectTunnelProxyBrowserHandle> {
  const compat = opts as ConnectTunnelProxyBrowserCompatOptions;

  const integrationInput: RegisterProxyIntegrationOptions & {
    profile?: ProxyProfileName | Partial<ProxyProfile>;
  } = {
    client,
    serviceWorker: opts.serviceWorker,
    ...(opts.preset === undefined ? {} : { preset: opts.preset }),
    ...(compat.profile === undefined ? {} : { profile: compat.profile }),
    ...(opts.runtimeGlobalKey === undefined ? {} : { runtimeGlobalKey: opts.runtimeGlobalKey }),
    ...(opts.runtime === undefined ? {} : { runtime: opts.runtime }),
    ...(opts.plugins === undefined ? {} : { plugins: opts.plugins }),
  };

  let registered = false;
  let integration: Awaited<ReturnType<typeof registerProxyIntegration>> | null = null;
  try {
    integration = await registerProxyIntegration(integrationInput);
    registered = true;
  } finally {
    if (!registered) {
      client.close();
    }
  }

  return {
    client,
    runtime: integration.runtime,
    dispose: async () => {
      let firstError: unknown = null;
      try {
        await integration.dispose();
      } catch (error) {
        firstError = error;
      }

      try {
        client.close();
      } catch (error) {
        if (firstError == null) firstError = error;
      }

      if (firstError != null) throw firstError;
    },
  };
}

function connectProxyControllerClient(
  client: Client,
  opts: Readonly<{
    runtime?: RegisterProxyIntegrationOptions["runtime"];
    allowedOrigins: RegisterProxyControllerWindowOptions["allowedOrigins"];
    targetWindow?: RegisterProxyControllerWindowOptions["targetWindow"];
    expectedSource?: RegisterProxyControllerWindowOptions["expectedSource"];
  }>
): ConnectTunnelProxyControllerBrowserHandle {
  let runtime: ProxyRuntime | null = null;
  let controller: ReturnType<typeof registerProxyControllerWindow> | null = null;

  try {
    runtime = createProxyRuntime({
      client,
      ...(opts.runtime ?? {}),
    });
    controller = registerProxyControllerWindow({
      runtime,
      allowedOrigins: opts.allowedOrigins,
      ...(opts.targetWindow === undefined ? {} : { targetWindow: opts.targetWindow }),
      ...(opts.expectedSource === undefined ? {} : { expectedSource: opts.expectedSource }),
    });
  } catch (error) {
    try {
      client.close();
    } catch {
      // Best effort cleanup.
    }
    throw error;
  }

  return {
    client,
    runtime,
    dispose: () => {
      controller?.dispose();
      client.close();
    },
  };
}

export async function connectTunnelProxyBrowser(
  grant: ChannelInitGrant,
  opts: ConnectTunnelProxyBrowserOptions
): Promise<ConnectTunnelProxyBrowserHandle> {
  const client = await connectTunnelBrowser(grant, opts.connect ?? {});
  return await connectProxyBrowserClient(client, opts);
}

export async function connectArtifactProxyBrowser(
  artifact: ConnectArtifact,
  opts: ConnectArtifactProxyBrowserOptions = {}
): Promise<ConnectTunnelProxyBrowserHandle> {
  const scope = extractProxyRuntimeScopeV1(artifact, "service_worker") as Extract<ProxyRuntimeScopeV1, { mode: "service_worker" }>;
  const client = await connectBrowser(artifact, opts.connect ?? {});
  const nextOpts = scopeRuntimeToIntegrationOptions(scope, opts);
  return await connectProxyBrowserClient(client, nextOpts);
}

export async function connectTunnelProxyControllerBrowser(
  grant: ChannelInitGrant,
  opts: ConnectTunnelProxyControllerBrowserOptions
): Promise<ConnectTunnelProxyControllerBrowserHandle> {
  const client = await connectTunnelBrowser(grant, opts.connect ?? {});
  return connectProxyControllerClient(client, opts);
}

export async function connectArtifactProxyControllerBrowser(
  artifact: ConnectArtifact,
  opts: ConnectArtifactProxyControllerBrowserOptions = {}
): Promise<ConnectTunnelProxyControllerBrowserHandle> {
  const scope = extractProxyRuntimeScopeV1(artifact, "controller_bridge") as Extract<ProxyRuntimeScopeV1, { mode: "controller_bridge" }>;
  const client = await connectBrowser(artifact, opts.connect ?? {});
  const runtime = resolveRuntimeLimitsFromScope(scope, opts.runtime);
  return connectProxyControllerClient(client, {
    ...(runtime === undefined ? {} : { runtime }),
    allowedOrigins: opts.allowedOrigins ?? scope.controllerBridge.allowedOrigins,
    ...(opts.targetWindow === undefined ? {} : { targetWindow: opts.targetWindow }),
    ...(opts.expectedSource === undefined ? {} : { expectedSource: opts.expectedSource }),
  });
}

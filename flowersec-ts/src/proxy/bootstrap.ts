import type { Client } from "../client.js";
import type { ConnectArtifact } from "../connect/artifact.js";
import type { ConnectBrowserOptions } from "../browser/connect.js";
import { connectBrowser } from "../browser/connect.js";

import {
  registerProxyIntegration,
  type ProxyIntegrationPlugin,
  type RegisterProxyIntegrationOptions,
  type ProxyIntegrationServiceWorkerOptions,
} from "./integration.js";
import { registerProxyControllerWindow, type RegisterProxyControllerWindowOptions } from "./controllerWindow.js";
import type { ProxyPresetInput } from "./preset.js";
import {
  extractProxyRuntimeScopeV1,
  resolvePresetInputFromScope,
  resolveRuntimeLimitsFromScope,
  resolveRuntimePresetLimits,
  type ProxyRuntimeScopeV1,
} from "./runtimeScope.js";
import { createProxyRuntime, type ProxyRuntime } from "./runtime.js";

export type ConnectArtifactProxyBrowserHandle = Readonly<{
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

export type ConnectArtifactProxyControllerBrowserHandle = Readonly<{
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
  capabilityNonce?: RegisterProxyControllerWindowOptions["capabilityNonce"];
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
  opts: Omit<RegisterProxyIntegrationOptions, "client">
): Promise<ConnectArtifactProxyBrowserHandle> {
  const integrationInput: RegisterProxyIntegrationOptions = {
    client,
    serviceWorker: opts.serviceWorker,
    ...(opts.preset === undefined ? {} : { preset: opts.preset }),
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
    capabilityNonce?: RegisterProxyControllerWindowOptions["capabilityNonce"];
  }>
): ConnectArtifactProxyControllerBrowserHandle {
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
      ...(opts.capabilityNonce === undefined ? {} : { capabilityNonce: opts.capabilityNonce }),
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

export async function connectArtifactProxyBrowser(
  artifact: ConnectArtifact,
  opts: ConnectArtifactProxyBrowserOptions = {}
): Promise<ConnectArtifactProxyBrowserHandle> {
  const scope = extractProxyRuntimeScopeV1(artifact, "service_worker") as Extract<ProxyRuntimeScopeV1, { mode: "service_worker" }>;
  const client = await connectBrowser(artifact, opts.connect ?? {});
  const nextOpts = scopeRuntimeToIntegrationOptions(scope, opts);
  return await connectProxyBrowserClient(client, nextOpts);
}

export async function connectArtifactProxyControllerBrowser(
  artifact: ConnectArtifact,
  opts: ConnectArtifactProxyControllerBrowserOptions = {}
): Promise<ConnectArtifactProxyControllerBrowserHandle> {
  const scope = extractProxyRuntimeScopeV1(artifact, "controller_bridge") as Extract<ProxyRuntimeScopeV1, { mode: "controller_bridge" }>;
  const client = await connectBrowser(artifact, opts.connect ?? {});
  const runtime = resolveRuntimeLimitsFromScope(scope, opts.runtime);
  return connectProxyControllerClient(client, {
    ...(runtime === undefined ? {} : { runtime }),
    allowedOrigins: opts.allowedOrigins ?? scope.controllerBridge.allowedOrigins,
    ...(opts.targetWindow === undefined ? {} : { targetWindow: opts.targetWindow }),
    ...(opts.expectedSource === undefined ? {} : { expectedSource: opts.expectedSource }),
    ...(opts.capabilityNonce === undefined ? {} : { capabilityNonce: opts.capabilityNonce }),
  });
}

import type { Client } from "../client.js";
import type { TunnelConnectBrowserOptions } from "../browser/connect.js";
import { connectTunnelBrowser } from "../browser/connect.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";

import {
  registerProxyIntegration,
  type ProxyIntegrationPlugin,
  type ProxyIntegrationServiceWorkerOptions,
  type RegisterProxyIntegrationOptions,
} from "./integration.js";
import { registerProxyControllerWindow, type RegisterProxyControllerWindowOptions } from "./controllerWindow.js";
import type { ProxyProfile, ProxyProfileName } from "./profiles.js";
import { createProxyRuntime, type ProxyRuntime } from "./runtime.js";

export type ConnectTunnelProxyBrowserOptions = Readonly<{
  connect?: TunnelConnectBrowserOptions;
  profile?: ProxyProfileName | Partial<ProxyProfile>;
  runtimeGlobalKey?: string;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  serviceWorker: ProxyIntegrationServiceWorkerOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

export type ConnectTunnelProxyBrowserHandle = Readonly<{
  client: Client;
  runtime: ProxyRuntime;
  dispose: () => Promise<void>;
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

export async function connectTunnelProxyBrowser(
  grant: ChannelInitGrant,
  opts: ConnectTunnelProxyBrowserOptions
): Promise<ConnectTunnelProxyBrowserHandle> {
  const client = await connectTunnelBrowser(grant, opts.connect ?? {});

  const integrationInput: RegisterProxyIntegrationOptions = {
    client,
    serviceWorker: opts.serviceWorker,
    ...(opts.profile === undefined ? {} : { profile: opts.profile }),
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

export async function connectTunnelProxyControllerBrowser(
  grant: ChannelInitGrant,
  opts: ConnectTunnelProxyControllerBrowserOptions
): Promise<ConnectTunnelProxyControllerBrowserHandle> {
  const client = await connectTunnelBrowser(grant, opts.connect ?? {});
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

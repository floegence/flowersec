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
import type { ProxyProfile, ProxyProfileName } from "./profiles.js";
import type { ProxyRuntime } from "./runtime.js";

export type ConnectTunnelProxyBrowserOptions = Readonly<{
  connect?: TunnelConnectBrowserOptions;
  profile?: ProxyProfileName | Partial<ProxyProfile>;
  runtime?: RegisterProxyIntegrationOptions["runtime"];
  serviceWorker: ProxyIntegrationServiceWorkerOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

export type ConnectTunnelProxyBrowserHandle = Readonly<{
  client: Client;
  runtime: ProxyRuntime;
  dispose: () => Promise<void>;
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

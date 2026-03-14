import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import type { ClientObserverLike } from "../observability/observer.js";
import type { AutoReconnectConfig, ConnectConfig as ReconnectConnectConfig } from "../reconnect/index.js";
import type { DirectConnectBrowserOptions, TunnelConnectBrowserOptions } from "./connect.js";
import { connectDirectBrowser, connectTunnelBrowser } from "./connect.js";
import { requestChannelGrant, type ControlplaneConfig } from "./controlplane.js";

type SharedReconnectOptions = Readonly<{
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

type TunnelReconnectConnectOptions = Omit<TunnelConnectBrowserOptions, "observer" | "signal">;
type DirectReconnectConnectOptions = Omit<DirectConnectBrowserOptions, "observer" | "signal">;

export type TunnelBrowserReconnectConfig = SharedReconnectOptions & Readonly<{
  mode?: "tunnel";
  connect?: TunnelReconnectConnectOptions;
  grant?: ChannelInitGrant;
  getGrant?: () => Promise<ChannelInitGrant>;
  controlplane?: ControlplaneConfig;
}>;

export type DirectBrowserReconnectConfig = SharedReconnectOptions & Readonly<{
  mode: "direct";
  connect?: DirectReconnectConnectOptions;
  directInfo?: DirectConnectInfo;
  getDirectInfo?: () => Promise<DirectConnectInfo>;
}>;

export type BrowserReconnectConfig = TunnelBrowserReconnectConfig | DirectBrowserReconnectConfig;

async function resolveTunnelGrant(config: TunnelBrowserReconnectConfig): Promise<ChannelInitGrant> {
  if (config.getGrant) return await config.getGrant();
  if (config.grant) return config.grant;
  if (config.controlplane) return await requestChannelGrant(config.controlplane);
  throw new Error("Tunnel reconnect config requires `getGrant`, `grant`, or `controlplane`");
}

async function resolveDirectInfo(config: DirectBrowserReconnectConfig): Promise<DirectConnectInfo> {
  if (config.getDirectInfo) return await config.getDirectInfo();
  if (config.directInfo) return config.directInfo;
  throw new Error("Direct reconnect config requires `getDirectInfo` or `directInfo`");
}

export function createTunnelBrowserReconnectConfig(config: TunnelBrowserReconnectConfig): ReconnectConnectConfig {
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) =>
      await connectTunnelBrowser(await resolveTunnelGrant(config), {
        ...(config.connect ?? {}),
        signal,
        observer,
      }),
  };
}

export function createDirectBrowserReconnectConfig(config: DirectBrowserReconnectConfig): ReconnectConnectConfig {
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) =>
      await connectDirectBrowser(await resolveDirectInfo(config), {
        ...(config.connect ?? {}),
        signal,
        observer,
      }),
  };
}

export function createBrowserReconnectConfig(config: BrowserReconnectConfig): ReconnectConnectConfig {
  if (config.mode === "direct") {
    return createDirectBrowserReconnectConfig(config);
  }
  return createTunnelBrowserReconnectConfig(config);
}

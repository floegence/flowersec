import type { ConnectArtifact } from "../connect/artifact.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import type { ClientObserverLike } from "../observability/observer.js";
import type { AutoReconnectConfig, ConnectConfig as ReconnectConnectConfig } from "../reconnect/index.js";
import type { ConnectBrowserOptions, DirectConnectBrowserOptions, TunnelConnectBrowserOptions } from "./connect.js";
import { connectBrowser, connectDirectBrowser, connectTunnelBrowser } from "./connect.js";
import {
  requestChannelGrant,
  requestConnectArtifact,
  requestEntryConnectArtifact,
  type ConnectArtifactRequestConfig,
  type ControlplaneConfig,
  type EntryConnectArtifactRequestConfig,
} from "./controlplane.js";

type SharedReconnectOptions = Readonly<{
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

type ArtifactFactoryArgs = Readonly<{
  traceId?: string;
}>;

type TunnelReconnectConnectOptions = Omit<TunnelConnectBrowserOptions, "observer" | "signal">;
type DirectReconnectConnectOptions = Omit<DirectConnectBrowserOptions, "observer" | "signal">;
type BrowserReconnectConnectOptions = Omit<ConnectBrowserOptions, "observer" | "signal">;

type ArtifactAwareTunnelReconnectConfig = Readonly<{
  artifact?: ConnectArtifact;
  getArtifact?: (args: ArtifactFactoryArgs) => Promise<ConnectArtifact>;
  artifactControlplane?: ConnectArtifactRequestConfig | EntryConnectArtifactRequestConfig;
}>;

type ArtifactAwareDirectReconnectConfig = Readonly<{
  artifact?: ConnectArtifact;
  getArtifact?: (args: ArtifactFactoryArgs) => Promise<ConnectArtifact>;
  artifactControlplane?: ConnectArtifactRequestConfig | EntryConnectArtifactRequestConfig;
}>;

export type TunnelBrowserReconnectConfig = SharedReconnectOptions &
  ArtifactAwareTunnelReconnectConfig &
  Readonly<{
  mode?: "tunnel";
  connect?: TunnelReconnectConnectOptions;
  grant?: ChannelInitGrant;
  getGrant?: () => Promise<ChannelInitGrant>;
  controlplane?: ControlplaneConfig;
}>;

export type DirectBrowserReconnectConfig = SharedReconnectOptions &
  ArtifactAwareDirectReconnectConfig &
  Readonly<{
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

async function resolveConnectArtifact(
  config: ArtifactAwareTunnelReconnectConfig | ArtifactAwareDirectReconnectConfig,
  traceId?: string
): Promise<ConnectArtifact> {
  if (config.getArtifact) {
    return await config.getArtifact(traceId === undefined ? {} : { traceId });
  }
  if (config.artifact) return config.artifact;
  if (config.artifactControlplane) {
    const correlation =
      traceId === undefined
        ? config.artifactControlplane.correlation
        : ({ traceId } satisfies Readonly<{ traceId?: string }>);
    if ("entryTicket" in config.artifactControlplane) {
      return await requestEntryConnectArtifact({
        ...config.artifactControlplane,
        ...(correlation === undefined ? {} : { correlation }),
      });
    }
    return await requestConnectArtifact({
      ...config.artifactControlplane,
      ...(correlation === undefined ? {} : { correlation }),
    });
  }
  throw new Error("Artifact reconnect config requires `getArtifact`, `artifact`, or `artifactControlplane`");
}

function updateTraceId(current: string | undefined, artifact: ConnectArtifact): string | undefined {
  return artifact.correlation?.trace_id ?? current;
}

export function createTunnelBrowserReconnectConfig(config: TunnelBrowserReconnectConfig): ReconnectConnectConfig {
  let traceId = config.artifact?.correlation?.trace_id;
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) => {
      if (config.getArtifact || config.artifact || config.artifactControlplane) {
        const artifact = await resolveConnectArtifact(config, traceId);
        if (artifact.transport !== "tunnel") {
          throw new Error("Tunnel reconnect config requires a tunnel ConnectArtifact");
        }
        traceId = updateTraceId(traceId, artifact);
        return await connectBrowser(artifact, {
          ...((config.connect ?? {}) as BrowserReconnectConnectOptions),
          signal,
          observer,
        });
      }
      return await connectTunnelBrowser(await resolveTunnelGrant(config), {
        ...(config.connect ?? {}),
        signal,
        observer,
      });
    },
  };
}

export function createDirectBrowserReconnectConfig(config: DirectBrowserReconnectConfig): ReconnectConnectConfig {
  let traceId = config.artifact?.correlation?.trace_id;
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) => {
      if (config.getArtifact || config.artifact || config.artifactControlplane) {
        const artifact = await resolveConnectArtifact(config, traceId);
        if (artifact.transport !== "direct") {
          throw new Error("Direct reconnect config requires a direct ConnectArtifact");
        }
        traceId = updateTraceId(traceId, artifact);
        return await connectBrowser(artifact, {
          ...((config.connect ?? {}) as BrowserReconnectConnectOptions),
          signal,
          observer,
        });
      }
      return await connectDirectBrowser(await resolveDirectInfo(config), {
        ...(config.connect ?? {}),
        signal,
        observer,
      });
    },
  };
}

export function createBrowserReconnectConfig(config: BrowserReconnectConfig): ReconnectConnectConfig {
  if (config.mode === "direct") {
    return createDirectBrowserReconnectConfig(config);
  }
  return createTunnelBrowserReconnectConfig(config);
}

import type { ConnectArtifact } from "../connect/artifact.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import type { ClientObserverLike } from "../observability/observer.js";
import type { ConnectOptions } from "../facade.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import type { AutoReconnectConfig, ConnectConfig as ReconnectConnectConfig } from "../reconnect/index.js";
import {
  resolveConnectArtifact,
  type ArtifactAwareReconnectConfig,
  type ArtifactFactoryArgs,
  updateTraceId,
} from "../reconnect/artifactControlplane.js";
import type {
  RequestConnectArtifactInput,
  RequestEntryConnectArtifactInput,
} from "../controlplane/index.js";

import { connectDirectNode, connectNode, connectTunnelNode } from "./connect.js";

type SharedReconnectOptions = Readonly<{
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

type TunnelReconnectConnectOptions = Omit<TunnelConnectOptions, "observer" | "signal">;
type DirectReconnectConnectOptions = Omit<DirectConnectOptions, "observer" | "signal">;
type NodeReconnectConnectOptions = TunnelReconnectConnectOptions | DirectReconnectConnectOptions;

type ArtifactAwareTunnelReconnectConfig = ArtifactAwareReconnectConfig &
  Readonly<{
    artifact?: ConnectArtifact;
    getArtifact?: (args: ArtifactFactoryArgs) => Promise<ConnectArtifact>;
    artifactControlplane?: RequestConnectArtifactInput | RequestEntryConnectArtifactInput;
  }>;

type ArtifactAwareDirectReconnectConfig = ArtifactAwareReconnectConfig &
  Readonly<{
    artifact?: ConnectArtifact;
    getArtifact?: (args: ArtifactFactoryArgs) => Promise<ConnectArtifact>;
    artifactControlplane?: RequestConnectArtifactInput | RequestEntryConnectArtifactInput;
  }>;

export type TunnelNodeReconnectConfig = SharedReconnectOptions &
  ArtifactAwareTunnelReconnectConfig &
  Readonly<{
    mode?: "tunnel";
    connect?: TunnelReconnectConnectOptions;
    grant?: ChannelInitGrant;
    getGrant?: () => Promise<ChannelInitGrant>;
  }>;

export type DirectNodeReconnectConfig = SharedReconnectOptions &
  ArtifactAwareDirectReconnectConfig &
  Readonly<{
    mode: "direct";
    connect?: DirectReconnectConnectOptions;
    directInfo?: DirectConnectInfo;
    getDirectInfo?: () => Promise<DirectConnectInfo>;
  }>;

export type NodeReconnectConfig = TunnelNodeReconnectConfig | DirectNodeReconnectConfig;

async function resolveTunnelGrant(config: TunnelNodeReconnectConfig): Promise<ChannelInitGrant> {
  if (config.getGrant) return await config.getGrant();
  if (config.grant) return config.grant;
  throw new Error("Tunnel reconnect config requires `getGrant` or `grant`");
}

async function resolveDirectInfo(config: DirectNodeReconnectConfig): Promise<DirectConnectInfo> {
  if (config.getDirectInfo) return await config.getDirectInfo();
  if (config.directInfo) return config.directInfo;
  throw new Error("Direct reconnect config requires `getDirectInfo` or `directInfo`");
}

export function createTunnelNodeReconnectConfig(config: TunnelNodeReconnectConfig): ReconnectConnectConfig {
  let traceId = config.artifact?.correlation?.trace_id;
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) => {
      if (config.getArtifact || config.artifact || config.artifactControlplane) {
        const artifact = await resolveConnectArtifact(config, traceId, signal);
        if (artifact.transport !== "tunnel") {
          throw new Error("Tunnel reconnect config requires a tunnel ConnectArtifact");
        }
        traceId = updateTraceId(traceId, artifact);
        const connectOptions = {
          ...(config.connect === undefined ? {} : (config.connect as NodeReconnectConnectOptions)),
          signal,
          observer,
        } as ConnectOptions;
        return await connectNode(artifact, connectOptions);
      }
      const connectOptions = {
        ...(config.connect === undefined ? {} : config.connect),
        signal,
        observer,
      } as TunnelConnectOptions;
      return await connectTunnelNode(await resolveTunnelGrant(config), connectOptions);
    },
  };
}

export function createDirectNodeReconnectConfig(config: DirectNodeReconnectConfig): ReconnectConnectConfig {
  let traceId = config.artifact?.correlation?.trace_id;
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) => {
      if (config.getArtifact || config.artifact || config.artifactControlplane) {
        const artifact = await resolveConnectArtifact(config, traceId, signal);
        if (artifact.transport !== "direct") {
          throw new Error("Direct reconnect config requires a direct ConnectArtifact");
        }
        traceId = updateTraceId(traceId, artifact);
        const connectOptions = {
          ...(config.connect === undefined ? {} : (config.connect as NodeReconnectConnectOptions)),
          signal,
          observer,
        } as ConnectOptions;
        return await connectNode(artifact, connectOptions);
      }
      const connectOptions = {
        ...(config.connect === undefined ? {} : config.connect),
        signal,
        observer,
      } as DirectConnectOptions;
      return await connectDirectNode(await resolveDirectInfo(config), connectOptions);
    },
  };
}

export function createNodeReconnectConfig(config: NodeReconnectConfig): ReconnectConnectConfig {
  if (config.mode === "direct") {
    return createDirectNodeReconnectConfig(config);
  }
  return createTunnelNodeReconnectConfig(config);
}

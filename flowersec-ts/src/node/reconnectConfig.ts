import type { ClientObserverLike } from "../observability/observer.js";
import type { ConnectOptions } from "../facade.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import type { AutoReconnectConfig, ConnectConfig as ReconnectConnectConfig } from "../reconnect/index.js";
import { createArtifactResolver, updateTraceId, type ArtifactSource } from "../reconnect/artifactControlplane.js";
import { connectNode } from "./connect.js";

export type NodeReconnectConfig = Readonly<{
  source: ArtifactSource;
  connect?: Omit<TunnelConnectOptions, "observer" | "signal"> | Omit<DirectConnectOptions, "observer" | "signal">;
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

export type TunnelNodeReconnectConfig = NodeReconnectConfig;
export type DirectNodeReconnectConfig = NodeReconnectConfig;

export function createNodeReconnectConfig(config: NodeReconnectConfig): ReconnectConnectConfig {
  if (config.source.kind === "once" && config.autoReconnect?.enabled) {
    throw new Error("automatic reconnect requires a refreshable artifact source");
  }
  let traceId = config.source.kind === "once" ? config.source.artifact.correlation?.trace_id : undefined;
  const acquire = createArtifactResolver(config.source);
  return {
    ...(config.observer === undefined ? {} : { observer: config.observer }),
    ...(config.autoReconnect === undefined ? {} : { autoReconnect: config.autoReconnect }),
    connectOnce: async ({ signal, observer }) => {
      const artifact = await acquire({ ...(traceId === undefined ? {} : { traceId }), signal });
      traceId = updateTraceId(traceId, artifact);
      return await connectNode(artifact, { ...(config.connect ?? {}), signal, observer } as ConnectOptions);
    },
  };
}

export const createTunnelNodeReconnectConfig = createNodeReconnectConfig;
export const createDirectNodeReconnectConfig = createNodeReconnectConfig;

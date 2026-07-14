import type { ClientObserverLike } from "../observability/observer.js";
import type { AutoReconnectConfig, ConnectConfig as ReconnectConnectConfig } from "../reconnect/index.js";
import { createArtifactResolver, updateTraceId, type ArtifactSource } from "../reconnect/artifactControlplane.js";
import type { ConnectBrowserOptions, DirectConnectBrowserOptions, TunnelConnectBrowserOptions } from "./connect.js";
import { connectBrowser } from "./connect.js";

export type BrowserReconnectConfig = Readonly<{
  source: ArtifactSource;
  connect?: Omit<TunnelConnectBrowserOptions, "observer" | "signal"> | Omit<DirectConnectBrowserOptions, "observer" | "signal">;
  observer?: ClientObserverLike;
  autoReconnect?: AutoReconnectConfig;
}>;

export type TunnelBrowserReconnectConfig = BrowserReconnectConfig;
export type DirectBrowserReconnectConfig = BrowserReconnectConfig;

export function createBrowserReconnectConfig(config: BrowserReconnectConfig): ReconnectConnectConfig {
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
      return await connectBrowser(artifact, { ...(config.connect ?? {}), signal, observer } as ConnectBrowserOptions);
    },
  };
}

export const createTunnelBrowserReconnectConfig = createBrowserReconnectConfig;
export const createDirectBrowserReconnectConfig = createBrowserReconnectConfig;

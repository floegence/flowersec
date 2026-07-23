import type { Client } from "../client.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import { connectDirect as connectDirectInternal } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import { connectTunnel as connectTunnelInternal } from "../tunnel-client/connect.js";
import { resolveConnectArtifact } from "./resolveArtifact.js";
import type { ConnectArtifact } from "./artifact.js";

export type ConnectOptions = TunnelConnectOptions | DirectConnectOptions;

export async function connectLegacy(input: ConnectArtifact, opts: ConnectOptions): Promise<Client> {
  const normalized = await resolveConnectArtifact(input, opts);
  const nextObserver = normalized.observer ?? opts.observer;
  const nextOpts = (nextObserver === opts.observer ? opts : { ...opts, observer: nextObserver }) as ConnectOptions;
  if (normalized.kind === "direct") {
    return await connectDirectInternal(normalized.input, nextOpts as DirectConnectOptions);
  }
  return await connectTunnelInternal(normalized.input, nextOpts as TunnelConnectOptions);
}

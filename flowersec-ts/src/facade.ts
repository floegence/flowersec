import type { Client } from "./client.js";
import type { DirectConnectOptions } from "./direct-client/connect.js";
import { connectDirect as connectDirectInternal } from "./direct-client/connect.js";
import type { TunnelConnectOptions } from "./tunnel-client/connect.js";
import { connectTunnel as connectTunnelInternal } from "./tunnel-client/connect.js";

import type { ChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";

export type { ChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
export { assertChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
export type { DirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";
export { assertDirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";

export type { ClientObserverLike } from "./observability/observer.js";

export type { Client, ClientPath } from "./client.js";

export type { FlowersecErrorCode, FlowersecPath, FlowersecStage } from "./utils/errors.js";
export { FlowersecError } from "./utils/errors.js";

export type { TunnelConnectOptions } from "./tunnel-client/connect.js";

export type { DirectConnectOptions } from "./direct-client/connect.js";

export { RpcCallError } from "./rpc/callError.js";

export async function connectTunnel(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectTunnel(grant: unknown, opts: TunnelConnectOptions): Promise<Client> {
  return await connectTunnelInternal(grant, opts);
}

export async function connectDirect(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectDirect(info: unknown, opts: DirectConnectOptions): Promise<Client> {
  return await connectDirectInternal(info, opts);
}

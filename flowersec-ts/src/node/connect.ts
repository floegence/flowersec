import type { Client } from "../client.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import { connectDirect } from "../direct-client/connect.js";
import { connectTunnel } from "../tunnel-client/connect.js";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

import { createNodeWsFactory } from "./wsFactory.js";

export async function connectTunnelNode(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectTunnelNode(grant: unknown, opts: TunnelConnectOptions): Promise<Client> {
  return await connectTunnel(grant, { ...opts, wsFactory: opts.wsFactory ?? createNodeWsFactory() });
}

export async function connectDirectNode(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectDirectNode(info: unknown, opts: DirectConnectOptions): Promise<Client> {
  return await connectDirect(info, { ...opts, wsFactory: opts.wsFactory ?? createNodeWsFactory() });
}

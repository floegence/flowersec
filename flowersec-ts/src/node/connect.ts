import type { Client } from "../client.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import { connectDirect } from "../direct-client/connect.js";
import { connectTunnel } from "../tunnel-client/connect.js";
import { connectLegacy, type ConnectOptions } from "../connect/legacyFacade.js";
import type { ConnectArtifact } from "../connect/artifact.js";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

import { createNodeWsFactory } from "./wsFactory.js";
import { defaultWsMaxPayload } from "./wsDefaults.js";

export async function connectNode(input: ConnectArtifact, opts: ConnectOptions): Promise<Client> {
  const wsFactory =
    opts.wsFactory ??
    createNodeWsFactory({
      maxPayload: defaultWsMaxPayload(opts),
      perMessageDeflate: false,
    });
  return await connectLegacy(input, { ...opts, wsFactory });
}

export async function connectTunnelNode(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectTunnelNode(grant: unknown, opts: TunnelConnectOptions): Promise<Client> {
  const wsFactory =
    opts.wsFactory ??
    createNodeWsFactory({
      maxPayload: defaultWsMaxPayload(opts),
      perMessageDeflate: false,
    });
  return await connectTunnel(grant, { ...opts, wsFactory });
}

export async function connectDirectNode(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectDirectNode(info: unknown, opts: DirectConnectOptions): Promise<Client> {
  const wsFactory =
    opts.wsFactory ??
    createNodeWsFactory({
      maxPayload: defaultWsMaxPayload(opts),
      perMessageDeflate: false,
    });
  return await connectDirect(info, { ...opts, wsFactory });
}

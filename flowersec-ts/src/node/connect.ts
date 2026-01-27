import type { Client } from "../client.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import { connectDirect } from "../direct-client/connect.js";
import { connectTunnel } from "../tunnel-client/connect.js";
import { connect, type ConnectOptions } from "../facade.js";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

import { createNodeWsFactory } from "./wsFactory.js";

const defaultMaxHandshakePayload = 8 * 1024;
const defaultMaxRecordBytes = 1 << 20;
const handshakeFrameOverheadBytes = 4 + 1 + 1 + 4;
const wsMaxPayloadSlackBytes = 64;

function defaultWsMaxPayload(opts: Readonly<{ maxHandshakePayload?: number; maxRecordBytes?: number }>): number {
  const maxHandshakePayload = opts.maxHandshakePayload ?? 0;
  const maxRecordBytes = opts.maxRecordBytes ?? 0;

  const hp =
    Number.isSafeInteger(maxHandshakePayload) && maxHandshakePayload > 0 ? maxHandshakePayload : defaultMaxHandshakePayload;
  const rb = Number.isSafeInteger(maxRecordBytes) && maxRecordBytes > 0 ? maxRecordBytes : defaultMaxRecordBytes;

  const handshakeMax = Math.min(Number.MAX_SAFE_INTEGER, hp + handshakeFrameOverheadBytes);
  const max = Math.max(rb, handshakeMax);
  return Math.min(Number.MAX_SAFE_INTEGER, max + wsMaxPayloadSlackBytes);
}

export async function connectNode(input: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectNode(input: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectNode(input: unknown, opts: ConnectOptions): Promise<Client> {
  const wsFactory =
    opts.wsFactory ??
    createNodeWsFactory({
      maxPayload: defaultWsMaxPayload(opts),
      perMessageDeflate: false,
    });
  return await connect(input, { ...opts, wsFactory });
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

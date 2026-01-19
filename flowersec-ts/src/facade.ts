import type { Client } from "./client.js";
import type { DirectConnectOptions } from "./direct-client/connect.js";
import { connectDirect as connectDirectInternal } from "./direct-client/connect.js";
import type { TunnelConnectOptions } from "./tunnel-client/connect.js";
import { connectTunnel as connectTunnelInternal } from "./tunnel-client/connect.js";
import { FlowersecError } from "./utils/errors.js";

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

export type ConnectOptions = TunnelConnectOptions | DirectConnectOptions;

export async function connectTunnel(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectTunnel(grant: unknown, opts: TunnelConnectOptions): Promise<Client> {
  return await connectTunnelInternal(grant, opts);
}

export async function connectDirect(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectDirect(info: unknown, opts: DirectConnectOptions): Promise<Client> {
  return await connectDirectInternal(info, opts);
}

function maybeParseJSON(input: unknown): unknown {
  if (typeof input !== "string") return input;
  const s = input.trim();
  if (s === "") return input;
  if (s[0] !== "{" && s[0] !== "[") return input;
  try {
    return JSON.parse(s);
  } catch {
    return input;
  }
}

// connect auto-detects direct vs tunnel inputs and calls connectDirect/connectTunnel.
//
// It is a convenience wrapper intended for cases where the caller only has an input JSON object
// (or a JSON string) and does not want to branch on ws_url vs tunnel_url manually.
export async function connect(input: unknown, opts: ConnectOptions): Promise<Client> {
  const v = maybeParseJSON(input);
  if (v != null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (o["ws_url"] !== undefined) return await connectDirectInternal(v, opts as DirectConnectOptions);
    if (o["grant_client"] !== undefined) return await connectTunnelInternal(v, opts as TunnelConnectOptions);
    if (o["tunnel_url"] !== undefined) return await connectTunnelInternal(v, opts as TunnelConnectOptions);
    if (o["token"] !== undefined || o["role"] !== undefined) return await connectTunnelInternal(v, opts as TunnelConnectOptions);
    throw new FlowersecError({
      path: "auto",
      stage: "validate",
      code: "invalid_input",
      message: "invalid input: expected DirectConnectInfo (ws_url) or ChannelInitGrant (tunnel_url or grant_client)",
    });
  }
  throw new FlowersecError({
    path: "auto",
    stage: "validate",
    code: "invalid_input",
    message: "invalid input: expected an object or a JSON string",
  });
}

import type { Client } from "../client.js";
import type { DirectConnectOptions } from "../direct-client/connect.js";
import type { TunnelConnectOptions } from "../tunnel-client/connect.js";
import { connectDirect } from "../direct-client/connect.js";
import { connectTunnel } from "../tunnel-client/connect.js";
import { connect, type ConnectOptions } from "../facade.js";
import { FlowersecError } from "../utils/errors.js";

import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";

export type TunnelConnectBrowserOptions = Omit<TunnelConnectOptions, "origin" | "wsFactory">;

export type DirectConnectBrowserOptions = Omit<DirectConnectOptions, "origin" | "wsFactory">;

export type ConnectBrowserOptions = Omit<ConnectOptions, "origin" | "wsFactory">;

function getBrowserOrigin(): string {
  if (typeof window === "undefined") return "";
  const o = (window as any)?.location?.origin;
  return typeof o === "string" ? o : "";
}

export async function connectBrowser(input: unknown, opts?: ConnectBrowserOptions): Promise<Client>;
export async function connectBrowser(input: unknown, opts: ConnectBrowserOptions = {}): Promise<Client> {
  const origin = getBrowserOrigin();
  if (origin === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_origin", message: "missing browser origin" });
  }
  return await connect(input, { ...opts, origin } as ConnectOptions);
}

export async function connectTunnelBrowser(grant: ChannelInitGrant, opts?: TunnelConnectBrowserOptions): Promise<Client>;
export async function connectTunnelBrowser(grant: unknown, opts: TunnelConnectBrowserOptions = {}): Promise<Client> {
  const origin = getBrowserOrigin();
  if (origin === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_origin", path: "tunnel", message: "missing browser origin" });
  }
  return await connectTunnel(grant, { ...opts, origin });
}

export async function connectDirectBrowser(info: DirectConnectInfo, opts?: DirectConnectBrowserOptions): Promise<Client>;
export async function connectDirectBrowser(info: unknown, opts: DirectConnectBrowserOptions = {}): Promise<Client> {
  const origin = getBrowserOrigin();
  if (origin === "") {
    throw new FlowersecError({ stage: "validate", code: "missing_origin", path: "direct", message: "missing browser origin" });
  }
  return await connectDirect(info, { ...opts, origin });
}

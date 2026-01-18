import type { DirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { assertDirectConnectInfo } from "../gen/flowersec/direct/v1.gen.js";
import { connectCore, type ConnectOptionsBase } from "../client-connect/connectCore.js";
import type { Client } from "../client.js";

// DirectConnectOptions controls transport and handshake limits.
export type DirectConnectOptions = ConnectOptionsBase;

// connectDirect connects to a direct websocket endpoint and returns an RPC-ready session.
export async function connectDirect(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client> {
  const ready = assertDirectConnectInfo(info);
  return await connectCore({
    path: "direct",
    wsUrl: ready.ws_url,
    channelId: ready.channel_id,
    e2eePskB64u: ready.e2ee_psk_b64u,
    defaultSuite: ready.default_suite,
    opts,
  });
}

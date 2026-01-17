import type { SecureChannel } from "./e2ee/secureChannel.js";
import type { RpcClient } from "./rpc/client.js";
import type { RpcProxy } from "./rpc-proxy/rpcProxy.js";
import type { YamuxSession } from "./yamux/session.js";
import type { YamuxStream } from "./yamux/stream.js";

export type ClientPath = "tunnel" | "direct";

// Client is a high-level session that bundles SecureChannel + yamux + RPC.
export type Client = Readonly<{
  path: ClientPath;
  endpointInstanceId?: string;
  secure: SecureChannel;
  mux: YamuxSession;
  rpc: RpcClient;
  rpcProxy: RpcProxy;
  openStream: (kind: string) => Promise<YamuxStream>;
  close: () => void;
}>;


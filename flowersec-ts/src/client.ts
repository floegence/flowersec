import type { SecureChannel } from "./e2ee/secureChannel.js";
import type { RpcClient } from "./rpc/client.js";
import type { YamuxSession } from "./yamux/session.js";
import type { YamuxStream } from "./yamux/stream.js";

export type ClientPath = "tunnel" | "direct";

// Client is a high-level session intended as the default user entrypoint.
//
// It intentionally does NOT expose the underlying SecureChannel or YamuxSession
// so the stable surface is not coupled to lower-level implementation details.
export type Client = Readonly<{
  path: ClientPath;
  endpointInstanceId?: string;
  rpc: RpcClient;
  openStream: (kind: string) => Promise<YamuxStream>;
  ping: () => Promise<void>;
  close: () => void;
}>;

// ClientInternal exposes the underlying stack for advanced integrations.
//
// It is exported only from @floegence/flowersec-core/internal and may change without notice.
export type ClientInternal = Client &
  Readonly<{
    secure: SecureChannel;
    mux: YamuxSession;
  }>;

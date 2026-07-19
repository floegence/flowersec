import type { SecureChannel } from "./e2ee/secureChannel.js";
import type { RpcClient } from "./rpc/client.js";
import type { YamuxSession } from "./yamux/session.js";
import type { YamuxStream } from "./yamux/stream.js";

export type ClientPath = "tunnel" | "direct";

// Client is a high-level session intended as the default user entrypoint.
//
// It intentionally does NOT expose the underlying SecureChannel or YamuxSession
// so the public contract is not coupled to lower-level implementation details.
export type Client = Readonly<{
  path: ClientPath;
  endpointInstanceId?: string;
  rpc: RpcClient;
  openStream: (kind: string, opts?: Readonly<{ signal?: AbortSignal }>) => Promise<YamuxStream>;
  ping: () => Promise<void>;
  /** Emits an authenticated rekey record and advances the E2EE send key. */
  rekey: () => Promise<void>;
  /** Performs an acknowledged Yamux round trip and returns RTT in milliseconds. */
  probeLiveness: () => Promise<number>;
  close: () => void;
}>;

// ClientInternal exposes the underlying stack to SDK transport implementations.
// Stable package entrypoints export Client instead.
export type ClientInternal = Client &
  Readonly<{
    secure: SecureChannel;
    mux: YamuxSession;
  }>;

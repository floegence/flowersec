import type { Client } from "./client.js";
import type { DirectConnectOptions } from "./direct-client/connect.js";
import { connectDirect as connectDirectInternal } from "./direct-client/connect.js";
import type { TunnelConnectOptions } from "./tunnel-client/connect.js";
import { connectTunnel as connectTunnelInternal } from "./tunnel-client/connect.js";
import { normalizeConnectInput } from "./connect/internalNormalize.js";
import { withObserverContext } from "./observability/observer.js";
import {
  type ConnectArtifact,
  type CorrelationContext,
  type CorrelationKV,
  type DirectClientConnectArtifact,
  type ScopeMetadataEntry,
  type TunnelClientConnectArtifact,
} from "./connect/artifact.js";

import type { ChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
import type { DirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";

export type { ChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
export { assertChannelInitGrant } from "./gen/flowersec/controlplane/v1.gen.js";
export type { DirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";
export { assertDirectConnectInfo } from "./gen/flowersec/direct/v1.gen.js";
export type {
  ConnectArtifact,
  CorrelationContext,
  CorrelationKV,
  DirectClientConnectArtifact,
  ScopeMetadataEntry,
  TunnelClientConnectArtifact,
};
export { assertConnectArtifact } from "./connect/artifact.js";

export type { ClientObserverLike } from "./observability/observer.js";

export type { Client, ClientPath } from "./client.js";

export type { FlowersecErrorCode, FlowersecPath, FlowersecStage } from "./utils/errors.js";
export { FlowersecError } from "./utils/errors.js";

export type { TunnelConnectOptions } from "./tunnel-client/connect.js";

export type { DirectConnectOptions } from "./direct-client/connect.js";

export type ConnectOptions = TunnelConnectOptions | DirectConnectOptions;

type _AssertFalse<T extends false> = T;

// Type-level regression guard: tunnel-only options must not be accepted by direct connects.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _TunnelOptsNotDirect = _AssertFalse<TunnelConnectOptions extends DirectConnectOptions ? true : false>;
// Type-level regression guard: direct-only options must not be accepted by tunnel connects.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _DirectOptsNotTunnel = _AssertFalse<DirectConnectOptions extends TunnelConnectOptions ? true : false>;

export async function connectTunnel(grant: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connectTunnel(grant: unknown, opts: TunnelConnectOptions): Promise<Client> {
  return await connectTunnelInternal(grant, opts);
}

export async function connectDirect(info: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connectDirect(info: unknown, opts: DirectConnectOptions): Promise<Client> {
  return await connectDirectInternal(info, opts);
}

// connect auto-detects direct vs tunnel inputs and calls connectDirect/connectTunnel.
//
// It is a convenience wrapper intended for cases where the caller only has an input JSON object
// (or a JSON string) and does not want to branch on ws_url vs tunnel_url manually.
export async function connect(input: DirectConnectInfo, opts: DirectConnectOptions): Promise<Client>;
export async function connect(input: ChannelInitGrant, opts: TunnelConnectOptions): Promise<Client>;
export async function connect(input: ConnectArtifact, opts: ConnectOptions): Promise<Client>;
export async function connect(input: unknown, opts: ConnectOptions): Promise<Client>;
export async function connect(input: unknown, opts: ConnectOptions): Promise<Client> {
  const normalized = await normalizeConnectInput(input, opts);
  const nextOpts =
    normalized.correlation == null
      ? opts
      : ({
          ...opts,
          observer: withObserverContext(opts.observer, {
            ...(normalized.correlation.trace_id === undefined ? {} : { traceId: normalized.correlation.trace_id }),
            ...(normalized.correlation.session_id === undefined ? {} : { sessionId: normalized.correlation.session_id }),
          }),
        } as ConnectOptions);
  if (normalized.kind === "direct") {
    return await connectDirectInternal(normalized.input, nextOpts as DirectConnectOptions);
  }
  return await connectTunnelInternal(normalized.input, nextOpts as TunnelConnectOptions);
}

import type { Client } from "./client.js";
import type { DirectConnectOptions } from "./direct-client/connect.js";
import { connectDirect as connectDirectInternal } from "./direct-client/connect.js";
import type { TunnelConnectOptions } from "./tunnel-client/connect.js";
import { connectTunnel as connectTunnelInternal } from "./tunnel-client/connect.js";
import { resolveConnectArtifact } from "./connect/resolveArtifact.js";
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
export type { LivenessOptions } from "./client-connect/connectCore.js";
export type { WebSocketLimits } from "./ws-client/binaryTransport.js";
export type { YamuxLimits } from "./yamux/session.js";

export type { FlowersecErrorCode, FlowersecPath, FlowersecStage } from "./utils/errors.js";
export { FlowersecError } from "./utils/errors.js";
export {
  AllowPlaintextForLoopback,
  createNetworkPlaintextPolicy,
  PlaintextRiskAcceptance,
  RequireTLS,
} from "./client-connect/transportSecurity.js";
export type {
  NetworkPlaintextPolicyOptions,
  TransportSecurityPolicy,
  TransportSecurityPolicyInput,
  TransportSecurityPolicyPreset,
} from "./client-connect/transportSecurity.js";

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

// connect resolves an artifact to its explicit direct or tunnel transport.
export async function connect(input: ConnectArtifact, opts: ConnectOptions): Promise<Client> {
  const normalized = await resolveConnectArtifact(input, opts);
  const nextObserver = normalized.observer ?? opts.observer;
  const nextOpts = (nextObserver === opts.observer ? opts : { ...opts, observer: nextObserver }) as ConnectOptions;
  if (normalized.kind === "direct") {
    return await connectDirectInternal(normalized.input, nextOpts as DirectConnectOptions);
  }
  return await connectTunnelInternal(normalized.input, nextOpts as TunnelConnectOptions);
}

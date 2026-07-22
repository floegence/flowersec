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
export type {
  ByteStreamV2,
  CarrierKind,
  IncomingStreamV2,
  JsonObjectV2,
  JsonPrimitiveV2,
  JsonValueV2,
  OperationOptionsV2,
  PathKind,
  StreamOpenOptionsV2,
  SessionTerminationV2,
} from "./v2/contract.js";
export type {
  CarrierSessionV2,
  CarrierStreamV2,
  NativeCarrierSessionV2,
  NativeCarrierStreamV2,
  WebSocketBinaryTransportV2,
  WebSocketResourcePolicyV2,
} from "./v2/carrier.js";
export { SessionV2, establishSessionV2 } from "./v2/session.js";
export type {
  SessionConfigV2,
  SessionDeadlineFactoryV2,
  SessionDeadlineHandleV2,
  SessionDeadlinePhaseV2,
  SessionDeadlinesV2,
} from "./v2/session.js";
export {
  AdmissionSessionV2Error,
  establishAdmittedNativeSessionV2,
  establishAdmittedWebSocketSessionV2,
} from "./v2/admittedSession.js";
export type {
  NetworkModeV2,
  RuntimeCapabilityDescriptorV2,
  RuntimeCapabilityTupleV2,
  SessionRoleV2,
  UnsupportedRuntimeCarrierV2,
  BrowserRuntimeFeaturesV2,
} from "./v2/capability.js";
export {
  BROWSER_RUNTIME_CAPABILITY_V2,
  NODE_RUNTIME_CAPABILITY_V2,
  decodeRuntimeCapabilityDescriptorV2,
  detectBrowserRuntimeCapabilityV2,
  encodeRuntimeCapabilityDescriptorV2,
  runtimeCapabilityDigestHexV2,
  runtimeCapabilityDigestV2,
  validateRuntimeCapabilityDescriptorV2,
} from "./v2/capability.js";
export {
  ArtifactV2Error,
  decodeArtifactV2JSON,
  encodeArtifactV2JSON,
  validateArtifactV2,
} from "./v2/artifact.js";
export type {
  ArtifactCandidateV2,
  ArtifactCarrierV2,
  ArtifactPathKindV2,
  ArtifactV2,
  ArtifactV2ErrorCode,
  CanonicalArtifactCandidateV2,
  CanonicalCandidateSetV2,
  CorrelationContextV2,
  CorrelationTagV2,
  DirectArtifactPathV2,
  ScopeMetadataV2,
  SessionContractV2,
  TunnelArtifactPathV2,
} from "./v2/artifact.js";
export {
  TRANSPORT_V2_VERSION_POLICY,
  createArtifactAcquireContextV2,
  createArtifactLeaseV2,
  createArtifactV2Resolver,
} from "./v2/artifactLease.js";
export type {
  ArtifactAcquireContextV2,
  ArtifactAcquireContextOptionsV2,
  ArtifactDecoderV2,
  ArtifactInputV2,
  ArtifactLeaseV2,
  ArtifactSourceV2,
  ArtifactVersionPolicyV2,
} from "./v2/artifactLease.js";
export { createSessionReconnectManagerV2 } from "./v2/reconnect.js";
export type {
  SessionAutoReconnectConfigV2,
  SessionReconnectConfigV2,
  SessionReconnectManagerV2,
  SessionReconnectStateV2,
  SessionReconnectStatusV2,
} from "./v2/reconnect.js";
export type { LivenessOptions } from "./client-connect/connectCore.js";
export type { WebSocketLimits } from "./ws-client/binaryTransport.js";
export type { YamuxLimits } from "./yamux/session.js";

export type {
  FlowersecCandidateDiagnostic,
  FlowersecErrorCode,
  FlowersecPath,
  FlowersecStage,
} from "./utils/errors.js";
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

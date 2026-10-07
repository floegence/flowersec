import type { SessionResourceSpec } from "./sessionAdmission.js";
import type { RPCApplicationConfig } from "./rpcApplication.js";
import { captureSendQueueBytes, captureStreamSendQueueBytes } from "./sendBudget.js";
import type { V4AutomaticLivenessPolicy } from "../liveness.js";
import { captureAutomaticLiveness, selectedIdleDuration } from "./sessionActivity.js";
import { timeAdd } from "./timeArithmetic.js";
import type { V4EnvironmentSessionSpec } from "./environment.js";
import type { ClientPreparationFields } from "./credentialVerifier.js";
import type { ReadyIdentitySigner, NoiseProfile } from "./noiseHandshake.js";
import type { V4AuthenticatedTransport } from "./session.js";
import type { V4ConsumerTLS13Verification } from "../../generated/transportV4APIResults.js";
export interface ReliableClientLimits {
  readonly maxFrame: number;
  readonly maxStreams: number;
  readonly receiveQueueBytes: number;
  readonly maxDataBytes: number;
  readonly maxCursorBytes: number;
  readonly maxWriteBytes: number;
  /** Aggregate local SDK send queue, including retained ciphertext tails. */
  readonly sessionSendQueueBytes?: number;
  /** Maximum SDK-owned send allocation for a single local direction. */
  readonly streamSendQueueBytes?: number;
  readonly writeDeadlineMS: bigint;
  readonly operationDeadlineMS: bigint;
  readonly rekeyPrepareMS: bigint;
  readonly rekeyProtocolMS: bigint;
  readonly rekeyConfirmationMS: bigint;
  readonly cryptoKeys: number;
  /** Local upper bound admitted before acquiring connection material. */
  readonly maxGeneralOutstanding?: number;
  readonly localIdleDurationMS?: bigint;
  readonly automaticLiveness?: V4AutomaticLivenessPolicy;
  /** Native DATA assembly only. Depth two shares at most 16 client candidates;
   * lack of a next permit falls back to the same depth-one receive path. */
  readonly nativeDataAssemblyDepth?: 1 | 2;
}
export function captureReliableClientLimits(limits: ReliableClientLimits): ReliableClientLimits {
  if (limits.maxGeneralOutstanding !== undefined && (!Number.isSafeInteger(limits.maxGeneralOutstanding) || limits.maxGeneralOutstanding < 1 || limits.maxGeneralOutstanding > 1024)) throw new Error("configuration_capacity");
  const automaticLiveness = captureAutomaticLiveness(limits.automaticLiveness);
  selectedIdleDuration(0n, limits.localIdleDurationMS);
  captureSendQueueBytes(limits.sessionSendQueueBytes);
  captureStreamSendQueueBytes(limits.streamSendQueueBytes, "client");
  if (limits.nativeDataAssemblyDepth !== undefined && limits.nativeDataAssemblyDepth !== 1 && limits.nativeDataAssemblyDepth !== 2) throw new Error("configuration_capacity");
  return Object.freeze({ ...limits, ...(automaticLiveness === undefined ? {} : { automaticLiveness }) });
}
/** A message leg limits the complete route's guarantees and datagrams. Every
 * raw QUIC/WT leg still binds application scopes to native streams, leaving
 * its maintenance stream exclusively for admission, handshake and scope zero. */
export function routeReliableTransport(fields: ClientPreparationFields, transport: V4AuthenticatedTransport): V4AuthenticatedTransport {
  if (fields.reliableProgress !== "shared_ordered" || transport.nativeStreams === undefined) return transport;
  return Object.freeze({ role: transport.role, mode: transport.mode, nativeStreams: transport.nativeStreams,
    ...(transport.authenticateHop === undefined ? {} : { authenticateHop: transport.authenticateHop.bind(transport) }),
    ...(transport.checkPreparation === undefined ? {} : { checkPreparation: transport.checkPreparation.bind(transport) }),
    ...(transport.activate === undefined ? {} : { activate: transport.activate.bind(transport) }),
    ...(transport.exportBinding === undefined ? {} : { exportBinding: transport.exportBinding.bind(transport) }),
    read: transport.read.bind(transport), write: transport.write.bind(transport), submit: transport.submit.bind(transport),
    close: transport.close.bind(transport), waitTermination: transport.waitTermination.bind(transport) });
}
export function reliableClientSpec(fields: ClientPreparationFields, transport: V4AuthenticatedTransport, signer: ReadyIdentitySigner, privateKey: Uint8Array,
  limits: ReliableClientLimits, runtimeBytes: bigint, verification: V4ConsumerTLS13Verification, application?: RPCApplicationConfig, applicationProfile: "services" | "execution" = "services"): V4EnvironmentSessionSpec {
  transport = routeReliableTransport(fields, transport);
  const services = application !== undefined, execution = services && applicationProfile === "execution";
  const internal = services ? execution ? 11 : 10 : 0;
  const n = Math.min(fields.maxStreams, limits.maxStreams, 1024 + internal);
  const idle = selectedIdleDuration(fields.idleDurationMS, limits.localIdleDurationMS);
  // Admit enough silence for the complete locally promised rekey work window.
  if (idle !== 0n && idle < timeAdd(timeAdd(limits.rekeyPrepareMS, limits.rekeyProtocolMS), limits.rekeyConfirmationMS)) throw new Error("configuration_capacity");
  if (fields.applicationProfile !== (services ? applicationProfile === "services" ? 1n : 2n : 0n) || services &&
      (n < internal || limits.receiveQueueBytes < 16384 || limits.maxWriteBytes < 16384 || limits.cryptoKeys < 4 * (internal + 1))) throw new Error("configuration_capacity");
  const resources = reliableClientResourceSpec(fields.maxFrame, fields.maxStreams, fields.rpcMaxGeneralOutstanding, fields.profile as NoiseProfile,
    transport, limits, runtimeBytes, application, applicationProfile, fields.rekeyBurst, fields.rekeyRefill);
  const spec: V4EnvironmentSessionSpec = {
    ...(application === undefined ? {} : { application }),
    idleDurationMS: fields.idleDurationMS,
    ...(limits.localIdleDurationMS === undefined ? {} : { localIdleDurationMS: limits.localIdleDurationMS }),
    ...(limits.automaticLiveness === undefined ? {} : { automaticLiveness: limits.automaticLiveness }),
    transport, maxFrame: fields.maxFrame, maxReceiveDirections: n,
    crypto: { keys: limits.cryptoKeys, maintenance: { calls: 64n, blocks: 8192n, bytes: 1048576n } },
    noise: { role: "client", profile: fields.profile as NoiseProfile, localStaticPrivate: privateKey, localStaticPublic: fields.noiseKeys[0]!, peerStaticPublic: fields.noiseKeys[1]!, psk: fields.psk,
      authorizationDeadline: fields.sessionDeadline, preparationDeadline: fields.preparationDeadline, contextDigest: new Uint8Array(32), fsb: new Uint8Array(), fsa: new Uint8Array() },
    signer, peerReadyPublicKey: fields.identityKeys[1]!, ready: { localCertificateDigest: fields.identities[0]!, peerCertificateDigest: fields.identities[1]!,
      fsbDigest: new Uint8Array(32), fsaDigest: new Uint8Array(32), admissionBinding: new Uint8Array(32), transportContextDigest: new Uint8Array(32), selectedFeatures: 0n },
    streams: resources.streams,
    info: { application_profile: services ? applicationProfile : "transport", selected_features: 0n, guarantees: { reliable_progress: fields.reliableProgress === "shared_ordered" || transport.nativeStreams === undefined ? "shared_ordered" : "independent_within_profile",
      bound_stream_input_isolation: fields.reliableProgress === "shared_ordered" || transport.nativeStreams === undefined ? "shared_failure_scope" : "bound_stream_within_profile", datagram: false,
      local_consumer_tls13_verification: verification, scope: fields.pathKind === 1 ? "complete_relay_path" : "complete_direct_path", assumptions: fields.pathKind === 1 ? "trusted_relay_and_peers_within_transport_profile" : "authenticated_peer_within_transport_profile" } },
  };
  return spec;
}

/** The same resource-bearing shape is used before Acquire and after material
 * verification. Pre-Acquire callers supply their configured upper bounds. */
export function reliableClientResourceSpec(maxFrame: number, maxStreams: number, maxGeneral: number, profile: NoiseProfile,
  transport: SessionResourceSpec["transport"], limits: ReliableClientLimits, runtimeBytes: bigint, application?: RPCApplicationConfig,
  applicationProfile: "services" | "execution" = "services", rekeyBurst = 1n, rekeyRefill = 1000n): SessionResourceSpec {
  const services = application !== undefined, execution = services && applicationProfile === "execution";
  const internal = services ? execution ? 11 : 10 : 0;
  const n = Math.min(maxStreams, limits.maxStreams, 1024 + internal), business = Math.max(0, n - internal), ingress = Math.min(128, Math.max(4, n));
  if (maxGeneral > (limits.maxGeneralOutstanding ?? 1024)) throw new Error("configuration_capacity");
  return {
    maxFrame, maxReceiveDirections: n, transport, noise: { role: "client", profile },
    crypto: { keys: limits.cryptoKeys, maintenance: { calls: 64n, blocks: 8192n, bytes: 1048576n } },
    info: { application_profile: services ? applicationProfile : "transport" },
    ...(application === undefined ? {} : { application }),
    streams: { ...(limits.nativeDataAssemblyDepth === undefined ? {} : { nativeDataAssemblyDepth: limits.nativeDataAssemblyDepth }),
      limits: { direction: 0, maxActive: n, maxPending: Math.min(128, n), ingressItems: ingress, ingressBytes: Math.min(524288, Math.max(16384, maxFrame)),
      terminalCapacity: Math.min(4096, Math.max(n * 4, n + ingress)), rejectionReserve: ingress,
      runtimeBytes, perClass: [business, services ? 10 : 0, execution ? 1 : 0], perOpener: [[business, services ? 5 : 0, execution ? 1 : 0], [business, services ? 5 : 0, 0]], protected: [[0, services ? 5 : 0, execution ? 1 : 0], [0, services ? 5 : 0, 0]] },
      receive: { maxDataBytes: limits.maxDataBytes, queueBytes: limits.receiveQueueBytes, maxCursorBytes: limits.maxCursorBytes, receiveLimit: BigInt(limits.receiveQueueBytes), runtimeBytes, cursorRuntimeBytes: runtimeBytes, decoderRuntimeBytes: runtimeBytes },
      sendQueueBytes: captureSendQueueBytes(limits.sessionSendQueueBytes),
      streamSendQueueBytes: captureStreamSendQueueBytes(limits.streamSendQueueBytes, "client"),
      maxWriteBytes: limits.maxWriteBytes, writeDeadlineMS: limits.writeDeadlineMS, operationDeadlineMS: limits.operationDeadlineMS,
      rekeyMaxScopes: Math.min(maxStreams, 1035),
      rpcMaxGeneralOutstanding: maxGeneral,
      rekeyBurst: rekeyBurst, rekeyRefillMS: rekeyRefill, rekeyPrepareMS: limits.rekeyPrepareMS, rekeyProtocolMS: limits.rekeyProtocolMS, rekeyConfirmationMS: limits.rekeyConfirmationMS },
  };
}

/** Signed stream maxima may exceed the local active-stream limit. Preserve the
 * original rekey-scope sizing while reserving its maximum before acquisition. */
export function reliableClientAdmissionSpec(profile: NoiseProfile, transport: SessionResourceSpec["transport"], limits: ReliableClientLimits,
  runtimeBytes: bigint, application?: RPCApplicationConfig, applicationProfile?: "services" | "execution",
  initialRawStreams?: SessionResourceSpec["initialRawStreams"]): SessionResourceSpec {
  const spec = reliableClientResourceSpec(limits.maxFrame, limits.maxStreams, limits.maxGeneralOutstanding ?? 1024,
    profile, transport, limits, runtimeBytes, application, applicationProfile);
  return { ...spec, ...(initialRawStreams === undefined ? {} : { initialRawStreams }), streams: { ...spec.streams, rekeyMaxScopes: 1035 } };
}

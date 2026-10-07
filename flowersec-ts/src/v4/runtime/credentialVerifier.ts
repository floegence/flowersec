import type { V4ConnectionRequirements } from "../../generated/transportV4APIResults.js";
import type * as StreamHandlersTypes from "../streamHandlers.js";
import { applicationResumeFeature, type CheckpointSessionPolicy } from "./checkpointToken.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import type { TrustedClock } from "./clock.js";
import { TimeError } from "./timeArithmetic.js";
import { TrustedDeadline } from "./deadline.js";
import { type CredentialNamespace, isCredentialNamespace, type CredentialEvidence, type CredentialNamespaceSubscription } from "./credentialNamespace.js";
import { CredentialWork, credentialWorkCharge, type OwnedCredentialMap, checkCredentialTime, credentialDigest, credentialOwner, equalCredential, requireCredential, type CredentialResources } from "./credentialSupport.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { CBORDecoder, cborDecoderCharge } from "./cbor.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { V4AuthenticatedSessionConfig } from "./session.js";
import { ownProfile } from "./wireRegistry.js";

import { HopAuthenticationPreparation } from "./hopAuthentication.js";
import { verifyRelayCredentials, RelayCredentialPreparation, type VerifiedRelayCredentials } from "./relayCredentials.js";
import type { PoolServerAllowConfiguration, PoolServerAllowRecipient, PreparedPoolServerAllow, TunnelServerAllowRequest } from "./poolServerAllow.js";

export type ActivationSource = "live_authority" | "preauthorized_pool";
export interface LiveTunnelGrantScopeConfig {
  readonly authority: string; readonly issuerKeyID: Uint8Array;
  readonly revocationPolicyID: string; readonly revocationPolicyRevision: bigint;
  readonly maxNotAfterMS: bigint;
}
export interface CredentialVerifierConfig {
  readonly resources: CredentialResources; readonly clock: TrustedClock;
  readonly namespaces: readonly CredentialNamespace[];
  readonly tenant: string; readonly audience: string; readonly clientSubject: string; readonly serverSubject: string;
  readonly cryptoProfiles: readonly string[];
  readonly tunnel?: Readonly<{ role: 0 | 1; audience: string; service: string; relaySubject: string; candidateCapacity?: number; liveGrant?: LiveTunnelGrantScopeConfig }>;
}
export interface CredentialInput {
  /** Trusted per-material transport installation; never decoded authority. */
  readonly poolServerAllow?: PoolServerAllowConfiguration;
  readonly artifact: Uint8Array; readonly clientCertificate: Uint8Array; readonly serverCertificate: Uint8Array;
  readonly tunnel?: Readonly<{ grant?: Uint8Array; relayCertificate: Uint8Array; candidateGrants?: readonly Readonly<{ candidateIndex: number; grant: Uint8Array; relayCertificate: Uint8Array }>[] }>;
  readonly activation?: Uint8Array; readonly source: ActivationSource; readonly candidateIndex: number;
}
export function credentialVerifierCharge(runtimeBytes: bigint): ResourceVector {
  requireCredential(runtimeBytes > 0n, "configuration_capacity");
  // Original material, result projection, route/set encoding and bounded crypto
  // temporaries stay paid through the verified closure's last use.
  return new ResourceVector([524288n + runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
/** Owns every additional tunnel verification and hop position before the
 * configured credential provider can publish or remove an original lease. */
const liveMaterialDecoderConfig = (runtimeBytes: bigint) => Object.freeze({ bytes: 73728, nodes: 8, textBytes: 32, arrayItems: 3, runtimeBytes });
interface PendingLiveTunnel {
  readonly scope: CredentialEvidence; readonly relayCertificate: Uint8Array; readonly endpointCertificate: Uint8Array;
  readonly preparation: RelayCredentialPreparation; readonly decoder: CBORDecoder;
}
export class TunnelCredentialPreparation {
  #reference: ResourceReference | undefined; #work: CredentialWork | undefined;
  #decoder: CBORDecoder | undefined;
  readonly #relays: RelayCredentialPreparation[] = []; readonly #hops: HopAuthenticationPreparation[] = [];
  constructor(config: CredentialVerifierConfig) {
    requireCredential(config.tunnel !== undefined, "configuration_capacity"); const resources = config.resources, capacity = config.tunnel.candidateCapacity ?? 1;
    requireCredential(Number.isSafeInteger(capacity) && capacity >= 1 && capacity <= 16, "configuration_capacity");
    const material = credentialVerifierCharge(resources.runtimeBytes).add(new ResourceVector([resources.runtimeBytes, 0n, 0n, 0n, 0n, 0n, 1n, 0n, 0n, 0n, 0n]));
    const refs = resources.root.reserveBatch([material, credentialWorkCharge(270336, resources.runtimeBytes), cborDecoderCharge(liveMaterialDecoderConfig(resources.runtimeBytes))].map((charge, index) => ({ owner: credentialOwner(resources, `tunnel_preparation_${index}`), accounts: resources.accounts, charge })));
    try {
      this.#decoder = new CBORDecoder(liveMaterialDecoderConfig(resources.runtimeBytes), refs[2]!);
      this.#reference = refs[0]!.take(material); this.#work = new CredentialWork(resources, 270336, refs[1]!);
      this.#work.prepaySignatures(65536, 32768); this.#work.prepayParsers(65536, 32768, 8);
      for (let index = 0; index < capacity; index++) { this.#relays.push(new RelayCredentialPreparation(resources, config.namespaces)); this.#hops.push(new HopAuthenticationPreparation(resources)); } Object.freeze(this);
    } catch (error) { this.close(); throw error; } finally { for (const ref of refs) ref.release(); }
  }
  takeMaterial(): ResourceReference { requireCredential(this.#reference !== undefined); this.#reference.check(); const result = this.#reference; this.#reference = undefined; return result; }
  takeWork(reference: ResourceReference): CredentialWork { requireCredential(this.#work !== undefined && this.#work.sameEnvironment(reference)); const result = this.#work; this.#work = undefined; return result; }
  takeLiveDecoder(): CBORDecoder { requireCredential(this.#decoder !== undefined); const result = this.#decoder; this.#decoder = undefined; return result; }
  takeRelay(): RelayCredentialPreparation { const result = this.#relays.shift(); requireCredential(result !== undefined); return result; }
  takeHop(): HopAuthenticationPreparation { const result = this.#hops.shift(); requireCredential(result !== undefined); return result; }
  close(): void { this.#decoder?.close(); this.#decoder = undefined; for (const hop of this.#hops.splice(0)) hop.close(); for (const relay of this.#relays.splice(0)) relay.close(); this.#work?.close(); this.#work = undefined; this.#reference?.release(); this.#reference = undefined; }
}
function clearCredentialEvidence(evidence: CredentialEvidence): void {
  evidence.issuer.fill(0); evidence.digest.fill(0); evidence.permissionDigest.fill(0); evidence.lease?.fill(0); evidence.grant?.fill(0);
}
const token = Symbol("original verified credential closure");
function notifyCallback(callback: (() => void) | undefined): void {
  if (callback === undefined) return;
  try {
    const result: unknown = callback();
    if (result !== undefined && typeof result === "object" && result !== null && "then" in result && typeof (result as { then?: unknown }).then === "function")
      void Promise.resolve(result).catch(() => undefined);
  } catch { /* Revocation is a safety signal; the owning Session observes the denied state. */ }
}

interface TunnelCandidateOwner { readonly relay: VerifiedRelayCredentials; hop: HopAuthenticationPreparation | undefined; }
interface ClosureState {
  readonly tunnelCandidates: Map<number, TunnelCandidateOwner>; selectionSealed: boolean;
  liveTunnel: PendingLiveTunnel | undefined;
  handshakeChecksPrepared: boolean; relay: VerifiedRelayCredentials | undefined; hop: HopAuthenticationPreparation | undefined; readonly pathKind: 0 | 1; readonly localRole: 0 | 1;
  work: CredentialWork | undefined; readonly reference: ResourceReference;
  readonly config: CredentialVerifierConfig; readonly maps: OwnedCredentialMap[]; readonly evidence: CredentialEvidence[];
  activation: OwnedCredentialMap | undefined; once: OwnedCredentialMap | undefined; candidateIndex: number;
  readonly profile: string; readonly source: ActivationSource; readonly candidateID: Uint8Array; readonly routeDigest: Uint8Array;
  readonly artifactDigest: Uint8Array; readonly activationDigest: Uint8Array; readonly certificateDigests: readonly Uint8Array[];
  readonly attemptID: Uint8Array; readonly psk: Uint8Array; readonly nonce: Uint8Array;
  readonly noiseKeys: readonly Uint8Array[]; readonly identityKeys: readonly Uint8Array[];
  from: bigint; initiation: bigint; sessionEnd: bigint;
  readonly preparationDeadline: TrustedDeadline; readonly sessionDeadline: TrustedDeadline;
  readonly allowed: bigint; readonly required: bigint;
  readonly resumePolicy: CheckpointSessionPolicy | undefined;
  readonly maxFrame: bigint; readonly maxStreams: bigint; readonly maxCredit: bigint; readonly applicationProfile: bigint; readonly idleDurationMS: bigint;
  readonly rpcMaxGeneralOutstanding: bigint; readonly rekeyBurst: bigint; readonly rekeyRefill: bigint;
  readonly subscriptions: CredentialNamespaceSubscription[];
  readonly freshness: Map<CredentialNamespace, { generation: bigint; sequence: bigint; deadline: TrustedDeadline }>;
  denied: unknown; revoked: (() => void) | undefined; changed: (() => void) | undefined;
  claimed: boolean; detached: boolean; closed: boolean;
}
const closures = new WeakMap<VerifiedCredentialClosure, ClosureState>();
/** Internal, admission-owned projection; never a public authentication token. */
export interface AuthorizedCarrierCandidate {
  readonly candidateIndex: number; readonly candidateID: Uint8Array; readonly routeDigest: Uint8Array; readonly route: Uint8Array;
  readonly accessClass: bigint; readonly pathKind: 0 | 1; readonly reliableProgress?: "shared_ordered" | "native_bound";
}
export interface ClientPreparationFields {
  readonly candidateIndex: number; readonly candidates: readonly AuthorizedCarrierCandidate[]; readonly totalCandidateAttempts: number;
  readonly preparationBytes: number; readonly totalPreparationBytes: number; readonly preparationWork: number; readonly preparationAddressAttempts?: number; readonly totalPreparationWork?: number;
  readonly accessClass: bigint; readonly pathKind: 0 | 1;
  readonly reliableProgress?: "shared_ordered" | "native_bound";
  readonly source: ActivationSource; readonly profile: string; readonly tenant: string;
  readonly issuer: Uint8Array; readonly lease: Uint8Array; readonly artifactDigest: Uint8Array; readonly candidateID: Uint8Array;
  readonly routeDigest: Uint8Array; readonly route: Uint8Array; readonly attempt: Uint8Array; readonly nonce: Uint8Array;
  readonly activation: Uint8Array; readonly clientCertificate: Uint8Array; readonly serverCertificate: Uint8Array;
  readonly identities: readonly Uint8Array[]; readonly noiseKeys: readonly Uint8Array[]; readonly identityKeys: readonly Uint8Array[]; readonly psk: Uint8Array;
  readonly allowed: bigint; readonly required: bigint; readonly resume: boolean;
  readonly maxFrame: number; readonly maxStreams: number; readonly maxCredit: bigint; readonly applicationProfile: bigint; readonly idleDurationMS: bigint;
  readonly rpcMaxGeneralOutstanding: number; readonly rekeyBurst: bigint; readonly rekeyRefill: bigint;
  readonly preparationDeadline: TrustedDeadline; readonly sessionDeadline: TrustedDeadline;
}
export type CarrierPreparationFields = Pick<ClientPreparationFields, "preparationBytes" | "preparationWork" | "accessClass" | "pathKind" | "source" | "required" | "maxFrame" | "route" | "preparationDeadline"> & Partial<Pick<ClientPreparationFields, "candidateIndex" | "candidates" | "totalCandidateAttempts" | "totalPreparationBytes" | "preparationAddressAttempts" | "totalPreparationWork">>;
/** Bounded, non-secret projection for the independently authenticated control
 * authority. The authority resolves its own original Artifact and once record. */
export interface LiveAuthorizationRequest {
  readonly tenant: string; readonly audience: string; readonly cryptoProfile: string; readonly authority: string;
  readonly issuer: Uint8Array; readonly lease: Uint8Array; readonly attempt: Uint8Array;
  readonly artifact: Uint8Array; readonly clientIdentity: Uint8Array; readonly serverIdentity: Uint8Array;
  readonly candidateIndex: number; readonly candidateID: Uint8Array; readonly routeDigest: Uint8Array;
  readonly activationNotAfterMS: bigint; readonly attemptNo: 1;
}
export function isVerifiedCredentialClosure(value: unknown): value is VerifiedCredentialClosure {
  return typeof value === "object" && value !== null && closures.has(value as VerifiedCredentialClosure);
}
function original(value: VerifiedCredentialClosure): ClosureState {
  const state = closures.get(value); requireCredential(state !== undefined && !state.closed, "credential_closed"); return state;
}

export interface PoolSpendFields {
  readonly tenant: string; readonly audience: string; readonly profile: string; readonly authority: string; readonly winnerAuthority: string;
  readonly namespace: string; readonly namespaceGeneration: bigint; readonly capacityDigest: Uint8Array; readonly signingKey: string;
  readonly issuer: Uint8Array; readonly lease: Uint8Array; readonly attempt: Uint8Array; readonly artifactDigest: Uint8Array; readonly proofDigest: Uint8Array;
  readonly proof: Uint8Array; readonly candidateID: Uint8Array; readonly candidateIndex: bigint; readonly routeDigest: Uint8Array; readonly descriptor: Uint8Array;
  readonly candidateSet: Uint8Array; readonly routeSet: Uint8Array; readonly sessionNonce: Uint8Array; readonly identities: readonly Uint8Array[];
  readonly issuedAt: bigint; readonly activationEnd: bigint; readonly sessionEnd: bigint; readonly initiationEnd: bigint;
}
/** Private server projection, obtained only after authenticating the exact FSB
 * against the original local transport context. It contains no session secret. */
export interface ServerAdmissionFields {
  readonly source: ActivationSource; readonly tenant: string; readonly audience: string; readonly profile: string;
  readonly spendAuthority: string; readonly winnerAuthority: string; readonly signingKey: string;
  readonly issuer: Uint8Array; readonly lease: Uint8Array; readonly attempt: Uint8Array;
  readonly artifactDigest: Uint8Array; readonly proofDigest: Uint8Array; readonly candidateID: Uint8Array; readonly candidateSet: Uint8Array;
  readonly routeDigest: Uint8Array; readonly sessionNonce: Uint8Array; readonly identities: readonly Uint8Array[];
  readonly admissionBinding: Uint8Array; readonly issuedAt: bigint; readonly activationEnd: bigint; readonly sessionEnd: bigint; readonly initiationEnd: bigint;
}
interface PoolFactsState { closure: VerifiedCredentialClosure; reference: ResourceReference; fields: PoolSpendFields; closed: boolean }
const poolFacts = new WeakMap<VerifiedPoolSpendFacts, PoolFactsState>();
export class VerifiedPoolSpendFacts {
  constructor(capability: symbol, state: PoolFactsState) { requireCredential(capability === token); poolFacts.set(this, state); Object.freeze(this); }
  check(reference: ResourceReference): void {
    const state = poolFacts.get(this); requireCredential(state !== undefined && !state.closed);
    requireCredential(state.reference.sameEnvironment(reference)); state.closure.checkPreparation(reference);
  }
  fields(reference: ResourceReference): PoolSpendFields {
    this.check(reference); const fields = poolFacts.get(this)!.fields;
    return Object.freeze({ ...fields, issuer: new Uint8Array(fields.issuer), lease: new Uint8Array(fields.lease), attempt: new Uint8Array(fields.attempt),
      artifactDigest: new Uint8Array(fields.artifactDigest), proofDigest: new Uint8Array(fields.proofDigest), proof: new Uint8Array(fields.proof),
      candidateID: new Uint8Array(fields.candidateID), routeDigest: new Uint8Array(fields.routeDigest), descriptor: new Uint8Array(fields.descriptor),
      candidateSet: new Uint8Array(fields.candidateSet), routeSet: new Uint8Array(fields.routeSet), sessionNonce: new Uint8Array(fields.sessionNonce),
      capacityDigest: new Uint8Array(fields.capacityDigest), identities: Object.freeze(fields.identities.map(value => new Uint8Array(value))) });
  }
  close(): void {
    const state = poolFacts.get(this); if (state === undefined || state.closed) return; state.closed = true;
    for (const value of Object.values(state.fields)) if (value instanceof Uint8Array) value.fill(0);
    for (const value of state.fields.identities) value.fill(0); state.reference.release();
  }
  toJSON(): object { return {}; }
}
export function isVerifiedPoolSpendFacts(value: unknown): value is VerifiedPoolSpendFacts { return value instanceof VerifiedPoolSpendFacts && poolFacts.has(value); }

/** Unforgeable internal mathematical/authorization closure. It is never an
 * assertion of durable spend, server admission, provider identity or READY.
 * It cannot be serialized/restored or constructed with asserted success. */
export class VerifiedCredentialClosure {
  constructor(capability: symbol, state: ClosureState) {
    requireCredential(capability === token, "credential_untrusted"); closures.set(this, state); Object.freeze(this);
  }
  /** Internal synchronous handoff from the verified material's current owner. */
  withOriginalMaterialReference<T>(handoff: (reference: ResourceReference) => T): T {
    const state = original(this); this.checkPreparation(state.reference); return handoff(state.reference);
  }
  checkPreparation(reference: ResourceReference): void {
    const s = original(this); requireCredential(!s.detached, "credential_closed"); this.#check(s, reference); s.preparationDeadline.check(); checkCredentialTime(s.config.clock, s.from, s.initiation);
  }
  originalPreparationDeadline(reference: ResourceReference): TrustedDeadline {
    this.checkPreparation(reference); return original(this).preparationDeadline;
  }
  /** Pool retention cannot extend original signed preparation or certificate authority. */
  checkPoolInstallExpiry(expiry: bigint, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(expiry > s.config.clock.sample().requireInterval().upperMS && expiry <= s.preparationDeadline.cap && expiry <= s.sessionDeadline.cap, "credential_binding");
  }
  checkApplicationProfile(profile: "transport" | "services" | "execution", reference: ResourceReference): void {
    this.checkPreparation(reference);
    if (original(this).applicationProfile !== (profile === "transport" ? 0n : profile === "services" ? 1n : 2n)) throw new Error("connection_requirement_unavailable");
  }
  checkConnectionRequirements(request: V4ConnectionRequirements, reference: ResourceReference, candidateIndex = original(this).candidateIndex): void {
    this.checkPreparation(reference);
    const s = original(this), artifact = s.maps[0]!, candidates = [...artifact.items("candidates")];
    requireCredential(Number.isSafeInteger(candidateIndex) && candidateIndex >= 0 && candidateIndex < candidates.length, "credential_binding");
    const candidate = candidates[candidateIndex]!;
    if (s.activation !== undefined) checkSelection({ source: s.source, candidateIndex }, artifact, s.activation, s.artifactDigest,
      artifact.bytes("candidate_id", candidate, "Candidate"), candidateRouteDigest(artifact, candidate), s.once!);
    if (request.application_profile !== undefined) this.checkApplicationProfile(request.application_profile, reference);
    if (request.datagram && (s.allowed & 1n) === 0n) throw new Error("connection_requirement_unavailable");
    const legs = s.pathKind === 0 ? ["direct_leg"] : ["client_leg", "server_leg"];
    const hasMessageLeg = legs.some(name => artifact.uint("carrier", artifact.field(name, candidate, "Candidate"), "Leg") === 1n);
    if ((request.datagram || request.independent_reliable_read_progress || request.bound_stream_input_isolation) && hasMessageLeg) {
      throw new Error("connection_requirement_unavailable");
    }
  }
  clientPreparation(reference: ResourceReference, candidateIndex = original(this).candidateIndex): ClientPreparationFields {
    this.checkPreparation(reference); const s = original(this), artifact = s.maps[0]!, candidates = [...artifact.items("candidates")];
    requireCredential(Number.isSafeInteger(candidateIndex) && candidateIndex >= 0 && candidateIndex < candidates.length && (!s.selectionSealed || candidateIndex === s.candidateIndex), "credential_binding");
    const activation = s.activation;
    const authorizedIndices = activation === undefined ? [s.candidateIndex] : checkSelection({ source: s.source, candidateIndex }, artifact, activation,
      s.artifactDigest, artifact.bytes("candidate_id", candidates[candidateIndex]!, "Candidate"), candidateRouteDigest(artifact, candidates[candidateIndex]!), s.once!);
    const availableIndices = s.selectionSealed ? [s.candidateIndex] : s.pathKind === 0 || s.source === "live_authority" ? authorizedIndices : authorizedIndices.filter(index => s.tunnelCandidates.has(index));
    requireCredential(availableIndices.includes(candidateIndex), "credential_binding");
    const route = (index: number): Uint8Array => {
      const candidate = candidates[index]!, pathKind = Number(artifact.uint("path_kind", candidate, "Candidate")) as 0 | 1;
      requireCredential(pathKind === s.pathKind, "connection_requirement_unavailable");
      const buffer = new Uint8Array(16384), writer = new FixedCBORWriter(buffer), copied: Uint8Array[] = [];
      try {
        const id = artifact.bytes("candidate_id", candidate, "Candidate"); copied.push(id); writer.map(pathKind === 0 ? 3 : 4).uint(0).uint(pathKind).uint(1).data(id);
        for (const [id, name] of pathKind === 0 ? [[2, "direct_leg"]] as const : [[3, "client_leg"], [4, "server_leg"]] as const) {
          const leg = artifact.encoded(artifact.field(name, candidate, "Candidate")); copied.push(leg); writer.uint(id).encoded(leg);
        }
        return new Uint8Array(writer.result());
      } finally { buffer.fill(0); for (const value of copied) value.fill(0); }
    };
    const project = (index: number): AuthorizedCarrierCandidate => {
      const candidate = candidates[index]!, pathKind = Number(artifact.uint("path_kind", candidate, "Candidate")) as 0 | 1;
      requireCredential(pathKind === s.pathKind, "connection_requirement_unavailable");
      if (pathKind === 0) checkClosure(artifact, candidate, [s.evidence[0]!.namespace, s.evidence[1]!.namespace, s.evidence[2]!.namespace]);
      const candidateID = artifact.bytes("candidate_id", candidate, "Candidate"); let routeBytes: Uint8Array | undefined, routeDigest: Uint8Array | undefined;
      try {
        routeBytes = route(index); routeDigest = credentialDigest("route_digest", routeBytes);
        const pathLeg = artifact.field(pathKind === 0 ? "direct_leg" : s.localRole === 0 ? "client_leg" : "server_leg", candidate, "Candidate");
        const messageRoute = (pathKind === 0 ? ["direct_leg"] : ["client_leg", "server_leg"]).some(name => artifact.uint("carrier", artifact.field(name, candidate, "Candidate"), "Leg") === 1n);
        return Object.freeze({ candidateIndex: index, candidateID, routeDigest, route: routeBytes,
          accessClass: artifact.uint("access_class", pathLeg, "Leg"), pathKind, reliableProgress: messageRoute ? "shared_ordered" as const : "native_bound" as const });
      } catch (error) { candidateID.fill(0); routeBytes?.fill(0); routeDigest?.fill(0); throw error; }
    };
    const projected: AuthorizedCarrierCandidate[] = [];
    try { for (const index of availableIndices) projected.push(project(index)); }
    catch (error) { for (const candidate of projected) { candidate.candidateID.fill(0); candidate.routeDigest.fill(0); candidate.route.fill(0); } throw error; }
    const selected = projected.find(value => value.candidateIndex === candidateIndex); requireCredential(selected !== undefined, "credential_binding");
    const resume = artifact.field("resume_policy"); let preparationBytes = 0, totalPreparationBytes = 0, preparationWork = 0, totalCandidateAttempts = 1, preparationAddressAttempts = 1, totalPreparationWork = 0;
    if (s.source === "preauthorized_pool") {
      requireCredential(activation !== undefined);
      const selection = activation.field("candidate_selection"), budget = activation.field("attempt_budget", selection, "PoolSelectionRef"), perCandidate = activation.field("per_candidate", budget, "PoolAttemptBudget");
      totalCandidateAttempts = Number(min(activation.uint("total_address_attempts", budget, "PoolAttemptBudget"), activation.uint("total_work_units", budget, "PoolAttemptBudget")));
      totalPreparationBytes = Number(activation.uint("total_preauth_bytes", budget, "PoolAttemptBudget"));
      totalPreparationWork = Number(activation.uint("total_work_units", budget, "PoolAttemptBudget")); preparationAddressAttempts = Number(activation.uint("address_attempts", perCandidate, "CandidateAttemptBudget"));
      preparationBytes = Number(min(activation.uint("preauth_bytes", perCandidate, "CandidateAttemptBudget"), BigInt(totalPreparationBytes)));
      preparationWork = Number(min(activation.uint("work_units", perCandidate, "CandidateAttemptBudget"), activation.uint("total_work_units", budget, "PoolAttemptBudget")));
    }
    return Object.freeze({ candidateIndex, candidates: Object.freeze(projected), totalCandidateAttempts, totalPreparationBytes, preparationAddressAttempts, totalPreparationWork,
      ...(selected.reliableProgress === undefined ? {} : { reliableProgress: selected.reliableProgress }), pathKind: selected.pathKind, accessClass: selected.accessClass, source: s.source, profile: s.profile, tenant: s.config.tenant,
      issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"), artifactDigest: new Uint8Array(s.artifactDigest), candidateID: new Uint8Array(selected.candidateID), routeDigest: new Uint8Array(selected.routeDigest), route: new Uint8Array(selected.route),
      attempt: new Uint8Array(s.attemptID), nonce: new Uint8Array(s.nonce), activation: activation?.encoded() ?? new Uint8Array(), clientCertificate: s.maps[1]!.encoded(), serverCertificate: s.maps[2]!.encoded(),
      identities: s.certificateDigests.map(x => new Uint8Array(x)), noiseKeys: s.noiseKeys.map(x => new Uint8Array(x)), identityKeys: s.identityKeys.map(x => new Uint8Array(x)), psk: new Uint8Array(s.psk),
      allowed: s.allowed, required: s.required, resume: artifact.doc.boolean(artifact.field("enabled", resume, "ResumePolicy")), maxFrame: Number(s.maxFrame), maxStreams: Number(s.maxStreams), maxCredit: s.maxCredit,
      applicationProfile: s.applicationProfile, idleDurationMS: s.idleDurationMS, rpcMaxGeneralOutstanding: Number(s.rpcMaxGeneralOutstanding), rekeyBurst: s.rekeyBurst, rekeyRefill: s.rekeyRefill,
      preparationDeadline: s.preparationDeadline, sessionDeadline: s.sessionDeadline, preparationBytes, preparationWork });
  }
  clientPreparationForCandidate(reference: ResourceReference, candidateIndex: number): ClientPreparationFields {
    return this.clientPreparation(reference, candidateIndex);
  }
  /** Commits the original prepared member before TxA. All later spend, hop,
   * HELLO/FSB and Session facts read the same closure-owned selection. */
  selectClientCandidate(reference: ResourceReference, candidateIndex: number): ClientPreparationFields {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(!s.claimed && !s.selectionSealed, "credential_binding");
    const owner = s.pathKind === 1 && s.source === "preauthorized_pool" ? s.tunnelCandidates.get(candidateIndex) : undefined;
    if (s.pathKind === 1 && s.source === "preauthorized_pool") { requireCredential(owner !== undefined, "credential_binding"); owner.relay.check(reference); }
    const fields = this.clientPreparation(reference, candidateIndex);
    if (owner !== undefined) {
      s.relay = owner.relay; s.hop = owner.hop;
      for (const [index, other] of s.tunnelCandidates) if (index !== candidateIndex) { other.hop?.close(); other.relay.close(); s.tunnelCandidates.delete(index); }
      s.sessionEnd = min(s.sessionEnd, owner.relay.deadline.cap); s.sessionDeadline.tighten(s.sessionEnd);
    }
    s.candidateIndex = candidateIndex; s.candidateID.set(fields.candidateID); s.routeDigest.set(fields.routeDigest); s.selectionSealed = true;
    return fields;
  }
  /** One original client attempt, selected before carrier preparation. No
   * activation success or durable-spend fact is inferred from this binding. */
  beginLivePreparation(attempt: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "live_authority" && s.activation === undefined && !s.claimed && !s.attemptID.some(n => n !== 0) &&
      attempt.length === 16 && attempt.some(n => n !== 0), "credential_binding");
    s.attemptID.set(attempt);
  }
  /** Routing binds an accepted live attempt to this original signed snapshot.
   * The hello remains unauthenticated until the matching FSB signature and
   * independently signed activation proof pass the admission gate. */
  bindAcceptedLiveAttempt(helloBytes: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    if (s.source !== "live_authority" || s.activation !== undefined) return;
    requireCredential(!s.claimed && !s.attemptID.some(byte => byte !== 0), "credential_binding");
    const hello = s.work!.parse(helloBytes, "ClientHello", 16384);
    let attempt: Uint8Array | undefined;
    try {
      requireCredential(hello.text("crypto_profile_id") === s.profile &&
        equalCredential(hello.bytes("artifact_digest"), s.artifactDigest) && equalCredential(hello.bytes("candidate_id"), s.candidateID) &&
        equalCredential(hello.bytes("route_digest"), s.routeDigest) && equalCredential(hello.bytes("client_nonce"), s.nonce), "credential_binding");
      attempt = hello.bytes("attempt_id"); this.beginLivePreparation(attempt, reference);
    } finally { attempt?.fill(0); hello.close(); }
  }
  liveAuthorizationRequest(reference: ResourceReference): LiveAuthorizationRequest {
    this.checkPreparation(reference); const s = original(this), artifact = s.maps[0]!;
    requireCredential(s.source === "live_authority" && s.activation === undefined && s.attemptID.some(n => n !== 0), "credential_binding");
    return Object.freeze({ tenant: s.config.tenant, audience: s.config.audience, cryptoProfile: s.profile,
      authority: s.once!.text("spend_authority_id"), issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"),
      attempt: new Uint8Array(s.attemptID), artifact: new Uint8Array(s.artifactDigest),
      clientIdentity: new Uint8Array(s.certificateDigests[0]!), serverIdentity: new Uint8Array(s.certificateDigests[1]!),
      candidateIndex: s.candidateIndex, candidateID: new Uint8Array(s.candidateID), routeDigest: new Uint8Array(s.routeDigest),
      activationNotAfterMS: s.initiation, attemptNo: 1 });
  }
  /** Install the authority's actual signed response once, under the original
   * prepared carrier/admission guard. A query receipt cannot pass this gate. */
  /** A verified original authority response proves durable spend even when a
   * later relay handoff fails. This observation neither installs nor activates it. */
  observeLiveSpend(bytes: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "live_authority" && s.activation === undefined && s.attemptID.some(n => n !== 0), "credential_binding");
    const activation = s.work!.parse(bytes, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: s.source } });
    let evidence: CredentialEvidence | undefined;
    try {
      const verified = validateActivation(s.config, s.work!, s.maps[0]!, activation, s.evidence[0]!, s.once!,
        s.source, s.candidateIndex, s.artifactDigest, s.candidateID, s.routeDigest);
      evidence = verified.evidence;
      requireCredential(equalCredential(activation.bytes("attempt_id"), s.attemptID), "credential_binding");
      this.checkPreparation(reference);
    } finally { if (evidence !== undefined) clearCredentialEvidence(evidence); activation.close(); }
  }
  installLiveAuthorization(bytes: Uint8Array, reference: ResourceReference): Uint8Array {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "live_authority" && s.activation === undefined && s.attemptID.some(n => n !== 0), "credential_binding");
    let activation: OwnedCredentialMap | undefined, relay: VerifiedRelayCredentials | undefined, activationEvidence: CredentialEvidence | undefined;
    let activationBytes: Uint8Array | undefined, grantBytes: Uint8Array | undefined;
    try {
      if (s.pathKind === 1) {
        const pending = s.liveTunnel; requireCredential(pending !== undefined, "credential_binding");
        const doc = pending.decoder.decode(bytes);
        try {
          requireCredential(doc.sameEnvironment(reference) && doc.kind() === "array" && doc.size() === 3, "control_response_invalid");
          const label = doc.firstChild(), proof = doc.nextSibling(label), grant = doc.nextSibling(proof);
          requireCredential(doc.kind(label) === "text" && doc.text(label) === "live-tunnel-material-1" && doc.kind(proof) === "bytes" && doc.size(proof) > 0 && doc.size(proof) <= 4096 &&
            doc.kind(grant) === "bytes" && doc.size(grant) > 0 && doc.size(grant) <= 65536 && doc.nextSibling(grant) < 0, "control_response_invalid");
          activationBytes = new Uint8Array(doc.size(proof)); grantBytes = new Uint8Array(doc.size(grant)); doc.copyPayload(proof, activationBytes); doc.copyPayload(grant, grantBytes);
        } finally { doc.release(); }
      } else { activationBytes = new Uint8Array(bytes); }
      requireCredential(activationBytes !== undefined);
      activation = s.work!.parse(activationBytes, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: s.source } });
      const verified = validateActivation(s.config, s.work!, s.maps[0]!, activation, s.evidence[0]!, s.once!,
        s.source, s.candidateIndex, s.artifactDigest, s.candidateID, s.routeDigest);
      activationEvidence = verified.evidence;
      requireCredential(equalCredential(activation.bytes("attempt_id"), s.attemptID), "credential_binding");
      if (s.pathKind === 1) {
        const pending = s.liveTunnel!, policy = s.config.tunnel!;
        pending.scope.namespace.checkEvidence(pending.scope);
        relay = verifyRelayCredentials({ ...s.config, audience: policy.audience, service: policy.service,
          endpointSubject: s.localRole === 0 ? s.config.clientSubject : s.config.serverSubject, relaySubject: policy.relaySubject },
          { grant: grantBytes!, endpointCertificate: pending.endpointCertificate, relayCertificate: pending.relayCertificate }, pending.preparation);
        requireCredential(relay.role === s.localRole, "credential_binding");
        const artifact = s.maps[0]!, candidate = [...artifact.items("candidates")][s.candidateIndex]!;
        validateTunnelGrantProjection(s.config, s.work!, artifact, candidate, activation, s.localRole, s.evidence.slice(0, 3),
          s.artifactDigest, s.routeDigest, grantBytes!, pending.relayCertificate, relay, pending.scope);
      }
      this.checkPreparation(reference);
      s.preparationDeadline.tighten(min(s.initiation, verified.initiation));
      const sessionEnd = min(s.sessionEnd, verified.sessionEnd, relay?.deadline.cap ?? s.sessionEnd); s.sessionDeadline.tighten(sessionEnd);
      s.from = max(s.from, verified.issued); s.initiation = min(s.initiation, verified.initiation); s.sessionEnd = sessionEnd;
      s.activationDigest.set(s.work!.digest(activation, "activation_digest"));
      s.evidence.push(verified.evidence); activationEvidence = undefined; s.maps.push(activation); s.activation = activation; activation = undefined;
      if (relay !== undefined) {
        s.relay = relay; relay = undefined;
        s.relay.onRevoked(error => { if (s.closed || s.denied !== undefined) return; s.denied = error; notifyCallback(s.revoked); });
        s.liveTunnel!.decoder.close(); s.liveTunnel!.preparation.close(); s.liveTunnel!.relayCertificate.fill(0); s.liveTunnel!.endpointCertificate.fill(0); s.liveTunnel = undefined;
      }
      this.checkPreparation(reference);
      const installed = activationBytes; activationBytes = undefined; return installed;
    } catch (error) { s.denied = error; throw error; }
    finally { if (activationEvidence !== undefined) clearCredentialEvidence(activationEvidence); activation?.close(); relay?.close(); activationBytes?.fill(0); grantBytes?.fill(0); }
  }
  checkClientIdentity(privateKey: Uint8Array, identityKey: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(equalCredential(identityKey, s.identityKeys[0]!));
    const key = ownProfile(s.profile)!.dh_algorithm === 0 ? x25519.getPublicKey(privateKey) : p256.getPublicKey(privateKey, false);
    try { requireCredential(equalCredential(key, s.noiseKeys[0]!)); } finally { key.fill(0); }
  }
  checkServerIdentity(privateKey: Uint8Array, identityKey: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(equalCredential(identityKey, s.identityKeys[1]!));
    const key = ownProfile(s.profile)!.dh_algorithm === 0 ? x25519.getPublicKey(privateKey) : p256.getPublicKey(privateKey, false);
    try { requireCredential(equalCredential(key, s.noiseKeys[1]!)); } finally { key.fill(0); }
  }
  prepayHandshakeChecks(reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this); if (s.handshakeChecksPrepared) return; s.work!.prepaySignatures(65536, 16384);
    // Live proof installation retains one original position. Admission uses
    // two temporary maps at a time; those maps retire before the FSA checks.
    s.work!.prepayParsers(65536, 16384, 3); s.handshakeChecksPrepared = true;
  }
  /** A rejection is authenticated with its supplied server certificate too.
   * Its zero identity sentinel never becomes a certificate-digest check. */
  authenticateAdmission(map: OwnedCredentialMap, work: CredentialWork, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this), bytes = map.bytes("server_certificate");
    const certificate = work.parse(bytes, "IdentityCertificate", 8192); bytes.fill(0);
    try {
      requireCredential(certificate.text("tenant_id") === s.config.tenant && certificate.text("audience") === s.config.audience &&
        certificate.text("subject_id") === s.config.serverSubject && certificate.text("crypto_profile_id") === s.profile && certificate.uint("role") === 1n, "credential_untrusted");
      const namespace = s.config.namespaces.find(n => n.matches(certificate)); requireCredential(namespace !== undefined, "credential_untrusted");
      checkCredentialTime(s.config.clock, certificate.uint("issued_at_ms"), certificate.uint("expires_at_ms"));
      const evidence = namespace.verifyCredential(certificate, 0, work), parentPolicy = s.evidence[0]!.namespace.policyRequirements(s.evidence[0]!), childPolicy = namespace.policyRequirements(evidence);
      requireCredential(parentPolicy.staleness <= childPolicy.staleness && parentPolicy.signerLifetime <= childPolicy.signerLifetime);
      namespace.checkPolicy(parentPolicy.staleness, parentPolicy.signerLifetime);
      const key = certificate.bytes("ed25519_public_key"); try { work.verify(map, key); } finally { key.fill(0); }
      if (map.uint("status") === 0n) requireCredential(equalCredential(evidence.digest, s.certificateDigests[1]!) && equalCredential(map.bytes("server_identity_digest"), evidence.digest));
      this.checkPreparation(reference);
    } finally { certificate.close(); }
  }
  #check(s: ClosureState, reference: ResourceReference): void {
    if (s.denied !== undefined) throw s.denied;
    s.relay?.check(reference);
    for (const subscription of s.subscriptions) subscription.check();
    s.work?.check(); s.reference.check(); requireCredential(s.reference.sameEnvironment(reference));
    s.sessionDeadline.check(); checkCredentialTime(s.config.clock, s.from, s.sessionEnd);
    let staleness = (1n << 64n) - 1n, signerLifetime = staleness;
    for (const evidence of s.evidence) {
      evidence.namespace.check(reference); evidence.namespace.checkEvidence(evidence);
      const policy = evidence.namespace.policyRequirements(evidence); staleness = min(staleness, policy.staleness); signerLifetime = min(signerLifetime, policy.signerLifetime);
    }
    for (const namespace of new Set(s.evidence.map(e => e.namespace))) {
      namespace.checkPolicy(staleness, signerLifetime);
      const original = s.freshness.get(namespace), [generation, sequence] = namespace.activeVersion(), cap = namespace.availableUntil(staleness);
      // A callback installed after an original deadline expired cannot revive
      // that Session, even when its new namespace Head is independently fresh.
      original?.deadline.check();
      if (original?.generation !== generation || original.sequence !== sequence) s.freshness.set(namespace, { generation, sequence, deadline: new TrustedDeadline(s.config.clock, cap) });
      else if (cap < original.deadline.cap) original.deadline.tighten(cap);
    }
  }
  attachNamespaces(capability: symbol, prepared?: Map<CredentialNamespace, CredentialNamespaceSubscription>): void {
    requireCredential(capability === token, "credential_untrusted"); const s = original(this);
    for (const ns of new Set(s.evidence.map(e => e.namespace))) {
      const subscription = prepared === undefined ? ns.reserveSubscription(s.reference) : prepared.get(ns);
      requireCredential(subscription !== undefined); s.subscriptions.push(subscription); prepared?.delete(ns);
      subscription.attach(ns, s.reference, () => {
        if (s.closed || s.denied !== undefined) return;
        try { this.#check(s, s.reference); notifyCallback(s.changed); }
        catch (error) {
          if (error instanceof TimeError && ["time_unavailable", "time_continuity", "time_pending"].includes(error.code)) return;
          s.denied = error; notifyCallback(s.revoked);
        }
      });
    }
    this.#check(s, s.reference);
  }
  /** Fix the opposite leg and original recipient before the consumer's TxA-P.
   * Verification grants no publication: only Connect uses this prepared slot
   * after its own consume call explicitly succeeds. */
  poolServerAllowCandidate(reference: ResourceReference): number | undefined {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "preauthorized_pool" && s.localRole === 0, "credential_binding");
    return s.pathKind === 1 ? s.candidateIndex : undefined;
  }
  requiresPoolServerAllow(reference: ResourceReference): boolean {
    this.checkPreparation(reference); const s = original(this);
    return s.source === "preauthorized_pool" && s.pathKind === 1 && s.localRole === 1;
  }
  checkPoolServerAllow(request: TunnelServerAllowRequest, grant: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "preauthorized_pool" && s.pathKind === 1 && s.localRole === 1 && s.relay !== undefined && s.activation !== undefined &&
      request.tenant === s.config.tenant && request.audience === s.config.audience && request.candidateIndex === s.candidateIndex &&
      equalCredential(request.artifact, s.artifactDigest) && equalCredential(request.attempt, s.attemptID) && equalCredential(request.candidateID, s.candidateID) && equalCredential(request.routeDigest, s.routeDigest), "credential_binding");
    const originalGrant = s.relay.grant(reference); let map: OwnedCredentialMap | undefined;
    const copied: Uint8Array[] = [], keep = (bytes: Uint8Array): Uint8Array => { copied.push(bytes); return bytes; };
    try {
      requireCredential(equalCredential(grant, originalGrant) && equalCredential(request.grant, keep(s.relay.grantDigest(reference))), "credential_binding");
      map = s.work!.parse(originalGrant, "Grant", 65536);
      const artifact = s.maps[0]!, candidate = [...artifact.items("candidates")][s.candidateIndex]!, leg = artifact.field("server_leg", candidate, "Candidate");
      requireCredential(equalCredential(request.pairing, keep(map.bytes("pairing_id"))) && equalCredential(request.relayIdentity, keep(map.bytes("relay_identity_digest"))) &&
        equalCredential(request.leg, keep(artifact.bytes("leg_id", leg, "Leg"))) && request.notAfterMS > 0n && request.notAfterMS <= min(map.uint("not_after_ms"), s.sessionDeadline.cap), "credential_binding");
      // The accepted instruction can shorten this original preparation. Keep
      // that bound on the closure so every later HOP/admission check retains it.
      const allowed = s.preparationDeadline.fork(min(request.notAfterMS, s.preparationDeadline.cap));
      s.preparationDeadline.tightenFrom(allowed);
    } finally { originalGrant.fill(0); map?.close(); for (const bytes of copied) bytes.fill(0); }
  }
  preparePoolServerAllow(recipient: PoolServerAllowRecipient, reference: ResourceReference): PreparedPoolServerAllow {
    this.checkPreparation(reference); const s = original(this), policy = s.config.tunnel;
    requireCredential(s.source === "preauthorized_pool" && s.pathKind === 1 && s.localRole === 0 && s.selectionSealed &&
      s.relay !== undefined && s.activation !== undefined && policy !== undefined && recipient.candidateIndex === s.candidateIndex, "credential_binding");
    requireCredential(recipient.recipient.length === 16 && recipient.recipient.some(value => value !== 0) && recipient.incarnation.length === 16 &&
      recipient.incarnation.some(value => value !== 0) && recipient.grant.length > 0 && recipient.grant.length <= 65536, "credential_binding");
    const owned = s.work!.reserve("pool_server_allow", new ResourceVector([164864n + s.config.resources.runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    let relay: VerifiedRelayCredentials | undefined, request: TunnelServerAllowRequest | undefined;
    let preparation: RelayCredentialPreparation | undefined, relayBytes: Uint8Array | undefined, clientGrant: Uint8Array | undefined, serverCertificate: Uint8Array | undefined;
    const retained: Uint8Array[] = [], retain = (bytes: Uint8Array): Uint8Array => { retained.push(bytes); return bytes; };
    let grant: Uint8Array | undefined, closed = false;
    const clear = (): void => {
      if (closed) return; closed = true; relay?.close(); grant?.fill(0);
      for (const value of retained) value.fill(0);
      owned.release();
    };
    try {
      preparation = new RelayCredentialPreparation(s.config.resources, s.config.namespaces);
      relayBytes = s.relay.certificate("relay", reference); clientGrant = s.relay.grant(reference); serverCertificate = s.maps[2]!.encoded();
      grant = new Uint8Array(recipient.grant);
      relay = verifyRelayCredentials({ ...s.config, audience: policy.audience, service: policy.service, endpointSubject: s.config.serverSubject, relaySubject: policy.relaySubject },
        { grant, endpointCertificate: serverCertificate, relayCertificate: relayBytes }, preparation);
      requireCredential(relay.role === 1, "credential_binding");
      const artifact = s.maps[0]!, candidate = [...artifact.items("candidates")][s.candidateIndex]!;
      validateTunnelGrantProjection(s.config, s.work!, artifact, candidate, s.activation, 1, s.evidence.slice(0, 3), s.artifactDigest, s.routeDigest, grant, relayBytes, relay);
      const server = s.work!.parse(grant, "Grant", 65536); let client: OwnedCredentialMap | undefined;
      try {
        client = s.work!.parse(clientGrant, "Grant", 65536);
        for (const name of ["pairing_id", "service", "audience", "relay_identity_digest"]) {
          const a = server.encoded(server.field(name)), b = client.encoded(client.field(name));
          try { requireCredential(equalCredential(a, b), "credential_binding"); } finally { a.fill(0); b.fill(0); }
        }
        const leg = artifact.field("server_leg", candidate, "Candidate");
        request = Object.freeze({ tenant: s.config.tenant, audience: s.config.audience, artifact: retain(new Uint8Array(s.artifactDigest)), grant: retain(relay.grantDigest(reference)),
          relayIdentity: retain(credentialDigest("certificate_digest", relayBytes)), attempt: retain(new Uint8Array(s.attemptID)), pairing: retain(server.bytes("pairing_id")), leg: retain(artifact.bytes("leg_id", leg, "Leg")),
          recipient: retain(new Uint8Array(recipient.recipient)), incarnation: retain(new Uint8Array(recipient.incarnation)), candidateIndex: s.candidateIndex,
          candidateID: retain(new Uint8Array(s.candidateID)), routeDigest: retain(new Uint8Array(s.routeDigest)), notAfterMS: min(server.uint("not_after_ms"), s.sessionDeadline.cap, s.preparationDeadline.cap) });
      } finally { server.close(); client?.close(); }
      const deadline = s.preparationDeadline.fork(request.notAfterMS);
      const check = (): void => { requireCredential(!closed, "credential_closed"); owned.check(); this.checkPreparation(reference); relay!.check(reference); deadline.check(); };
      check();
      return Object.freeze({ request, grant, check, remainingMS: () => { check(); return deadline.remainingMS(); }, close: clear });
    } catch (error) { clear(); throw error; }
    finally { preparation?.close(); relayBytes?.fill(0); clientGrant?.fill(0); serverCertificate?.fill(0); }
  }
  poolSpendFacts(reference: ResourceReference): VerifiedPoolSpendFacts {
    const state = original(this); this.checkPreparation(reference); requireCredential(state.source === "preauthorized_pool");
    const artifact = state.maps[0]!, activation = state.activation!, once = state.once!, selection = activation.field("candidate_selection");
    const candidates = [...artifact.items("candidates")], candidateIndex = candidates.findIndex(node => equalCredential(artifact.bytes("candidate_id", node, "Candidate"), state.candidateID));
    requireCredential(candidateIndex === state.candidateIndex, "credential_binding"); const candidate = candidates[candidateIndex]!; state.selectionSealed = true;
    const fields: PoolSpendFields = Object.freeze({ tenant: state.config.tenant, audience: state.config.audience, profile: state.profile,
      authority: once.text("spend_authority_id"), winnerAuthority: once.text("winner_authority_id"), signingKey: activation.text("signing_key_id"),
      namespace: artifact.text("revocation_authority_id"), namespaceGeneration: artifact.uint("revocation_authority_generation"), capacityDigest: artifact.bytes("namespace_capacity_digest"),
      issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"), attempt: new Uint8Array(state.attemptID),
      artifactDigest: new Uint8Array(state.artifactDigest), proofDigest: new Uint8Array(state.activationDigest), proof: activation.encoded(),
      candidateID: new Uint8Array(state.candidateID), candidateIndex: BigInt(candidateIndex), routeDigest: new Uint8Array(state.routeDigest), descriptor: artifact.encoded(artifact.field(state.pathKind === 0 ? "direct_leg" : "client_leg", candidate, "Candidate")),
      candidateSet: activation.bytes("candidate_set_digest", selection, "PoolSelectionRef"), routeSet: activation.bytes("route_selection"),
      sessionNonce: new Uint8Array(state.nonce), identities: Object.freeze(state.certificateDigests.map(value => new Uint8Array(value))),
      issuedAt: activation.uint("issued_at_ms"), activationEnd: state.initiation, sessionEnd: state.sessionEnd, initiationEnd: artifact.uint("initiation_not_after_ms") });
    return new VerifiedPoolSpendFacts(token, { closure: this, reference: state.reference.borrow(), fields, closed: false });
  }
  /** Authenticate the client request against the original locally negotiated
   * context before any server admission transaction or signed success. This
   * does not grant once authority or assert that the carrier has been checked. */
  authenticateClientAdmission(fsbBytes: Uint8Array, transportContext: Uint8Array, reference: ResourceReference): Uint8Array {
    const s = original(this); requireCredential(!s.claimed && (s.activation !== undefined || s.source === "live_authority"), "credential_binding");
    this.checkPreparation(reference);
    let context: OwnedCredentialMap | undefined, fsb: OwnedCredentialMap | undefined;
    try {
      context = s.work!.parse(transportContext, "TransportContext", 2048);
      const selected = context.uint("selected_features");
      requireCredential(context.text("crypto_profile_id") === s.profile && context.uint("path_kind") === BigInt(s.pathKind) &&
        (selected & ~s.allowed) === 0n && (selected & s.required) === s.required &&
        equalCredential(context.bytes("artifact_digest"), s.artifactDigest) && equalCredential(context.bytes("route_digest"), s.routeDigest) &&
        equalCredential(context.bytes("attempt_id"), s.attemptID) && equalCredential(context.bytes("session_nonce"), s.nonce));
      const artifact = s.maps[0]!, candidate = [...artifact.items("candidates")].find(n => equalCredential(artifact.bytes("candidate_id", n, "Candidate"), s.candidateID))!;
      requireCredential(context.uint("access_class") === artifact.uint("access_class", artifact.field(s.pathKind === 0 ? "direct_leg" : "server_leg", candidate, "Candidate"), "Leg"));
      fsb = s.work!.parse(fsbBytes, "FSB4", 65536, 16384, { selectors: { activation_source_profile: s.source } });
      s.work!.verify(fsb, s.identityKeys[0]!, { selectors: { activation_source_profile: s.source } });
      for (const name of ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"])
        requireCredential(equalCredential(fsb.encoded(fsb.field(name)), artifact.encoded(artifact.field(name))));
      requireCredential(equalCredential(fsb.bytes("artifact_digest"), s.artifactDigest) && equalCredential(fsb.bytes("candidate_id"), s.candidateID) &&
        equalCredential(fsb.bytes("attempt_id"), s.attemptID) &&
        equalCredential(fsb.bytes("client_certificate"), s.maps[1]!.encoded()) && equalCredential(fsb.bytes("route_digest"), s.routeDigest) &&
        equalCredential(fsb.bytes("transport_context_digest"), s.work!.digest(context, "transport_context_digest")) &&
        equalCredential(fsb.bytes("hello_transcript_digest"), context.bytes("hello_transcript_digest")) &&
        fsb.uint("selected_features") === selected && fsb.uint("binding_mode") === context.uint("binding_mode"));
      if (s.activation === undefined) {
        // Only this already authenticated client request can install the
        // authority's actual proof; ClientHello grants no consume authority.
        const proof = fsb.bytes("activation_authorization");
        try { this.installLiveAuthorization(proof, reference).fill(0); } finally { proof.fill(0); }
      }
      requireCredential(equalCredential(fsb.bytes("activation_authorization"), s.activation!.encoded()), "credential_binding");
      this.checkPreparation(reference);
      return s.work!.digest(fsb, "admission_binding");
    } finally { context?.close(); fsb?.close(); }
  }
  /** Derive server storage facts from the independently verified request. */
  serverAdmissionFields(fsb: Uint8Array, context: Uint8Array, reference: ResourceReference): ServerAdmissionFields {
    const binding = this.authenticateClientAdmission(fsb, context, reference), s = original(this), artifact = s.maps[0]!, activation = s.activation!;
    return Object.freeze({ source: s.source, tenant: s.config.tenant, audience: s.config.audience, profile: s.profile,
      spendAuthority: activation.text("authority_id"), signingKey: activation.text("signing_key_id"),
      winnerAuthority: s.source === "preauthorized_pool" ? s.once!.text("winner_authority_id") : "",
      issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"), attempt: new Uint8Array(s.attemptID),
      artifactDigest: new Uint8Array(s.artifactDigest), proofDigest: new Uint8Array(s.activationDigest), candidateID: new Uint8Array(s.candidateID),
      candidateSet: s.source === "preauthorized_pool" ? activation.bytes("candidate_set_digest", activation.field("candidate_selection"), "PoolSelectionRef") : new Uint8Array(),
      routeDigest: new Uint8Array(s.routeDigest), sessionNonce: new Uint8Array(s.nonce), identities: s.certificateDigests.map(value => new Uint8Array(value)),
      admissionBinding: binding, issuedAt: activation.uint("issued_at_ms"), activationEnd: activation.uint("activation_not_after_ms"), sessionEnd: activation.uint("session_not_after_ms"), initiationEnd: artifact.uint("initiation_not_after_ms") });
  }
  /** Bind the real authenticated FSB/FSA and Noise inputs before their first
   * credential-bearing handshake output. Actual once/provider gates remain
   * the admission owner's responsibility, not a boolean supplied here. */
  checkSessionInputs(config: V4AuthenticatedSessionConfig, transportContext: Uint8Array): void {
    const s = original(this); requireCredential(!s.claimed && s.activation !== undefined, "credential_binding"); this.checkPreparation(config.reservations.session);
    requireCredential(config.noise.clock === s.config.clock && config.noise.profile === s.profile && config.ledger.profile === s.profile);
    requireCredential(config.noise.authorizationDeadline.belongsTo(s.config.clock) && config.noise.preparationDeadline.belongsTo(s.config.clock) &&
      config.noise.authorizationDeadline.cap <= s.sessionEnd && config.noise.preparationDeadline.cap <= s.initiation);
    const role = config.noise.role === "client" ? 0 : 1, peer = 1 - role;
    requireCredential(equalCredential(config.noise.psk, s.psk) && equalCredential(config.noise.localStaticPublic, s.noiseKeys[role]!) &&
      equalCredential(config.noise.peerStaticPublic, s.noiseKeys[peer]!) && equalCredential(config.signer.publicKey, s.identityKeys[role]!) && equalCredential(config.peerReadyPublicKey, s.identityKeys[peer]!));
    const privateKey = config.noise.localStaticPrivate;
    const actualPublic = ownProfile(s.profile)!.dh_algorithm === 0 ? x25519.getPublicKey(privateKey) : p256.getPublicKey(privateKey, false);
    try { requireCredential(equalCredential(actualPublic, s.noiseKeys[role]!)); } finally { actualPublic.fill(0); }
    const selected = BigInt(config.ready.selectedFeatures);
    requireCredential((selected & ~s.allowed) === 0n && (selected & s.required) === s.required && selected === config.info.selected_features);
    requireCredential(BigInt(config.maxFrame) === s.maxFrame && BigInt(config.streams.limits.maxActive) <= s.maxStreams && (config.idleDurationMS ?? 0n) === s.idleDurationMS &&
      config.streams.receive.receiveLimit <= s.maxCredit && config.streams.rekeyBurst === s.rekeyBurst && config.streams.rekeyRefillMS === s.rekeyRefill);
    requireCredential(config.info.application_profile === ["transport", "services", "execution"][Number(s.applicationProfile)] &&
      BigInt(config.streams.rpcMaxGeneralOutstanding ?? 0) === s.rpcMaxGeneralOutstanding);
    requireCredential(s.applicationProfile === 0n || s.maxStreams >= 1n && s.maxCredit >= 16384n);
    let context: OwnedCredentialMap | undefined, fsa: OwnedCredentialMap | undefined;
    try {
      const admission = this.authenticateClientAdmission(config.noise.fsb, transportContext, config.reservations.session);
      context = s.work!.parse(transportContext, "TransportContext", 2048);
      requireCredential(context.uint("selected_features") === selected);
      const contextDigest = s.work!.digest(context, "transport_context_digest");
      requireCredential(equalCredential(contextDigest, config.noise.contextDigest) && equalCredential(contextDigest, config.ready.transportContextDigest));
      fsa = s.work!.parse(config.noise.fsa, "FSA4", 16384); s.work!.verify(fsa, s.identityKeys[1]!);
      requireCredential(equalCredential(fsa.bytes("server_certificate"), s.maps[2]!.encoded()) &&
        equalCredential(fsa.bytes("route_digest"), s.routeDigest) && equalCredential(fsa.bytes("transport_context_digest"), contextDigest) &&
        equalCredential(fsa.bytes("hello_transcript_digest"), context.bytes("hello_transcript_digest")) &&
        fsa.uint("selected_features") === selected && fsa.uint("binding_mode") === context.uint("binding_mode"));
      requireCredential(fsa.uint("status") === 0n && fsa.uint("code") === 0n &&
        equalCredential(fsa.bytes("client_identity_digest"), s.certificateDigests[0]!) && equalCredential(fsa.bytes("server_identity_digest"), s.certificateDigests[1]!));
      const fsbDigest = credentialDigest("fsb_digest", config.noise.fsb), fsaDigest = s.work!.digest(fsa, "fsa_digest");
      requireCredential(equalCredential(fsbDigest, config.ready.fsbDigest) && equalCredential(fsaDigest, config.ready.fsaDigest) &&
        equalCredential(admission, config.ready.admissionBinding) && equalCredential(admission, fsa.bytes("admission_binding")) &&
        equalCredential(config.ready.localCertificateDigest, s.certificateDigests[role]!) && equalCredential(config.ready.peerCertificateDigest, s.certificateDigests[peer]!));
      this.checkPreparation(config.reservations.session);
    } finally { context?.close(); fsa?.close(); }
  }
  claimSession(config: V4AuthenticatedSessionConfig, transportContext: Uint8Array): CredentialSessionBinding {
    this.checkSessionInputs(config, transportContext); const s = original(this);
    const deadline = new TrustedDeadline(s.config.clock, s.sessionEnd), retained = s.reference.borrow(); s.claimed = true;
    return new CredentialSessionBinding(token, this, retained, deadline);
  }
  availableUntil(): bigint {
    const s = original(this);
    this.#check(s, s.reference); return min(s.sessionEnd, ...Array.from(s.freshness.values(), w => w.deadline.cap));
  }
  checkpointPolicy(reference: ResourceReference): CheckpointSessionPolicy | undefined { this.checkOriginal(reference); return original(this).resumePolicy; }
  checkOriginal(reference: ResourceReference): void { const s = original(this); requireCredential(s.claimed); this.#check(s, reference); }
  applicationContext(role: "client" | "server", reference: ResourceReference): StreamHandlersTypes.V4AuthenticatedContext {
    this.checkOriginal(reference); return this.#applicationContext(role);
  }
  /** Internal pre-CAS projection. The exchange must authenticate the original
   * FSB and transport context before requesting this view. */
  serverRequestContext(fsb: Uint8Array, context: Uint8Array, reference: ResourceReference): StreamHandlersTypes.V4AuthenticatedContext {
    const binding = this.authenticateClientAdmission(fsb, context, reference);
    binding.fill(0); return this.#applicationContext("server");
  }
  #applicationContext(role: "client" | "server"): StreamHandlersTypes.V4AuthenticatedContext {
    const state = original(this), client = role === "client";
    return Object.freeze({ tenant: state.config.tenant, audience: state.config.audience, localRole: role,
      localSubject: client ? state.config.clientSubject : state.config.serverSubject,
      peerSubject: client ? state.config.serverSubject : state.config.clientSubject,
      peerIdentityDigest: Array.from(state.certificateDigests[client ? 1 : 0]!, n => n.toString(16).padStart(2, "0")).join("") });
  }
  tunnelCredentials(reference: ResourceReference): VerifiedRelayCredentials {
    this.checkPreparation(reference); const owner = original(this).relay; requireCredential(owner !== undefined, "credential_binding"); return owner;
  }
  takeTunnelHopPreparation(reference: ResourceReference): HopAuthenticationPreparation | undefined {
    this.checkPreparation(reference); const s = original(this); requireCredential(s.pathKind === 1); const result = s.hop; s.hop = undefined; s.selectionSealed = true; const owner = s.tunnelCandidates.get(s.candidateIndex); if (owner !== undefined) owner.hop = undefined; return result;
  }
  /** Original signed activation selection for authority issuance and the
   * shared ParentWinner. Local Grant/certificate deadlines still constrain
   * the closure, but cannot change this immutable parent authorization. */
  parentSelectionFields(reference: ResourceReference): Omit<ServerAdmissionFields, "admissionBinding"> {
    this.checkPreparation(reference); const s = original(this), artifact = s.maps[0]!, activation = s.activation!; requireCredential(activation !== undefined);
    return Object.freeze({ source: s.source, tenant: s.config.tenant, audience: s.config.audience, profile: s.profile,
      spendAuthority: activation.text("authority_id"), signingKey: activation.text("signing_key_id"), winnerAuthority: s.source === "preauthorized_pool" ? s.once!.text("winner_authority_id") : "",
      issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"), attempt: new Uint8Array(s.attemptID), artifactDigest: new Uint8Array(s.artifactDigest), proofDigest: new Uint8Array(s.activationDigest),
      candidateID: new Uint8Array(s.candidateID), candidateSet: s.source === "preauthorized_pool" ? activation.bytes("candidate_set_digest", activation.field("candidate_selection"), "PoolSelectionRef") : new Uint8Array(),
      routeDigest: new Uint8Array(s.routeDigest), sessionNonce: new Uint8Array(s.nonce), identities: s.certificateDigests.map(value => new Uint8Array(value)),
      issuedAt: activation.uint("issued_at_ms"), activationEnd: activation.uint("activation_not_after_ms"), sessionEnd: activation.uint("session_not_after_ms"), initiationEnd: artifact.uint("initiation_not_after_ms") });
  }
  /** Drop handshake-only arenas and secrets while keeping the same original
   * evidence, namespace subscriptions and authorization deadlines. */
  detachSessionIO(): void {
    const s = original(this); requireCredential(s.claimed);
    if (s.detached) return; s.detached = true;
    for (const map of s.maps) map.close(); s.maps.length = 0;
    s.activation = s.once = undefined;
    s.work?.close(); s.work = undefined;
    for (const bytes of [s.candidateID, s.routeDigest, s.artifactDigest, s.activationDigest, s.attemptID, s.psk, s.nonce, ...s.noiseKeys, ...s.identityKeys]) bytes.fill(0);
  }
  close(): void {
    const s = closures.get(this); if (s === undefined || s.closed) return; s.closed = true;
    s.liveTunnel?.decoder.close(); s.liveTunnel?.preparation.close(); s.liveTunnel?.relayCertificate.fill(0); s.liveTunnel?.endpointCertificate.fill(0); s.liveTunnel = undefined;
    s.relay?.close(); s.relay = undefined; s.hop?.close(); s.hop = undefined; for (const owner of s.tunnelCandidates.values()) { owner.relay.close(); owner.hop?.close(); } s.tunnelCandidates.clear();
    s.revoked = s.changed = undefined; for (const subscription of s.subscriptions) subscription.close(); s.subscriptions.length = 0; s.freshness.clear();
    for (const map of s.maps) map.close(); s.maps.length = 0; s.activation = s.once = undefined;
    for (const bytes of [s.candidateID, s.routeDigest, s.artifactDigest, s.activationDigest, ...s.certificateDigests, s.attemptID, s.psk, s.nonce, ...s.noiseKeys, ...s.identityKeys]) bytes.fill(0);
    for (const e of s.evidence) clearCredentialEvidence(e); s.config.tunnel?.liveGrant?.issuerKeyID.fill(0);
    s.work?.close(); s.work = undefined; s.reference.release();
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.VerifiedCredentialClosure"; }
}
export class CredentialSessionBinding {
  #reference: ResourceReference | undefined;
  #deliveryReferences = 0;
  #closed = false;
  #deliveryRevoked: (() => void) | undefined;
  constructor(capability: symbol, private readonly closure: VerifiedCredentialClosure, reference: ResourceReference, readonly deadline: TrustedDeadline) {
    requireCredential(capability === token); this.#reference = reference; Object.freeze(this);
  }
  check(): void { requireCredential(this.#reference !== undefined, "credential_closed"); this.closure.checkOriginal(this.#reference); this.deadline.check(); }
  checkpointPolicy(selected: bigint): CheckpointSessionPolicy | undefined {
    this.check(); return (selected & applicationResumeFeature()) === 0n ? undefined : this.closure.checkpointPolicy(this.#reference!);
  }
  applicationContext(role: "client" | "server"): StreamHandlersTypes.V4AuthenticatedContext {
    this.check(); return this.closure.applicationContext(role, this.#reference!);
  }
  onRevoked(callback: () => void, deliveryRevoked?: () => void): void {
    const s = original(this.closure); requireCredential(s.revoked === undefined); this.#deliveryRevoked = deliveryRevoked;
    s.revoked = () => { deliveryRevoked?.(); callback(); }; if (s.denied !== undefined) notifyCallback(s.revoked);
  }
  /** Delivery retains the original authorization without retaining transport
   * keys or using a fresh credential/namespace subscription. */
  retainDelivery(): Readonly<{ check(): void; remainingMS(): bigint; observe(changed: () => void): () => void; release(): void }> {
    this.check(); const state = original(this.closure), reference = state.reference.borrow(); this.#deliveryReferences++;
    let active = true;
    return Object.freeze({ check: () => {
      requireCredential(active, "credential_closed"); this.closure.checkOriginal(reference); this.deadline.check();
    }, observe: changed => {
      requireCredential(active && state.changed === undefined, "credential_binding"); state.changed = changed;
      return () => { if (state.changed === changed) state.changed = undefined; };
    }, remainingMS: () => {
      requireCredential(active, "credential_closed"); this.closure.checkOriginal(reference);
      return min(this.deadline.remainingMS(), ...Array.from(state.freshness.values(), w => w.deadline.remainingMS()));
    }, release: () => {
      if (!active) return; active = false; reference.release(); this.#deliveryReferences--;
      if (this.#closed && this.#deliveryReferences === 0) { this.#deliveryRevoked = undefined; this.closure.close(); }
    } });
  }
  remainingMS(): bigint {
    this.check(); const s = original(this.closure);
    return min(this.deadline.remainingMS(), ...Array.from(s.freshness.values(), w => w.deadline.remainingMS()));
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    const state = closures.get(this.closure);
    if (state !== undefined && !state.closed) { state.revoked = this.#deliveryRevoked; this.closure.detachSessionIO(); }
    this.#reference?.release(); this.#reference = undefined;
    if (this.#deliveryReferences === 0) { this.#deliveryRevoked = undefined; this.closure.close(); }
  }
}

/** One bounded verification job; input bytes are copied into canonical arenas
 * before return. Source profile is fixed before interpretation and never falls
 * back between pool and live. Only the original selected candidate is admitted. */
export function verifyDirectCredentials(config: CredentialVerifierConfig, input: CredentialInput, reservation: ResourceReference,
  subscriptions?: Map<CredentialNamespace, CredentialNamespaceSubscription>, prepared?: TunnelCredentialPreparation): VerifiedCredentialClosure {
  const captured: CredentialVerifierConfig = Object.freeze({ ...config, ...(config.tunnel === undefined ? {} : { tunnel: Object.freeze({ ...config.tunnel, ...(config.tunnel.liveGrant === undefined ? {} : { liveGrant: Object.freeze({ ...config.tunnel.liveGrant, issuerKeyID: new Uint8Array(config.tunnel.liveGrant.issuerKeyID) }) }) }) }), namespaces: Object.freeze([...config.namespaces]), cryptoProfiles: Object.freeze([...config.cryptoProfiles]) });
  requireCredential(captured.namespaces.length > 0 && captured.namespaces.length <= 8 && captured.cryptoProfiles.length > 0 && captured.cryptoProfiles.every(p => ownProfile(p) !== undefined), "configuration_capacity");
  requireCredential(input.source === "live_authority" || input.source === "preauthorized_pool", "credential_invalid");
  requireCredential(Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16, "credential_invalid");
  const reference = reservation.take(credentialVerifierCharge(config.resources.runtimeBytes));
  let liveTunnel: PendingLiveTunnel | undefined, relay: VerifiedRelayCredentials | undefined, hop: HopAuthenticationPreparation | undefined, work: CredentialWork | undefined, result: VerifiedCredentialClosure | undefined; const tunnelCandidates = new Map<number, TunnelCandidateOwner>(); const maps: OwnedCredentialMap[] = []; const acquiredEvidence: CredentialEvidence[] = [], acquiredKeys: Uint8Array[] = [];
  try {
    if (prepared !== undefined) work = prepared.takeWork(reference);
    else {
      const workRef = config.resources.root.reserve({ owner: credentialOwner(config.resources, "verification_work"), accounts: config.resources.accounts, charge: credentialWorkCharge(270336, config.resources.runtimeBytes) });
      try { requireCredential(reference.sameEnvironment(workRef)); work = new CredentialWork(config.resources, 270336, workRef); } finally { workRef.release(); }
    }
    for (const n of captured.namespaces) { requireCredential(isCredentialNamespace(n) && n.clock === config.clock); n.check(reference); }
    const artifact = work.parse(input.artifact, "Artifact", 65536); maps.push(artifact);
    const profile = artifact.text("crypto_profile_id");
    requireCredential(captured.cryptoProfiles.includes(profile) && artifact.text("tenant_id") === captured.tenant && artifact.text("audience") === captured.audience, "credential_untrusted");
    const resolve = (map: OwnedCredentialMap): CredentialNamespace => {
      const matches = captured.namespaces.filter(n => n.matches(map)); requireCredential(matches.length === 1, "credential_untrusted"); return matches[0]!;
    };
    const parentNamespace = resolve(artifact), parent = parentNamespace.verifyCredential(artifact, 1, work); acquiredEvidence.push(parent);
    checkCredentialTime(config.clock, artifact.uint("issued_at_ms"), artifact.uint("initiation_not_after_ms"));
    const clients: CredentialEvidence[] = [], noiseKeys: Uint8Array[] = [], identityKeys: Uint8Array[] = [];
    for (const [role, bytes] of [input.clientCertificate, input.serverCertificate].entries()) {
      const certificate = work.parse(bytes, "IdentityCertificate", 8192); maps.push(certificate);
      requireCredential(certificate.text("tenant_id") === captured.tenant && certificate.text("audience") === captured.audience && certificate.text("crypto_profile_id") === profile &&
        certificate.text("subject_id") === (role === 0 ? captured.clientSubject : captured.serverSubject) && certificate.uint("role") === BigInt(role), "credential_untrusted");
      checkCredentialTime(config.clock, certificate.uint("issued_at_ms"), certificate.uint("expires_at_ms"));
      const evidence = resolve(certificate).verifyCredential(certificate, 0, work); acquiredEvidence.push(evidence);
      requireCredential(equalCredential(evidence.digest, artifact.bytes(role === 0 ? "client_identity_digest" : "server_identity_digest")));
      const parentPolicy = parent.namespace.policyRequirements(parent), childPolicy = evidence.namespace.policyRequirements(evidence);
      requireCredential(parentPolicy.staleness <= childPolicy.staleness && parentPolicy.signerLifetime <= childPolicy.signerLifetime, "credential_untrusted");
      clients.push(evidence);
      const noise = certificate.field("noise_static_public_key"), noiseKey = certificate.bytes("public_key_bytes", noise, "NoiseStaticPublicKey"), identity = certificate.bytes("ed25519_public_key");
      acquiredKeys.push(noiseKey, identity); validateIdentityKey(profile, certificate.uint("algorithm", noise, "NoiseStaticPublicKey"), noiseKey, identity); noiseKeys.push(noiseKey); identityKeys.push(identity);
    }
    const candidates = [...artifact.items("candidates")], candidate = candidates[input.candidateIndex]; requireCredential(candidate !== undefined);
    const pathKind = Number(artifact.uint("path_kind", candidate, "Candidate")) as 0 | 1, localRole = captured.tunnel?.role ?? 0;
    requireCredential(pathKind === 0 ? input.tunnel === undefined && captured.tunnel === undefined : pathKind === 1 && input.tunnel !== undefined && captured.tunnel !== undefined, "credential_untrusted");
    const candidateID = artifact.bytes("candidate_id", candidate, "Candidate"), routeDigest = candidateRouteDigest(artifact, candidate);
    if (pathKind === 0) checkClosure(artifact, candidate, [parent.namespace, clients[0]!.namespace, clients[1]!.namespace]);
    const artifactDigest = work.digest(artifact, "artifact_digest");
    const onceBytes = parentNamespace.onceAuthority(parent.issuer), once = work.parse(onceBytes, "OnceAuthorityRef", 412); maps.push(once); onceBytes.fill(0);
    const pendingLive = input.source === "live_authority" && (input.activation === undefined || input.activation.length === 0);
    let activation: OwnedCredentialMap | undefined, activationEvidence: CredentialEvidence | undefined;
    let issued = artifact.uint("issued_at_ms"), initiation = artifact.uint("initiation_not_after_ms"), sessionEnd = artifact.uint("session_not_after_ms");
    if (!pendingLive) {
      requireCredential(input.activation !== undefined, "credential_invalid");
      activation = work.parse(input.activation, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: input.source } }); maps.push(activation);
      const verified = validateActivation(config, work, artifact, activation, parent, once, input.source, input.candidateIndex, artifactDigest, candidateID, routeDigest);
      issued = verified.issued; initiation = verified.initiation; sessionEnd = verified.sessionEnd; activationEvidence = verified.evidence; acquiredEvidence.push(activationEvidence);
    }
    let scopeEvidence: CredentialEvidence | undefined, relayEvidence: CredentialEvidence | undefined;
    if (pathKind === 1 && pendingLive) {
      const policy = captured.tunnel!, scope = policy.liveGrant, bytes = input.tunnel!;
      requireCredential(scope !== undefined && (bytes.grant === undefined || bytes.grant.length === 0) && (bytes.candidateGrants === undefined || bytes.candidateGrants.length === 0), "credential_untrusted");
      const scopeNamespace = captured.namespaces.find(namespace => namespace.authority === scope.authority);
      requireCredential(scopeNamespace !== undefined, "credential_untrusted");
      const authorized = scopeNamespace.preauthorizeGrantScope(artifact, localRole, policy.audience, policy.service, scope.issuerKeyID,
        scope.revocationPolicyID, scope.revocationPolicyRevision, min(scope.maxNotAfterMS, sessionEnd), work);
      scopeEvidence = authorized.evidence; acquiredEvidence.push(scopeEvidence); initiation = min(initiation, authorized.preparationEnd);
      const relayMap = work.parse(bytes.relayCertificate, "IdentityCertificate", 8192);
      try {
        requireCredential(relayMap.text("tenant_id") === captured.tenant && relayMap.text("audience") === policy.audience && relayMap.text("subject_id") === policy.relaySubject && relayMap.text("crypto_profile_id") === profile && relayMap.uint("role") === 2n, "credential_untrusted");
        const ns = captured.namespaces.find(value => value.matches(relayMap)); requireCredential(ns !== undefined, "credential_untrusted");
        checkCredentialTime(config.clock, relayMap.uint("issued_at_ms"), relayMap.uint("expires_at_ms"));
        relayEvidence = ns.verifyCredential(relayMap, 0, work); acquiredEvidence.push(relayEvidence);
        const key = relayMap.bytes("ed25519_public_key");
        try { const point = ed25519.Point.fromBytes(key, false); requireCredential(!point.is0() && point.isTorsionFree() && equalCredential(point.toBytes(), key)); } finally { key.fill(0); }
        const baseline = parent.namespace.policyRequirements(parent);
        for (const child of [scopeEvidence, relayEvidence]) { const p = child.namespace.policyRequirements(child); requireCredential(baseline.staleness <= p.staleness && baseline.signerLifetime <= p.signerLifetime); }
        checkTunnelClosure(artifact, candidate, localRole, [parent.namespace, clients[0]!.namespace, clients[1]!.namespace], scopeNamespace, undefined, bytes.relayCertificate, work, captured.namespaces);
      } finally { relayMap.close(); }
      const preparation = prepared?.takeRelay() ?? new RelayCredentialPreparation(captured.resources, captured.namespaces);
      let decoder: CBORDecoder | undefined;
      try {
        if (prepared !== undefined) decoder = prepared.takeLiveDecoder();
        else { const ref = captured.resources.root.reserve({ owner: credentialOwner(captured.resources, "live_tunnel_response"), accounts: captured.resources.accounts, charge: cborDecoderCharge(liveMaterialDecoderConfig(captured.resources.runtimeBytes)) }); try { decoder = new CBORDecoder(liveMaterialDecoderConfig(captured.resources.runtimeBytes), ref); } finally { ref.release(); } }
        liveTunnel = { scope: scopeEvidence, relayCertificate: new Uint8Array(bytes.relayCertificate), endpointCertificate: new Uint8Array(localRole === 0 ? input.clientCertificate : input.serverCertificate), preparation, decoder };
      } catch (error) { preparation.close(); decoder?.close(); throw error; }
    }
    if (pathKind === 1 && !pendingLive) {
      const policy = captured.tunnel!, bytes = input.tunnel!, capacity = policy.candidateCapacity ?? 1;
      requireCredential(Number.isSafeInteger(capacity) && capacity >= 1 && capacity <= 16 && bytes.grant instanceof Uint8Array && bytes.grant.length > 0 && bytes.grant.length <= 65536 &&
        (bytes.candidateGrants === undefined || Array.isArray(bytes.candidateGrants) && bytes.candidateGrants.length < capacity) && (input.source === "preauthorized_pool" || (bytes.candidateGrants?.length ?? 0) === 0), "credential_invalid");
      const supplied = [{ candidateIndex: input.candidateIndex, grant: bytes.grant, relayCertificate: bytes.relayCertificate }, ...(bytes.candidateGrants ?? [])];
      const authorized = checkSelection({ source: input.source, candidateIndex: input.candidateIndex }, artifact, activation!, artifactDigest, candidateID, routeDigest, once), seen = new Set<number>();
      for (const suppliedCandidate of supplied) {
        const index = suppliedCandidate.candidateIndex, node = candidates[index];
        requireCredential(Number.isSafeInteger(index) && index >= 0 && index < 16 && !seen.has(index) && authorized.includes(index) && node !== undefined && artifact.uint("path_kind", node, "Candidate") === 1n &&
          suppliedCandidate.grant instanceof Uint8Array && suppliedCandidate.grant.length > 0 && suppliedCandidate.grant.length <= 65536 && suppliedCandidate.relayCertificate instanceof Uint8Array && suppliedCandidate.relayCertificate.length > 0 && suppliedCandidate.relayCertificate.length <= 8192, "credential_binding"); seen.add(index);
        const relayReference = prepared?.takeRelay() ?? new RelayCredentialPreparation(captured.resources, captured.namespaces);
        let candidateRelay: VerifiedRelayCredentials | undefined, candidateHop: HopAuthenticationPreparation | undefined;
        const digest = candidateRouteDigest(artifact, node);
        try {
          candidateRelay = verifyRelayCredentials({ ...captured, audience: policy.audience, service: policy.service, endpointSubject: localRole === 0 ? captured.clientSubject : captured.serverSubject, relaySubject: policy.relaySubject },
            { grant: suppliedCandidate.grant, endpointCertificate: localRole === 0 ? input.clientCertificate : input.serverCertificate, relayCertificate: suppliedCandidate.relayCertificate }, relayReference);
          requireCredential(candidateRelay.role === localRole, "credential_binding");
          validateTunnelGrantProjection(captured, work, artifact, node, activation!, localRole, [parent, ...clients], artifactDigest, digest, suppliedCandidate.grant, suppliedCandidate.relayCertificate, candidateRelay);
          candidateHop = prepared?.takeHop() ?? new HopAuthenticationPreparation(captured.resources);
          tunnelCandidates.set(index, { relay: candidateRelay, hop: candidateHop }); candidateRelay = undefined; candidateHop = undefined;
        } finally { digest.fill(0); relayReference.close(); candidateRelay?.close(); candidateHop?.close(); }
      }
      relay = tunnelCandidates.get(input.candidateIndex)!.relay; hop = tunnelCandidates.get(input.candidateIndex)!.hop;
    }
    const contract = artifact.field("session_contract"), rekey = artifact.field("rekey_envelope", contract, "SessionContract");
    const state: ClosureState = {
      config: captured, liveTunnel, tunnelCandidates, selectionSealed: false, handshakeChecksPrepared: prepared !== undefined, relay, hop: hop = pathKind === 1 && pendingLive ? prepared?.takeHop() : hop, pathKind, localRole, reference, work, maps, activation, once, candidateIndex: input.candidateIndex, evidence: [parent, ...clients, ...(scopeEvidence === undefined ? [] : [scopeEvidence]), ...(relayEvidence === undefined ? [] : [relayEvidence]), ...(activationEvidence === undefined ? [] : [activationEvidence])],
      profile, source: input.source, candidateID, routeDigest, artifactDigest, activationDigest: activation === undefined ? new Uint8Array(32) : work.digest(activation, "activation_digest"),
      certificateDigests: clients.map(c => new Uint8Array(c.digest)), attemptID: activation?.bytes("attempt_id") ?? new Uint8Array(16), psk: artifact.bytes("e2ee_psk"), nonce: artifact.bytes("session_nonce"),
      noiseKeys, identityKeys, from: max(artifact.uint("issued_at_ms"), issued, maps[1]!.uint("issued_at_ms"), maps[2]!.uint("issued_at_ms")),
      preparationDeadline: new TrustedDeadline(config.clock, initiation), sessionDeadline: new TrustedDeadline(config.clock, min(sessionEnd, clients[0]!.expires, clients[1]!.expires)),
      resumePolicy: artifact.doc.boolean(artifact.field("enabled", artifact.field("resume_policy"), "ResumePolicy")) ? Object.freeze({
        maxIssuedTokenDurationMS: artifact.uint("max_issued_token_duration_ms", artifact.field("resume_policy"), "ResumePolicy"),
        maxTokenBytes: Number(artifact.uint("max_token_bytes", artifact.field("resume_policy"), "ResumePolicy")) }) : undefined,
      initiation, sessionEnd: min(sessionEnd, clients[0]!.expires, clients[1]!.expires), allowed: artifact.uint("allowed_features"), required: artifact.uint("required_features"),
      maxFrame: artifact.uint("max_frame", contract, "SessionContract"), maxStreams: artifact.uint("max_streams", contract, "SessionContract"),
      idleDurationMS: artifact.uint("idle_duration_ms", contract, "SessionContract"),
      maxCredit: artifact.uint("max_credit", contract, "SessionContract"), applicationProfile: artifact.uint("application_profile", contract, "SessionContract"),
      rpcMaxGeneralOutstanding: artifact.optional("rpc_max_general_outstanding", contract, "SessionContract") < 0 ? 0n : artifact.uint("rpc_max_general_outstanding", contract, "SessionContract"),
      rekeyBurst: artifact.uint("burst_rounds", rekey, "RekeyEnvelope"), rekeyRefill: artifact.uint("refill_period_ms", rekey, "RekeyEnvelope"), subscriptions: [], freshness: new Map(), denied: undefined, revoked: undefined, changed: undefined, claimed: false, detached: false, closed: false,
    };
    result = new VerifiedCredentialClosure(token, state);
    for (const [index, owner] of tunnelCandidates) owner.relay.onRevoked(error => { if (state.closed || state.denied !== undefined || state.candidateIndex !== index) return; state.denied = error; notifyCallback(state.revoked); });
    if (tunnelCandidates.size === 0) relay?.onRevoked(error => { if (state.closed || state.denied !== undefined) return; state.denied = error; notifyCallback(state.revoked); });
    result.checkPreparation(reference); result.attachNamespaces(token, subscriptions); return result;
  } catch (error) {
    if (result !== undefined) result.close(); else { liveTunnel?.decoder.close(); liveTunnel?.preparation.close(); liveTunnel?.relayCertificate.fill(0); liveTunnel?.endpointCertificate.fill(0); hop?.close(); relay?.close(); for (const owner of tunnelCandidates.values()) { owner.hop?.close(); owner.relay.close(); } tunnelCandidates.clear(); for (const e of acquiredEvidence) clearCredentialEvidence(e); for (const key of acquiredKeys) key.fill(0); captured.tunnel?.liveGrant?.issuerKeyID.fill(0); for (const map of maps) map.close(); work?.close(); reference.release(); }
    for (const subscription of subscriptions?.values() ?? []) subscription.close(); subscriptions?.clear();
    throw error;
  }
}
export function validateActivation(config: CredentialVerifierConfig, work: CredentialWork, artifact: OwnedCredentialMap, activation: OwnedCredentialMap,
  parent: CredentialEvidence, once: OwnedCredentialMap, source: ActivationSource, candidateIndex: number,
  artifactDigest: Uint8Array, candidateID: Uint8Array, routeDigest: Uint8Array): Readonly<{ issued: bigint; initiation: bigint; sessionEnd: bigint; evidence: CredentialEvidence }> {
  return validateActivationProjection(config, work, artifact, activation, parent, once, source, candidateIndex, artifactDigest, candidateID, routeDigest);
}
/** Authority-only unsigned preparation. Evidence remains a signing permission;
 * the ordinary credential verifier always verifies the actual signature. */
export function validateActivationIssuance(config: CredentialVerifierConfig, work: CredentialWork, artifact: OwnedCredentialMap, activation: OwnedCredentialMap,
  parent: CredentialEvidence, once: OwnedCredentialMap, candidateIndex: number, artifactDigest: Uint8Array, candidateID: Uint8Array, routeDigest: Uint8Array,
  signingKey: Uint8Array): Readonly<{ issued: bigint; initiation: bigint; sessionEnd: bigint; evidence: CredentialEvidence }> {
  return validateActivationProjection(config, work, artifact, activation, parent, once, "live_authority", candidateIndex, artifactDigest, candidateID, routeDigest, signingKey);
}
function validateActivationProjection(config: CredentialVerifierConfig, work: CredentialWork, artifact: OwnedCredentialMap, activation: OwnedCredentialMap,
  parent: CredentialEvidence, once: OwnedCredentialMap, source: ActivationSource, candidateIndex: number, artifactDigest: Uint8Array, candidateID: Uint8Array, routeDigest: Uint8Array,
  signingKey?: Uint8Array): Readonly<{ issued: bigint; initiation: bigint; sessionEnd: bigint; evidence: CredentialEvidence }> {
  for (const [a, b] of [["tenant_id", "tenant_id"], ["artifact_issuer_key_id", "issuer_key_id"], ["lease_id", "lease_id"], ["audience", "audience"],
    ["client_identity_digest", "client_identity_digest"], ["server_identity_digest", "server_identity_digest"]] as const) {
    requireCredential(equalCredential(activation.encoded(activation.field(a)), artifact.encoded(artifact.field(b))));
  }
  requireCredential(equalCredential(activation.bytes("artifact_digest"), artifactDigest));
  const issued = activation.uint("issued_at_ms"), initiation = activation.uint("activation_not_after_ms"), sessionEnd = activation.uint("session_not_after_ms");
  checkCredentialTime(config.clock, issued, initiation);
  requireCredential(issued >= artifact.uint("issued_at_ms") && initiation <= artifact.uint("initiation_not_after_ms") && sessionEnd <= artifact.uint("session_not_after_ms"));
  requireCredential(activation.text("authority_id") === once.text("spend_authority_id"));
  const evidence = signingKey === undefined ? parent.namespace.verifyActivation(activation, parent, work) : parent.namespace.authorizeActivationIssuance(activation, parent, signingKey, work);
  checkSelection({ source, candidateIndex }, artifact, activation, artifactDigest, candidateID, routeDigest, once);
  return { issued, initiation, sessionEnd, evidence };
}
export function validateIdentityKey(profile: string, algorithm: bigint, noise: Uint8Array, identity: Uint8Array): void {
  const p = ownProfile(profile)!; requireCredential(algorithm === BigInt(p.dh_algorithm));
  const point = ed25519.Point.fromBytes(identity, false); requireCredential(!point.is0() && point.isTorsionFree() && equalCredential(point.toBytes(), identity), "credential_invalid");
  if (algorithm === 0n) {
    const contribution = x25519.getSharedSecret(new Uint8Array(32).fill(0x5a), noise);
    try { requireCredential(contribution.some(x => x !== 0), "credential_invalid"); } finally { contribution.fill(0); }
  } else {
    requireCredential(noise.length === 65 && noise[0] === 4, "credential_invalid"); const point = p256.Point.fromBytes(noise); point.assertValidity(); requireCredential(equalCredential(point.toBytes(false), noise));
  }
}
export function candidateRouteBytes(artifact: OwnedCredentialMap, candidate: number): Uint8Array {
  const buffer = new Uint8Array(65536), writer = new FixedCBORWriter(buffer), kind = artifact.uint("path_kind", candidate, "Candidate");
  writer.map(kind === 0n ? 3 : 4).uint(0).uint(kind).uint(1).data(artifact.bytes("candidate_id", candidate, "Candidate"));
  const fields = kind === 0n ? [[2, "direct_leg"]] as const : [[3, "client_leg"], [4, "server_leg"]] as const;
  try { for (const [id, field] of fields) writer.uint(id).encoded(artifact.encoded(artifact.field(field, candidate, "Candidate"))); return new Uint8Array(writer.result()); }
  finally { buffer.fill(0); }
}
export function candidateRouteDigest(artifact: OwnedCredentialMap, candidate: number): Uint8Array {
  const bytes = candidateRouteBytes(artifact, candidate); try { return credentialDigest("route_digest", bytes); } finally { bytes.fill(0); }
}
function validateTunnelGrantProjection(config: CredentialVerifierConfig, work: CredentialWork, artifact: OwnedCredentialMap,
  candidate: number, activation: OwnedCredentialMap, role: 0 | 1, common: readonly CredentialEvidence[], artifactDigest: Uint8Array,
  routeDigest: Uint8Array, grantBytes: Uint8Array, relayBytes: Uint8Array, relay: VerifiedRelayCredentials, scope?: CredentialEvidence): void {
  const grant = work.parse(grantBytes, "Grant", 65536);
  let routeBytes: Uint8Array | undefined;
  try {
    const ref = grant.field("parent_ref"), contract = artifact.field("session_contract"), ns = config.namespaces.find(value => value.matches(grant));
    requireCredential(ns !== undefined, "credential_untrusted");
    routeBytes = candidateRouteBytes(artifact, candidate);
    for (const [name, originalName] of [["artifact_digest", undefined], ["namespace_capacity_digest", "namespace_capacity_digest"], ["artifact_issuer_key_id", "issuer_key_id"], ["lease_id", "lease_id"]] as const) {
      const expected = originalName === undefined ? artifactDigest : artifact.bytes(originalName);
      try { requireCredential(equalCredential(grant.bytes(name, ref, "GrantParentRef"), expected)); } finally { if (originalName !== undefined) expected.fill(0); }
    }
    for (const [name, originalName] of [["authority_generation", "revocation_authority_generation"], ["revocation_epoch", "revocation_epoch"], ["revocation_policy_revision", "revocation_policy_revision"], ["issued_at_ms", "issued_at_ms"], ["initiation_not_after_ms", "initiation_not_after_ms"], ["session_not_after_ms", "session_not_after_ms"]] as const)
      requireCredential(grant.uint(name, ref, "GrantParentRef") === artifact.uint(originalName));
    for (const name of ["tenant_id", "revocation_authority_id", "revocation_policy_id"]) requireCredential(grant.text(name, ref, "GrantParentRef") === artifact.text(name));
    requireCredential(equalCredential(grant.encoded(grant.field("route_descriptor")), routeBytes) && equalCredential(grant.bytes("route_digest"), routeDigest) &&
      equalCredential(grant.bytes("session_contract_digest"), work.digest(artifact, "session_contract_digest", contract)) &&
      grant.uint("max_envelope_bytes", grant.field("limits"), "GrantLimits") === artifact.uint("max_frame", contract, "SessionContract") + 8n && equalCredential(grant.bytes("attempt_id"), activation.bytes("attempt_id")));
    const identities = [...grant.items("identity_digests")]; requireCredential(identities.length === 2);
    for (const [index, node] of identities.entries()) {
      const digest = new Uint8Array(grant.doc.size(node)); grant.doc.copyPayload(node, digest);
      try { requireCredential(equalCredential(digest, common[index + 1]!.digest)); } finally { digest.fill(0); }
    }
    if (scope !== undefined) {
      const namespace = grant.field("namespace"); scope.namespace.checkEvidence(scope);
      requireCredential(ns === scope.namespace && equalCredential(grant.bytes("issuer_key_id"), scope.issuer) && grant.uint("revocation_epoch", namespace, "GrantNamespace") === scope.cohort &&
        grant.text("revocation_policy_id", namespace, "GrantNamespace") === scope.policyID && grant.uint("revocation_policy_revision", namespace, "GrantNamespace") === scope.policyRevision &&
        grant.uint("role_mask", namespace, "GrantNamespace") === (4n | 1n << BigInt(role)) && grant.uint("not_after_ms") <= scope.expires, "credential_binding");
    }
    checkTunnelClosure(artifact, candidate, role, common.map(value => value.namespace), ns, relay, relayBytes, work, config.namespaces);
  } finally { routeBytes?.fill(0); grant.close(); }
}

function checkTunnelClosure(artifact: OwnedCredentialMap, candidate: number, role: 0 | 1, commonNamespaces: readonly CredentialNamespace[], grantNamespace: CredentialNamespace, relay: VerifiedRelayCredentials | undefined, relayBytes: Uint8Array, work: CredentialWork, namespaces: readonly CredentialNamespace[]): void {
  const certificate = work.parse(relayBytes, "IdentityCertificate", 8192);
  try {
    const relayNamespace = namespaces.find(ns => ns.matches(certificate)); requireCredential(relayNamespace !== undefined);
    const contexts = [...commonNamespaces, grantNamespace, relayNamespace], seen = new Set<CredentialNamespace>(), masks = new Map<CredentialNamespace, bigint>(), mask = 4n | 1n << BigInt(role);
    for (const ns of commonNamespaces) masks.set(ns, 7n);
    for (const ns of [grantNamespace, relayNamespace]) masks.set(ns, (masks.get(ns) ?? 0n) | mask);
    for (const node of artifact.items("revocation_namespace_refs", candidate, "Candidate")) {
      const ns = contexts.find(value => artifact.text("tenant_id", node, "RevocationNamespaceRef") === value.tenant && artifact.text("revocation_authority_id", node, "RevocationNamespaceRef") === value.authority);
      if (ns === undefined) { requireCredential((artifact.uint("role_mask", node, "RevocationNamespaceRef") & mask) !== mask); continue; }
      const required = masks.get(ns)!; requireCredential((artifact.uint("role_mask", node, "RevocationNamespaceRef") & required) === required && !seen.has(ns)); ns.checkReference(artifact, node); seen.add(ns);
    }
    requireCredential(contexts.every(ns => seen.has(ns))); relay?.check();
  } finally { certificate.close(); }
}
function checkClosure(artifact: OwnedCredentialMap, candidate: number, contexts: readonly CredentialNamespace[]): void {
  const references = [...artifact.items("revocation_namespace_refs", candidate, "Candidate")], seen = new Set<CredentialNamespace>();
  for (const node of references) {
    const ns = contexts.find(n => artifact.text("tenant_id", node, "RevocationNamespaceRef") === n.tenant && artifact.text("revocation_authority_id", node, "RevocationNamespaceRef") === n.authority);
    requireCredential(ns !== undefined && !seen.has(ns) && artifact.uint("role_mask", node, "RevocationNamespaceRef") === 3n); ns.checkReference(artifact, node); seen.add(ns);
  }
  requireCredential(contexts.every(n => seen.has(n)));
}
export function checkSelection(input: Pick<CredentialInput, "source" | "candidateIndex">, artifact: OwnedCredentialMap, activation: OwnedCredentialMap, artifactDigest: Uint8Array, candidateID: Uint8Array, route: Uint8Array, once: OwnedCredentialMap): number[] {
  if (input.source === "live_authority") { requireCredential(equalCredential(activation.bytes("candidate_selection"), candidateID) && equalCredential(activation.bytes("route_selection"), route)); return [input.candidateIndex]; }
  const selection = activation.field("candidate_selection"), schema = "PoolSelectionRef";
  requireCredential(equalCredential(activation.bytes("artifact_digest", selection, schema), artifactDigest) &&
    equalCredential(activation.encoded(activation.field("once_authority_ref", selection, schema)), once.encoded()));
  const indices = [...activation.items("candidate_indices", selection, schema)], candidates = [...artifact.items("candidates")], buffer = new Uint8Array(2048);
  const writer = new FixedCBORWriter(buffer).map(2).uint(0).data(artifactDigest).uint(1).array(indices.length); let found = false;
  for (const node of indices) {
    const index = Number(activation.doc.uint(node)), candidate = candidates[index]; requireCredential(candidate !== undefined); found ||= index === input.candidateIndex;
    writer.map(3).uint(0).uint(index).uint(1).data(artifact.bytes("candidate_id", candidate, "Candidate")).uint(2).data(candidateRouteDigest(artifact, candidate));
  }
  try { requireCredential(found && equalCredential(credentialDigest("candidate_set_digest", writer.result()), activation.bytes("candidate_set_digest", selection, schema)) &&
    equalCredential(credentialDigest("route_set_digest", writer.result()), activation.bytes("route_selection"))); return indices.map(node => Number(activation.doc.uint(node))); } finally { buffer.fill(0); }
}
function min(...values: bigint[]): bigint { return values.reduce((a, b) => a < b ? a : b); }
function max(...values: bigint[]): bigint { return values.reduce((a, b) => a > b ? a : b); }
for (const ctor of [VerifiedPoolSpendFacts, VerifiedCredentialClosure, CredentialSessionBinding, TunnelCredentialPreparation]) { Object.freeze(ctor.prototype); Object.freeze(ctor); }

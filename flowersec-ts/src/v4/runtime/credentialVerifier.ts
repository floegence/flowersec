import type * as StreamHandlersTypes from "../streamHandlers.js";
import { applicationResumeFeature, type CheckpointSessionPolicy } from "./checkpointToken.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import type { TrustedClock } from "./clock.js";
import { TimeError } from "./timeArithmetic.js";
import { TrustedDeadline } from "./deadline.js";
import { type CredentialNamespace, isCredentialNamespace, type CredentialEvidence, type CredentialNamespaceSubscription } from "./credentialNamespace.js";
import { CredentialWork, type OwnedCredentialMap, checkCredentialTime, credentialDigest, credentialOwner, equalCredential, requireCredential, type CredentialResources } from "./credentialSupport.js";
import { FixedCBORWriter } from "./openAdmission.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { V4AuthenticatedSessionConfig } from "./session.js";
import { ownProfile } from "./wireRegistry.js";

export type ActivationSource = "live_authority" | "preauthorized_pool";
export interface CredentialVerifierConfig {
  readonly resources: CredentialResources; readonly clock: TrustedClock;
  readonly namespaces: readonly CredentialNamespace[];
  readonly tenant: string; readonly audience: string; readonly clientSubject: string; readonly serverSubject: string;
  readonly cryptoProfiles: readonly string[];
}
export interface CredentialInput {
  readonly artifact: Uint8Array; readonly clientCertificate: Uint8Array; readonly serverCertificate: Uint8Array;
  readonly activation?: Uint8Array; readonly source: ActivationSource; readonly candidateIndex: number;
}
export function credentialVerifierCharge(runtimeBytes: bigint): ResourceVector {
  requireCredential(runtimeBytes > 0n, "configuration_capacity");
  // Original material, result projection, route/set encoding and bounded crypto
  // temporaries stay paid through the verified closure's last use.
  return new ResourceVector([524288n + runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
const token = Symbol("original verified credential closure");
interface ClosureState {
  work: CredentialWork | undefined; readonly reference: ResourceReference;
  readonly config: CredentialVerifierConfig; readonly maps: OwnedCredentialMap[]; readonly evidence: CredentialEvidence[];
  activation: OwnedCredentialMap | undefined; once: OwnedCredentialMap | undefined; readonly candidateIndex: number;
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
export interface ClientPreparationFields {
  readonly preparationBytes: number; readonly preparationWork: number;
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
  checkPreparation(reference: ResourceReference): void {
    const s = original(this); requireCredential(!s.detached, "credential_closed"); this.#check(s, reference); s.preparationDeadline.check(); checkCredentialTime(s.config.clock, s.from, s.initiation);
  }
  checkApplicationProfile(profile: "transport" | "services" | "execution", reference: ResourceReference): void {
    this.checkPreparation(reference);
    if (original(this).applicationProfile !== (profile === "transport" ? 0n : profile === "services" ? 1n : 2n)) throw new Error("connection_requirement_unavailable");
  }
  clientPreparation(reference: ResourceReference): ClientPreparationFields {
    this.checkPreparation(reference); const s = original(this), artifact = s.maps[0]!;
    const candidate = [...artifact.items("candidates")].find(n => equalCredential(artifact.bytes("candidate_id", n, "Candidate"), s.candidateID))!;
    const buffer = new Uint8Array(16384), writer = new FixedCBORWriter(buffer);
    writer.map(3).uint(0).uint(0).uint(1).data(s.candidateID).uint(2).encoded(artifact.encoded(artifact.field("direct_leg", candidate, "Candidate")));
    const route = new Uint8Array(writer.result()); buffer.fill(0);
    const resume = artifact.field("resume_policy");
    const activation = s.activation;
    let preparationBytes = 0, preparationWork = 0;
    if (s.source === "preauthorized_pool") {
      requireCredential(activation !== undefined);
      const selection = activation.field("candidate_selection"), budget = activation.field("attempt_budget", selection, "PoolSelectionRef"), perCandidate = activation.field("per_candidate", budget, "PoolAttemptBudget");
      preparationBytes = Number(min(activation.uint("preauth_bytes", perCandidate, "CandidateAttemptBudget"), activation.uint("total_preauth_bytes", budget, "PoolAttemptBudget")));
      preparationWork = Number(min(activation.uint("work_units", perCandidate, "CandidateAttemptBudget"), activation.uint("total_work_units", budget, "PoolAttemptBudget")));
    }
    return Object.freeze({ source: s.source, profile: s.profile, tenant: s.config.tenant, issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"),
      artifactDigest: new Uint8Array(s.artifactDigest), candidateID: new Uint8Array(s.candidateID), routeDigest: new Uint8Array(s.routeDigest), route,
      attempt: new Uint8Array(s.attemptID), nonce: new Uint8Array(s.nonce), activation: activation?.encoded() ?? new Uint8Array(), clientCertificate: s.maps[1]!.encoded(), serverCertificate: s.maps[2]!.encoded(),
      identities: s.certificateDigests.map(x => new Uint8Array(x)), noiseKeys: s.noiseKeys.map(x => new Uint8Array(x)), identityKeys: s.identityKeys.map(x => new Uint8Array(x)), psk: new Uint8Array(s.psk),
      allowed: s.allowed, required: s.required, resume: artifact.doc.boolean(artifact.field("enabled", resume, "ResumePolicy")),
      maxFrame: Number(s.maxFrame), maxStreams: Number(s.maxStreams), maxCredit: s.maxCredit, applicationProfile: s.applicationProfile, idleDurationMS: s.idleDurationMS,
      rpcMaxGeneralOutstanding: Number(s.rpcMaxGeneralOutstanding), rekeyBurst: s.rekeyBurst, rekeyRefill: s.rekeyRefill, preparationDeadline: s.preparationDeadline, sessionDeadline: s.sessionDeadline, preparationBytes, preparationWork });
  }
  /** One original client attempt, selected before carrier preparation. No
   * activation success or durable-spend fact is inferred from this binding. */
  beginLivePreparation(attempt: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "live_authority" && s.activation === undefined && !s.claimed && !s.attemptID.some(n => n !== 0) &&
      attempt.length === 16 && attempt.some(n => n !== 0), "credential_binding");
    s.attemptID.set(attempt);
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
  installLiveAuthorization(bytes: Uint8Array, reference: ResourceReference): void {
    this.checkPreparation(reference); const s = original(this);
    requireCredential(s.source === "live_authority" && s.activation === undefined && s.attemptID.some(n => n !== 0), "credential_binding");
    let activation: OwnedCredentialMap | undefined;
    try {
      activation = s.work!.parse(bytes, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: s.source } });
      const verified = validateActivation(s.config, s.work!, s.maps[0]!, activation, s.evidence[0]!, s.once!,
        s.source, s.candidateIndex, s.artifactDigest, s.candidateID, s.routeDigest);
      requireCredential(equalCredential(activation.bytes("attempt_id"), s.attemptID), "credential_binding");
      this.checkPreparation(reference);
      s.preparationDeadline.tighten(verified.initiation);
      const sessionEnd = min(s.sessionEnd, verified.sessionEnd); s.sessionDeadline.tighten(sessionEnd);
      s.from = max(s.from, verified.issued); s.initiation = verified.initiation; s.sessionEnd = sessionEnd;
      s.activationDigest.set(s.work!.digest(activation, "activation_digest"));
      s.evidence.push(verified.evidence); s.maps.push(activation); s.activation = activation; activation = undefined;
      this.checkPreparation(reference);
    } catch (error) { s.denied = error; throw error; }
    finally { activation?.close(); }
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
    this.checkPreparation(reference); const s = original(this); s.work!.prepaySignatures(65536, 16384); s.work!.prepayParsers(65536, 16384, 3);
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
  attachNamespaces(capability: symbol): void {
    requireCredential(capability === token, "credential_untrusted"); const s = original(this);
    for (const ns of new Set(s.evidence.map(e => e.namespace))) s.subscriptions.push(ns.subscribe(s.reference, () => {
      if (s.closed || s.denied !== undefined) return;
      try { this.#check(s, s.reference); s.changed?.(); }
      catch (error) {
        if (error instanceof TimeError && ["time_unavailable", "time_continuity", "time_pending"].includes(error.code)) return;
        s.denied = error; s.revoked?.();
      }
    }));
    this.#check(s, s.reference);
  }
  poolSpendFacts(reference: ResourceReference): VerifiedPoolSpendFacts {
    const state = original(this); this.checkPreparation(reference); requireCredential(state.source === "preauthorized_pool");
    const artifact = state.maps[0]!, activation = state.activation!, once = state.once!, selection = activation.field("candidate_selection");
    const candidates = [...artifact.items("candidates")], candidateIndex = candidates.findIndex(node => equalCredential(artifact.bytes("candidate_id", node, "Candidate"), state.candidateID));
    const candidate = candidates[candidateIndex]!;
    const fields: PoolSpendFields = Object.freeze({ tenant: state.config.tenant, audience: state.config.audience, profile: state.profile,
      authority: once.text("spend_authority_id"), winnerAuthority: once.text("winner_authority_id"), signingKey: activation.text("signing_key_id"),
      namespace: artifact.text("revocation_authority_id"), namespaceGeneration: artifact.uint("revocation_authority_generation"), capacityDigest: artifact.bytes("namespace_capacity_digest"),
      issuer: artifact.bytes("issuer_key_id"), lease: artifact.bytes("lease_id"), attempt: new Uint8Array(state.attemptID),
      artifactDigest: new Uint8Array(state.artifactDigest), proofDigest: new Uint8Array(state.activationDigest), proof: activation.encoded(),
      candidateID: new Uint8Array(state.candidateID), candidateIndex: BigInt(candidateIndex), routeDigest: new Uint8Array(state.routeDigest), descriptor: artifact.encoded(artifact.field("direct_leg", candidate, "Candidate")),
      candidateSet: activation.bytes("candidate_set_digest", selection, "PoolSelectionRef"), routeSet: activation.bytes("route_selection"),
      sessionNonce: new Uint8Array(state.nonce), identities: Object.freeze(state.certificateDigests.map(value => new Uint8Array(value))),
      issuedAt: activation.uint("issued_at_ms"), activationEnd: state.initiation, sessionEnd: state.sessionEnd, initiationEnd: artifact.uint("initiation_not_after_ms") });
    return new VerifiedPoolSpendFacts(token, { closure: this, reference: state.reference.borrow(), fields, closed: false });
  }
  /** Authenticate the client request against the original locally negotiated
   * context before any server admission transaction or signed success. This
   * does not grant once authority or assert that the carrier has been checked. */
  authenticateClientAdmission(fsbBytes: Uint8Array, transportContext: Uint8Array, reference: ResourceReference): Uint8Array {
    const s = original(this); requireCredential(!s.claimed && s.activation !== undefined, "credential_binding");
    this.checkPreparation(reference);
    let context: OwnedCredentialMap | undefined, fsb: OwnedCredentialMap | undefined;
    try {
      context = s.work!.parse(transportContext, "TransportContext", 2048);
      const selected = context.uint("selected_features");
      requireCredential(context.text("crypto_profile_id") === s.profile && context.uint("path_kind") === 0n &&
        (selected & ~s.allowed) === 0n && (selected & s.required) === s.required &&
        equalCredential(context.bytes("artifact_digest"), s.artifactDigest) && equalCredential(context.bytes("route_digest"), s.routeDigest) &&
        equalCredential(context.bytes("attempt_id"), s.attemptID) && equalCredential(context.bytes("session_nonce"), s.nonce));
      const artifact = s.maps[0]!, candidate = [...artifact.items("candidates")].find(n => equalCredential(artifact.bytes("candidate_id", n, "Candidate"), s.candidateID))!;
      requireCredential(context.uint("access_class") === artifact.uint("access_class", artifact.field("direct_leg", candidate, "Candidate"), "Leg"));
      fsb = s.work!.parse(fsbBytes, "FSB4", 65536, 16384, { selectors: { activation_source_profile: s.source } });
      s.work!.verify(fsb, s.identityKeys[0]!, { selectors: { activation_source_profile: s.source } });
      for (const name of ["tenant_id", "issuer_key_id", "lease_id", "session_nonce"])
        requireCredential(equalCredential(fsb.encoded(fsb.field(name)), artifact.encoded(artifact.field(name))));
      requireCredential(equalCredential(fsb.bytes("artifact_digest"), s.artifactDigest) && equalCredential(fsb.bytes("candidate_id"), s.candidateID) &&
        equalCredential(fsb.bytes("attempt_id"), s.attemptID) && equalCredential(fsb.bytes("activation_authorization"), s.activation.encoded()) &&
        equalCredential(fsb.bytes("client_certificate"), s.maps[1]!.encoded()) && equalCredential(fsb.bytes("route_digest"), s.routeDigest) &&
        equalCredential(fsb.bytes("transport_context_digest"), s.work!.digest(context, "transport_context_digest")) &&
        equalCredential(fsb.bytes("hello_transcript_digest"), context.bytes("hello_transcript_digest")) &&
        fsb.uint("selected_features") === selected && fsb.uint("binding_mode") === context.uint("binding_mode"));
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
      admissionBinding: binding, issuedAt: activation.uint("issued_at_ms"), activationEnd: s.initiation, sessionEnd: s.sessionEnd, initiationEnd: artifact.uint("initiation_not_after_ms") });
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
    s.revoked = s.changed = undefined; for (const subscription of s.subscriptions) subscription.close(); s.subscriptions.length = 0; s.freshness.clear();
    for (const map of s.maps) map.close(); s.maps.length = 0; s.activation = s.once = undefined;
    for (const bytes of [s.candidateID, s.routeDigest, s.artifactDigest, s.activationDigest, ...s.certificateDigests, s.attemptID, s.psk, s.nonce, ...s.noiseKeys, ...s.identityKeys]) bytes.fill(0);
    for (const e of s.evidence) { e.issuer.fill(0); e.digest.fill(0); e.permissionDigest.fill(0); e.lease?.fill(0); }
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
    s.revoked = () => { deliveryRevoked?.(); callback(); }; if (s.denied !== undefined) s.revoked();
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
 * back between pool and live. Only the selected direct candidate is admitted. */
export function verifyDirectCredentials(config: CredentialVerifierConfig, input: CredentialInput, reservation: ResourceReference): VerifiedCredentialClosure {
  const captured: CredentialVerifierConfig = Object.freeze({ ...config, namespaces: Object.freeze([...config.namespaces]), cryptoProfiles: Object.freeze([...config.cryptoProfiles]) });
  requireCredential(captured.namespaces.length > 0 && captured.namespaces.length <= 8 && captured.cryptoProfiles.length > 0 && captured.cryptoProfiles.every(p => ownProfile(p) !== undefined), "configuration_capacity");
  requireCredential(input.source === "live_authority" || input.source === "preauthorized_pool", "credential_invalid");
  requireCredential(Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16, "credential_invalid");
  const reference = reservation.take(credentialVerifierCharge(config.resources.runtimeBytes));
  let work: CredentialWork | undefined, result: VerifiedCredentialClosure | undefined; const maps: OwnedCredentialMap[] = [];
  try {
    const workRef = config.resources.root.reserve({ owner: credentialOwner(config.resources, "verification_work"), accounts: config.resources.accounts,
      charge: new ResourceVector([270336n + config.resources.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]) });
    try { requireCredential(reference.sameEnvironment(workRef)); work = new CredentialWork(config.resources, 270336, workRef); } finally { workRef.release(); }
    for (const n of captured.namespaces) { requireCredential(isCredentialNamespace(n) && n.clock === config.clock); n.check(reference); }
    const artifact = work.parse(input.artifact, "Artifact", 65536); maps.push(artifact);
    const profile = artifact.text("crypto_profile_id");
    requireCredential(captured.cryptoProfiles.includes(profile) && artifact.text("tenant_id") === captured.tenant && artifact.text("audience") === captured.audience, "credential_untrusted");
    const resolve = (map: OwnedCredentialMap): CredentialNamespace => {
      const matches = captured.namespaces.filter(n => n.matches(map)); requireCredential(matches.length === 1, "credential_untrusted"); return matches[0]!;
    };
    const parentNamespace = resolve(artifact), parent = parentNamespace.verifyCredential(artifact, 1, work);
    checkCredentialTime(config.clock, artifact.uint("issued_at_ms"), artifact.uint("initiation_not_after_ms"));
    const clients: CredentialEvidence[] = [], noiseKeys: Uint8Array[] = [], identityKeys: Uint8Array[] = [];
    for (const [role, bytes] of [input.clientCertificate, input.serverCertificate].entries()) {
      const certificate = work.parse(bytes, "IdentityCertificate", 8192); maps.push(certificate);
      requireCredential(certificate.text("tenant_id") === captured.tenant && certificate.text("audience") === captured.audience && certificate.text("crypto_profile_id") === profile &&
        certificate.text("subject_id") === (role === 0 ? captured.clientSubject : captured.serverSubject) && certificate.uint("role") === BigInt(role), "credential_untrusted");
      checkCredentialTime(config.clock, certificate.uint("issued_at_ms"), certificate.uint("expires_at_ms"));
      const evidence = resolve(certificate).verifyCredential(certificate, 0, work);
      requireCredential(equalCredential(evidence.digest, artifact.bytes(role === 0 ? "client_identity_digest" : "server_identity_digest")));
      const parentPolicy = parent.namespace.policyRequirements(parent), childPolicy = evidence.namespace.policyRequirements(evidence);
      requireCredential(parentPolicy.staleness <= childPolicy.staleness && parentPolicy.signerLifetime <= childPolicy.signerLifetime, "credential_untrusted");
      clients.push(evidence);
      const noise = certificate.field("noise_static_public_key"), noiseKey = certificate.bytes("public_key_bytes", noise, "NoiseStaticPublicKey"), identity = certificate.bytes("ed25519_public_key");
      validateIdentityKey(profile, certificate.uint("algorithm", noise, "NoiseStaticPublicKey"), noiseKey, identity); noiseKeys.push(noiseKey); identityKeys.push(identity);
    }
    const candidates = [...artifact.items("candidates")], candidate = candidates[input.candidateIndex]; requireCredential(candidate !== undefined);
    requireCredential(artifact.uint("path_kind", candidate, "Candidate") === 0n, "credential_untrusted");
    const candidateID = artifact.bytes("candidate_id", candidate, "Candidate"), routeDigest = candidateRouteDigest(artifact, candidate);
    checkClosure(artifact, candidate, [parent.namespace, clients[0]!.namespace, clients[1]!.namespace]);
    const artifactDigest = work.digest(artifact, "artifact_digest");
    const onceBytes = parentNamespace.onceAuthority(parent.issuer), once = work.parse(onceBytes, "OnceAuthorityRef", 412); maps.push(once); onceBytes.fill(0);
    const pendingLive = input.source === "live_authority" && (input.activation === undefined || input.activation.length === 0);
    let activation: OwnedCredentialMap | undefined, activationEvidence: CredentialEvidence | undefined;
    let issued = artifact.uint("issued_at_ms"), initiation = artifact.uint("initiation_not_after_ms"), sessionEnd = artifact.uint("session_not_after_ms");
    if (!pendingLive) {
      requireCredential(input.activation !== undefined, "credential_invalid");
      activation = work.parse(input.activation, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: input.source } }); maps.push(activation);
      const verified = validateActivation(config, work, artifact, activation, parent, once, input.source, input.candidateIndex, artifactDigest, candidateID, routeDigest);
      issued = verified.issued; initiation = verified.initiation; sessionEnd = verified.sessionEnd; activationEvidence = verified.evidence;
    }
    const contract = artifact.field("session_contract"), rekey = artifact.field("rekey_envelope", contract, "SessionContract");
    const state: ClosureState = {
      config: captured, reference, work, maps, activation, once, candidateIndex: input.candidateIndex, evidence: [parent, ...clients, ...(activationEvidence === undefined ? [] : [activationEvidence])],
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
    result = new VerifiedCredentialClosure(token, state); result.checkPreparation(reference); result.attachNamespaces(token); return result;
  } catch (error) { if (result !== undefined) result.close(); else { for (const map of maps) map.close(); work?.close(); reference.release(); } throw error; }
}
function validateActivation(config: CredentialVerifierConfig, work: CredentialWork, artifact: OwnedCredentialMap, activation: OwnedCredentialMap,
  parent: CredentialEvidence, once: OwnedCredentialMap, source: ActivationSource, candidateIndex: number,
  artifactDigest: Uint8Array, candidateID: Uint8Array, routeDigest: Uint8Array): Readonly<{ issued: bigint; initiation: bigint; sessionEnd: bigint; evidence: CredentialEvidence }> {
  for (const [a, b] of [["tenant_id", "tenant_id"], ["artifact_issuer_key_id", "issuer_key_id"], ["lease_id", "lease_id"], ["audience", "audience"],
    ["client_identity_digest", "client_identity_digest"], ["server_identity_digest", "server_identity_digest"]] as const) {
    requireCredential(equalCredential(activation.encoded(activation.field(a)), artifact.encoded(artifact.field(b))));
  }
  requireCredential(equalCredential(activation.bytes("artifact_digest"), artifactDigest));
  const issued = activation.uint("issued_at_ms"), initiation = activation.uint("activation_not_after_ms"), sessionEnd = activation.uint("session_not_after_ms");
  checkCredentialTime(config.clock, issued, initiation);
  requireCredential(issued >= artifact.uint("issued_at_ms") && initiation <= artifact.uint("initiation_not_after_ms") && sessionEnd <= artifact.uint("session_not_after_ms"));
  requireCredential(activation.text("authority_id") === once.text("spend_authority_id"));
  const evidence = parent.namespace.verifyActivation(activation, parent, work);
  checkSelection({ source, candidateIndex }, artifact, activation, artifactDigest, candidateID, routeDigest, once);
  return { issued, initiation, sessionEnd, evidence };
}
function validateIdentityKey(profile: string, algorithm: bigint, noise: Uint8Array, identity: Uint8Array): void {
  const p = ownProfile(profile)!; requireCredential(algorithm === BigInt(p.dh_algorithm));
  const point = ed25519.Point.fromBytes(identity, false); requireCredential(!point.is0() && point.isTorsionFree() && equalCredential(point.toBytes(), identity), "credential_invalid");
  if (algorithm === 0n) {
    const contribution = x25519.getSharedSecret(new Uint8Array(32).fill(0x5a), noise);
    try { requireCredential(contribution.some(x => x !== 0), "credential_invalid"); } finally { contribution.fill(0); }
  } else {
    requireCredential(noise.length === 65 && noise[0] === 4, "credential_invalid"); const point = p256.Point.fromBytes(noise); point.assertValidity(); requireCredential(equalCredential(point.toBytes(false), noise));
  }
}
function candidateRouteDigest(artifact: OwnedCredentialMap, candidate: number): Uint8Array {
  const buffer = new Uint8Array(65536), writer = new FixedCBORWriter(buffer), kind = artifact.uint("path_kind", candidate, "Candidate");
  writer.map(kind === 0n ? 3 : 4).uint(0).uint(kind).uint(1).data(artifact.bytes("candidate_id", candidate, "Candidate"));
  const fields = kind === 0n ? [[2, "direct_leg"]] as const : [[3, "client_leg"], [4, "server_leg"]] as const;
  try {
    for (const [id, field] of fields) writer.uint(id).encoded(artifact.encoded(artifact.field(field, candidate, "Candidate")));
    return credentialDigest("route_digest", writer.result());
  } finally { buffer.fill(0); }
}
function checkClosure(artifact: OwnedCredentialMap, candidate: number, contexts: readonly CredentialNamespace[]): void {
  const references = [...artifact.items("revocation_namespace_refs", candidate, "Candidate")], seen = new Set<CredentialNamespace>();
  for (const node of references) {
    const ns = contexts.find(n => artifact.text("tenant_id", node, "RevocationNamespaceRef") === n.tenant && artifact.text("revocation_authority_id", node, "RevocationNamespaceRef") === n.authority);
    requireCredential(ns !== undefined && !seen.has(ns) && artifact.uint("role_mask", node, "RevocationNamespaceRef") === 3n); ns.checkReference(artifact, node); seen.add(ns);
  }
  requireCredential(contexts.every(n => seen.has(n)));
}
function checkSelection(input: Pick<CredentialInput, "source" | "candidateIndex">, artifact: OwnedCredentialMap, activation: OwnedCredentialMap, artifactDigest: Uint8Array, candidateID: Uint8Array, route: Uint8Array, once: OwnedCredentialMap): void {
  if (input.source === "live_authority") { requireCredential(equalCredential(activation.bytes("candidate_selection"), candidateID) && equalCredential(activation.bytes("route_selection"), route)); return; }
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
    equalCredential(credentialDigest("route_set_digest", writer.result()), activation.bytes("route_selection"))); } finally { buffer.fill(0); }
}
function min(...values: bigint[]): bigint { return values.reduce((a, b) => a < b ? a : b); }
function max(...values: bigint[]): bigint { return values.reduce((a, b) => a > b ? a : b); }
for (const ctor of [VerifiedPoolSpendFacts, VerifiedCredentialClosure, CredentialSessionBinding]) { Object.freeze(ctor.prototype); Object.freeze(ctor); }

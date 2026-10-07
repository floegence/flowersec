import type { TrustedClock } from "./clock.js";
import { TrustedDeadline } from "./deadline.js";
import { TimeError } from "./timeArithmetic.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, requireCredential, equalCredential, checkCredentialTime, type CredentialResources, type OwnedCredentialMap } from "./credentialSupport.js";
import { type CredentialNamespace, type CredentialEvidence, type CredentialNamespaceSubscription, isCredentialNamespace } from "./credentialNamespace.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { wireDomains } from "./schemaRegistry.js";
import { verifyEd25519 } from "./ed25519.js";
import type { ReadyIdentitySigner } from "./noiseHandshake.js";

export interface RelayCredentialConfig {
  readonly resources: CredentialResources;
  readonly clock: TrustedClock;
  readonly namespaces: readonly CredentialNamespace[];
  readonly tenant: string;
  readonly audience: string;
  readonly service: string;
  readonly endpointSubject: string;
  readonly relaySubject: string;
  readonly cryptoProfiles: readonly string[];
}
export interface RelayCredentialInput {
  readonly grant: Uint8Array;
  readonly endpointCertificate: Uint8Array;
  readonly relayCertificate: Uint8Array;
}
export interface RelayLimits {
  readonly envelopeBytes: bigint; readonly totalBytes: bigint; readonly datagramBytes: bigint;
  readonly rateBytesPerSecond: bigint; readonly queueBytes: bigint;
  readonly pendingMappings: bigint; readonly residentMappings: bigint; readonly totalMappings: bigint; readonly queueItems: bigint;
}
export interface RelayClaimFields {
  readonly tenant: string; readonly audience: string; readonly endpointAudience: string; readonly profile: string; readonly service: string;
  readonly parentAuthority: string; readonly parentPolicy: string;
  readonly issuer: Uint8Array; readonly lease: Uint8Array; readonly artifact: Uint8Array; readonly parentCapacity: Uint8Array;
  readonly attempt: Uint8Array; readonly candidate: Uint8Array; readonly pairing: Uint8Array; readonly leg: Uint8Array;
  readonly grantID: Uint8Array; readonly grantDigest: Uint8Array; readonly route: Uint8Array; readonly contract: Uint8Array;
  readonly identities: readonly Uint8Array[]; readonly relayIdentity: Uint8Array; readonly relayIncarnation: Uint8Array;
  readonly parentGeneration: bigint; readonly parentCohort: bigint; readonly parentPolicyRevision: bigint;
  readonly parentIssuedAt: bigint; readonly parentInitiationEnd: bigint; readonly parentSessionEnd: bigint;
  readonly generation: bigint; readonly cohort: bigint; readonly issuedAt: bigint; readonly notAfter: bigint;
  readonly endpointRole: 0 | 1; readonly possession: Uint8Array; readonly challenge: Uint8Array; readonly limits: RelayLimits;
}
export function relayCredentialCharge(runtimeBytes: bigint): ResourceVector {
  requireCredential(runtimeBytes > 0n, "configuration_capacity");
  return new ResourceVector([262144n + runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]);
}
/** Original relay verification backing and namespace positions prepared before
 * a source can issue or remove a once-only parent lease. */
export class RelayCredentialPreparation {
  #reference: ResourceReference | undefined; #work: CredentialWork | undefined;
  readonly #subscriptions = new Map<CredentialNamespace, CredentialNamespaceSubscription>();
  constructor(resources: CredentialResources, namespaces: readonly CredentialNamespace[]) {
    requireCredential(namespaces.length > 0 && namespaces.length <= 8 && namespaces.every(isCredentialNamespace), "configuration_capacity");
    const refs = resources.root.reserveBatch([relayCredentialCharge(resources.runtimeBytes), credentialWorkCharge(65536, resources.runtimeBytes)].map((charge, index) => ({ owner: credentialOwner(resources, `relay_preparation_${index}`), accounts: resources.accounts, charge })));
    try {
      this.#reference = refs[0]!.take(relayCredentialCharge(resources.runtimeBytes)); this.#work = new CredentialWork(resources, 65536, refs[1]!);
      this.#work.prepaySignatures(65536, 32768); this.#work.prepayParsers(65536, 32768, 4);
      for (const namespace of namespaces) this.#subscriptions.set(namespace, namespace.reserveSubscription(this.#reference)); Object.freeze(this);
    } catch (error) { this.close(); throw error; } finally { for (const ref of refs) ref.release(); }
  }
  take(namespaces: readonly CredentialNamespace[]): Readonly<{ reference: ResourceReference; work: CredentialWork; subscriptions: Map<CredentialNamespace, CredentialNamespaceSubscription> }> {
    requireCredential(this.#reference !== undefined && this.#work !== undefined && namespaces.length === this.#subscriptions.size && namespaces.every(namespace => this.#subscriptions.has(namespace)));
    this.#reference.check(); this.#work.check(); for (const subscription of this.#subscriptions.values()) subscription.check();
    const result = { reference: this.#reference, work: this.#work, subscriptions: new Map(this.#subscriptions) }; this.#reference = undefined; this.#work = undefined; this.#subscriptions.clear(); return Object.freeze(result);
  }
  close(): void { for (const subscription of this.#subscriptions.values()) subscription.close(); this.#subscriptions.clear(); this.#work?.close(); this.#work = undefined; this.#reference?.release(); this.#reference = undefined; }
}
const capability = Symbol("original verified relay claim"), owners = new WeakSet<VerifiedRelayCredentials>(), claims = new WeakSet<VerifiedRelayClaim>();
function copyFields(fields: RelayClaimFields): RelayClaimFields {
  const output = { ...fields, limits: Object.freeze({ ...fields.limits }), identities: Object.freeze(fields.identities.map(value => new Uint8Array(value))) };
  for (const [key, value] of Object.entries(output)) if (value instanceof Uint8Array) Object.assign(output, { [key]: new Uint8Array(value) });
  return Object.freeze(output);
}
/** Endpoint possession on the original physical challenge. Durable claims,
 * pairing and relay proof publication remain separate once boundaries. */
export class VerifiedRelayClaim {
  #reference: ResourceReference | undefined;
  readonly #fields: RelayClaimFields;
  constructor(token: symbol, private readonly owner: VerifiedRelayCredentials, fields: RelayClaimFields, reference: ResourceReference) {
    requireCredential(token === capability, "credential_untrusted"); this.#fields = copyFields(fields); this.#reference = reference; claims.add(this); Object.freeze(this);
  }
  check(reference?: ResourceReference): void { requireCredential(this.#reference !== undefined, "credential_closed"); this.owner.check(reference ?? this.#reference); }
  belongsTo(owner: VerifiedRelayCredentials, reference: ResourceReference): boolean { this.check(reference); return this.owner === owner; }
  fields(reference: ResourceReference): RelayClaimFields { this.check(reference); return copyFields(this.#fields); }
  grant(reference: ResourceReference): Uint8Array { this.check(reference); return this.owner.grant(reference); }
  parentReference(reference: ResourceReference): Uint8Array { this.check(reference); return this.owner.parentReference(reference); }
  close(): void { const reference = this.#reference; if (reference === undefined) return; this.#reference = undefined; for (const value of Object.values(this.#fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of this.#fields.identities) value.fill(0); reference.release(); this.owner.releaseClaim(capability); }
  toJSON(): object { return {}; }
}
export function isVerifiedRelayCredentials(value: unknown): value is VerifiedRelayCredentials { return value instanceof VerifiedRelayCredentials && owners.has(value); }
export function isVerifiedRelayClaim(value: unknown): value is VerifiedRelayClaim { return value instanceof VerifiedRelayClaim && claims.has(value); }

/** Owns only public leg material and independently trusted parent facts.
 * No Artifact, PSK, opposite-hop roots or e2e keys enter the relay owner. */
export class VerifiedRelayCredentials {
  readonly deadline: TrustedDeadline;
  readonly role: 0 | 1;
  readonly #reference: ResourceReference;
  readonly #work: CredentialWork;
  readonly #maps: readonly [OwnedCredentialMap, OwnedCredentialMap, OwnedCredentialMap];
  readonly #evidence: readonly CredentialEvidence[];
  readonly #config: RelayCredentialConfig;
  readonly #subscriptions: CredentialNamespaceSubscription[] = [];
  readonly #freshness = new Map<CredentialNamespace, { generation: bigint; sequence: bigint; deadline: TrustedDeadline }>();
  #closed = false; #cleaned = false; #claimCount = 0; #claimBound = false; #denied: unknown; #revoked: ((error: unknown) => void) | undefined;
  constructor(token: symbol, config: RelayCredentialConfig, maps: readonly [OwnedCredentialMap, OwnedCredentialMap, OwnedCredentialMap], evidence: readonly CredentialEvidence[], work: CredentialWork, reference: ResourceReference) {
    requireCredential(token === capability, "credential_untrusted"); this.#config = config; this.#maps = maps; this.#evidence = evidence; this.#work = work; this.#reference = reference;
    this.role = Number(maps[1].uint("role")) as 0 | 1;
    this.deadline = new TrustedDeadline(config.clock, evidence.reduce((end, item) => item.expires < end ? item.expires : end, evidence[0]!.expires)); owners.add(this);
    Object.freeze(this);
  }
  attach(token: symbol, prepared?: Map<CredentialNamespace, CredentialNamespaceSubscription>): void {
    requireCredential(token === capability);
    const namespaces = [...new Set(this.#evidence.map(value => value.namespace))];
    try {
      for (const namespace of namespaces) {
        const subscription = prepared === undefined ? namespace.reserveSubscription(this.#reference) : prepared.get(namespace); requireCredential(subscription !== undefined); prepared?.delete(namespace);
        this.#subscriptions.push(subscription); subscription.attach(namespace, this.#reference, () => {
          if (this.#closed || this.#denied !== undefined) return;
          try { this.check(); } catch (error) {
            if (error instanceof TimeError && ["time_unavailable", "time_continuity", "time_pending"].includes(error.code)) return;
            this.#denied = error; this.#revoked?.(error);
          }
        });
      }
      this.check();
    } catch (error) { this.close(); throw error; }
  }
  onRevoked(callback: (error: unknown) => void): void {
    requireCredential(!this.#closed && this.#revoked === undefined && typeof callback === "function"); this.#revoked = callback;
    if (this.#denied !== undefined) callback(this.#denied);
  }
  check(reference: ResourceReference = this.#reference): void {
    if (this.#denied !== undefined) throw this.#denied;
    requireCredential(!this.#closed && reference.sameEnvironment(this.#reference), "credential_closed"); this.#reference.check(); reference.check(); this.deadline.check();
    const parentPolicy = this.#evidence[0]!.namespace.policyRequirements(this.#evidence[0]!);
    for (const item of this.#evidence) {
      item.namespace.checkEvidence(item); item.namespace.checkPolicy(parentPolicy.staleness, parentPolicy.signerLifetime);
      const [generation, sequence] = item.namespace.activeVersion(), end = item.namespace.availableUntil(parentPolicy.staleness), previous = this.#freshness.get(item.namespace);
      previous?.deadline.check();
      if (previous?.generation !== generation || previous.sequence !== sequence) this.#freshness.set(item.namespace, { generation, sequence, deadline: new TrustedDeadline(this.#config.clock, end) });
      else if (end < previous.deadline.cap) previous.deadline.tighten(end);
    }
    for (const subscription of this.#subscriptions) subscription.check(); this.deadline.check();
  }
  grant(reference: ResourceReference): Uint8Array { this.check(reference); return this.#maps[0].encoded(); }
  grantDigest(reference: ResourceReference): Uint8Array { this.check(reference); return new Uint8Array(this.#evidence[2]!.digest); }
  parentReference(reference: ResourceReference): Uint8Array { this.check(reference); const grant = this.#maps[0]; return grant.encoded(grant.field("parent_ref")); }
  certificate(role: "endpoint" | "relay", reference: ResourceReference): Uint8Array { this.check(reference); return this.#maps[role === "endpoint" ? 1 : 2].encoded(); }
  descriptor(reference: ResourceReference): Uint8Array { this.check(reference); const grant = this.#maps[0], route = grant.field("route_descriptor"); return grant.encoded(grant.field(this.role === 0 ? "client_leg" : "server_leg", route, "Route")); }
  limits(reference: ResourceReference): RelayLimits {
    this.check(reference); const grant = this.#maps[0], limits = grant.field("limits"), read = (name: string) => grant.uint(name, limits, "GrantLimits");
    return Object.freeze({ envelopeBytes: read("max_envelope_bytes"), totalBytes: read("max_total_bytes"), datagramBytes: read("max_datagram_bytes"), rateBytesPerSecond: read("max_rate_bytes_per_s"), queueBytes: read("max_queue_bytes"), pendingMappings: read("max_pending_native_mappings"), residentMappings: read("max_resident_native_mappings"), totalMappings: read("max_total_native_mappings"), queueItems: read("max_queue_items") });
  }
  possessionMessage(contextBytes: Uint8Array, role: 0 | 1 | 2, reference: ResourceReference): Uint8Array {
    this.check(reference); const grant = this.#maps[0], context = this.#work.parse(contextBytes, "HopChallengeContext", 129, 128);
    try {
      const route = grant.field("route_descriptor"), leg = grant.field(this.role === 0 ? "client_leg" : "server_leg", route, "Route");
      requireCredential(equalCredential(context.bytes("leg_id"), grant.bytes("leg_id", leg, "Leg")) && context.uint("dialer_role") === grant.uint("dialer_role", leg, "Leg") &&
        context.uint("listener_role") === grant.uint("listener_role", leg, "Leg") && (context.uint("dialer_role") === BigInt(role) || context.uint("listener_role") === BigInt(role)) && (role === 2 || role === this.role));
      const domain = wireDomains.find(value => value.name === "grant_possession"); requireCredential(domain?.operation === "ed25519");
      const label = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(value => Number.parseInt(value, 16)));
      const fields = [this.#evidence[2]!.digest, grant.bytes("route_digest"), context.bytes("leg_id"), grant.bytes("pairing_id"), contextBytes];
      const output = new Uint8Array(label.length + fields.reduce((n, value) => n + 4 + value.length, 0) + 1); output.set(label); let at = label.length;
      for (const field of fields) { new DataView(output.buffer).setUint32(at, field.length); at += 4; output.set(field, at); at += field.length; } output[at] = role; return output;
    } finally { context.close(); }
  }
  signPossession(context: Uint8Array, role: 0 | 1 | 2, signer: ReadyIdentitySigner, reference: ResourceReference): Uint8Array {
    this.check(reference); const key = this.#maps[role === 2 ? 2 : 1].bytes("ed25519_public_key"), message = this.possessionMessage(context, role, reference);
    try { requireCredential(equalCredential(key, signer.publicKey)); const proof = signer.sign(message); requireCredential(proof instanceof Uint8Array && proof.length === 64 && verifyEd25519(proof, message, key)); return new Uint8Array(proof); }
    finally { key.fill(0); message.fill(0); }
  }
  verifyPossession(context: Uint8Array, role: 0 | 1 | 2, proof: Uint8Array, reference: ResourceReference): void {
    const message = this.possessionMessage(context, role, reference), key = this.#maps[role === 2 ? 2 : 1].bytes("ed25519_public_key");
    try { requireCredential(verifyEd25519(proof, message, key)); this.check(reference); } finally { message.fill(0); key.fill(0); }
  }
  bindClaim(contextBytes: Uint8Array, endpointProof: Uint8Array, reference: ResourceReference): VerifiedRelayClaim {
    this.check(reference); requireCredential(!this.#claimBound); this.verifyPossession(contextBytes, this.role, endpointProof, reference);
    const context = this.#work.parse(contextBytes, "HopChallengeContext", 129, 128), grant = this.#maps[0], parent = grant.field("parent_ref"), route = grant.field("route_descriptor"), namespace = grant.field("namespace");
    try {
      const parentRead = (name: string) => grant.uint(name, parent, "GrantParentRef"), ids = [...grant.items("identity_digests")].map(node => { const bytes = new Uint8Array(grant.doc.size(node)); grant.doc.copyPayload(node, bytes); return bytes; });
      const fields: RelayClaimFields = { tenant: this.#config.tenant, audience: grant.text("audience"), endpointAudience: this.#maps[1].text("audience"), profile: this.#maps[1].text("crypto_profile_id"), service: grant.text("service"),
        parentAuthority: grant.text("revocation_authority_id", parent, "GrantParentRef"), parentPolicy: grant.text("revocation_policy_id", parent, "GrantParentRef"),
        issuer: grant.bytes("artifact_issuer_key_id", parent, "GrantParentRef"), lease: grant.bytes("lease_id", parent, "GrantParentRef"), artifact: grant.bytes("artifact_digest", parent, "GrantParentRef"), parentCapacity: grant.bytes("namespace_capacity_digest", parent, "GrantParentRef"),
        attempt: grant.bytes("attempt_id"), candidate: grant.bytes("candidate_id", route, "Route"), pairing: grant.bytes("pairing_id"), leg: context.bytes("leg_id"), grantID: grant.bytes("grant_id"), grantDigest: new Uint8Array(this.#evidence[2]!.digest), route: grant.bytes("route_digest"), contract: grant.bytes("session_contract_digest"), identities: ids, relayIdentity: new Uint8Array(this.#evidence[3]!.digest),
        relayIncarnation: context.bytes(context.uint("dialer_role") === 2n ? "dialer_incarnation" : "listener_incarnation"), parentGeneration: parentRead("authority_generation"), parentCohort: parentRead("revocation_epoch"), parentPolicyRevision: parentRead("revocation_policy_revision"), parentIssuedAt: parentRead("issued_at_ms"), parentInitiationEnd: parentRead("initiation_not_after_ms"), parentSessionEnd: parentRead("session_not_after_ms"),
        generation: grant.uint("generation", namespace, "GrantNamespace"), cohort: grant.uint("revocation_epoch", namespace, "GrantNamespace"), issuedAt: grant.uint("issued_at_ms"), notAfter: grant.uint("not_after_ms"), endpointRole: this.role, possession: new Uint8Array(endpointProof), challenge: new Uint8Array(contextBytes), limits: this.limits(reference) };
      const claim = new VerifiedRelayClaim(capability, this, fields, this.#reference.borrow()); this.#claimCount++; this.#claimBound = true;
      for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of ids) value.fill(0); return claim;
    } finally { context.close(); }
  }
  releaseClaim(token: symbol): void { requireCredential(token === capability && this.#claimCount > 0); this.#claimCount--; this.#cleanup(); }
  close(): void { if (this.#closed) return; this.#closed = true; this.#revoked = undefined; for (const subscription of this.#subscriptions) subscription.close(); this.#cleanup(); }
  #cleanup(): void { if (!this.#closed || this.#claimCount !== 0 || this.#cleaned) return; this.#cleaned = true; for (const map of this.#maps) map.close(); this.#work.close(); this.#reference.release(); }
  cleanupComplete(): boolean { return this.#cleaned; }
  toJSON(): object { return {}; }
}
export function verifyRelayCredentials(config: RelayCredentialConfig, input: RelayCredentialInput, reservation: ResourceReference | RelayCredentialPreparation): VerifiedRelayCredentials {
  const captured = Object.freeze({ ...config, namespaces: Object.freeze([...config.namespaces]), cryptoProfiles: Object.freeze([...config.cryptoProfiles]) });
  requireCredential(captured.namespaces.length > 0 && captured.namespaces.length <= 8 && captured.namespaces.every(value => isCredentialNamespace(value) && value.clock === config.clock), "configuration_capacity");
  const prepared = reservation instanceof RelayCredentialPreparation ? reservation.take(captured.namespaces) : undefined;
  const reference = (prepared?.reference ?? reservation as ResourceReference).take(relayCredentialCharge(config.resources.runtimeBytes)); let work: CredentialWork | undefined = prepared?.work, owner: VerifiedRelayCredentials | undefined; const maps: OwnedCredentialMap[] = [];
  try {
    if (work === undefined) {
      const workRef = config.resources.root.reserve({ owner: credentialOwner(config.resources, "relay_verification"), accounts: config.resources.accounts, charge: credentialWorkCharge(65536, config.resources.runtimeBytes) });
      try { requireCredential(reference.sameEnvironment(workRef)); work = new CredentialWork(config.resources, 65536, workRef); work.prepaySignatures(65536, 32768); work.prepayParsers(65536, 32768, 4); } finally { workRef.release(); }
    }
    requireCredential(work.sameEnvironment(reference));
    const grant = work.parse(input.grant, "Grant", 65536); maps.push(grant);
    const endpoint = work.parse(input.endpointCertificate, "IdentityCertificate", 8192); maps.push(endpoint);
    const relay = work.parse(input.relayCertificate, "IdentityCertificate", 8192); maps.push(relay);
    const resolve = (map: OwnedCredentialMap): CredentialNamespace => { const matches = captured.namespaces.filter(value => value.matches(map)); requireCredential(matches.length === 1, "credential_untrusted"); return matches[0]!; };
    const role = endpoint.uint("role"), profile = endpoint.text("crypto_profile_id"), namespace = grant.field("namespace"), parent = grant.field("parent_ref");
    requireCredential(role <= 1n && grant.text("tenant_id") === captured.tenant && endpoint.text("tenant_id") === captured.tenant && relay.text("tenant_id") === captured.tenant &&
      grant.text("audience") === captured.audience && relay.text("audience") === captured.audience && grant.text("service") === captured.service &&
      endpoint.text("subject_id") === captured.endpointSubject && relay.text("subject_id") === captured.relaySubject && relay.uint("role") === 2n &&
      captured.cryptoProfiles.includes(profile) && relay.text("crypto_profile_id") === profile && grant.uint("role_mask", namespace, "GrantNamespace") === (4n | 1n << role), "credential_untrusted");
    const grantEvidence = resolve(grant).verifyCredential(grant, 2, work), endpointEvidence = resolve(endpoint).verifyCredential(endpoint, 0, work), relayEvidence = resolve(relay).verifyCredential(relay, 0, work);
    const parentNamespaces = captured.namespaces.filter(value => value.tenant === grant.text("tenant_id", parent, "GrantParentRef") && value.authority === grant.text("revocation_authority_id", parent, "GrantParentRef"));
    requireCredential(parentNamespaces.length === 1, "credential_untrusted"); const parentEvidence = parentNamespaces[0]!.verifyGrantParent(grant, endpoint.text("audience"), profile, work);
    const ids = [...grant.items("identity_digests")], expected = new Uint8Array(32); grant.doc.copyPayload(ids[Number(role)]!, expected);
    requireCredential(equalCredential(expected, endpointEvidence.digest) && equalCredential(grant.bytes("relay_identity_digest"), relayEvidence.digest)); expected.fill(0);
    checkCredentialTime(config.clock, grant.uint("issued_at_ms"), grant.uint("not_after_ms")); checkCredentialTime(config.clock, grant.uint("issued_at_ms", parent, "GrantParentRef"), grant.uint("initiation_not_after_ms", parent, "GrantParentRef"));
    const parentPolicy = parentEvidence.namespace.policyRequirements(parentEvidence);
    for (const evidence of [endpointEvidence, grantEvidence, relayEvidence]) { const policy = evidence.namespace.policyRequirements(evidence); requireCredential(parentPolicy.staleness <= policy.staleness && parentPolicy.signerLifetime <= policy.signerLifetime, "credential_untrusted"); }
    owner = new VerifiedRelayCredentials(capability, captured, [grant, endpoint, relay], [parentEvidence, endpointEvidence, grantEvidence, relayEvidence], work, reference); owner.attach(capability, prepared?.subscriptions); return owner;
  } catch (error) { if (owner !== undefined) owner.close(); else { for (const map of maps) map.close(); work?.close(); reference.release(); } throw error; } finally { for (const subscription of prepared?.subscriptions.values() ?? []) subscription.close(); prepared?.subscriptions.clear(); }
}

for (const constructor of [VerifiedRelayCredentials, VerifiedRelayClaim, RelayCredentialPreparation]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

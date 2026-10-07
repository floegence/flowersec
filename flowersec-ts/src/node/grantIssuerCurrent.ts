import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency } from "../v4/runtime/environment.js";
import type { CredentialNamespace} from "../v4/runtime/credentialNamespace.js";
import { isCredentialNamespace, type CredentialEvidence } from "../v4/runtime/credentialNamespace.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, credentialDigest, requireCredential, equalCredential, checkCredentialTime, type OwnedCredentialMap } from "../v4/runtime/credentialSupport.js";
import { verifyDirectCredentials, credentialVerifierCharge, validateActivation, validateActivationIssuance, validateIdentityKey, candidateRouteBytes, TunnelCredentialPreparation, type CredentialVerifierConfig, type CredentialInput, type VerifiedCredentialClosure } from "../v4/runtime/credentialVerifier.js";
import { verifyRelayCredentials, RelayCredentialPreparation, type VerifiedRelayCredentials, type RelayLimits } from "../v4/runtime/relayCredentials.js";
import { SignedMapCodec, signedMapCodecCharge, SoftwareSigningKey, softwareSigningKeyCharge } from "../v4/runtime/signedMap.js";
import { cborDecoderCharge } from "../v4/runtime/cbor.js";
import { FixedCBORWriter } from "../v4/runtime/cborWriter.js";
import { wireMaps } from "../v4/runtime/schemaRegistry.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { TrustedDeadline } from "../v4/runtime/deadline.js";
import { isOriginalLiveGrantTransaction, type OriginalLiveGrantTransaction } from "./liveTunnelAuthorityCurrent.js";
import { SQLiteAdmissionStore } from "./sqliteAdmission.js";
import { isOriginalRegisteredGrantPublication, type RegisteredTunnelControlAuthority } from "./registeredTunnelControl.js";

export interface GrantIssuerSigningPolicy {
  readonly namespace: CredentialNamespace;
  readonly issuerKeyID: Uint8Array;
  readonly seed: Uint8Array;
  readonly revocationPolicyID: string;
  readonly revocationPolicyRevision: bigint;
}
/** Local authority configuration. The configured route and forwarding limits
 * are independently trusted deployment policy, never received Grant claims. */
export interface GrantIssuerOptions {
  readonly environment: V4TransportEnvironment;
  readonly credentials: Omit<CredentialVerifierConfig, "resources" | "clock" | "tunnel">;
  readonly relayAudience: string; readonly relaySubject: string; readonly service: string;
  readonly routeDigest: Uint8Array;
  readonly signing: readonly [GrantIssuerSigningPolicy, GrantIssuerSigningPolicy];
  readonly limits: RelayLimits;
  readonly maxLifetimeMS: bigint; readonly transactionMS: bigint;
  readonly activationStore: SQLiteAdmissionStore;
}
export interface GrantIssuanceInput extends Omit<CredentialInput, "tunnel"> {
  readonly activation: Uint8Array;
  readonly relayCertificate: Uint8Array;
}
const issuerCapability = Symbol("original configured Grant issuer"), issuances = new WeakSet<OriginalGrantIssuance>();
/** The original signing transaction owns these verified materials. Imported
 * credentials and a successful lookup cannot construct this capability. */
export class OriginalGrantIssuance {
  readonly #issuer: GrantIssuer; readonly #closure: VerifiedCredentialClosure;
  readonly #legs: readonly [VerifiedRelayCredentials, VerifiedRelayCredentials];
  #closed = false;
  constructor(token: symbol, issuer: GrantIssuer, closure: VerifiedCredentialClosure, legs: readonly [VerifiedRelayCredentials, VerifiedRelayCredentials]) {
    requireCredential(token === issuerCapability); this.#issuer = issuer; this.#closure = closure; this.#legs = legs; issuances.add(this); Object.freeze(this);
  }
  check(reference: ResourceReference): void { requireCredential(!this.#closed, "credential_closed"); this.#issuer.check(reference); this.#closure.checkPreparation(reference); for (const leg of this.#legs) leg.check(reference); }
  original(reference: ResourceReference): Readonly<{ closure: VerifiedCredentialClosure; legs: readonly [VerifiedRelayCredentials, VerifiedRelayCredentials] }> {
    this.check(reference); return Object.freeze({ closure: this.#closure, legs: this.#legs });
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#closure.close(); for (const leg of this.#legs) leg.close(); }
  toJSON(): object { return {}; }
}
export function isOriginalGrantIssuance(value: unknown): value is OriginalGrantIssuance { return value instanceof OriginalGrantIssuance && issuances.has(value); }
type MapValue = string | bigint | Uint8Array | Readonly<{ encoded: Uint8Array }>;
export function encodeCredentialMap(buffer: Uint8Array, schema: string, fields: Readonly<Record<string, MapValue>>): Uint8Array {
  const spec = wireMaps[schema]; requireCredential(spec !== undefined);
  const entries = Object.entries(spec.fields).filter(([, field]) => field.name !== undefined && Object.hasOwn(fields, field.name));
  requireCredential(entries.length === Object.keys(fields).length);
  const writer = new FixedCBORWriter(buffer).map(entries.length);
  for (const [id, field] of entries) {
    writer.uint(Number(id)); const value = fields[field.name!]!;
    if (typeof value === "bigint") writer.uint(value);
    else if (typeof value === "string") { const encoded = new TextEncoder().encode(value); try { writer.data(encoded, true); } finally { encoded.fill(0); } }
    else if (value instanceof Uint8Array) writer.data(value);
    else writer.encoded(value.encoded);
  }
  return new Uint8Array(writer.result());
}
function clearEvidence(evidence: CredentialEvidence): void { for (const bytes of [evidence.issuer, evidence.digest, evidence.permissionDigest, evidence.lease, evidence.grant]) bytes?.fill(0); }
function arrayBytes(buffer: Uint8Array, items: readonly Uint8Array[], encoded = false): Uint8Array {
  const writer = new FixedCBORWriter(buffer).array(items.length); for (const item of items) { if (encoded) writer.encoded(item); else writer.data(item); } return new Uint8Array(writer.result());
}
/** Issues both roles under original namespace permission, then durably records
 * their exact signed material before returning any Grant to a caller. */
export class GrantIssuer {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #options: Omit<GrantIssuerOptions, "signing">;
  readonly #policies: readonly [Omit<GrantIssuerSigningPolicy, "seed">, Omit<GrantIssuerSigningPolicy, "seed">];
  readonly #keys: readonly [SoftwareSigningKey, SoftwareSigningKey]; readonly #dependency: EnvironmentDependency;
  #closed = false; #busy = false; #released = false;
  constructor(token: symbol, input: GrantIssuerOptions) {
    requireCredential(token === issuerCapability); this.#runtime = originalEnvironment(input.environment);
    requireCredential(input.activationStore instanceof SQLiteAdmissionStore && input.routeDigest instanceof Uint8Array && input.routeDigest.length === 32 && input.routeDigest.some(byte => byte !== 0) &&
      typeof input.maxLifetimeMS === "bigint" && input.maxLifetimeMS > 0n && input.maxLifetimeMS <= 604800000n && typeof input.transactionMS === "bigint" && input.transactionMS > 0n && input.transactionMS <= 60000n &&
      input.credentials.namespaces.length > 0 && input.credentials.namespaces.length <= 8 && input.signing.length === 2 && [input.relayAudience, input.relaySubject, input.service].every(value => typeof value === "string" && value.length > 0 && value.length <= 1024), "configuration_capacity");
    for (const policy of input.signing) requireCredential(isCredentialNamespace(policy.namespace) && input.credentials.namespaces.includes(policy.namespace) && policy.namespace.clock === this.#runtime.clock &&
      policy.issuerKeyID instanceof Uint8Array && policy.issuerKeyID.length === 16 && policy.seed instanceof Uint8Array && policy.seed.length === 32 && typeof policy.revocationPolicyID === "string" && policy.revocationPolicyID.length > 0 && policy.revocationPolicyID.length <= 1024 &&
      typeof policy.revocationPolicyRevision === "bigint" && policy.revocationPolicyRevision >= 0n && policy.revocationPolicyRevision <= 0xffffffffffffffffn, "configuration_capacity");
    for (const value of Object.values(input.limits)) requireCredential(typeof value === "bigint" && value >= 0n && value <= 0xffffffffffffffffn, "configuration_capacity");
    const keyConfig = { schemas: ["Grant"], runtimeBytes: this.#runtime.resources.runtimeBytes }, keys: SoftwareSigningKey[] = [];
    const dependency = this.#runtime.admitDependency("grant_issuer", new ResourceVector([65536n + this.#runtime.resources.runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    const references: ResourceReference[] = [];
    try {
      references.push(...this.#runtime.resources.root.reserveBatch([0, 1].map(side => ({ owner: credentialOwner(this.#runtime.resources, `grant_issuer_key_${side}`), accounts: this.#runtime.resources.accounts, charge: softwareSigningKeyCharge(keyConfig) }))));
      for (const [side, policy] of input.signing.entries()) { policy.namespace.check(dependency.reference); keys.push(new SoftwareSigningKey(keyConfig, policy.seed, references[side]!)); }
      this.#keys = Object.freeze(keys) as unknown as readonly [SoftwareSigningKey, SoftwareSigningKey]; this.#dependency = dependency;
      this.#policies = Object.freeze(input.signing.map(policy => Object.freeze({ namespace: policy.namespace, issuerKeyID: new Uint8Array(policy.issuerKeyID), revocationPolicyID: policy.revocationPolicyID, revocationPolicyRevision: policy.revocationPolicyRevision }))) as unknown as readonly [Omit<GrantIssuerSigningPolicy, "seed">, Omit<GrantIssuerSigningPolicy, "seed">];
      const credentials = Object.freeze({ ...input.credentials, namespaces: Object.freeze([...input.credentials.namespaces]), cryptoProfiles: Object.freeze([...input.credentials.cryptoProfiles]) });
      this.#options = Object.freeze({ environment: input.environment, credentials, relayAudience: input.relayAudience, relaySubject: input.relaySubject, service: input.service, routeDigest: new Uint8Array(input.routeDigest), limits: Object.freeze({ ...input.limits }), maxLifetimeMS: input.maxLifetimeMS, transactionMS: input.transactionMS, activationStore: input.activationStore });
      dependency.onClose(() => this.close()); Object.freeze(this);
    } catch (error) { for (const key of keys) key.close(); dependency.release(); throw error; } finally { for (const reference of references) reference.release(); }
  }
  check(reference?: ResourceReference): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); if (reference !== undefined) requireCredential(reference.sameEnvironment(this.#dependency.reference), "credential_binding"); }
  issue(input: GrantIssuanceInput): Promise<Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>> { if (input.source !== "preauthorized_pool") throw new Error("original_live_authority_required"); return this.#issue(input); }
  /** @internal Original live authority continuation. */
  issueOriginalLive(input: GrantIssuanceInput, transaction: OriginalLiveGrantTransaction): Promise<Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>> {
    requireCredential(isOriginalLiveGrantTransaction(transaction) && transaction.belongsTo(this) && input.source === "live_authority", "credential_binding");
    return this.#issue(input, transaction);
  }
  /** @internal Original registered pool publication continuation. */
  issueOriginalRegistered(input: GrantIssuanceInput, publication: RegisteredTunnelControlAuthority): Promise<Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>> {
    requireCredential(input.source === "preauthorized_pool" && isOriginalRegisteredGrantPublication(publication, this), "credential_binding");
    return this.#issue(input, undefined, publication);
  }
  async #issue(input: GrantIssuanceInput, transaction?: OriginalLiveGrantTransaction, publication?: RegisteredTunnelControlAuthority): Promise<Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>> {
    this.check(); if (this.#busy) throw new Error("credential_busy"); this.#busy = true;
    const runtime = this.#runtime, options = this.#options, decoder = { bytes: 65536, nodes: 16384, textBytes: 4096, arrayItems: 16384, runtimeBytes: runtime.resources.runtimeBytes }, codecConfig = { schema: "Grant", decoder, runtimeBytes: runtime.resources.runtimeBytes };
    const references: ResourceReference[] = [], maps: OwnedCredentialMap[] = [], evidence: CredentialEvidence[] = [], bytes: Uint8Array[] = [], preparations: RelayCredentialPreparation[] = [];
    let guardReference: ResourceReference | undefined;
    let work: CredentialWork | undefined, codec: SignedMapCodec | undefined, closurePreparation: TunnelCredentialPreparation | undefined, closure: VerifiedCredentialClosure | undefined, issuance: OriginalGrantIssuance | undefined;
    const activationBacking = new Uint8Array(4096); bytes.push(activationBacking);
    const legs: VerifiedRelayCredentials[] = []; let scratch: Uint8Array | undefined;
    try {
      requireCredential(input.source === "live_authority" || input.source === "preauthorized_pool");
      requireCredential(Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16);
      const config: CredentialVerifierConfig = { ...options.credentials, resources: runtime.resources, clock: runtime.clock, tunnel: { role: 0, audience: options.relayAudience, service: options.service, relaySubject: options.relaySubject } };
      references.push(...runtime.resources.root.reserveBatch([credentialWorkCharge(524288, runtime.resources.runtimeBytes), cborDecoderCharge(decoder), signedMapCodecCharge(codecConfig), credentialVerifierCharge(runtime.resources.runtimeBytes), options.activationStore.relayCharge()].map((charge, index) => ({ owner: credentialOwner(runtime.resources, `grant_issuance_${index}`), accounts: runtime.resources.accounts, charge }))));
      // CredentialWork takes the primary reservation. Retain an alias from its
      // moved reservation for repeated transaction guard checks.
      work = new CredentialWork(runtime.resources, 524288, references[0]!);
      guardReference = work.borrowReference();
      work.prepayParsers(65536, 16384, 8); work.prepaySignatures(65536, 16384);
      codec = new SignedMapCodec(codecConfig, references[1]!, references[2]!); scratch = new Uint8Array(65536);
      closurePreparation = new TunnelCredentialPreparation(config);
      for (let side = 0; side < 2; side++) preparations.push(new RelayCredentialPreparation(runtime.resources, config.namespaces));
      const parse = (raw: Uint8Array, schema: string, cap: number): OwnedCredentialMap => { const map = work!.parse(raw, schema, cap, 16384, schema === "ActivationAuthorization" ? { selectors: { activation_source_profile: input.source } } : {}); maps.push(map); return map; };
      const artifact = parse(input.artifact, "Artifact", 65536), profile = artifact.text("crypto_profile_id");
      const resolve = (map: OwnedCredentialMap): CredentialNamespace => { const namespaces = config.namespaces.filter(namespace => namespace.matches(map)); requireCredential(namespaces.length === 1, "credential_untrusted"); return namespaces[0]!; };
      requireCredential(artifact.text("tenant_id") === config.tenant && artifact.text("audience") === config.audience && config.cryptoProfiles.includes(profile), "credential_untrusted");
      checkCredentialTime(runtime.clock, artifact.uint("issued_at_ms"), artifact.uint("initiation_not_after_ms"));
      const parent = resolve(artifact).verifyCredential(artifact, 1, work); evidence.push(parent);
      const certificates = [input.clientCertificate, input.serverCertificate, input.relayCertificate], subjects = [config.clientSubject, config.serverSubject, options.relaySubject];
      for (const [role, raw] of certificates.entries()) {
        const certificate = parse(raw, "IdentityCertificate", 8192);
        requireCredential(certificate.text("tenant_id") === config.tenant && certificate.text("audience") === (role === 2 ? options.relayAudience : config.audience) && certificate.text("subject_id") === subjects[role] && certificate.uint("role") === BigInt(role) && certificate.text("crypto_profile_id") === profile, "credential_untrusted");
        checkCredentialTime(runtime.clock, certificate.uint("issued_at_ms"), certificate.uint("expires_at_ms")); const fact = resolve(certificate).verifyCredential(certificate, 0, work); evidence.push(fact);
        if (role < 2) requireCredential(equalCredential(fact.digest, artifact.bytes(role === 0 ? "client_identity_digest" : "server_identity_digest")), "credential_binding");
        const noise = certificate.field("noise_static_public_key"), noiseKey = certificate.bytes("public_key_bytes", noise, "NoiseStaticPublicKey"), identity = certificate.bytes("ed25519_public_key");
        try { validateIdentityKey(profile, certificate.uint("algorithm", noise, "NoiseStaticPublicKey"), noiseKey, identity); } finally { noiseKey.fill(0); identity.fill(0); }
      }
      const candidate = [...artifact.items("candidates")][input.candidateIndex]; requireCredential(candidate !== undefined && artifact.uint("path_kind", candidate, "Candidate") === 1n, "credential_untrusted");
      const route = candidateRouteBytes(artifact, candidate); bytes.push(route); const routeDigest = credentialDigest("route_digest", route); bytes.push(routeDigest);
      requireCredential(equalCredential(routeDigest, options.routeDigest), "credential_untrusted");
      const candidateID = artifact.bytes("candidate_id", candidate, "Candidate"); bytes.push(candidateID);
      const onceBytes = parent.namespace.onceAuthority(parent.issuer); bytes.push(onceBytes); const once = parse(onceBytes, "OnceAuthorityRef", 412), activation = parse(input.activation, "ActivationAuthorization", 4096);
      const activationPublicKey = new Uint8Array(32); bytes.push(activationPublicKey);
      if (transaction !== undefined) transaction.copyActivationPublicKey(activationPublicKey);
      const validity = transaction === undefined ? validateActivation(config, work, artifact, activation, parent, once, input.source, input.candidateIndex, parent.digest, candidateID, routeDigest) :
        validateActivationIssuance(config, work, artifact, activation, parent, once, input.candidateIndex, parent.digest, candidateID, routeDigest, activationPublicKey); evidence.push(validity.evidence);
      const attempt = activation.bytes("attempt_id"); bytes.push(attempt); const issued = validity.issued, notAfter = validity.sessionEnd < issued + options.maxLifetimeMS ? validity.sessionEnd : issued + options.maxLifetimeMS;
      requireCredential(notAfter >= validity.initiation && notAfter <= 0xffffffffffffffffn, "credential_untrusted");
      const deadline = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), options.transactionMS, validity.initiation);
      const guard = (): void => { this.check(guardReference); transaction?.check(guardReference!); deadline.check(); for (const fact of evidence) fact.namespace.checkEvidence(fact); };
      guard();
      const parentFields = ["tenant_id", "revocation_authority_id", "namespace_capacity_digest", "revocation_policy_id", "revocation_policy_revision", "lease_id", "revocation_epoch", "issued_at_ms", "initiation_not_after_ms", "session_not_after_ms"] as const;
      const parentValues: Record<string, MapValue> = {};
      for (const name of parentFields) { const encoded = artifact.encoded(artifact.field(name)); bytes.push(encoded); parentValues[name] = { encoded }; }
      parentValues.authority_generation = artifact.uint("revocation_authority_generation"); parentValues.artifact_issuer_key_id = parent.issuer; parentValues.artifact_digest = parent.digest;
      const parentRef = encodeCredentialMap(scratch, "GrantParentRef", parentValues); bytes.push(parentRef);
      const identities = arrayBytes(scratch, [evidence[1]!.digest, evidence[2]!.digest]); bytes.push(identities);
      const legRefs: Uint8Array[] = [];
      for (const [role, field] of ["client_leg", "server_leg"].entries()) { const leg = artifact.field(field, candidate, "Candidate"), id = artifact.bytes("leg_id", leg, "Leg"); bytes.push(id); const encoded = encodeCredentialMap(scratch, "GrantLegRef", { leg_id: id, logical_role: BigInt(role) }); legRefs.push(encoded); bytes.push(encoded); }
      const encodedLegs = arrayBytes(scratch, legRefs, true); bytes.push(encodedLegs);
      const contract = work.digest(artifact, "session_contract_digest", artifact.field("session_contract")); bytes.push(contract);
      const maxEnvelope = artifact.uint("max_frame", artifact.field("session_contract"), "SessionContract") + 8n;
      requireCredential(options.limits.envelopeBytes === maxEnvelope, "configuration_capacity");
      const limits = encodeCredentialMap(scratch, "GrantLimits", { max_envelope_bytes: maxEnvelope, max_total_bytes: options.limits.totalBytes, max_datagram_bytes: options.limits.datagramBytes, max_rate_bytes_per_s: options.limits.rateBytesPerSecond, max_queue_bytes: options.limits.queueBytes, max_pending_native_mappings: options.limits.pendingMappings, max_resident_native_mappings: options.limits.residentMappings, max_total_native_mappings: options.limits.totalMappings, max_queue_items: options.limits.queueItems }); bytes.push(limits);
      const pairing = new Uint8Array(16), ids = [new Uint8Array(16), new Uint8Array(16)], nonces = [new Uint8Array(32), new Uint8Array(32)], signatures = new Uint8Array(64); bytes.push(pairing, ...ids, ...nonces, signatures);
      for (const random of [pairing, ...ids, ...nonces]) { runtime.fillRandom(random); requireCredential(random.some(byte => byte !== 0), "credential_invalid"); }
      requireCredential(!equalCredential(ids[0]!, ids[1]!) && !equalCredential(nonces[0]!, nonces[1]!) && !equalCredential(pairing, attempt) && !equalCredential(pairing, artifact.bytes("lease_id")), "credential_invalid");
      const grants: Uint8Array[] = [], drafts: Uint8Array[] = [], signers: Uint8Array[] = [];
      for (let side = 0; side < 2; side++) {
        const policy = this.#policies[side]!, facts = policy.namespace.grantIssuanceFacts(issued, guardReference!); bytes.push(facts.capacity);
        const namespace = encodeCredentialMap(scratch, "GrantNamespace", { tenant_id: facts.tenant, revocation_authority_id: facts.authority, generation: facts.generation, namespace_capacity_digest: facts.capacity, role_mask: 4n | 1n << BigInt(side), revocation_epoch: facts.cohort, revocation_policy_id: policy.revocationPolicyID, revocation_policy_revision: policy.revocationPolicyRevision }); bytes.push(namespace);
        const draft = encodeCredentialMap(scratch, "Grant", { tenant_id: config.tenant, grant_id: ids[side]!, replay_nonce: nonces[side]!, parent_ref: { encoded: parentRef }, route_descriptor: { encoded: route }, route_digest: routeDigest, attempt_id: attempt, pairing_id: pairing, identity_digests: { encoded: identities }, legs: { encoded: encodedLegs }, service: options.service, audience: options.relayAudience, issuer_key_id: policy.issuerKeyID, namespace: { encoded: namespace }, issued_at_ms: issued, not_after_ms: notAfter, limits: { encoded: limits }, session_contract_digest: contract, relay_identity_digest: evidence[3]!.digest, signature: signatures }); bytes.push(draft);
        const map = work.parse(draft, "Grant", 65536), publicKey = new Uint8Array(32); bytes.push(publicKey);
        try { guard(); this.#keys[side]!.copyPublicKey(publicKey); policy.namespace.authorizeGrantIssuance(map, publicKey, work); } finally { map.close(); }
        drafts.push(draft); signers.push(publicKey);
      }
      let actualActivation = input.activation;
      if (transaction !== undefined) {
        actualActivation = await transaction.beforeSign(drafts as unknown as readonly [Uint8Array, Uint8Array], signers as unknown as readonly [Uint8Array, Uint8Array], work, activationBacking);
      }
      for (let side = 0; side < 2; side++) {
        const signed = codec.sign(drafts[side]!, this.#keys[side]!, {}, () => { guard(); return true; });
        try { const count = signed.copyEncoded(scratch); const grant = new Uint8Array(scratch.subarray(0, count)); grants.push(grant); bytes.push(grant); } finally { signed.release(); scratch.fill(0); }
      }
      guard();
      closure = verifyDirectCredentials(config, { ...input, activation: actualActivation, tunnel: { grant: grants[0]!, relayCertificate: input.relayCertificate } }, references[3]!, undefined, closurePreparation); closurePreparation = undefined;
      for (let side = 0; side < 2; side++) legs.push(verifyRelayCredentials({ resources: runtime.resources, clock: runtime.clock, namespaces: config.namespaces, tenant: config.tenant, audience: options.relayAudience, service: options.service, endpointSubject: side === 0 ? config.clientSubject : config.serverSubject, relaySubject: options.relaySubject, cryptoProfiles: config.cryptoProfiles }, { grant: grants[side]!, endpointCertificate: certificates[side]!, relayCertificate: input.relayCertificate }, preparations[side]!));
      issuance = new OriginalGrantIssuance(issuerCapability, this, closure, Object.freeze(legs) as unknown as readonly [VerifiedRelayCredentials, VerifiedRelayCredentials]); closure = undefined;
      if (transaction === undefined) await options.activationStore.recordRelayIssuance(issuance, references[4]!, deadline, guard);
      else await transaction.complete(issuance, references[4]!, deadline, guard);
      guard(); publication?.captureOriginalWinner(this, issuance, this.#dependency.reference); guard();
      // Only an acknowledged original durable transaction reaches publication.
      return Object.freeze({ clientGrant: new Uint8Array(grants[0]!), serverGrant: new Uint8Array(grants[1]!) });
    } finally {
      issuance?.close(); closure?.close(); if (issuance === undefined) for (const leg of legs) leg.close(); closurePreparation?.close(); for (const preparation of preparations) preparation.close(); for (const map of maps) map.close(); for (const fact of evidence) clearEvidence(fact); for (const value of bytes) value.fill(0); scratch?.fill(0); codec?.close(); work?.close(); guardReference?.release(); for (const reference of references) reference.release(); this.#busy = false; this.#cleanup();
    }
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void { if (!this.#closed || this.#busy || this.#released) return; this.#released = true; for (const key of this.#keys) key.close(); for (const policy of this.#policies) policy.issuerKeyID.fill(0); this.#options.routeDigest.fill(0); this.#dependency.release(); }
}
export function createGrantIssuer(options: GrantIssuerOptions): GrantIssuer { return new GrantIssuer(issuerCapability, options); }
Object.freeze(GrantIssuer.prototype); Object.freeze(GrantIssuer); Object.freeze(OriginalGrantIssuance.prototype); Object.freeze(OriginalGrantIssuance);

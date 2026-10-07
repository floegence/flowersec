import { createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type EnvironmentDependency, type V4CredentialBuffers, type V4CredentialLengths, type V4CredentialPolicy, type V4EnvironmentMaterial } from "../v4/runtime/environment.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, equalCredential, requireCredential, type OwnedCredentialMap } from "../v4/runtime/credentialSupport.js";
import { candidateRouteDigest } from "../v4/runtime/credentialVerifier.js";
import { cborDecoderCharge } from "../v4/runtime/cbor.js";
import { SignedMapCodec, signedMapCodecCharge, SoftwareSigningKey, softwareSigningKeyCharge } from "../v4/runtime/signedMap.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { TrustedDeadline, timerChunk } from "../v4/runtime/deadline.js";
import { bindLiveAuthorizationConfig, type V4LiveAuthorizationConfig, type V4LiveAuthorizationRequest } from "../v4/runtime/liveAuthorization.js";
import { encodeLiveAuthorizationRequest, encodeLiveTunnelMaterial } from "../v4/runtime/liveAuthorizationWire.js";
import { wireMaps } from "../v4/runtime/schemaRegistry.js";
import type { GrantIssuer} from "./grantIssuerCurrent.js";
import { createGrantIssuer, encodeCredentialMap, type GrantIssuerOptions, type GrantIssuanceInput, type OriginalGrantIssuance } from "./grantIssuerCurrent.js";
import { SQLiteAdmissionStore } from "./sqliteAdmission.js";
import { isRegisteredLiveTunnelServerControl, type RegisteredLiveTunnelControlAuthority } from "./registeredLiveTunnelControl.js";

const original = Symbol("original live Grant transaction"), transactions = new WeakSet<OriginalLiveGrantTransaction>();
const control = Symbol("original server Grant control"), controls = new WeakSet<LiveTunnelServerControl>();
const maximum = 0xffffffffffffffffn;
const activationDecoder = (runtimeBytes: bigint) => ({ bytes: 4096, nodes: 2048, textBytes: 2048, arrayItems: 1024, runtimeBytes });
export interface LiveTunnelAuthorityOptions {
  readonly issuer: GrantIssuerOptions;
  /** Trusted original Artifact registration; request fields only select within it. */
  readonly material: Omit<GrantIssuanceInput, "activation" | "source">;
  readonly authority: string; readonly signingKeyID: string; readonly activationSeed: Uint8Array;
  readonly serverControl: LiveTunnelServerControl | RegisteredLiveTunnelControlAuthority;
  readonly maxActivationMS: bigint; readonly maxSessionMS: bigint; readonly workMS: bigint;
  /** Independent application policy, called once only after original TxA. */
  readonly authorize: (request: V4LiveAuthorizationRequest, options: Readonly<{ signal: AbortSignal; check(): void }>) => Promise<boolean>;
}
export interface LiveAuthorityProjection {
  readonly tenant: string; readonly issuer: Uint8Array; readonly audience: string; readonly identities: readonly [Uint8Array, Uint8Array];
  readonly lease: Uint8Array; readonly invocation: Uint8Array; readonly candidate: Uint8Array;
  readonly authority: string; readonly signingKeyID: string;
  readonly activationDraft: Uint8Array; readonly grantDrafts: readonly [Uint8Array, Uint8Array];
  readonly activationSigner: Uint8Array; readonly grantSigners: readonly [Uint8Array, Uint8Array];
  readonly recipient: Uint8Array; readonly incarnation: Uint8Array;
  readonly initiationEnd: bigint; readonly sessionEnd: bigint;
}
/** Private original owner. Reopening or importing a row cannot construct this
 * object or enter its once-only policy/sign/publication continuation. */
export class OriginalLiveGrantTransaction {
  readonly #authority: LiveTunnelAuthority; readonly #reference: ResourceReference; readonly #key: SoftwareSigningKey;
  readonly #codec: SignedMapCodec; readonly #activation: Uint8Array; readonly #input: GrantIssuanceInput;
  readonly #request: V4LiveAuthorizationRequest; readonly #abort: AbortController; readonly #deadline: TrustedDeadline;
  readonly #publication: OriginalLiveServerPublication; readonly #journal: ResourceReference; readonly #projectionWork: CredentialWork;
  readonly #unsignedBuffers: readonly [Uint8Array, Uint8Array] = [new Uint8Array(65536), new Uint8Array(65536)]; readonly #proofBacking = new Uint8Array(4096);
  #projection: LiveAuthorityProjection | undefined; #proof: Uint8Array | undefined; #begun = false; #allowed = false; #committed = false; #closed = false;
  constructor(token: symbol, authority: LiveTunnelAuthority, reference: ResourceReference, key: SoftwareSigningKey, codec: SignedMapCodec,
    input: GrantIssuanceInput, request: V4LiveAuthorizationRequest, deadline: TrustedDeadline, abort: AbortController, journal: ResourceReference, publication: OriginalLiveServerPublication, projectionWork: CredentialWork) {
    requireCredential(token === original); this.#authority = authority; this.#reference = reference.borrow(); this.#key = key; this.#codec = codec;
    this.#activation = input.activation; this.#input = input; this.#request = request; this.#abort = abort; this.#deadline = deadline; this.#journal = journal;
    this.#publication = publication; this.#projectionWork = projectionWork; transactions.add(this); Object.freeze(this);
  }
  check(reference?: ResourceReference): void {
    requireCredential(!this.#closed && !this.#abort.signal.aborted, "credential_closed"); this.#authority.check(); this.#reference.check(); this.#deadline.check();
    if (reference !== undefined) requireCredential(reference.sameEnvironment(this.#reference), "credential_binding"); this.#publication.check();
  }
  belongsTo(issuer: GrantIssuer): boolean { return this.#authority.ownsIssuer(issuer); }
  copyActivationPublicKey(destination: Uint8Array): void { this.check(); this.#key.copyPublicKey(destination); }
  async beforeSign(drafts: readonly [Uint8Array, Uint8Array], signers: readonly [Uint8Array, Uint8Array], work: CredentialWork, destination: Uint8Array): Promise<Uint8Array> {
    this.check(); requireCredential(this.#projection === undefined && !this.#begun);
    const proof = work.parse(this.#activation, "ActivationAuthorization", 4096, 2048, { selectors: { activation_source_profile: "live_authority" } });
    try {
      const issuer = proof.bytes("artifact_issuer_key_id"), leaseID = proof.bytes("lease_id"), tenant = new TextEncoder().encode(proof.text("tenant_id"));
      const lease = new Uint8Array(1 + tenant.length + 32); lease[0] = tenant.length; lease.set(tenant, 1); lease.set(issuer, tenant.length + 1); lease.set(leaseID, tenant.length + 17); issuer.fill(0); leaseID.fill(0); tenant.fill(0);
      const invocation = new Uint8Array(16), activationSigner = new Uint8Array(32); this.#authority.random(invocation); this.#key.copyPublicKey(activationSigner);
      this.#projection = Object.freeze({ tenant: proof.text("tenant_id"), issuer: proof.bytes("artifact_issuer_key_id"), audience: proof.text("audience"), identities: [proof.bytes("client_identity_digest"), proof.bytes("server_identity_digest")] as const, lease, invocation, candidate: proof.bytes("candidate_selection"), authority: proof.text("authority_id"), signingKeyID: proof.text("signing_key_id"),
        activationDraft: new Uint8Array(this.#activation), grantDrafts: [new Uint8Array(drafts[0]), new Uint8Array(drafts[1])] as const, activationSigner,
        grantSigners: [new Uint8Array(signers[0]), new Uint8Array(signers[1])] as const, recipient: this.#publication.recipient(), incarnation: this.#publication.incarnation(),
        initiationEnd: this.#authority.parentInitiation(), sessionEnd: proof.uint("session_not_after_ms") });
    } finally { proof.close(); }
    await this.#publication.prepare(this.#input, this.#request.attempt, () => this.check()); this.check();
    await this.#authority.store().recordLiveTxA(this, this.#journal, this.#deadline); this.#begun = true; this.check();
    const allowed = await this.#authority.policy(this.#request, this.#abort.signal, () => this.check()); this.check();
    if (allowed !== true) throw new Error("live_authorization_denied"); this.#allowed = true;
    const signed = this.#codec.sign(this.#activation, this.#key, { selectors: { activation_source_profile: "live_authority" } }, () => { this.check(); return true; });
    try { const count = signed.copyEncoded(this.#proofBacking); requireCredential(destination.length >= count, "configuration_capacity"); this.#proof = this.#proofBacking.subarray(0, count); destination.set(this.#proof); return destination.subarray(0, count); } finally { signed.release(); }
  }
  projection(reference: ResourceReference): LiveAuthorityProjection { this.check(reference); requireCredential(this.#projection !== undefined); return this.#projection; }
  proof(reference: ResourceReference): Uint8Array { this.check(reference); requireCredential(this.#begun && this.#allowed && this.#proof !== undefined); return this.#proof; }
  checkCompleteProjection(reference: ResourceReference, grants: readonly [Uint8Array, Uint8Array]): void {
    this.check(reference); const fixed = this.projection(reference), proof = this.proof(reference);
    requireCredential(matchesUnsignedCredential(this.#projectionWork, "ActivationAuthorization", fixed.activationDraft, proof, this.#unsignedBuffers) &&
      matchesUnsignedCredential(this.#projectionWork, "Grant", fixed.grantDrafts[0], grants[0], this.#unsignedBuffers) &&
      matchesUnsignedCredential(this.#projectionWork, "Grant", fixed.grantDrafts[1], grants[1], this.#unsignedBuffers), "credential_binding");
  }
  async complete(issuance: OriginalGrantIssuance, reservation: ResourceReference, deadline: TrustedDeadline, guard: () => void): Promise<void> {
    this.check(reservation); requireCredential(this.#begun && this.#allowed && !this.#committed);
    await this.#authority.store().recordRelayIssuance(issuance, reservation, deadline, guard, this); this.#committed = true; this.check();
  }
  async publish(serverGrant: Uint8Array, clientGrant: Uint8Array): Promise<void> {
    this.check(); requireCredential(this.#committed && this.#proof !== undefined);
    await this.#publication.publish(this.#input, this.#proof, serverGrant, () => this.check(), clientGrant); this.check();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#publication.close();
    if (this.#projection !== undefined) for (const value of Object.values(this.#projection)) { if (value instanceof Uint8Array) value.fill(0); else if (Array.isArray(value)) for (const bytes of value) if (bytes instanceof Uint8Array) bytes.fill(0); }
    this.#proofBacking.fill(0); for (const bytes of this.#unsignedBuffers) bytes.fill(0); this.#reference.release();
  }
}
export function isOriginalLiveGrantTransaction(value: unknown): value is OriginalLiveGrantTransaction { return value instanceof OriginalLiveGrantTransaction && transactions.has(value); }
/** Exact unsigned comparison, including every fixed projection field. */
export function matchesUnsignedCredential(work: CredentialWork, schema: "ActivationAuthorization" | "Grant", unsigned: Uint8Array, signed: Uint8Array, backing?: readonly [Uint8Array, Uint8Array]): boolean {
  const signature = Number(Object.entries(wireMaps[schema]!.fields).find(([, field]) => field.name === "signature")![0]);
  const maps: OwnedCredentialMap[] = []; const [a, b] = backing ?? [new Uint8Array(65536), new Uint8Array(65536)];
  try {
    const context = schema === "ActivationAuthorization" ? { selectors: { activation_source_profile: "live_authority" } } : {};
    maps.push(work.parse(unsigned, schema, schema === "Grant" ? 65536 : 4096, 16384, context), work.parse(signed, schema, schema === "Grant" ? 65536 : 4096, 16384, context));
    const x = maps[0]!.doc.copyWithoutField(signature, a), y = maps[1]!.doc.copyWithoutField(signature, b); return equalCredential(a.subarray(0, x), b.subarray(0, y));
  } finally { for (const map of maps) map.close(); a.fill(0); b.fill(0); }
}
interface ServerRecord {
  readonly material: Omit<GrantIssuanceInput, "source">; readonly grantBacking: Uint8Array; readonly responseBacking: Uint8Array;
  readonly prepared: V4EnvironmentMaterial; readonly reference: ResourceReference;
  activationLength: number; grantLength: number; consumed: boolean; transferred: boolean;
}
export interface OriginalLiveServerPublication {
  check(): void; recipient(): Uint8Array; incarnation(): Uint8Array;
  prepare(input: GrantIssuanceInput, attempt: Uint8Array, guard: () => void): Promise<void>;
  publish(input: GrantIssuanceInput, activation: Uint8Array, grant: Uint8Array, guard: () => void, clientGrant?: Uint8Array): void | Promise<void>;
  close(): void;
}
export function isOriginalLiveControlCapability(value: unknown): boolean { return value === original; }
class OriginalServerGrantPublication implements OriginalLiveServerPublication {
  #published = false; #closed = false;
  constructor(readonly owner: LiveTunnelServerControl, readonly reference: ResourceReference, readonly record: ServerRecord) {}
  check(): void { requireCredential(!this.#closed, "credential_closed"); this.reference.check(); this.owner.checkPublication(control, this); }
  async prepare(_input: GrantIssuanceInput, _attempt: Uint8Array, guard: () => void): Promise<void> { this.check(); guard(); }
  recipient(): Uint8Array { return this.owner.recipient(); }
  incarnation(): Uint8Array { return this.owner.incarnation(); }
  publish(input: GrantIssuanceInput, activation: Uint8Array, grant: Uint8Array, guard: () => void): void { this.check(); requireCredential(!this.#published); guard(); this.owner.publish(control, this, input, activation, grant); this.#published = true; }
  close(): void { if (this.#closed) return; this.#closed = true; this.owner.finish(control, this, this.#published); this.reference.release(); }
}
/** SDK-owned original authenticated control inbox for one configured endpoint.
 * A publication reserves its actual material position before authority TxA.
 * takePreparedHop transfers that position to the first prepared ingress. */
export class LiveTunnelServerControl {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #dependency: EnvironmentDependency;
  readonly #recipient: Uint8Array; readonly #incarnation: Uint8Array; readonly #policy: V4CredentialPolicy;
  #publication: OriginalServerGrantPublication | undefined; #record: ServerRecord | undefined; #closed = false; #released = false;
  #timer: ReturnType<typeof setTimeout> | undefined;
  constructor(token: symbol, environment: V4TransportEnvironment, policy: V4CredentialPolicy, recipient: Uint8Array, incarnation: Uint8Array) {
    requireCredential(token === control && policy.tunnel?.role === 1 && policy.tunnel.liveGrant !== undefined && policy.tunnel.liveGrant.issuerKeyID instanceof Uint8Array && policy.tunnel.liveGrant.issuerKeyID.length === 16 && recipient.length === 16 && incarnation.length === 16 && recipient.some(byte => byte !== 0) && incarnation.some(byte => byte !== 0), "configuration_capacity");
    this.#runtime = originalEnvironment(environment); this.#recipient = new Uint8Array(recipient); this.#incarnation = new Uint8Array(incarnation);
    const liveGrant = policy.tunnel.liveGrant;
    this.#policy = Object.freeze({ ...policy, authorities: Object.freeze([...policy.authorities]), cryptoProfiles: Object.freeze([...policy.cryptoProfiles]), tunnel: Object.freeze({ ...policy.tunnel, liveGrant: Object.freeze({ ...liveGrant, issuerKeyID: new Uint8Array(liveGrant.issuerKeyID) }) }) });
    this.#dependency = this.#runtime.admitDependency("live_tunnel_server_control", new ResourceVector([4096n + this.#runtime.resources.runtimeBytes, 0n, 0n, 2n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => this.close()); controls.add(this); Object.freeze(this);
  }
  check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  recipient(): Uint8Array { this.check(); return new Uint8Array(this.#recipient); }
  incarnation(): Uint8Array { this.check(); return new Uint8Array(this.#incarnation); }
  reserve(token: symbol, input: GrantIssuanceInput, attempt: Uint8Array): OriginalServerGrantPublication {
    this.check(); requireCredential(token === original); if (this.#publication !== undefined || this.#record !== undefined) throw new Error("credential_busy");
    requireCredential(input.artifact.length <= 65536 && input.clientCertificate.length <= 8192 && input.serverCertificate.length <= 8192 && input.relayCertificate.length <= 8192, "configuration_capacity");
    const reference = this.#runtime.reserveConnectionWork("live_original_server_allow", new ResourceVector([270336n + this.#runtime.resources.runtimeBytes, 0n, 0n, 8n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
    let prepared: V4EnvironmentMaterial | undefined; let record: ServerRecord | undefined;
    try {
      prepared = this.#runtime.verify(this.#policy, { artifact: input.artifact, clientCertificate: input.clientCertificate, serverCertificate: input.serverCertificate, source: "live_authority", candidateIndex: input.candidateIndex, tunnel: { relayCertificate: input.relayCertificate } });
      this.#runtime.beginOriginalLivePublication(prepared, attempt, reference);
      // All fixed transfer and receiver verification backing exists before TxA.
      record = { material: { artifact: new Uint8Array(input.artifact), clientCertificate: new Uint8Array(input.clientCertificate), serverCertificate: new Uint8Array(input.serverCertificate), relayCertificate: new Uint8Array(input.relayCertificate), activation: new Uint8Array(4096), candidateIndex: input.candidateIndex },
        grantBacking: new Uint8Array(65536), responseBacking: new Uint8Array(69696), prepared, reference: reference.borrow(), activationLength: 0, grantLength: 0, consumed: false, transferred: false };
      const publication = new OriginalServerGrantPublication(this, reference, record); this.#publication = publication; return publication;
    } catch (error) { if (record !== undefined) this.#clear(record); else void prepared?.closeMaterial(); reference.release(); throw error; }
  }
  checkPublication(token: symbol, publication: OriginalServerGrantPublication): void {
    this.check(); requireCredential(token === control && publication === this.#publication, "credential_binding");
    this.#runtime.checkOriginalLivePublication(publication.record.prepared, publication.record.reference);
  }
  publish(token: symbol, publication: OriginalServerGrantPublication, input: GrantIssuanceInput, activation: Uint8Array, grant: Uint8Array): void {
    this.checkPublication(token, publication); requireCredential(this.#record === undefined && activation.length > 0 && activation.length <= 4096 && grant.length > 0 && grant.length <= 65536, "credential_binding");
    const record = publication.record;
    requireCredential(record.material.candidateIndex === input.candidateIndex && equalCredential(record.material.artifact, input.artifact) && equalCredential(record.material.clientCertificate, input.clientCertificate) && equalCredential(record.material.serverCertificate, input.serverCertificate) && equalCredential(record.material.relayCertificate, input.relayCertificate), "credential_binding");
    const response = encodeLiveTunnelMaterial(activation, grant, record.responseBacking);
    this.#runtime.installOriginalLivePublication(record.prepared, response, record.reference); record.responseBacking.fill(0);
    record.material.activation.set(activation); record.grantBacking.set(grant); record.activationLength = activation.length; record.grantLength = grant.length;
    this.#record = record;
    const tick = (): void => {
      this.#timer = undefined; if (this.#record !== record) return;
      try { this.check(); this.#runtime.checkOriginalLivePublication(record.prepared, record.reference); this.#timer = setTimeout(tick, 1000); }
      catch { this.#clearRecord(); }
    };
    this.#timer = setTimeout(tick, 1000);
  }
  finish(token: symbol, publication: OriginalServerGrantPublication, published: boolean): void {
    requireCredential(token === control); if (this.#publication !== publication) return; this.#publication = undefined;
    if (!published || this.#record !== publication.record) this.#clear(publication.record);
    else if (this.#closed) this.#clearRecord();
    this.#cleanup();
  }
  credentials(): Readonly<{
    source: "live_authority"; policy: V4CredentialPolicy;
    resolve(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths>;
    resolveHop(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>, buffers: V4CredentialBuffers): Promise<V4CredentialLengths>;
    takePreparedHop(request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial>;
  }> {
    this.check();
    const takePreparedHop = async (request: Readonly<{ signal: AbortSignal; hello: Uint8Array }>): Promise<V4EnvironmentMaterial> => {
      this.check(); if (request.signal.aborted || this.#record === undefined || this.#record.consumed) throw new Error("material_unavailable");
      const record = this.#record; this.#runtime.checkOriginalLivePublication(record.prepared, record.reference);
      const ref = this.#runtime.reserveConnectionWork("live_server_allow_hello", credentialWorkCharge(65536, this.#runtime.resources.runtimeBytes)); let work: CredentialWork | undefined;
      try {
        work = new CredentialWork(this.#runtime.resources, 65536, ref); const hello = work.parse(request.hello, "HOP_AUTH_HELLO", 65536, 16384, { selectors: { hop_sender_role: "relay" } });
        try { const certificate = hello.bytes("identity_certificate"); try { requireCredential(equalCredential(certificate, record.material.relayCertificate), "credential_binding"); } finally { certificate.fill(0); } } finally { hello.close(); }
        requireCredential(!request.signal.aborted); this.#runtime.checkOriginalLivePublication(record.prepared, record.reference);
        record.consumed = true; record.transferred = true;
        // The published material itself enters HOP_AUTH, admission and READY.
        // Its original Environment and transaction state survive the transfer.
        this.#clearRecord(); return record.prepared;
      } finally { work?.close(); ref.release(); }
    };
    const unavailable = async (): Promise<V4CredentialLengths> => { throw new Error("original_prepared_server_material_required"); };
    return Object.freeze({ source: "live_authority", policy: this.#policy, resolve: unavailable, resolveHop: unavailable, takePreparedHop });
  }
  #clear(record: ServerRecord): void {
    if (!record.transferred) void record.prepared.closeMaterial(); for (const value of Object.values(record.material)) if (value instanceof Uint8Array) value.fill(0);
    record.grantBacking.fill(0); record.responseBacking.fill(0); record.reference.release();
  }
  #clearRecord(): void {
    if (this.#record === undefined) return;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    const record = this.#record; this.#record = undefined;
    // The active original publication retains this record until its call exits.
    if (this.#publication?.record !== record) this.#clear(record);
    this.#cleanup();
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#clearRecord(); this.#cleanup(); }
  #cleanup(): void {
    if (this.#closed && this.#publication === undefined && this.#record === undefined && !this.#released) {
      this.#released = true; this.#recipient.fill(0); this.#incarnation.fill(0); this.#policy.tunnel!.liveGrant!.issuerKeyID.fill(0); this.#dependency.release();
    }
  }
}
export function createLiveTunnelServerControl(environment: V4TransportEnvironment, policy: V4CredentialPolicy, recipient: Uint8Array, incarnation: Uint8Array): LiveTunnelServerControl { return new LiveTunnelServerControl(control, environment, policy, recipient, incarnation); }

export class LiveTunnelAuthority {
  readonly #runtime: ReturnType<typeof originalEnvironment>; readonly #options: Omit<LiveTunnelAuthorityOptions, "issuer" | "activationSeed">; readonly #issuer: GrantIssuer; readonly #store: SQLiteAdmissionStore;
  readonly #key: SoftwareSigningKey; readonly #dependency: EnvironmentDependency; #busy = false; #closed = false; #released = false; #parentInitiation = 0n;
  constructor(options: LiveTunnelAuthorityOptions) {
    this.#runtime = originalEnvironment(options.issuer.environment);
    requireCredential((options.serverControl instanceof LiveTunnelServerControl && controls.has(options.serverControl) || isRegisteredLiveTunnelServerControl(options.serverControl, this.#runtime)) && options.issuer.activationStore instanceof SQLiteAdmissionStore && Number.isSafeInteger(options.material.candidateIndex) && options.material.candidateIndex >= 0 && options.material.candidateIndex < 16 && typeof options.authorize === "function" &&
      /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(options.authority) && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(options.signingKeyID) && [options.maxActivationMS, options.workMS].every(value => typeof value === "bigint" && value > 0n && value <= 90000n) && typeof options.maxSessionMS === "bigint" && options.maxSessionMS > 0n && options.maxSessionMS <= maximum && options.activationSeed.length === 32, "configuration_capacity");
    for (const [bytes, maximumBytes] of [[options.material.artifact, 65536], [options.material.clientCertificate, 8192], [options.material.serverCertificate, 8192], [options.material.relayCertificate, 8192]] as const) requireCredential(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= maximumBytes, "configuration_capacity");
    const resources = this.#runtime.resources, keyConfig = { schemas: ["ActivationAuthorization"], runtimeBytes: resources.runtimeBytes };
    const bytes = options.material.artifact.length + options.material.clientCertificate.length + options.material.serverCertificate.length + options.material.relayCertificate.length;
    this.#dependency = this.#runtime.admitDependency("live_tunnel_authority", new ResourceVector([BigInt(bytes) + 8192n + resources.runtimeBytes, 0n, 0n, 8n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    let reference: ResourceReference | undefined, key: SoftwareSigningKey | undefined, issuer: GrantIssuer | undefined;
    let material: LiveTunnelAuthorityOptions["material"] | undefined;
    try {
      reference = this.#runtime.reserveConnectionWork("live_activation_key", softwareSigningKeyCharge(keyConfig));
      material = Object.freeze({ candidateIndex: options.material.candidateIndex, artifact: new Uint8Array(options.material.artifact), clientCertificate: new Uint8Array(options.material.clientCertificate), serverCertificate: new Uint8Array(options.material.serverCertificate), relayCertificate: new Uint8Array(options.material.relayCertificate) });
      key = new SoftwareSigningKey(keyConfig, options.activationSeed, reference); issuer = createGrantIssuer(options.issuer);
      this.#key = key; this.#issuer = issuer; this.#store = options.issuer.activationStore;
      this.#options = Object.freeze({ material, authority: options.authority, signingKeyID: options.signingKeyID, serverControl: options.serverControl, maxActivationMS: options.maxActivationMS, maxSessionMS: options.maxSessionMS, workMS: options.workMS, authorize: options.authorize });
      this.#dependency.onClose(() => this.close()); Object.freeze(this);
    } catch (error) { issuer?.close(); key?.close(); if (material !== undefined) for (const value of Object.values(material)) if (value instanceof Uint8Array) value.fill(0); this.#dependency.release(); throw error; }
    finally { reference?.release(); }
  }
  check(): void { requireCredential(!this.#closed, "credential_closed"); this.#dependency.check(); }
  ownsIssuer(issuer: GrantIssuer): boolean { return issuer === this.#issuer; }
  store(): SQLiteAdmissionStore { this.check(); return this.#store; }
  random(bytes: Uint8Array): void { this.check(); this.#runtime.fillRandom(bytes as Uint8Array<ArrayBuffer>); }
  parentInitiation(): bigint { return this.#parentInitiation; }
  async policy(request: V4LiveAuthorizationRequest, signal: AbortSignal, check: () => void): Promise<boolean> { check(); const result = await this.#options.authorize(request, Object.freeze({ signal, check })); check(); return result; }
  /** A configured in-process authenticated control endpoint. Its caller proves
   * possession of the independently trusted registered client identity key;
   * ordinary receipt lookup has no path to this original invocation. */
  clientAuthorization(environment: V4TransportEnvironment, identityKey: KeyObject): V4LiveAuthorizationConfig {
    this.check(); requireCredential(identityKey.type === "private" && identityKey.asymmetricKeyType === "ed25519", "configuration_capacity"); const target = originalEnvironment(environment);
    const dependency = target.admitDependency("live_authority_identity", new ResourceVector([target.resources.runtimeBytes + 4096n, 1n, 0n, 2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
    let retainedKey: KeyObject | undefined = identityKey, active = 0, closed = false;
    const cleanup = (): void => { if (closed && active === 0) { retainedKey = undefined; dependency.release(); } };
    dependency.onClose(() => { closed = true; cleanup(); });
    const requestAuthorization: V4LiveAuthorizationConfig["requestAuthorization"] = async (request, destination, operation) => {
      dependency.check(); operation.check(); requireCredential(!closed && retainedKey !== undefined, "credential_closed"); active++;
      const message = new Uint8Array(1152), challenge = new Uint8Array(32); let signature: Uint8Array | undefined;
      try {
        target.fillRandom(challenge); const encoded = encodeLiveAuthorizationRequest(request, message.subarray(32)); message.set(challenge, 0); const input = message.subarray(0, encoded.length + 32);
        signature = new Uint8Array(sign(null, input, retainedKey));
        const guard = (): void => { dependency.check(); operation.check(); requireCredential(!closed, "credential_closed"); };
        return await this.#authorize(request, input, signature, destination, operation.signal, guard);
      } finally { message.fill(0); challenge.fill(0); signature?.fill(0); active--; cleanup(); }
    };
    return bindLiveAuthorizationConfig(target, Object.freeze({ requestAuthorization, maxConcurrentRequests: 1, runtimeBytes: target.resources.runtimeBytes, providerBytes: 1n }));
  }
  /** The control transport supplies only original signed request bytes. This
   * method repeats the registered identity, exact request and original TxA/TxB
   * checks; neither an HTTP success nor an imported receipt can enter them. */
  async authorizeOriginalControlRequest(request: V4LiveAuthorizationRequest, authentication: Uint8Array, signature: Uint8Array, destination: Uint8Array, signal: AbortSignal, check: () => void): Promise<number> {
    this.check(); check(); requireCredential(authentication instanceof Uint8Array && authentication.length >= 33 && authentication.length <= 1152 && signature instanceof Uint8Array && signature.length === 64, "credential_binding");
    return await this.#authorize(request, authentication, signature, destination, signal, check);
  }
  async #authorize(request: V4LiveAuthorizationRequest, authentication: Uint8Array, signature: Uint8Array, destination: Uint8Array, signal: AbortSignal, consumerCheck: () => void): Promise<number> {
    this.check(); if (this.#busy) throw new Error("credential_busy"); requireCredential(!signal.aborted && destination.length >= 69696, "configuration_capacity"); this.#busy = true;
    const runtime = this.#runtime, options = this.#options, refs: ResourceReference[] = []; let work: CredentialWork | undefined, projectionWork: CredentialWork | undefined, codec: SignedMapCodec | undefined, transaction: OriginalLiveGrantTransaction | undefined, publication: OriginalLiveServerPublication | undefined;
    const abort = new AbortController(), cancel = (): void => abort.abort(); signal.addEventListener("abort", cancel, { once: true }); let timer: ReturnType<typeof setTimeout> | undefined;
    const owned: Uint8Array[] = []; const maps: OwnedCredentialMap[] = [];
    try {
      const requestBytes = new Uint8Array(1024); owned.push(requestBytes);
      const canonical = encodeLiveAuthorizationRequest(request, requestBytes);
      requireCredential(authentication.length === canonical.length + 32 && equalCredential(authentication.subarray(32), canonical), "credential_binding");
      request = Object.freeze({ ...request, issuer: new Uint8Array(request.issuer), lease: new Uint8Array(request.lease), attempt: new Uint8Array(request.attempt), artifact: new Uint8Array(request.artifact), clientIdentity: new Uint8Array(request.clientIdentity), serverIdentity: new Uint8Array(request.serverIdentity), candidateID: new Uint8Array(request.candidateID), routeDigest: new Uint8Array(request.routeDigest) });
      for (const value of Object.values(request)) if (value instanceof Uint8Array) owned.push(value);
      const decoder = activationDecoder(runtime.resources.runtimeBytes), codecConfig = { schema: "ActivationAuthorization", decoder, runtimeBytes: runtime.resources.runtimeBytes };
      refs.push(...runtime.resources.root.reserveBatch([credentialWorkCharge(524288, runtime.resources.runtimeBytes), cborDecoderCharge(decoder), signedMapCodecCharge(codecConfig), this.#store.relayCharge(), new ResourceVector([524288n + runtime.resources.runtimeBytes, 0n, 0n, 16n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]), credentialWorkCharge(524288, runtime.resources.runtimeBytes)].map((charge, index) => ({ owner: credentialOwner(runtime.resources, `original_live_authority_${index}`), accounts: runtime.resources.accounts, charge }))));
      work = new CredentialWork(runtime.resources, 524288, refs[0]!); work.prepayParsers(65536, 16384, 8); work.prepaySignatures(65536, 16384); codec = new SignedMapCodec(codecConfig, refs[1]!, refs[2]!);
      projectionWork = new CredentialWork(runtime.resources, 524288, refs[5]!); projectionWork.prepayParsers(65536, 16384, 4);
      const artifact = work.parse(options.material.artifact, "Artifact", 65536), certificate = work.parse(options.material.clientCertificate, "IdentityCertificate", 8192); maps.push(artifact, certificate);
      const candidate = [...artifact.items("candidates")][options.material.candidateIndex]; requireCredential(candidate !== undefined && artifact.uint("path_kind", candidate, "Candidate") === 1n);
      const publicBytes = certificate.bytes("ed25519_public_key"); owned.push(publicBytes);
      const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicBytes).toString("base64url") }, format: "jwk" }); requireCredential(verify(null, authentication, publicKey, signature), "credential_untrusted");
      const route = candidateRouteDigest(artifact, candidate), artifactDigest = work.digest(artifact, "artifact_digest"), candidateID = artifact.bytes("candidate_id", candidate, "Candidate"); owned.push(route, artifactDigest, candidateID);
      requireCredential(request.authority === options.authority && request.tenant === artifact.text("tenant_id") && request.audience === artifact.text("audience") && request.cryptoProfile === artifact.text("crypto_profile_id") && request.candidateIndex === options.material.candidateIndex && request.attemptNo === 1 &&
        equalCredential(request.issuer, artifact.bytes("issuer_key_id")) && equalCredential(request.lease, artifact.bytes("lease_id")) && equalCredential(request.artifact, artifactDigest) && equalCredential(request.clientIdentity, artifact.bytes("client_identity_digest")) && equalCredential(request.serverIdentity, artifact.bytes("server_identity_digest")) && equalCredential(request.candidateID, candidateID) && equalCredential(request.routeDigest, route), "credential_binding");
      const now = runtime.clock.sample().requireInterval(), issued = now.lowerMS; this.#parentInitiation = artifact.uint("initiation_not_after_ms");
      const activationEnd = [request.activationNotAfterMS, this.#parentInitiation, now.upperMS + options.maxActivationMS].reduce((a, b) => a < b ? a : b), sessionEnd = [artifact.uint("session_not_after_ms"), now.upperMS + options.maxSessionMS].reduce((a, b) => a < b ? a : b);
      requireCredential(now.upperMS < activationEnd && activationEnd <= sessionEnd && sessionEnd <= maximum);
      const deadline = TrustedDeadline.ageAt(runtime.clock, runtime.clock.sample(), options.workMS, activationEnd);
      const guard = (): void => { this.check(); refs[4]!.check(); deadline.check(); consumerCheck(); requireCredential(!abort.signal.aborted); };
      const tick = (): void => { try { guard(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch { abort.abort(); } }; tick(); guard();
      const scratch = new Uint8Array(4096), signaturePlaceholder = new Uint8Array(64); owned.push(scratch, signaturePlaceholder);
      const draft = encodeCredentialMap(scratch, "ActivationAuthorization", { schema_revision: 1n, authority_id: options.authority, signing_key_id: options.signingKeyID, tenant_id: request.tenant,
        artifact_issuer_key_id: request.issuer, lease_id: request.lease, artifact_digest: request.artifact, candidate_selection: request.candidateID, route_selection: request.routeDigest, attempt_id: request.attempt,
        client_identity_digest: request.clientIdentity, server_identity_digest: request.serverIdentity, audience: request.audience, issued_at_ms: issued, activation_not_after_ms: activationEnd, session_not_after_ms: sessionEnd, signature: signaturePlaceholder }); owned.push(draft);
      const input: GrantIssuanceInput = { ...options.material, activation: draft, source: "live_authority" };
      publication = options.serverControl.reserve(original, input, request.attempt);
      transaction = new OriginalLiveGrantTransaction(original, this, refs[4]!, this.#key, codec, input, request, deadline, abort, refs[3]!, publication, projectionWork); publication = undefined;
      const grants = await this.#issuer.issueOriginalLive(input, transaction);
      try { guard(); await transaction.publish(grants.serverGrant, grants.clientGrant); guard(); const result = encodeLiveTunnelMaterial(transaction.proof(refs[4]!), grants.clientGrant, destination); guard(); return result.length; }
      finally { grants.clientGrant.fill(0); grants.serverGrant.fill(0); }
    } finally {
      if (timer !== undefined) clearTimeout(timer); signal.removeEventListener("abort", cancel); transaction?.close(); publication?.close(); for (const map of maps) map.close(); for (const bytes of owned) bytes.fill(0); codec?.close(); projectionWork?.close(); work?.close(); for (const reference of refs) reference.release(); this.#busy = false; this.#cleanup();
    }
  }
  close(): void { this.#closed = true; this.#cleanup(); }
  #cleanup(): void { if (!this.#closed || this.#busy || this.#released) return; this.#released = true; this.#issuer.close(); this.#key.close(); for (const value of Object.values(this.#options.material)) if (value instanceof Uint8Array) value.fill(0); this.#dependency.release(); }
}
export function createLiveTunnelAuthority(options: LiveTunnelAuthorityOptions): LiveTunnelAuthority { return new LiveTunnelAuthority(options); }
for (const constructor of [OriginalLiveGrantTransaction, LiveTunnelServerControl, LiveTunnelAuthority]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

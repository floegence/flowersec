import { sha256 } from "@noble/hashes/sha2.js";
import type { OperationOptions } from "../public/contract.js";
import { V4ConnectionMaterial, type V4ConnectionMaterialSource } from "./public.js";
import type { V4ConnectionRequirements, V4CleanupStatus, V4TopUpError, V4TopUpErrorCode } from "../generated/transportV4APIResults.js";
import { topUpErrorProjection } from "../generated/transportV4APIResults.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, credentialDigest, equalCredential, type OwnedCredentialMap } from "./runtime/credentialSupport.js";
import { FixedCBORWriter, canonicalHeadBytes } from "./runtime/cborWriter.js";
import { TrustedDeadline, timerChunk } from "./runtime/deadline.js";
import { ResourceVector } from "./runtime/resources.js";
import { originalPoolJournal, type PoolJournalStore } from "./runtime/poolJournal.js";
import { bindCredentialSourceFacade, type V4EnvironmentRuntime, type V4EnvironmentCredentialSource, type V4CredentialPolicy, type V4CredentialBuffers, type V4CredentialLengths, type EnvironmentDependency } from "./runtime/environment.js";
import type { CredentialInput } from "./runtime/credentialVerifier.js";
import type { CBORDocument } from "./runtime/cbor.js";

export type V4TopUpState = "pending" | "installed" | "acked" | "terminal";
export interface V4TopUpOptions { readonly desiredCount?: number; readonly maxItemBytes?: number; }
export interface V4TopUpResult {
  readonly state?: V4TopUpState;
  readonly handle?: V4TopUpHandle;
  readonly adoptedOptions?: Readonly<{ desiredCount: number; maxItemBytes: number }>;
  readonly callError?: V4TopUpErrorCode | "canceled" | "deadline_exceeded";
  readonly cleanupStatus: V4CleanupStatus;
}
export type V4TopUpExchangeResult = Readonly<{ kind: "success" | "replay"; response: Uint8Array }> |
  Readonly<{ kind: "acknowledged" }> | Readonly<{ kind: "error"; error: V4TopUpError }>;
/** A qualified authenticated control provider. Completion ends the original
 * request buffer borrow even after cancellation. There is no automatic resend. */
export interface V4TopUpControlTransport {
  exchange(method: 41006 | 41007, canonicalRequest: Uint8Array, signal: AbortSignal): Promise<V4TopUpExchangeResult>;
}
export interface V4PoolSourceConfiguration {
  readonly sourceIncarnation: Uint8Array;
  readonly poolDigest: Uint8Array;
  readonly identityCertificate: Uint8Array;
  readonly fenceAuthorityKeyID: Uint8Array;
  readonly fenceAuthorityPublicKey: Uint8Array;
  readonly operationLifetimeMS: bigint;
  readonly callTimeoutMS: bigint;
  readonly maximumMaterials?: number;
  readonly control: V4TopUpControlTransport;
  readonly providerRuntimeBytes: bigint;
  readonly ownerFenceProof: (intent: Readonly<{ tenant: string; sourceIncarnation: Uint8Array; operationID: Uint8Array;
    requestDigest: Uint8Array; currentGeneration: bigint; deadlineMS: bigint }>, signal: AbortSignal) => Promise<Uint8Array>;
  readonly decodeMaterial: (canonicalMaterial: Uint8Array) => Omit<CredentialInput, "source">;
  /** The host explicitly provisions a fresh incarnation. Reopen never recreates
   * a missing journal, resets sequence, or substitutes another backing. */
  readonly create: boolean;
}
interface IdentityKeys { readonly signingPublicKey: Uint8Array; readonly noisePublicKey: Uint8Array; check(): void; }
interface Pending {
  // Creation stays fixed; one durable attempt high-water fence precedes every
  // send. The server commit generation is pinned by consistent Applied facts.
  id: Uint8Array; state: V4TopUpState; desired: number; maximum: number; pool: Uint8Array; generation: bigint; attemptGeneration: bigint;
  deadline: bigint; frontier: bigint; certificate: Uint8Array; identity: Uint8Array; requestDigest: Uint8Array;
  responseDigest?: Uint8Array; highest?: bigint; gap?: boolean; retired?: bigint; error?: V4TopUpErrorCode; applied?: AppliedEntry[];
}
interface AppliedEntry { sequence: bigint; generation: bigint; expiry: bigint; digest: Uint8Array; identity: Uint8Array; }
interface Material { sequence: bigint; generation: bigint; expiry: bigint; bytes: Uint8Array; digest: Uint8Array; identity: Uint8Array; }
interface Journal { next: bigint; retired: bigint; frontier: bigint; pending?: Pending; applied: AppliedEntry[]; materials: Material[]; fenced: boolean; }
const claims = new WeakMap<PoolJournalStore, Map<string, V4PreauthorizedPoolSource>>();
const sourceToken = Symbol("original durable pool source");
interface OperationObservation {
  readonly source: V4PreauthorizedPoolSource; readonly id: Uint8Array;
  readonly desired: number; readonly maximum: number;
  state: V4TopUpState; error?: V4TopUpResult["callError"]; responseDigest?: Uint8Array;
  active: number; handle: V4TopUpHandle; readonly waiters: Set<() => void>;
}
const handleToken = Symbol("pool TopUp observation"), handles = new WeakMap<V4TopUpHandle, OperationObservation>();
function operationCleanup(original: OperationObservation): V4CleanupStatus {
  return Object.freeze({ status: original.active === 0 ? "complete" : "pending", core_cleanup: original.active === 0 ? "complete" : "pending", pending_callbacks: BigInt(original.active) });
}
function operationSettled(original: OperationObservation): void {
  if (original.active === 0) for (const observe of [...original.waiters]) observe();
}
function operationResult(original: OperationObservation, error?: V4TopUpResult["callError"]): V4TopUpResult {
  const callError = error ?? original.error;
  return Object.freeze({ state: original.state, handle: original.handle,
    adoptedOptions: Object.freeze({ desiredCount: original.desired, maxItemBytes: original.maximum }),
    ...(callError === undefined ? {} : { callError }), cleanupStatus: operationCleanup(original) });
}
export class V4TopUpHandle {
  constructor(token: symbol, original: OperationObservation) {
    if (token !== handleToken) throw new Error("owner_unavailable"); handles.set(this, original); Object.freeze(this);
  }
  status(options?: OperationOptions): Promise<V4TopUpResult> { return handles.get(this)!.source.topUpStatus(this, options); }
  cleanupStatus(): V4CleanupStatus { return operationCleanup(handles.get(this)!); }
  waitCleanup(options: OperationOptions = {}): Promise<V4CleanupStatus> {
    const original = handles.get(this)!;
    options.signal?.throwIfAborted();
    if (original.active === 0) return Promise.resolve(operationCleanup(original));
    if (original.waiters.size >= 8) return Promise.reject(new Error("capacity_exhausted"));
    return new Promise((resolve, reject) => {
      const finish = (): void => { original.waiters.delete(finish); options.signal?.removeEventListener("abort", cancel); resolve(operationCleanup(original)); };
      const cancel = (): void => { original.waiters.delete(finish); options.signal?.removeEventListener("abort", cancel); reject(new Error("canceled")); };
      original.waiters.add(finish); options.signal?.addEventListener("abort", cancel, { once: true });
      if (options.signal?.aborted) cancel(); else if (original.active === 0) finish();
    });
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.TopUpHandle"; }
}
function failure(code: V4TopUpErrorCode): never { throw new Error(code); }
function fixed(bytes: Uint8Array, length: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length || !bytes.some(byte => byte !== 0)) failure("source_contract_invalid"); return new Uint8Array(bytes);
}
function bytes(doc: CBORDocument, node: number, length?: number): Uint8Array {
  if (node < 0 || doc.kind(node) !== "bytes" || length !== undefined && doc.size(node) !== length) failure("source_contract_invalid");
  const value = new Uint8Array(doc.size(node)); doc.copyPayload(node, value); return value;
}
const stateNames: readonly V4TopUpState[] = ["pending", "installed", "acked", "terminal"];
function snapshot(buffer: Uint8Array, tenant: string, incarnation: Uint8Array, journal: Journal): Uint8Array {
  const writer = new FixedCBORWriter(buffer).map(journal.pending === undefined ? 9 : 10);
  writer.uint(0).uint(2).uint(1).data(new TextEncoder().encode(tenant), true).uint(2).data(incarnation)
    .uint(3).uint(journal.next).uint(4).uint(journal.retired).uint(5).uint(journal.frontier);
  const pending = journal.pending;
  if (pending !== undefined) {
    const optional = [pending.responseDigest, pending.highest, pending.gap, pending.retired, pending.error, pending.applied].filter(value => value !== undefined).length;
    writer.uint(6).map(12 + optional).uint(0).data(pending.id).uint(1).uint(stateNames.indexOf(pending.state)).uint(2).uint(pending.desired)
      .uint(3).uint(pending.maximum).uint(4).data(pending.pool).uint(5).uint(pending.generation).uint(6).uint(pending.deadline)
      .uint(7).data(pending.certificate).uint(8).data(pending.identity).uint(9).data(pending.requestDigest);
    if (pending.responseDigest !== undefined) writer.uint(10).data(pending.responseDigest);
    if (pending.highest !== undefined) writer.uint(11).uint(pending.highest);
    if (pending.gap !== undefined) writer.uint(12).bool(pending.gap);
    if (pending.retired !== undefined) writer.uint(13).uint(pending.retired);
    if (pending.error !== undefined) writer.uint(14).data(new TextEncoder().encode(pending.error), true);
    if (pending.applied !== undefined) {
      writer.uint(15).array(pending.applied.length);
      for (const entry of pending.applied) writer.map(5).uint(0).uint(entry.sequence).uint(1).uint(entry.generation).uint(2).uint(entry.expiry)
        .uint(3).data(entry.digest).uint(4).data(entry.identity);
    }
    writer.uint(16).uint(pending.frontier).uint(17).uint(pending.attemptGeneration);
  }
  writer.uint(7).array(journal.materials.length);
  for (const material of journal.materials) writer.map(6).uint(0).uint(material.sequence).uint(1).uint(material.generation).uint(2).uint(material.expiry)
    .uint(3).data(material.bytes).uint(4).data(material.digest).uint(5).data(material.identity);
  writer.uint(8).bool(journal.fenced).uint(9).array(journal.applied.length);
  for (const entry of journal.applied) writer.map(5).uint(0).uint(entry.sequence).uint(1).uint(entry.generation).uint(2).uint(entry.expiry)
    .uint(3).data(entry.digest).uint(4).data(entry.identity);
  return writer.result();
}
/** Public acquisition and TopUp share one original durable pool owner. The
 * observation handle contains only immutable ID; it cannot send or reinstall. */
export class V4PreauthorizedPoolSource implements V4ConnectionMaterialSource {
  readonly #environment: V4EnvironmentRuntime;
  readonly #policy: V4CredentialPolicy;
  readonly #store: PoolJournalStore;
  readonly #configuration: V4PoolSourceConfiguration;
  readonly #keys: IdentityKeys;
  readonly #dependency: EnvironmentDependency;
  readonly #identityDigest: Uint8Array;
  #source!: V4EnvironmentCredentialSource;
  #journal!: Journal;
  #encoded: Uint8Array | undefined;
  #closed = false;
  #working: Promise<V4TopUpResult> | undefined;
  #active = 0;
  #mutation = false;
  #claim: string | undefined;
  readonly #abort = new AbortController();
  readonly #cleanupWaiters = new Set<() => void>();
  readonly #observations = new Map<string, OperationObservation>();
  #runningObservation: OperationObservation | undefined;
  /** @internal */
  constructor(token: symbol, environment: V4EnvironmentRuntime, policy: V4CredentialPolicy, store: PoolJournalStore, configuration: V4PoolSourceConfiguration, keys: IdentityKeys) {
    if (token !== sourceToken) failure("source_contract_invalid");
    this.#environment = environment; this.#policy = Object.freeze({ ...policy, cryptoProfiles: Object.freeze([...policy.cryptoProfiles]), authorities: Object.freeze([...policy.authorities]) }); this.#store = store; this.#keys = Object.freeze({ signingPublicKey: new Uint8Array(keys.signingPublicKey), noisePublicKey: new Uint8Array(keys.noisePublicKey), check: keys.check });
    this.#configuration = Object.freeze({ ...configuration, control: Object.freeze({ exchange: configuration.control.exchange.bind(configuration.control) }), sourceIncarnation: fixed(configuration.sourceIncarnation, 16), poolDigest: fixed(configuration.poolDigest, 32),
      identityCertificate: new Uint8Array(configuration.identityCertificate), fenceAuthorityKeyID: fixed(configuration.fenceAuthorityKeyID, 16), fenceAuthorityPublicKey: fixed(configuration.fenceAuthorityPublicKey, 32) });
    if (configuration.identityCertificate.length < 1 || configuration.identityCertificate.length > 8192 || configuration.operationLifetimeMS < 1n || configuration.callTimeoutMS < 1n ||
        configuration.operationLifetimeMS > 86400000n || configuration.callTimeoutMS > 120000n ||
        typeof configuration.providerRuntimeBytes !== "bigint" || configuration.providerRuntimeBytes < 1n ||
        !Number.isSafeInteger(configuration.maximumMaterials ?? 8) || (configuration.maximumMaterials ?? 8) < 4 || (configuration.maximumMaterials ?? 8) > 16) failure("configuration_capacity");
    originalPoolJournal(store, environment); keys.check();
    this.#dependency = environment.admitDependency("durable_pool_source", new ResourceVector([4194304n + environment.resources.runtimeBytes, configuration.providerRuntimeBytes, 0n, 4n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]));
    this.#dependency.onClose(() => this.close());
    try {
      this.#identityDigest = credentialDigest("certificate_digest", this.#configuration.identityCertificate);
      this.#parse("IdentityCertificate", this.#configuration.identityCertificate, certificate => {
        if (certificate.text("tenant_id") !== policy.tenant || certificate.text("subject_id") !== policy.clientSubject || certificate.uint("role") !== 0n ||
            certificate.text("audience") !== policy.audience || !equalCredential(certificate.bytes("ed25519_public_key"), keys.signingPublicKey) ||
            !equalCredential(certificate.bytes("public_key_bytes", certificate.field("noise_static_public_key"), "NoiseStaticPublicKey"), keys.noisePublicKey)) failure("source_contract_invalid");
      });
    } catch (error) { this.#dependency.close(); this.#dependency.release(); throw error; }
  }
  #check(): void {
    if (this.#closed) failure("source_unavailable"); this.#dependency.check(); this.#keys.check(); originalPoolJournal(this.#store, this.#environment);
  }
  #parse<T>(schema: string | undefined, encoded: Uint8Array, read: (map: OwnedCredentialMap, work: CredentialWork) => T): T {
    const resources = this.#environment.resources, cap = Math.max(8192, encoded.length);
    const ref = resources.root.reserve({ owner: credentialOwner(resources, "pool_codec"), accounts: resources.accounts, charge: credentialWorkCharge(cap, resources.runtimeBytes) });
    const work = new CredentialWork(resources, cap, ref); ref.release(); let map: OwnedCredentialMap | undefined;
    try { map = schema === undefined ? work.parseRecord(encoded, cap, 8192) : work.parse(encoded, schema, cap, 8192, {}); return read(map, work); }
    finally { map?.close(); work.close(); }
  }
  #decode(encoded: Uint8Array): Journal {
    return this.#parse(undefined, encoded, ({ doc }) => {
      const field = (id: number, node = 0): number => { const result = doc.field(node, id); if (result < 0) failure("source_state_unknown"); return result; };
      if (doc.uint(field(0)) !== 2n || doc.text(field(1)) !== this.#policy.tenant || !equalCredential(bytes(doc, field(2), 16), this.#configuration.sourceIncarnation) || doc.size(0) < 9 || doc.size(0) > 10) failure("source_state_unknown");
      const result: Journal = { next: doc.uint(field(3)), retired: doc.uint(field(4)), frontier: doc.uint(field(5)), applied: [], materials: [], fenced: doc.boolean(field(8)) };
      if (result.next < 1n || result.retired >= result.next) failure("source_state_unknown");
      const appliedRoot = field(9);
      if (doc.kind(appliedRoot) !== "array" || doc.size(appliedRoot) > 64) failure("source_state_unknown");
      let previousApplied = 0n;
      for (let item = doc.firstChild(appliedRoot); item >= 0; item = doc.nextSibling(item)) {
        if (doc.size(item) !== 5) failure("source_state_unknown");
        const entry: AppliedEntry = { sequence: doc.uint(field(0, item)), generation: doc.uint(field(1, item)), expiry: doc.uint(field(2, item)), digest: bytes(doc, field(3, item), 32), identity: bytes(doc, field(4, item), 32) };
        if (entry.sequence <= previousApplied || entry.sequence > result.frontier || entry.generation === 0n || entry.generation > originalPoolJournal(this.#store, this.#environment).generation() || entry.expiry === 0n || !entry.digest.some(byte => byte !== 0) || !entry.identity.some(byte => byte !== 0)) failure("source_state_unknown");
        previousApplied = entry.sequence; result.applied.push(entry);
      }
      if (result.frontier !== 0n && (result.applied.length === 0 || result.applied.at(-1)?.sequence !== result.frontier)) failure("source_state_unknown");
      const pendingNode = doc.field(0, 6);
      if (doc.size(0) >= 10 && pendingNode < 0) failure("source_state_unknown");
      if (pendingNode >= 0) {
        const state = stateNames[Number(doc.uint(field(1, pendingNode)))]; if (state === undefined) failure("source_state_unknown");
        const pending: Pending = { id: bytes(doc, field(0, pendingNode), 16), state, desired: Number(doc.uint(field(2, pendingNode))), maximum: Number(doc.uint(field(3, pendingNode))),
          pool: bytes(doc, field(4, pendingNode), 32), generation: doc.uint(field(5, pendingNode)), deadline: doc.uint(field(6, pendingNode)), attemptGeneration: doc.uint(field(17, pendingNode)), frontier: doc.uint(field(16, pendingNode)),
          certificate: bytes(doc, field(7, pendingNode)), identity: bytes(doc, field(8, pendingNode), 32), requestDigest: bytes(doc, field(9, pendingNode), 32) };
        if (pending.desired < 1 || pending.desired > 4 || pending.maximum < 1 || pending.maximum > 65536 || pending.certificate.length > 8192 || pending.generation === 0n || pending.generation > pending.attemptGeneration || pending.attemptGeneration > originalPoolJournal(this.#store, this.#environment).generation() || pending.frontier > result.frontier ||
            !equalCredential(credentialDigest("certificate_digest", pending.certificate), pending.identity)) failure("source_state_unknown");
        const digestNode = doc.field(pendingNode, 10), highestNode = doc.field(pendingNode, 11), gapNode = doc.field(pendingNode, 12), retiredNode = doc.field(pendingNode, 13), errorNode = doc.field(pendingNode, 14);
        if (digestNode >= 0) pending.responseDigest = bytes(doc, digestNode, 32);
        if (highestNode >= 0) pending.highest = doc.uint(highestNode);
        if (gapNode >= 0) pending.gap = doc.boolean(gapNode);
        if (retiredNode >= 0) pending.retired = doc.uint(retiredNode);
        if (errorNode >= 0) {
          const code = doc.text(errorNode) as V4TopUpErrorCode;
          if (topUpErrorProjection(code, "terminal") === undefined) failure("source_state_unknown"); pending.error = code;
        }
        const appliedNode = doc.field(pendingNode, 15);
        if (appliedNode >= 0) {
          if (doc.kind(appliedNode) !== "array" || doc.size(appliedNode) !== pending.desired) failure("source_state_unknown");
          pending.applied = [];
          for (let item = doc.firstChild(appliedNode); item >= 0; item = doc.nextSibling(item)) {
            if (doc.size(item) !== 5) failure("source_state_unknown");
            pending.applied.push({ sequence: doc.uint(field(0, item)), generation: doc.uint(field(1, item)), expiry: doc.uint(field(2, item)),
              digest: bytes(doc, field(3, item), 32), identity: bytes(doc, field(4, item), 32) });
          }
        }
        if ((state === "installed" || state === "acked") && (pending.responseDigest === undefined || pending.highest === undefined || pending.gap === undefined || pending.gap !== (pending.retired !== undefined) || pending.applied === undefined)) failure("source_state_unknown");
        if (state === "pending" && (pending.frontier !== result.frontier || [pending.responseDigest, pending.highest, pending.gap, pending.retired, pending.error, pending.applied].some(value => value !== undefined)) || state === "terminal" && pending.error === undefined) failure("source_state_unknown");
        if (pending.applied !== undefined) {
          if (pending.highest === undefined || pending.highest !== result.frontier || pending.highest < BigInt(pending.desired)) failure("source_state_unknown");
          let expected = pending.highest - BigInt(pending.desired) + 1n;
          if (pending.retired === undefined ? expected !== pending.frontier + 1n : pending.retired < pending.frontier || expected !== pending.retired + 1n) failure("source_state_unknown");
          let appliedGeneration = 0n;
          for (const entry of pending.applied) {
            if (entry.sequence !== expected++ || entry.sequence > result.frontier || entry.generation < pending.generation ||
                entry.generation > pending.attemptGeneration || entry.expiry === 0n ||
                !entry.digest.some(byte => byte !== 0) || !equalCredential(entry.identity, pending.identity)) failure("source_state_unknown");
            if (appliedGeneration === 0n) appliedGeneration = entry.generation;
            else if (appliedGeneration !== entry.generation) failure("source_state_unknown");
            const receipt = result.applied.find(original => original.sequence === entry.sequence);
            if (receipt === undefined || receipt.generation !== entry.generation || receipt.expiry !== entry.expiry ||
                !equalCredential(receipt.digest, entry.digest) || !equalCredential(receipt.identity, entry.identity)) failure("source_state_unknown");
          }
        }
        const sequence = new DataView(pending.id.buffer, pending.id.byteOffset, 8).getBigUint64(0);
        if (sequence + 1n !== result.next || sequence <= result.retired && state !== "acked" && state !== "terminal") failure("source_state_unknown");
        const intent = new Uint8Array(16384), requestDigest = sha256(this.#intent(pending, new FixedCBORWriter(intent))); intent.fill(0);
        if (!equalCredential(requestDigest, pending.requestDigest) || doc.size(pendingNode) !== 12 +
          [pending.responseDigest, pending.highest, pending.gap, pending.retired, pending.error, pending.applied].filter(value => value !== undefined).length) failure("source_state_unknown");
        result.pending = pending;
      }
      const array = field(7); if (doc.kind(array) !== "array" || doc.size(array) > (this.#configuration.maximumMaterials ?? 8)) failure("source_state_unknown");
      let previous = 0n;
      for (let item = doc.firstChild(array); item >= 0; item = doc.nextSibling(item)) {
        const material: Material = { sequence: doc.uint(field(0, item)), generation: doc.uint(field(1, item)), expiry: doc.uint(field(2, item)),
          bytes: bytes(doc, field(3, item)), digest: bytes(doc, field(4, item), 32), identity: bytes(doc, field(5, item), 32) };
        if (doc.size(item) !== 6 || material.sequence <= previous || material.sequence > result.frontier || material.bytes.length > 65536 || !equalCredential(sha256(material.bytes), material.digest)) failure("source_state_unknown");
        const receipt = result.applied.find(entry => entry.sequence === material.sequence);
        if (receipt === undefined || (receipt.generation !== material.generation || receipt.expiry !== material.expiry ||
            !equalCredential(receipt.digest, material.digest) || !equalCredential(receipt.identity, material.identity))) failure("source_state_unknown");
        previous = material.sequence; result.materials.push(material);
      }
      return result;
    });
  }
  /** @internal */
  async initialize(): Promise<this> {
    this.#check(); this.#active++;
    const claim = Array.from(this.#configuration.sourceIncarnation, byte => byte.toString(16).padStart(2, "0")).join("");
    let original = claims.get(this.#store); if (original === undefined) { original = new Map(); claims.set(this.#store, original); }
    if (original.has(claim)) { this.#active--; this.close(); failure("operation_conflict"); }
    original.set(claim, this); this.#claim = claim;
    try {
      const value = await this.#store.readPoolJournal(this.#configuration.sourceIncarnation, () => this.#check());
      if (this.#configuration.create) {
        if (value !== undefined) failure("source_state_unknown");
        this.#journal = { next: 1n, retired: 0n, frontier: 0n, applied: [], materials: [], fenced: false }; await this.#commit(this.#journal);
      } else { if (value === undefined) failure("source_state_unknown"); this.#encoded = value; this.#journal = this.#decode(value); }
      this.#source = this.#environment.registerSource(this.#policy, "preauthorized_pool", (request, buffers) => this.#acquireInstalled(request.signal, buffers));
      bindCredentialSourceFacade(this.#source, this); Object.freeze(this); return this;
    } catch (error) { this.close(); throw error; } finally { this.#active--; this.#collect(); }
  }
  async #commit(next: Journal, check?: () => void): Promise<void> {
    this.#check(); if (this.#mutation) failure("operation_conflict"); this.#mutation = true;
    const buffer = new Uint8Array(1048576);
    try {
      const encoded = snapshot(buffer, this.#policy.tenant, this.#configuration.sourceIncarnation, next);
      await this.#store.comparePoolJournal(this.#configuration.sourceIncarnation, this.#encoded, encoded, () => { this.#check(); check?.(); });
      this.#encoded?.fill(0); this.#encoded = new Uint8Array(encoded); this.#journal = next;
      if (next.pending !== undefined) {
        const id = Array.from(next.pending.id, byte => byte.toString(16).padStart(2, "0")).join("");
        if (this.#observations.has(id)) this.#operation(next.pending);
      }
    } catch (error) {
      if ((error as { writeState?: string }).writeState === "unknown" || (error as { writeState?: string }).writeState === "committed") this.close();
      throw error;
    } finally { buffer.fill(0); this.#mutation = false; }
  }
  acquire(requirements: V4ConnectionRequirements, options?: OperationOptions): Promise<V4ConnectionMaterial> {
    this.#check(); return this.#source.acquire(requirements, options).then(owner => new V4ConnectionMaterial(owner));
  }
  async #acquireInstalled(signal: AbortSignal, buffers: V4CredentialBuffers): Promise<V4CredentialLengths> {
    this.#active++; let removed: Material | undefined;
    try {
    this.#check(); if (this.#journal.fenced) failure("source_state_unknown"); signal.throwIfAborted();
    if (this.#mutation) failure("source_unavailable");
    const now = this.#environment.clock.sample().requireInterval();
    const material = this.#journal.materials.find(entry => entry.expiry > now.upperMS && equalCredential(entry.identity, this.#identityDigest));
    if (material === undefined) failure("source_exhausted");
    const decoded = this.#configuration.decodeMaterial(material.bytes);
    if (!equalCredential(decoded.clientCertificate, this.#configuration.identityCertificate)) failure("relink_required");
    // Remove availability durably before exposing bytes. Uncertain storage never
    // makes this artifact available again, including after process recovery.
    await this.#commit({ ...this.#journal, materials: this.#journal.materials.filter(entry => entry !== material) }); removed = material; signal.throwIfAborted();
    const lengths: V4CredentialLengths = { artifact: decoded.artifact.length, clientCertificate: decoded.clientCertificate.length,
      ...(decoded.poolServerAllow === undefined ? {} : { poolServerAllow: decoded.poolServerAllow }),
      serverCertificate: decoded.serverCertificate.length, activation: decoded.activation?.length ?? 0, candidateIndex: decoded.candidateIndex };
    for (const name of ["artifact", "clientCertificate", "serverCertificate", "activation"] as const) {
      const value = decoded[name]; if (value !== undefined) { if (value.length > buffers[name].length) failure("source_contract_invalid"); buffers[name].set(value); }
    }
    if (decoded.tunnel !== undefined) {
      const grant = decoded.tunnel.grant ?? new Uint8Array(), certificate = decoded.tunnel.relayCertificate;
      if (grant.length > buffers.tunnelGrant.length || certificate.length > buffers.relayCertificate.length) failure("source_contract_invalid");
      buffers.tunnelGrant.set(grant); buffers.relayCertificate.set(certificate);
      const candidates = decoded.tunnel.candidateGrants ?? [];
      if (candidates.length > (buffers.tunnelCandidates?.length ?? 0)) failure("source_contract_invalid");
      const tunnelCandidates = candidates.map((candidate, index) => {
        const destination = buffers.tunnelCandidates![index]!;
        if (candidate.grant.length > destination.grant.length || candidate.relayCertificate.length > destination.relayCertificate.length) failure("source_contract_invalid");
        destination.grant.set(candidate.grant); destination.relayCertificate.set(candidate.relayCertificate);
        return Object.freeze({ candidateIndex: candidate.candidateIndex, grant: candidate.grant.length, relayCertificate: candidate.relayCertificate.length });
      });
      return { ...lengths, tunnelGrant: grant.length, relayCertificate: certificate.length, tunnelCandidates: Object.freeze(tunnelCandidates) };
    } return lengths;
    } finally { removed?.bytes.fill(0); this.#active--; this.#collect(); }
  }
  cleanupStatus(): V4CleanupStatus { return Object.freeze({ status: this.#active === 0 ? "complete" : "pending", core_cleanup: this.#active === 0 ? "complete" : "pending", pending_callbacks: BigInt(this.#active) }); }
  #operation(pending: Pending): OperationObservation {
    const key = Array.from(pending.id, byte => byte.toString(16).padStart(2, "0")).join("");
    let original = this.#observations.get(key);
    if (original === undefined) {
      // Completed older owners are retained by their own handles, rather than
      // by an ever-growing source registry. Only active tails stay registered.
      for (const [id, entry] of this.#observations) if (entry.active === 0) this.#observations.delete(id);
      if (this.#observations.size >= 8 || pending.state === "terminal") failure("capacity_exhausted");
      original = { source: this, id: new Uint8Array(pending.id), desired: pending.desired, maximum: pending.maximum,
        state: pending.state, active: 0, handle: undefined as unknown as V4TopUpHandle, waiters: new Set() };
      original.handle = new V4TopUpHandle(handleToken, original); this.#observations.set(key, original);
    }
    original.state = pending.state; original.error = pending.error;
    if (pending.responseDigest !== undefined) original.responseDigest = new Uint8Array(pending.responseDigest);
    return original;
  }
  #observe(pending: Pending | undefined, error?: V4TopUpResult["callError"]): V4TopUpResult {
    if (pending !== undefined) return operationResult(this.#operation(pending), error);
    return Object.freeze({ ...(error === undefined ? {} : { callError: error }), cleanupStatus: this.cleanupStatus() });
  }
  async topUp(options: V4TopUpOptions = {}, wait: OperationOptions = {}): Promise<V4TopUpResult> {
    try {
      this.#check(); wait.signal?.throwIfAborted();
      const desired = options.desiredCount ?? 4, maximum = options.maxItemBytes ?? 65536;
      if (!Number.isSafeInteger(desired) || desired < 1 || desired > 4 || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > 65536) failure("configuration_capacity");
      if (this.#working === undefined) {
        this.#active++;
        this.#working = this.#run(desired, maximum).catch(error => this.#observe(this.#journal.pending, this.#error(error))).then(result => {
          const original = this.#runningObservation; this.#runningObservation = undefined;
          this.#working = undefined; this.#active--; if (original !== undefined) original.active--; this.#collect();
          return Object.freeze({ ...result, cleanupStatus: result.handle?.cleanupStatus() ?? this.cleanupStatus() });
        });
      }
      return await this.#wait(this.#working, wait.signal);
    } catch (error) { return this.#observe(undefined, this.#error(error)); }
  }
  async topUpStatus(handle: V4TopUpHandle, wait: OperationOptions = {}): Promise<V4TopUpResult> {
    // Capture the original operation's proven projection before cancellation,
    // source lifecycle or current-journal checks can fail.
    const original = handles.get(handle);
    if (original?.source !== this) return this.#observe(undefined, "stale_operation");
    if (this.#active >= 8) return operationResult(original, "capacity_exhausted");
    this.#active++; original.active++;
    let error: V4TopUpResult["callError"];
    try {
      this.#check(); wait.signal?.throwIfAborted(); const pending = this.#journal.pending;
      if (pending === undefined || !equalCredential(original.id, pending.id)) failure("stale_operation");
      original.state = pending.state; original.error = pending.error;
      if (pending.responseDigest !== undefined) original.responseDigest = new Uint8Array(pending.responseDigest);
      await this.#proof(pending, this.#observationSignal(wait.signal), original); wait.signal?.throwIfAborted();
      const current = this.#journal.pending;
      if (current !== undefined && equalCredential(original.id, current.id)) { original.state = current.state; original.error = current.error; if (current.responseDigest !== undefined) original.responseDigest = new Uint8Array(current.responseDigest); }
    } catch (failure) { error = this.#error(failure); }
    finally { original.active--; this.#active--; this.#collect(); operationSettled(original); }
    return operationResult(original, error);
  }
  async recoverPendingTopUps(tenant: string, incarnation: Uint8Array, wait: OperationOptions = {}): Promise<Readonly<{ handles: readonly V4TopUpHandle[]; callError?: V4TopUpResult["callError"] }>> {
    if (this.#active >= 8) return Object.freeze({ handles: Object.freeze([]), callError: "capacity_exhausted" });
    this.#active++; let observation: OperationObservation | undefined;
    try {
      this.#check(); wait.signal?.throwIfAborted();
      if (tenant !== this.#policy.tenant || !equalCredential(incarnation, this.#configuration.sourceIncarnation)) failure("permission_denied");
      const pending = this.#journal.pending;
      if (pending === undefined || pending.state === "terminal" || pending.state === "acked") return Object.freeze({ handles: Object.freeze([]) });
      observation = this.#operation(pending); observation.active++;
      await this.#proof(pending, this.#observationSignal(wait.signal), observation); wait.signal?.throwIfAborted();
      return Object.freeze({ handles: Object.freeze([observation.handle]) });
    } catch (error) { return Object.freeze({ handles: Object.freeze([]), callError: this.#error(error) }); }
    finally { if (observation !== undefined) observation.active--; this.#active--; this.#collect(); if (observation !== undefined) operationSettled(observation); }
  }
  #observationSignal(signal?: AbortSignal): AbortSignal {
    return AbortSignal.any([this.#abort.signal, AbortSignal.timeout(Number(this.#configuration.callTimeoutMS)), ...(signal === undefined ? [] : [signal])]);
  }
  async #proof(pending: Pending, signal: AbortSignal, observation: OperationObservation): Promise<{ bytes: Uint8Array; generation: bigint }> {
    this.#check(); const generation = originalPoolJournal(this.#store, this.#environment).generation();
    signal.throwIfAborted();
    const proofEnd = this.#environment.clock.sample().requireInterval().lowerMS + this.#configuration.callTimeoutMS;
    const proof = await this.#borrow(() => this.#configuration.ownerFenceProof(Object.freeze({ tenant: this.#policy.tenant,
      sourceIncarnation: new Uint8Array(this.#configuration.sourceIncarnation), operationID: new Uint8Array(pending.id),
      requestDigest: new Uint8Array(pending.requestDigest), currentGeneration: generation, deadlineMS: proofEnd }), signal), signal, observation);
    this.#check(); signal.throwIfAborted();
    if (proof.length > 512 || generation !== originalPoolJournal(this.#store, this.#environment).generation()) failure("stale_generation");
    this.#parse("OwnerFenceProof", proof, (map, work) => {
      work.verify(map, this.#configuration.fenceAuthorityPublicKey);
      const now = this.#environment.clock.sample().requireInterval();
      if (map.text("tenant_id") !== this.#policy.tenant || !equalCredential(map.bytes("source_incarnation"), this.#configuration.sourceIncarnation) ||
          !equalCredential(map.bytes("operation_id"), pending.id) || !equalCredential(map.bytes("request_digest"), pending.requestDigest) ||
          map.uint("current_generation") !== generation || !equalCredential(map.bytes("authority_key_id"), this.#configuration.fenceAuthorityKeyID) ||
          map.uint("issued_at_ms") > now.lowerMS || map.uint("expires_at_ms") <= now.upperMS || map.uint("expires_at_ms") > proofEnd) failure("permission_denied");
    }); return { bytes: new Uint8Array(proof), generation };
  }
  #intent(pending: Pending, writer: FixedCBORWriter): Uint8Array {
    return writer.map(8).uint(0).data(pending.id).uint(1).data(new TextEncoder().encode(this.#policy.tenant), true)
      .uint(2).data(this.#configuration.sourceIncarnation).uint(3).uint(pending.desired).uint(4).uint(pending.maximum)
      .uint(5).data(pending.pool).uint(8).uint(pending.deadline).uint(9).data(pending.identity).result();
  }
  async #run(desired: number, maximum: number): Promise<V4TopUpResult> {
    this.#check(); if (this.#journal.fenced) failure("source_state_unknown");
    let pending = this.#journal.pending, observation: OperationObservation;
    if (pending === undefined || pending.state === "acked" || pending.state === "terminal") {
      if (this.#journal.next === 0xffffffffffffffffn) failure("source_reset_required");
      const interval = this.#environment.clock.sample().requireInterval(), id = new Uint8Array(16), generation = originalPoolJournal(this.#store, this.#environment).generation();
      new DataView(id.buffer).setBigUint64(0, this.#journal.next); crypto.getRandomValues(id.subarray(8));
      pending = { id, state: "pending", desired, maximum, pool: new Uint8Array(this.#configuration.poolDigest),
        generation, attemptGeneration: generation, frontier: this.#journal.frontier, deadline: interval.lowerMS + this.#configuration.operationLifetimeMS,
        certificate: new Uint8Array(this.#configuration.identityCertificate), identity: new Uint8Array(this.#identityDigest), requestDigest: new Uint8Array(32) };
      const intent = new Uint8Array(16384); pending.requestDigest = sha256(this.#intent(pending, new FixedCBORWriter(intent))); intent.fill(0);
      observation = this.#operation(pending); observation.active++; this.#runningObservation = observation;
      await this.#commit({ ...this.#journal, next: this.#journal.next + 1n, pending });
    } else { observation = this.#operation(pending); observation.active++; this.#runningObservation = observation; }
    // The original append authority remains pending.deadline in the persisted
    // intent and wire request. A separate bounded call window lets the same ID
    // read a committed replay or authoritative terminal after a lost response,
    // without renewing that append deadline or allocating another operation.
    // Installed recovery uses only Applied facts and current fence authority.
    const now = this.#environment.clock.sample().requireInterval();
    const callEnd = now.lowerMS + this.#configuration.callTimeoutMS;
    const deadline = new TrustedDeadline(this.#environment.clock, callEnd);
    deadline.check();
    const stop = new AbortController(), onClose = () => stop.abort(); this.#abort.signal.addEventListener("abort", onClose, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = (): void => { try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch { stop.abort(); } }; tick();
    let proof: { bytes: Uint8Array; generation: bigint } | undefined;
    const buffer = new Uint8Array(524288);
    try {
      proof = await this.#proof(pending, stop.signal, observation); deadline.check();
      if (pending.state === "pending") {
        if (!equalCredential(pending.certificate, this.#configuration.identityCertificate) || !equalCredential(pending.identity, this.#identityDigest)) failure("relink_required");
        const writer = new FixedCBORWriter(buffer).map(10);
        writer.uint(0).data(pending.id).uint(1).data(new TextEncoder().encode(this.#policy.tenant), true).uint(2).data(this.#configuration.sourceIncarnation)
          .uint(3).uint(pending.desired).uint(4).uint(pending.maximum).uint(5).data(pending.pool).uint(6).uint(proof.generation)
          .uint(7).data(proof.bytes).uint(8).uint(pending.deadline).uint(9).data(pending.identity);
        pending = await this.#persistAttempt(pending, proof.generation); deadline.check();
        const response = await this.#exchange(41006, writer.result(), stop.signal, observation);
        this.#check(); deadline.check();
        if (response.kind === "error") return await this.#wireError(pending, response.error);
        if (response.kind !== "success" && response.kind !== "replay") failure("source_contract_invalid");
        pending = await this.#apply(pending, response.response); buffer.fill(0);
      }
      proof.bytes.fill(0); proof = await this.#proof(pending, stop.signal, observation);
      const currentProof = proof, writer = new FixedCBORWriter(buffer).reset().map(pending.retired === undefined ? 9 : 10);
      writer.uint(0).data(pending.id).uint(1).data(pending.pool).uint(2).data(pending.responseDigest!).uint(3).uint(pending.highest!).uint(4).bool(pending.gap!);
      if (pending.retired !== undefined) writer.uint(5).uint(pending.retired);
      writer.uint(6).bool(true).uint(7).data(pending.requestDigest).uint(8).uint(currentProof.generation).uint(9).data(currentProof.bytes);
      pending = await this.#persistAttempt(pending, currentProof.generation); deadline.check();
      const ack = await this.#exchange(41007, writer.result(), stop.signal, observation); this.#check(); deadline.check();
      if (ack.kind === "error") return await this.#wireError(pending, ack.error);
      if (ack.kind !== "acknowledged") failure("source_contract_invalid");
      pending = { ...pending, state: "acked" };
      const sequence = new DataView(pending.id.buffer, pending.id.byteOffset, 8).getBigUint64(0);
      await this.#commit({ ...this.#journal, pending, retired: sequence }); return this.#observe(pending);
    } finally { if (timer !== undefined) clearTimeout(timer); this.#abort.signal.removeEventListener("abort", onClose); buffer.fill(0); proof?.bytes.fill(0); }
  }
  async #persistAttempt(pending: Pending, generation: bigint): Promise<Pending> {
    // One durable high-water fence bounds all possible sends of this intent.
    // A commit refusal sends nothing; an unknown commit closes this owner and
    // leaves its persisted Pending facts for explicit recovery after restart.
    const check = (): void => {
      if (generation < pending.attemptGeneration || generation !== originalPoolJournal(this.#store, this.#environment).generation()) failure("stale_generation");
    };
    check();
    if (this.#journal.pending !== pending) failure("operation_conflict");
    const attempt = { ...pending, attemptGeneration: generation };
    await this.#commit({ ...this.#journal, pending: attempt }, check);
    check();
    return attempt;
  }
  async #wireError(pending: Pending, error: V4TopUpError): Promise<V4TopUpResult> {
    const projection = topUpErrorProjection(error.code, error.write_action);
    if (projection === undefined || projection.scope !== error.scope) failure("source_contract_invalid");
    if (error.write_action === "terminal") {
      const terminal = { ...pending, state: "terminal" as const, error: error.code };
      const { pending: removed, ...journal } = this.#journal; void removed;
      await this.#commit({ ...journal, retired: new DataView(pending.id.buffer, pending.id.byteOffset, 8).getBigUint64(0) });
      return this.#observe(terminal, error.code);
    } return this.#observe(pending, error.code);
  }
  async #apply(pending: Pending, encoded: Uint8Array): Promise<Pending> {
    if (encoded.length > 524288 || pending.attemptGeneration < pending.generation || pending.attemptGeneration > originalPoolJournal(this.#store, this.#environment).generation()) failure("source_contract_invalid");
    const applied = this.#parse("TopUpResponse", encoded, map => {
      const bindingGeneration = map.uint("binding_generation");
      // Authenticated replay can name any server commit generation between
      // local intent creation and the highest durably committed attempt. A G1
      // intent may first commit at G2 and replay under G3. Preserve creation
      // generation while pinning the response generation in Applied/material
      // facts; every entry must match that same response generation.
      if (bindingGeneration < pending.generation || bindingGeneration > pending.attemptGeneration ||
          !equalCredential(map.bytes("operation_id"), pending.id) || map.text("tenant_id") !== this.#policy.tenant ||
          !equalCredential(map.bytes("source_incarnation"), this.#configuration.sourceIncarnation) || !map.doc.boolean(map.field("server_committed"))) failure("source_contract_invalid");
      const projection = new Uint8Array(encoded.length), size = map.doc.copyWithoutField(9, projection), digest = sha256(projection.subarray(0, size)); projection.fill(0);
      if (!equalCredential(digest, map.bytes("response_digest"))) failure("source_contract_invalid");
      const materials: Material[] = [], gap = map.doc.boolean(map.field("gap_authorized")), retiredNode = map.optional("retired_artifact_through");
      const retired = retiredNode < 0 ? undefined : map.doc.uint(retiredNode), highest = map.uint("server_highest_artifact_sequence");
      if (this.#journal.frontier !== pending.frontier || gap !== (retired !== undefined) || retired !== undefined && retired < pending.frontier) failure("sequence_gap");
      let expected = gap ? retired! + 1n : pending.frontier + 1n;
      for (const node of map.items("entries")) {
        const bytes = map.bytes("material", node, "TopUpEntry");
        const entry: Material = { bytes, sequence: map.uint("artifact_sequence", node, "TopUpEntry"), generation: map.uint("binding_generation", node, "TopUpEntry"),
          expiry: map.uint("expiry_ms", node, "TopUpEntry"), digest: map.bytes("material_digest", node, "TopUpEntry"), identity: map.bytes("client_identity_digest", node, "TopUpEntry") };
        if (entry.sequence !== expected++ || entry.generation !== bindingGeneration || entry.bytes.length + canonicalHeadBytes(BigInt(entry.bytes.length)) > pending.maximum ||
            !equalCredential(sha256(entry.bytes), entry.digest) || !equalCredential(entry.identity, pending.identity)) failure("source_contract_invalid");
        materials.push(entry);
      }
      if (materials.length !== pending.desired || expected - 1n !== highest || this.#journal.materials.length + materials.length > (this.#configuration.maximumMaterials ?? 8)) failure("capacity_exhausted");
      return { materials, pending: { ...pending, state: "installed" as const, responseDigest: digest, highest, gap,
        applied: materials.map(({ sequence, generation, expiry, digest, identity }) => ({ sequence, generation, expiry, digest: new Uint8Array(digest), identity: new Uint8Array(identity) })), ...(retired === undefined ? {} : { retired }) } };
    });
    // Nothing is published to Acquire before all signed entries verify and the
    // same original durable transaction installs material plus Applied facts.
    for (const entry of applied.materials) {
      this.#check(); const now = this.#environment.clock.sample().requireInterval();
      if (entry.expiry <= now.upperMS) failure("relink_required");
      const input = this.#configuration.decodeMaterial(entry.bytes);
      if (!equalCredential(input.clientCertificate, pending.certificate)) failure("source_contract_invalid");
      const material = this.#environment.verify(this.#policy, { ...input, source: "preauthorized_pool" });
      try { this.#environment.checkOriginalPoolMaterialExpiry(material, entry.expiry, originalPoolJournal(this.#store, this.#environment).reference()); }
      finally { await material.closeMaterial(); }
    }
    if (this.#journal.pending?.state !== "pending" || !equalCredential(this.#journal.pending.id, pending.id)) failure("operation_conflict");
    await this.#commit({ ...this.#journal, pending: applied.pending, frontier: applied.pending.highest!, applied: [...this.#journal.applied, ...(applied.pending.applied ?? [])].filter((entry, index, entries) => entries.length - index <= 48 || this.#journal.materials.some(material => material.sequence === entry.sequence)), materials: [...this.#journal.materials, ...applied.materials] });
    return applied.pending;
  }
  async #borrow<T>(provider: () => Promise<T>, signal: AbortSignal, observation: OperationObservation, cleanup?: () => void): Promise<T> {
    signal.throwIfAborted(); if (this.#active >= 8) failure("capacity_exhausted"); this.#active++; observation.active++;
    const physical = Promise.resolve().then(provider).finally(() => {
      try { cleanup?.(); } finally { observation.active--; this.#active--; this.#collect(); operationSettled(observation); }
    });
    let cancel: (() => void) | undefined;
    try { return await Promise.race([physical, new Promise<T>((_, reject) => {
      cancel = () => reject(new Error("canceled")); signal.addEventListener("abort", cancel, { once: true }); if (signal.aborted) cancel();
    })]); } finally { if (cancel !== undefined) signal.removeEventListener("abort", cancel); }
  }
  async #exchange(method: 41006 | 41007, request: Uint8Array, signal: AbortSignal, observation: OperationObservation): Promise<V4TopUpExchangeResult> {
    signal.throwIfAborted(); if (this.#active >= 8) failure("capacity_exhausted");
    const owned = new Uint8Array(request);
    return await this.#borrow(() => this.#configuration.control.exchange(method, owned, signal), signal, observation, () => owned.fill(0));
  }
  #error(error: unknown): V4TopUpResult["callError"] {
    if (error instanceof Error && topUpErrorProjection(error.message as V4TopUpErrorCode, "none") !== undefined) return error.message as V4TopUpErrorCode;
    if (error instanceof Error && (error.name === "AbortError" || error.message === "canceled")) return "canceled";
    if (error instanceof Error && ["time_expired", "time_deadline_unrepresentable"].includes(error.message)) return "deadline_exceeded";
    return "source_unavailable";
  }
  async #wait(work: Promise<V4TopUpResult>, signal?: AbortSignal): Promise<V4TopUpResult> {
    if (signal === undefined) return await work;
    let stop: (() => void) | undefined;
    try { return await Promise.race([work, new Promise<V4TopUpResult>(resolve => {
      stop = () => {
        const pending = this.#journal.pending, original = this.#runningObservation;
        resolve(this.#observe(this.#working === work && original !== undefined && pending !== undefined && equalCredential(original.id, pending.id) ? pending : undefined, "canceled"));
      }; signal.addEventListener("abort", stop, { once: true }); if (signal.aborted) stop();
    })]); } finally { if (stop !== undefined) signal.removeEventListener("abort", stop); }
  }
  waitCleanup(options: OperationOptions = {}): Promise<V4CleanupStatus> {
    options.signal?.throwIfAborted();
    if (this.#active === 0) return Promise.resolve(this.cleanupStatus());
    if (this.#cleanupWaiters.size >= 8) return Promise.reject(new Error("capacity_exhausted"));
    return new Promise((resolve, reject) => {
      const finish = (): void => { this.#cleanupWaiters.delete(finish); options.signal?.removeEventListener("abort", cancel); resolve(this.cleanupStatus()); };
      const cancel = (): void => { this.#cleanupWaiters.delete(finish); options.signal?.removeEventListener("abort", cancel); reject(new Error("canceled")); };
      this.#cleanupWaiters.add(finish); options.signal?.addEventListener("abort", cancel, { once: true });
      if (options.signal?.aborted) cancel(); else if (this.#active === 0) finish();
    });
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#abort.abort(); this.#source?.close(); this.#dependency.close(); this.#collect(); }
  #collect(): void {
    if (this.#closed && this.#active === 0) { this.#encoded?.fill(0); this.#encoded = undefined; this.#configuration.identityCertificate.fill(0); this.#keys.signingPublicKey.fill(0); this.#keys.noisePublicKey.fill(0);
      for (const material of this.#journal?.materials ?? []) material.bytes.fill(0);
      if (this.#claim !== undefined) claims.get(this.#store)?.delete(this.#claim); this.#dependency.release(); }
    for (const original of this.#observations.values()) operationSettled(original);
    if (this.#active === 0) for (const observe of [...this.#cleanupWaiters]) observe();
  }
}
/** @internal Installed by the actual Node/Browser client with its immutable
 * original Ed25519 and static DH handles, never caller-supplied fake key facts. */
export async function createOriginalPoolSource(environment: V4EnvironmentRuntime, policy: V4CredentialPolicy, store: PoolJournalStore,
  configuration: V4PoolSourceConfiguration, keys: IdentityKeys): Promise<V4PreauthorizedPoolSource> {
  return await new V4PreauthorizedPoolSource(sourceToken, environment, policy, store, configuration, keys).initialize();
}

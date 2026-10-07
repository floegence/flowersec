import { registerPoolJournalStore, type PoolJournalStore } from "../v4/runtime/poolJournal.js";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type V4EnvironmentRuntime, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialDigest, equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedPoolSpendFacts, type VerifiedPoolSpendFacts, type PoolSpendFields } from "../v4/runtime/credentialVerifier.js";
import { encodePoolProjection, poolLeaseKey, type PoolRecordIdentity } from "../v4/runtime/poolRecord.js";
import { poolProjectionInspectionBytes, validatePersistedPoolProjection } from "../v4/runtime/poolRecordStorage.js";
import { validatePersistedPoolJournal } from "../v4/runtime/poolJournalStorage.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { topUpErrorProjection, type V4TopUpErrorCode } from "../generated/transportV4APIResults.js";
import { registerPoolSpendStore, type PoolSpendOwner, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { TrustedWindow, timerChunk, type TrustedDeadline } from "../v4/runtime/deadline.js";
import { storageFormatProjection, type StorageFormatProjection, type StorageFormatReason, type StorageRevision } from "../v4/storageFormat.js";

export type V4IndexedDBPoolFailure = "configuration_capacity" | "storage_unavailable" | "durability_unavailable" | "storage_format" | "history_unknown" | "fenced" | "spend_conflict" | "spent_unknown" | "capacity" | "owner_unavailable" | "closed";
export class V4IndexedDBPoolError extends Error {
  constructor(readonly code: V4IndexedDBPoolFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted", readonly format?: StorageFormatProjection) { super(format?.code ?? code); this.name = "V4IndexedDBPoolError"; }
}
function fail(code: V4IndexedDBPoolFailure): never { throw new V4IndexedDBPoolError(code); }
const token = Symbol("original IndexedDB pool"), format = "flowersec-v4-indexeddb-pool", revision = 1, maximum = 0xffffffffffffffffn;
const factory = globalThis.indexedDB;
export type V4IndexedDBPoolIdentity = PoolRecordIdentity;
export interface V4IndexedDBPoolLimits {
  readonly maxRecords: number; readonly maxRecordBytes: number; readonly transactionMS: bigint;
  readonly runtimeBytes: bigint; readonly providerRuntimeBytes: bigint;
  /** Host-qualified physical database/index/journal reservation, not a JS heap cap. */
  readonly storageBytes: bigint;
}
/** Optional host adapter. This trusted, bounded synchronous boundary must prove
 * complete non-rolled-back history outside this IndexedDB database/origin.
 * Strict IDB commits alone cannot prove continuity after eviction or rollback.
 * No boolean, promise, local record, or permissive default supplies that proof. */
export interface V4IndexedDBPoolContinuity {
  check(identity: V4IndexedDBPoolIdentity, epoch: bigint, provisioning: boolean): void;
  /** Independent host journals can compare each durable record during reopen
   * and fence every new lease before the original IDB transaction submits it.
   * Host fencing is irreversible; IDB transaction completion is still the sole
   * successful consume receipt. A failed IDB commit leaves history unavailable. */
  checkRecord?(identity: V4IndexedDBPoolIdentity, epoch: bigint, key: Uint8Array, projection: Uint8Array): void;
  checkRecords?(identity: V4IndexedDBPoolIdentity, epoch: bigint, count: number): void;
  reserveSpend?(identity: V4IndexedDBPoolIdentity, epoch: bigint, count: number, key: Uint8Array, projection: Uint8Array): void;
}
export interface V4IndexedDBPoolOpenOptions {
  readonly create: boolean; readonly identity: V4IndexedDBPoolIdentity; readonly continuity: V4IndexedDBPoolContinuity;
  readonly bindings: readonly Readonly<{ tenant: string; issuer: Uint8Array }>[];
}
interface BackingState { environment: V4EnvironmentRuntime; name: string; limits: V4IndexedDBPoolLimits; reference: ResourceReference | undefined; active: boolean; closed: boolean }
const backings = new WeakMap<V4IndexedDBPoolBacking, BackingState>();
export class V4IndexedDBPoolBacking {
  constructor(capability: symbol, state: BackingState) { if (capability !== token) fail("owner_unavailable"); backings.set(this, state); Object.freeze(this); }
  close(): void { const state = backings.get(this)!; state.closed = true; state.reference?.seal(); }
  /** The host discharges history obligations and removes the database. This
   * function only confirms actual absence; it never deletes security history. */
  async releaseRemoved(): Promise<void> {
    const state = backings.get(this)!; if (state.reference === undefined) return;
    if (state.active || factory === undefined || typeof factory.databases !== "function") fail("history_unknown");
    if ((await factory.databases()).some(db => db.name === state.name) || state.active) fail("history_unknown");
    state.closed = true; state.reference.release(); state.reference = undefined;
  }
  retainedStorageBytes(): bigint { const state = backings.get(this)!; return state.reference === undefined ? 0n : state.limits.storageBytes; }
  toJSON(): object { return {}; }
}
export function createV4IndexedDBPoolBacking(environment: V4TransportEnvironment, name: string, limits: V4IndexedDBPoolLimits): V4IndexedDBPoolBacking {
  if (factory === undefined || globalThis.isSecureContext !== true) fail("storage_unavailable");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(name) || !Number.isSafeInteger(limits.maxRecords) || limits.maxRecords < 1 || limits.maxRecords > 65536 ||
    !Number.isSafeInteger(limits.maxRecordBytes) || limits.maxRecordBytes < 8192 || limits.maxRecordBytes > 65536 ||
    typeof limits.transactionMS !== "bigint" || limits.transactionMS <= 0n || limits.transactionMS > 60000n ||
    typeof limits.runtimeBytes !== "bigint" || limits.runtimeBytes <= 0n || limits.runtimeBytes > maximum ||
    typeof limits.providerRuntimeBytes !== "bigint" || limits.providerRuntimeBytes <= 0n || limits.providerRuntimeBytes > maximum ||
    typeof limits.storageBytes !== "bigint" || limits.storageBytes < 65536n + BigInt(limits.maxRecords) * BigInt(limits.maxRecordBytes + 1024) * 3n || limits.storageBytes > maximum) fail("configuration_capacity");
  const owner = originalEnvironment(environment), c = Object.freeze({ ...limits }), resources = owner.resources;
  const reference = resources.root.reserve({ owner: { ...resources.owner, kind: "indexeddb_pool_disk" }, accounts: resources.accounts,
    charge: new ResourceVector([4096n + c.runtimeBytes, 0n, c.storageBytes, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
  return new V4IndexedDBPoolBacking(token, { environment: owner, name, limits: c, reference, active: false, closed: false });
}
interface Manifest {
  id: number; format: string; revision: number; authority: string; store: Uint8Array; generation: bigint; epoch: bigint;
  records: number; bytes: number; materialRecords: number; materialBytes: number; maxRecords: number; maxRecordBytes: number; storageBytes: bigint;
}
interface StoredSpend { key: Uint8Array; projection: Uint8Array; epoch: bigint; version: number; retainedUntil: bigint }
interface StoreState {
  backing: BackingState; dependency: EnvironmentDependency; disk: ResourceReference; database: IDBDatabase | undefined;
  identity: V4IndexedDBPoolIdentity; continuity: V4IndexedDBPoolContinuity["check"]; history: V4IndexedDBPoolContinuity; bindings: readonly Readonly<{ tenant: string; issuer: Uint8Array }>[];
  epoch: bigint; active: boolean; closed: boolean; poisoned: boolean; transaction: IDBTransaction | undefined;
  observedRevision: StorageRevision;
}
function formatFailure(reason: StorageFormatReason, observed: StorageRevision = { known: false, value: 0 }): V4IndexedDBPoolError {
  return new V4IndexedDBPoolError("storage_format", "not_submitted", storageFormatProjection(format, revision, observed, reason));
}
function observeStoreFailure(environment: V4EnvironmentRuntime, error: unknown, phase: "prepare" | "spend" = "spend"): void {
  if (!(error instanceof V4IndexedDBPoolError)) return;
  if (error.code === "spent_unknown") environment.diagnosticCounters.observe("spend_unknown", { phase: "spend", code: "spend_unknown" });
  else if (error.code === "spend_conflict") environment.diagnosticCounters.observe("reservation_conflict", { phase: "spend", code: "reservation_conflict" });
  else if (["storage_unavailable", "durability_unavailable", "storage_format", "history_unknown", "fenced"].includes(error.code)) environment.diagnosticCounters.observe("store_failure", { phase, code: "store_unavailable" });
}
function fixed(bytes: Uint8Array, length: number): Uint8Array { if (!(bytes instanceof Uint8Array) || bytes.length !== length || !bytes.some(n => n !== 0)) fail("configuration_capacity"); return new Uint8Array(bytes); }
function identifier(value: string): string { if (!/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(value)) fail("configuration_capacity"); return value; }
function checkManifest(value: unknown, state: StoreState): Manifest {
  const m = value as Manifest | undefined, c = state.backing.limits;
  if (m === undefined || m === null || Object.keys(m).sort().join() !== "authority,bytes,epoch,format,generation,id,materialBytes,materialRecords,maxRecordBytes,maxRecords,records,revision,storageBytes,store" ||
    m.id !== 1 || m.format !== format || m.revision !== revision || m.authority !== state.identity.authority || !(m.store instanceof Uint8Array) || !equalCredential(m.store, state.identity.storeID) ||
    m.generation !== state.identity.generation || typeof m.epoch !== "bigint" || m.epoch < 1n || m.epoch > maximum || m.maxRecords !== c.maxRecords || m.maxRecordBytes !== c.maxRecordBytes || m.storageBytes !== c.storageBytes ||
    !Number.isSafeInteger(m.materialRecords) || m.materialRecords < 0 || !Number.isSafeInteger(m.materialBytes) || m.materialBytes < 0 ||
    m.records + m.materialRecords > c.maxRecords || m.bytes + m.materialBytes > c.maxRecords * c.maxRecordBytes ||
    !Number.isSafeInteger(m.records) || m.records < 0 || m.records > c.maxRecords || !Number.isSafeInteger(m.bytes) || m.bytes < 0 || m.bytes > c.maxRecords * c.maxRecordBytes) fail("storage_format");
  return m;
}
/** Transaction completion is the only successful consume receipt. A later
 * read can never activate an attempt whose original commit was unknown. */
export class V4IndexedDBPoolStore implements PoolSpendStore, PoolJournalStore {
  readonly #state: StoreState;
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerPoolSpendStore(this);
    registerPoolJournalStore(this, { environment: state.backing.environment, reference: () => state.disk, generation: () => state.epoch, check: () => { this.#check(); this.#continuity(); } }); Object.freeze(this); }
  #continuity(provisioning = false): void {
    const s = this.#state; if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), s.epoch, provisioning) !== undefined) fail("history_unknown");
  }
  #check(): void { const s = this.#state; if (s.closed || s.poisoned || s.database === undefined || s.backing.closed) fail("closed"); s.dependency.check(); s.disk.check(); }
  #transaction(run: (transaction: IDBTransaction, guard: () => void, abort: (reason: unknown) => void) => void, check: () => void, signal?: AbortSignal, committedReceipt?: () => void, abortedReceipt?: () => void, observeFailure = true): Promise<void> {
    this.#check(); const s = this.#state; if (s.active) fail("capacity");
    const window = new TrustedWindow(s.backing.environment.clock, s.backing.limits.transactionMS);
    const transaction = s.database!.transaction(["manifest", "spend", "material_pool"], "readwrite", { durability: "strict" });
    s.active = true; s.transaction = transaction;
    return new Promise<void>((resolve, reject) => {
      let error: unknown, submitted = false, timer: ReturnType<typeof setTimeout> | undefined;
      const guard = (): void => { this.#check(); window.check(); check(); if (error !== undefined) throw error; };
      const abort = (reason: unknown): void => { error ??= reason; try { transaction.abort(); } catch { /* A committing transaction retains its real completion. */ } };
      const canceled = (): void => abort(new V4IndexedDBPoolError("owner_unavailable"));
      const tick = (): void => { try { guard(); timer = setTimeout(tick, timerChunk(window.remainingMS())); } catch (reason) { abort(reason); } };
      const finish = (committed: boolean): void => {
        if (timer !== undefined) clearTimeout(timer); signal?.removeEventListener("abort", canceled); s.active = false; s.transaction = undefined;
        try {
          if (committed) {
            committedReceipt?.();
            try { guard(); } catch { throw new V4IndexedDBPoolError("owner_unavailable", "committed"); }
            resolve();
          } else if (error !== undefined) { abortedReceipt?.(); throw error; }
          else { if (submitted) s.poisoned = true; throw new V4IndexedDBPoolError(submitted ? "spent_unknown" : "storage_unavailable", submitted ? "unknown" : "not_submitted"); }
        } catch (reason) { if (observeFailure) observeStoreFailure(s.backing.environment, reason); reject(reason); } finally { this.#cleanup(); }
      };
      transaction.oncomplete = () => finish(true); transaction.onabort = () => finish(false);
      // Do not cancel native errors' default abort; request success is never a receipt.
      transaction.onerror = () => { if (error === undefined) error = new V4IndexedDBPoolError("storage_unavailable"); };
      signal?.addEventListener("abort", canceled, { once: true }); tick(); if (signal?.aborted) canceled();
      try {
        guard(); if (transaction.durability !== "strict") fail("durability_unavailable");
        for (const [name, key] of [["manifest", "id"], ["spend", "key"], ["material_pool", "key"]] as const) { const store = transaction.objectStore(name); if (store.keyPath !== key || store.autoIncrement || store.indexNames.length !== 0) fail("storage_format"); }
        submitted = true; run(transaction, guard, abort);
      } catch (reason) { abort(reason); }
    });
  }
  /** Inspect only the singleton header before selecting the current record
   * reader. Opening a future database never requests an IDB version upgrade. */
  async #inspectFormat(): Promise<void> {
    this.#check(); const s = this.#state, database = s.database!;
    if (!database.objectStoreNames.contains("manifest")) throw formatFailure("manifest_unknown_or_invalid");
    const tx = database.transaction("manifest", "readonly"); s.active = true; s.transaction = tx;
    await new Promise<void>((resolve, reject) => {
      let failure: unknown;
      const stop = (error: unknown): void => { failure ??= error; try { tx.abort(); } catch { /* Observe the original transaction completion. */ } };
      const finish = (committed: boolean): void => {
        s.active = false; s.transaction = undefined;
        if (failure !== undefined) reject(failure);
        else if (!committed) reject(new V4IndexedDBPoolError(s.closed ? "closed" : "storage_unavailable"));
        else resolve();
        this.#cleanup();
      };
      tx.oncomplete = () => finish(true); tx.onabort = () => finish(false);
      tx.onerror = () => { failure ??= new V4IndexedDBPoolError("storage_unavailable"); };
      try {
        const manifest = tx.objectStore("manifest");
        if (manifest.keyPath !== "id" || manifest.autoIncrement || manifest.indexNames.length !== 0) throw formatFailure("manifest_unknown_or_invalid");
        const count = manifest.count(), get = manifest.get(1);
        get.onsuccess = () => {
          try {
            this.#check();
            const m = get.result as Partial<Manifest> | undefined;
            if (count.result !== 1 || m === undefined || m === null || typeof m !== "object" || m.id !== 1 || m.format !== format ||
                typeof m.revision !== "number" || !Number.isInteger(m.revision) || m.revision < 1 || m.revision > 0xffffffff ||
                typeof m.authority !== "string" || m.authority.length > 128 || !(m.store instanceof Uint8Array) || m.store.length !== 32 ||
                typeof m.generation !== "bigint" || m.generation < 1n || m.generation > maximum ||
                typeof m.epoch !== "bigint" || m.epoch < 1n || m.epoch >= maximum) throw formatFailure("manifest_unknown_or_invalid");
            if (m.authority !== s.identity.authority || !equalCredential(m.store, s.identity.storeID) || m.generation !== s.identity.generation) throw formatFailure("identity_mismatch");
            if (database.version !== m.revision) throw formatFailure("revision_conflict");
            s.observedRevision = { known: true, value: m.revision };
            if (m.revision !== revision) throw formatFailure(m.revision < revision ? "older_revision" : "newer_revision", s.observedRevision);
            if (Array.from(database.objectStoreNames).join() !== "manifest,material_pool,spend") throw formatFailure("schema_or_state_invalid", s.observedRevision);
          } catch (error) { stop(error); }
        };
      } catch (error) { stop(error); }
    });
  }
  async initialize(capability: symbol, created: boolean): Promise<void> {
    if (capability !== token) fail("owner_unavailable"); const s = this.#state, c = s.backing.limits;
    try {
    if (!created) await this.#inspectFormat();
    await this.#transaction((tx, guard, abort) => {
      const manifest = tx.objectStore("manifest"), spend = tx.objectStore("spend"), get = manifest.get(1);
      get.onsuccess = () => {
        try {
          guard();
          if (created) {
            if (get.result !== undefined) fail("history_unknown"); s.epoch = 1n; this.#continuity(true);
            manifest.add({ id: 1, format, revision, authority: s.identity.authority, store: s.identity.storeID, generation: s.identity.generation, epoch: s.epoch,
              records: 0, bytes: 0, materialRecords: 0, materialBytes: 0, maxRecords: c.maxRecords, maxRecordBytes: c.maxRecordBytes, storageBytes: c.storageBytes } satisfies Manifest);
          } else {
            const m = checkManifest(get.result, s); s.epoch = m.epoch; this.#continuity(); if (s.epoch === maximum) fail("fenced");
            let count = 0, bytes = 0; const scan = spend.openCursor();
            scan.onsuccess = () => {
              try {
                guard(); const cursor = scan.result;
                if (cursor === null) {
                  if (count !== m.records || bytes !== m.bytes) fail("storage_format");
                  let materials = 0, materialBytes = 0; const journalScan = tx.objectStore("material_pool").openCursor();
                  journalScan.onsuccess = () => {
                    try {
                      guard(); const entry = journalScan.result;
                      if (entry === null) {
                        if (materials !== m.materialRecords || materialBytes !== m.materialBytes || s.history.checkRecords?.(s.identity, s.epoch, count + materials) !== undefined) fail("history_unknown");
                        s.epoch++; this.#continuity(); manifest.put({ ...m, epoch: s.epoch }); return;
                      }
                      const row = entry.value as { key: Uint8Array; snapshot: Uint8Array };
                      if (++materials + count > c.maxRecords || !(row.key instanceof Uint8Array) || row.key.length !== 16 || !(row.snapshot instanceof Uint8Array) || row.snapshot.length < 1 || row.snapshot.length > c.maxRecordBytes) fail("storage_format");
                      try { validatePersistedPoolJournal(row.key, row.snapshot, s.epoch, sha256, bytes => credentialDigest("certificate_digest", bytes), code => topUpErrorProjection(code as V4TopUpErrorCode, "terminal") !== undefined); }
                      catch { fail("storage_format"); }
                      if (s.history.checkRecord?.(s.identity, s.epoch, row.key, row.snapshot) !== undefined) fail("history_unknown");
                      materialBytes += row.snapshot.length; entry.continue();
                    } catch (error) { s.poisoned = true; abort(error); }
                  }; return;
                }
                const row = cursor.value as StoredSpend;
                if (++count > c.maxRecords || !(row.key instanceof Uint8Array) || row.key.length < 34 || row.key.length > 161 || !(row.projection instanceof Uint8Array) || row.projection.length < 1 || row.projection.length > c.maxRecordBytes ||
                  row.version !== 1 || typeof row.epoch !== "bigint" || row.epoch < 1n || row.epoch > m.epoch || typeof row.retainedUntil !== "bigint" || row.retainedUntil < 1n || row.retainedUntil > maximum) fail("storage_format");
                try { validatePersistedPoolProjection(row.key, row.projection, s.identity, row.epoch, m.epoch, row.retainedUntil, bytes => credentialDigest("activation_digest", bytes)); }
                catch { fail("storage_format"); }
                if (s.history.checkRecord?.(s.identity, s.epoch, row.key, row.projection) !== undefined) fail("history_unknown"); bytes += row.projection.length; cursor.continue();
              } catch (error) { s.poisoned = true; abort(error); }
            };
          }
        } catch (error) { s.poisoned = true; abort(error); }
      };
    }, () => undefined, undefined, undefined, undefined, false);
    } catch (error) {
      if (error instanceof V4IndexedDBPoolError && error.code === "storage_format" && error.format === undefined) throw formatFailure("schema_or_state_invalid", s.observedRevision);
      throw error;
    }
  }
  async #journal(key: Uint8Array, expected: Uint8Array | undefined, replacement: Uint8Array | undefined, check: () => void): Promise<Uint8Array | undefined> {
    this.#check(); const state = this.#state, limits = state.backing.limits, resources = state.backing.environment.resources;
    if (key.length !== 16 || (expected?.length ?? 0) > limits.maxRecordBytes || (replacement?.length ?? 0) > limits.maxRecordBytes) fail("capacity");
    const ref = resources.root.reserve({ owner: { ...resources.owner, kind: "indexeddb_pool_journal" }, accounts: resources.accounts,
      charge: new ResourceVector([BigInt(limits.maxRecordBytes * 4 + 65536), BigInt(limits.maxRecordBytes + 16384), 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]) });
    let result: Uint8Array | undefined;
    try {
      await this.#transaction((tx, guard, abort) => {
        const manifest = tx.objectStore("manifest"), materials = tx.objectStore("material_pool"), get = manifest.get(1);
        get.onsuccess = () => {
          try {
            guard(); ref.check(); check(); const current = checkManifest(get.result, state);
            if (current.epoch !== state.epoch) fail("fenced"); this.#continuity();
            const read = materials.get(key as Uint8Array<ArrayBuffer>);
            read.onsuccess = () => {
              try {
                guard(); check(); const row = read.result as { key: Uint8Array; snapshot: Uint8Array } | undefined;
                if (row !== undefined && (!(row.key instanceof Uint8Array) || !equalCredential(row.key, key) || !(row.snapshot instanceof Uint8Array) || row.snapshot.length < 1 || row.snapshot.length > limits.maxRecordBytes)) fail("storage_format");
                result = row?.snapshot;
                if (replacement === undefined) return;
                if (expected === undefined ? row !== undefined : row === undefined || !equalCredential(expected, row.snapshot)) fail("spend_conflict");
                const count = current.materialRecords + (row === undefined ? 1 : 0), bytes = current.materialBytes - (row?.snapshot.length ?? 0) + replacement.length;
                if (count + current.records > limits.maxRecords || bytes + current.bytes > limits.maxRecords * limits.maxRecordBytes) fail("capacity");
                check(); materials.put({ key, snapshot: replacement }); manifest.put({ ...current, materialRecords: count, materialBytes: bytes }); guard();
              } catch (error) { abort(error); }
            };
          } catch (error) { abort(error); }
        };
      }, () => { ref.check(); check(); });
      return result;
    } finally { ref.release(); }
  }
  readPoolJournal(key: Uint8Array, check: () => void): Promise<Uint8Array | undefined> { return this.#journal(key, undefined, undefined, check); }
  async comparePoolJournal(key: Uint8Array, expected: Uint8Array | undefined, replacement: Uint8Array, check: () => void): Promise<void> {
    await this.#journal(key, expected, replacement, check);
  }
  consume(facts: VerifiedPoolSpendFacts, owner: PoolSpendOwner, deadline: TrustedDeadline, admission: ResourceReference, guard: () => void): Promise<void> {
    const s = this.#state, c = s.backing.limits;
    this.#check(); if (!isVerifiedPoolSpendFacts(facts) || !deadline.belongsTo(s.backing.environment.clock) || !s.dependency.reference.sameEnvironment(admission)) fail("owner_unavailable");
    facts.check(admission); const r = s.backing.environment.resources;
    const reference = r.root.reserve({ owner: { ...r.owner, kind: "indexeddb_pool_consume" }, accounts: r.accounts,
      charge: new ResourceVector([BigInt(c.maxRecordBytes * 3 + 32768) + c.runtimeBytes, 0n, 0n, 4n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]) });
    let fields: PoolSpendFields | undefined, projection: Uint8Array | undefined, key: Uint8Array | undefined;
    const check = (): void => { reference.check(); admission.check(); deadline.check(); facts.check(admission); if (guard() !== undefined) fail("owner_unavailable"); };
    try {
      check(); fields = facts.fields(admission);
      if (fields.authority !== s.identity.authority || !s.bindings.some(binding => binding.tenant === fields!.tenant && equalCredential(binding.issuer, fields!.issuer))) fail("owner_unavailable");
      const connect = fixed(owner.connect, 16), carrier = fixed(owner.carrier, 16); if (owner.generation < 1n || owner.generation > maximum) fail("configuration_capacity");
      const now = deadline.sample().requireInterval(), end = fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS;
      if (now.lowerMS < fields.issuedAt || end > maximum - 604800000n) fail("configuration_capacity");
      const retainedUntil = end + 604800000n; key = poolLeaseKey(fields); projection = new Uint8Array(c.maxRecordBytes);
      const body = new Uint8Array(encodePoolProjection(projection, fields, s.identity, s.epoch, { connect, carrier, generation: owner.generation }, deadline.cap, now.upperMS, retainedUntil));
      const record: StoredSpend = { key, projection: body, epoch: s.epoch, version: 1, retainedUntil };
      const operation = this.#transaction((tx, originalGuard, stop) => {
        const manifest = tx.objectStore("manifest"), spend = tx.objectStore("spend"), request = manifest.get(1);
        request.onsuccess = () => {
          try {
            originalGuard(); const m = checkManifest(request.result, s); if (m.epoch !== s.epoch) fail("fenced"); this.#continuity();
            if (m.records + m.materialRecords >= c.maxRecords || m.bytes + m.materialBytes + body.length > c.maxRecords * c.maxRecordBytes) fail("capacity");
            const existing = spend.getKey(key! as Uint8Array<ArrayBuffer>);
            existing.onsuccess = () => {
              try {
                originalGuard(); if (existing.result !== undefined) fail("spend_conflict");
                if (s.history.reserveSpend?.(s.identity, s.epoch, m.records, key!, body) !== undefined) fail("history_unknown"); originalGuard();
                owner.spendDispatched?.(); spend.add(record); manifest.put({ ...m, records: m.records + 1, bytes: m.bytes + body.length }); originalGuard();
              } catch (error) { stop(error); }
            };
          } catch (error) { stop(error); }
        };
      }, check, owner.signal, owner.spent, owner.unspent);
      return operation.finally(() => {
        body.fill(0); connect.fill(0); carrier.fill(0); projection?.fill(0); key?.fill(0);
        if (fields !== undefined) { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0); }
        reference.release();
      });
    } catch (error) {
      projection?.fill(0); key?.fill(0); if (fields !== undefined) { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0); }
      reference.release(); throw error;
    }
  }
  close(): void { const s = this.#state; s.closed = true; try { s.transaction?.abort(); } catch { /* Original completion remains owned. */ } this.#cleanup(); }
  #cleanup(): void {
    const s = this.#state; if (!s.closed || s.active) return; s.database?.close(); s.database = undefined;
    s.backing.active = false; s.disk.release(); s.dependency.release();
  }
  cleanupComplete(): boolean { return this.#state.closed && !this.#state.active && this.#state.database === undefined; }
  toJSON(): object { return {}; }
}

export function openV4IndexedDBPoolStore(backing: V4IndexedDBPoolBacking, options: V4IndexedDBPoolOpenOptions): Promise<V4IndexedDBPoolStore> {
  const b = backings.get(backing); if (b?.reference === undefined || b.active || b.closed || factory === undefined) return Promise.reject(new V4IndexedDBPoolError("owner_unavailable"));
  let dependency: EnvironmentDependency | undefined, disk: ResourceReference | undefined;
  try {
    if (typeof options.continuity?.check !== "function" || options.bindings.length < 1 || options.bindings.length > 64 || typeof options.create !== "boolean") fail("configuration_capacity");
    const identity = Object.freeze({ authority: identifier(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: options.identity.generation });
    if (identity.generation < 1n || identity.generation > maximum) fail("configuration_capacity");
    const bindings = Object.freeze(options.bindings.map(binding => Object.freeze({ tenant: identifier(binding.tenant), issuer: fixed(binding.issuer, 16) }))), continuity = options.continuity.check.bind(options.continuity), c = b.limits;
    b.reference.check(); disk = b.reference.borrow(); dependency = b.environment.admitDependency("indexeddb_pool_store", new ResourceVector([BigInt(c.maxRecordBytes * 2 + 32768) + c.runtimeBytes + poolProjectionInspectionBytes, c.providerRuntimeBytes, 0n, 4168n, 2n, 2n, 2n, 0n, 0n, 0n, 1n]));
    const state: StoreState = { backing: b, dependency, disk, database: undefined, identity, continuity, history: Object.freeze({ check: continuity,
      ...(options.continuity.checkRecord === undefined ? {} : { checkRecord: options.continuity.checkRecord.bind(options.continuity) }),
      ...(options.continuity.checkRecords === undefined ? {} : { checkRecords: options.continuity.checkRecords.bind(options.continuity) }),
      ...(options.continuity.reserveSpend === undefined ? {} : { reserveSpend: options.continuity.reserveSpend.bind(options.continuity) }) }), bindings, epoch: 0n, active: false, closed: false, poisoned: false, transaction: undefined, observedRevision: { known: false, value: 0 } };
    if (options.create && continuity(Object.freeze({ ...identity, storeID: new Uint8Array(identity.storeID) }), 0n, true) !== undefined) fail("history_unknown");
    const original = new TrustedWindow(b.environment.clock, c.transactionMS); b.active = true;
    return new Promise<V4IndexedDBPoolStore>((resolve, reject) => {
      let abandoned = false, store: V4IndexedDBPoolStore | undefined, created = false, timer: ReturnType<typeof setTimeout> | undefined;
      const abandon = (reason: unknown): void => { abandoned = true; state.closed = true; store?.close(); reject(reason); };
      state.dependency.onClose(() => abandon(new V4IndexedDBPoolError("closed")));
      const tick = (): void => { try { state.dependency.check(); original.check(); timer = setTimeout(tick, timerChunk(original.remainingMS())); } catch (error) { abandon(error); } };
      tick();
      const cleanup = (): void => { if (timer !== undefined) clearTimeout(timer); b.active = false; state.disk.release(); state.dependency.release(); };
      let request: IDBOpenDBRequest;
      try { request = factory.open(b.name); } catch { cleanup(); reject(new V4IndexedDBPoolError("storage_unavailable")); return; }
      request.onblocked = () => abandon(new V4IndexedDBPoolError("storage_unavailable"));
      request.onupgradeneeded = event => {
        if (abandoned || !options.create || event.oldVersion !== 0) { request.transaction!.abort(); return; }
        created = true; request.result.createObjectStore("manifest", { keyPath: "id" }); request.result.createObjectStore("spend", { keyPath: "key" }); request.result.createObjectStore("material_pool", { keyPath: "key" });
      };
      request.onerror = () => { cleanup(); reject(new V4IndexedDBPoolError(abandoned ? "closed" : "history_unknown")); };
      request.onsuccess = () => {
        const database = request.result;
        if (abandoned || options.create !== created) { database.close(); cleanup(); reject(new V4IndexedDBPoolError("history_unknown")); return; }
        state.database = database; store = new V4IndexedDBPoolStore(token, state);
        database.onversionchange = () => store!.close(); database.onclose = () => { state.poisoned = true; store!.close(); };
        void store.initialize(token, created).then(() => {
          if (timer !== undefined) clearTimeout(timer); if (abandoned) { store!.close(); return; } resolve(store!);
        }, error => { store!.close(); if (timer !== undefined) clearTimeout(timer); reject(error); });
      };
    }).catch(error => { observeStoreFailure(b.environment, error, "prepare"); throw error; });
  } catch (error) { dependency?.release(); disk?.release(); return Promise.reject(error); }
}
for (const ctor of [V4IndexedDBPoolBacking, V4IndexedDBPoolStore]) { Object.freeze(ctor.prototype); Object.freeze(ctor); }

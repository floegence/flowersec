import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type V4EnvironmentRuntime, type EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedPoolSpendFacts, type VerifiedPoolSpendFacts, type PoolSpendFields } from "../v4/runtime/credentialVerifier.js";
import { encodePoolProjection, poolLeaseKey, type PoolRecordIdentity } from "../v4/runtime/poolRecord.js";
import { registerPoolSpendStore, type PoolSpendOwner, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { TrustedWindow, timerChunk, type TrustedDeadline } from "../v4/runtime/deadline.js";

export type V4IndexedDBPoolFailure = "configuration_capacity" | "storage_unavailable" | "durability_unavailable" | "storage_format" | "history_unknown" | "fenced" | "spend_conflict" | "spent_unknown" | "capacity" | "owner_unavailable" | "closed";
export class V4IndexedDBPoolError extends Error {
  constructor(readonly code: V4IndexedDBPoolFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted") { super(code); this.name = "V4IndexedDBPoolError"; }
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
  records: number; bytes: number; maxRecords: number; maxRecordBytes: number; storageBytes: bigint;
}
interface StoredSpend { key: Uint8Array; projection: Uint8Array; epoch: bigint; version: number; retainedUntil: bigint }
interface StoreState {
  backing: BackingState; dependency: EnvironmentDependency; disk: ResourceReference; database: IDBDatabase | undefined;
  identity: V4IndexedDBPoolIdentity; continuity: V4IndexedDBPoolContinuity["check"]; bindings: readonly Readonly<{ tenant: string; issuer: Uint8Array }>[];
  epoch: bigint; active: boolean; closed: boolean; poisoned: boolean; transaction: IDBTransaction | undefined;
}
function fixed(bytes: Uint8Array, length: number): Uint8Array { if (!(bytes instanceof Uint8Array) || bytes.length !== length || !bytes.some(n => n !== 0)) fail("configuration_capacity"); return new Uint8Array(bytes); }
function identifier(value: string): string { if (!/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/u.test(value)) fail("configuration_capacity"); return value; }
function checkManifest(value: unknown, state: StoreState): Manifest {
  const m = value as Manifest | undefined, c = state.backing.limits;
  if (m === undefined || m === null || Object.keys(m).sort().join() !== "authority,bytes,epoch,format,generation,id,maxRecordBytes,maxRecords,records,revision,storageBytes,store" ||
    m.id !== 1 || m.format !== format || m.revision !== revision || m.authority !== state.identity.authority || !(m.store instanceof Uint8Array) || !equalCredential(m.store, state.identity.storeID) ||
    m.generation !== state.identity.generation || typeof m.epoch !== "bigint" || m.epoch < 1n || m.epoch > maximum || m.maxRecords !== c.maxRecords || m.maxRecordBytes !== c.maxRecordBytes || m.storageBytes !== c.storageBytes ||
    !Number.isSafeInteger(m.records) || m.records < 0 || m.records > c.maxRecords || !Number.isSafeInteger(m.bytes) || m.bytes < 0 || m.bytes > c.maxRecords * c.maxRecordBytes) fail("storage_format");
  return m;
}
/** Transaction completion is the only successful consume receipt. A later
 * read can never activate an attempt whose original commit was unknown. */
export class V4IndexedDBPoolStore implements PoolSpendStore {
  readonly #state: StoreState;
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerPoolSpendStore(this); Object.freeze(this); }
  #continuity(provisioning = false): void {
    const s = this.#state; if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), s.epoch, provisioning) !== undefined) fail("history_unknown");
  }
  #check(): void { const s = this.#state; if (s.closed || s.poisoned || s.database === undefined || s.backing.closed) fail("closed"); s.dependency.check(); s.disk.check(); }
  #transaction(run: (transaction: IDBTransaction, guard: () => void, abort: (reason: unknown) => void) => void, check: () => void, signal?: AbortSignal): Promise<void> {
    this.#check(); const s = this.#state; if (s.active) fail("capacity");
    const window = new TrustedWindow(s.backing.environment.clock, s.backing.limits.transactionMS);
    const transaction = s.database!.transaction(["manifest", "spend"], "readwrite", { durability: "strict" });
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
            try { guard(); } catch { throw new V4IndexedDBPoolError("owner_unavailable", "committed"); }
            resolve();
          } else if (error !== undefined) reject(error);
          else { if (submitted) s.poisoned = true; reject(new V4IndexedDBPoolError(submitted ? "spent_unknown" : "storage_unavailable", submitted ? "unknown" : "not_submitted")); }
        } catch (reason) { reject(reason); } finally { this.#cleanup(); }
      };
      transaction.oncomplete = () => finish(true); transaction.onabort = () => finish(false);
      // Do not cancel native errors' default abort; request success is never a receipt.
      transaction.onerror = () => { if (error === undefined) error = new V4IndexedDBPoolError("storage_unavailable"); };
      signal?.addEventListener("abort", canceled, { once: true }); tick(); if (signal?.aborted) canceled();
      try {
        guard(); if (transaction.durability !== "strict") fail("durability_unavailable");
        for (const [name, key] of [["manifest", "id"], ["spend", "key"]] as const) { const store = transaction.objectStore(name); if (store.keyPath !== key || store.autoIncrement || store.indexNames.length !== 0) fail("storage_format"); }
        submitted = true; run(transaction, guard, abort);
      } catch (reason) { abort(reason); }
    });
  }
  initialize(capability: symbol, created: boolean): Promise<void> {
    if (capability !== token) fail("owner_unavailable"); const s = this.#state, c = s.backing.limits;
    return this.#transaction((tx, guard, abort) => {
      const manifest = tx.objectStore("manifest"), spend = tx.objectStore("spend"), get = manifest.get(1);
      get.onsuccess = () => {
        try {
          guard();
          if (created) {
            if (get.result !== undefined) fail("history_unknown"); s.epoch = 1n; this.#continuity(true);
            manifest.add({ id: 1, format, revision, authority: s.identity.authority, store: s.identity.storeID, generation: s.identity.generation, epoch: s.epoch,
              records: 0, bytes: 0, maxRecords: c.maxRecords, maxRecordBytes: c.maxRecordBytes, storageBytes: c.storageBytes } satisfies Manifest);
          } else {
            const m = checkManifest(get.result, s); s.epoch = m.epoch; this.#continuity(); if (s.epoch === maximum) fail("fenced");
            let count = 0, bytes = 0; const scan = spend.openCursor();
            scan.onsuccess = () => {
              try {
                guard(); const cursor = scan.result;
                if (cursor === null) {
                  if (count !== m.records || bytes !== m.bytes) fail("storage_format"); s.epoch++; this.#continuity(); manifest.put({ ...m, epoch: s.epoch }); return;
                }
                const row = cursor.value as StoredSpend;
                if (++count > c.maxRecords || !(row.key instanceof Uint8Array) || row.key.length < 34 || row.key.length > 161 || !(row.projection instanceof Uint8Array) || row.projection.length < 1 || row.projection.length > c.maxRecordBytes ||
                  row.version !== 1 || typeof row.epoch !== "bigint" || row.epoch < 1n || row.epoch > m.epoch || typeof row.retainedUntil !== "bigint" || row.retainedUntil < 1n || row.retainedUntil > maximum) fail("storage_format");
                bytes += row.projection.length; cursor.continue();
              } catch (error) { s.poisoned = true; abort(error); }
            };
          }
        } catch (error) { s.poisoned = true; abort(error); }
      };
    }, () => undefined);
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
            if (m.records >= c.maxRecords || m.bytes + body.length > c.maxRecords * c.maxRecordBytes) fail("capacity");
            const existing = spend.getKey(key! as Uint8Array<ArrayBuffer>);
            existing.onsuccess = () => {
              try {
                originalGuard(); if (existing.result !== undefined) fail("spend_conflict");
                spend.add(record); manifest.put({ ...m, records: m.records + 1, bytes: m.bytes + body.length }); originalGuard();
              } catch (error) { stop(error); }
            };
          } catch (error) { stop(error); }
        };
      }, check, owner.signal);
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
    b.reference.check(); disk = b.reference.borrow(); dependency = b.environment.admitDependency("indexeddb_pool_store", new ResourceVector([BigInt(c.maxRecordBytes * 2 + 32768) + c.runtimeBytes, c.providerRuntimeBytes, 0n, 72n, 2n, 2n, 2n, 0n, 0n, 0n, 1n]));
    const state: StoreState = { backing: b, dependency, disk, database: undefined, identity, continuity, bindings, epoch: 0n, active: false, closed: false, poisoned: false, transaction: undefined };
    if (options.create && continuity(Object.freeze({ ...identity, storeID: new Uint8Array(identity.storeID) }), 0n, true) !== undefined) fail("history_unknown");
    const original = new TrustedWindow(b.environment.clock, c.transactionMS); b.active = true;
    return new Promise((resolve, reject) => {
      let abandoned = false, store: V4IndexedDBPoolStore | undefined, created = false, timer: ReturnType<typeof setTimeout> | undefined;
      const abandon = (reason: unknown): void => { abandoned = true; state.closed = true; store?.close(); reject(reason); };
      state.dependency.onClose(() => abandon(new V4IndexedDBPoolError("closed")));
      const tick = (): void => { try { state.dependency.check(); original.check(); timer = setTimeout(tick, timerChunk(original.remainingMS())); } catch (error) { abandon(error); } };
      tick();
      const cleanup = (): void => { if (timer !== undefined) clearTimeout(timer); b.active = false; state.disk.release(); state.dependency.release(); };
      let request: IDBOpenDBRequest;
      try { request = factory.open(b.name, revision); } catch (error) { cleanup(); reject(error); return; }
      request.onblocked = () => abandon(new V4IndexedDBPoolError("storage_unavailable"));
      request.onupgradeneeded = event => {
        if (abandoned || !options.create || event.oldVersion !== 0) { request.transaction!.abort(); return; }
        created = true; request.result.createObjectStore("manifest", { keyPath: "id" }); request.result.createObjectStore("spend", { keyPath: "key" });
      };
      request.onerror = () => { cleanup(); reject(new V4IndexedDBPoolError(abandoned ? "closed" : "history_unknown")); };
      request.onsuccess = () => {
        const database = request.result;
        if (abandoned || options.create !== created) { database.close(); cleanup(); reject(new V4IndexedDBPoolError("history_unknown")); return; }
        if (database.version !== revision || Array.from(database.objectStoreNames).join() !== "manifest,spend") { database.close(); cleanup(); reject(new V4IndexedDBPoolError("storage_format")); return; }
        state.database = database; store = new V4IndexedDBPoolStore(token, state);
        database.onversionchange = () => store!.close(); database.onclose = () => { state.poisoned = true; store!.close(); };
        void store.initialize(token, created).then(() => {
          if (timer !== undefined) clearTimeout(timer); if (abandoned) { store!.close(); return; } resolve(store!);
        }, error => { store!.close(); if (timer !== undefined) clearTimeout(timer); reject(error); });
      };
    });
  } catch (error) { dependency?.release(); disk?.release(); return Promise.reject(error); }
}
for (const ctor of [V4IndexedDBPoolBacking, V4IndexedDBPoolStore]) { Object.freeze(ctor.prototype); Object.freeze(ctor); }

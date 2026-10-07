import { registerPoolJournalStore, type PoolJournalStore } from "../v4/runtime/poolJournal.js";
import type { EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialOwner, equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedPoolSpendFacts, type VerifiedPoolSpendFacts, type PoolSpendFields } from "../v4/runtime/credentialVerifier.js";
import { registerPoolSpendStore, type PoolSpendOwner, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { poolLeaseKey as leaseKey, encodePoolProjection as encodeProjection } from "../v4/runtime/poolRecord.js";
import { poolProjectionInspectionBytes } from "../v4/runtime/poolRecordStorage.js";
import { TrustedWindow, type TrustedDeadline } from "../v4/runtime/deadline.js";
import { PoolStorageWorker, PoolWorkerError } from "./sqlitePoolWorkerV4.js";
import {
  V4SQLitePoolBacking, V4PoolStoreError, fail, maximum, fixed, quantity, identityText, storeCharge,
  sqliteBackingState, type BackingState,
  type V4SQLitePoolIdentity, type V4SQLitePoolContinuity, type V4SQLitePoolBinding, type V4SQLitePoolOpenOptions
} from "./sqliteV4.js";
export { createV4SQLitePoolBacking, createSQLitePoolBacking, V4SQLitePoolBacking, V4PoolStoreError } from "./sqliteV4.js";
export type { V4SQLitePoolLimits, V4SQLitePoolIdentity, V4SQLitePoolContinuity, V4SQLitePoolBinding, V4SQLitePoolOpenOptions, V4PoolStoreFailure } from "./sqliteV4.js";
const token = Symbol("node pool store"), minimumRetentionMS = 604800000n;
interface StoreState {
  backing: BackingState; dependency: EnvironmentDependency; disk: ResourceReference; identity: V4SQLitePoolIdentity; continuity: V4SQLitePoolContinuity["check"];
  bindings: readonly V4SQLitePoolBinding[]; worker: PoolStorageWorker | undefined; epoch: bigint; active: boolean; closed: boolean; poisoned: boolean; released: boolean;
}
function workerFailure(error: unknown): V4PoolStoreError {
  if (error instanceof V4PoolStoreError) return error;
  if (error instanceof PoolWorkerError) return new V4PoolStoreError(error.code, error.writeState, error.format);
  return new V4PoolStoreError("storage_unavailable");
}
/** Real local, serializable pool once authority. SQLite runs in one bounded
 * worker; the original Environment owns every authorization/continuity gate.
 * Only the original worker COMMIT receipt can report successful consumption. */
export class V4SQLitePoolStore implements PoolSpendStore, PoolJournalStore {
  readonly #state: StoreState;
  #cleanupResolve: (() => void) | undefined;
  readonly #cleanupWait = new Promise<void>(resolve => { this.#cleanupResolve = resolve; });
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerPoolSpendStore(this);
    registerPoolJournalStore(this, { environment: state.backing.environment, reference: () => state.disk,
      generation: () => state.epoch, check: () => { this.#check(); this.#continuity(); } }); Object.freeze(this); }
  #continuity(epoch = this.#state.epoch, provisioning = false): void {
    const s = this.#state;
    if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), epoch, provisioning) !== undefined) fail("history_unknown");
  }
  #check(): void {
    const s = this.#state; if (s.closed || s.poisoned) fail("closed");
    s.dependency.check(); s.disk.check();
  }
  async initialize(capability: symbol, create: boolean): Promise<void> {
    if (capability !== token) fail("owner_unavailable"); const s = this.#state;
    s.active = true; let committed = false;
    try {
      this.#check(); if (create) this.#continuity(0n, true); this.#check();
      s.worker = new PoolStorageWorker({ path: s.backing.path, limits: s.backing.limits, identity: s.identity }, () => {
        s.closed = true; this.#cleanup();
      });
      s.epoch = await s.worker.run({ kind: "open", create }, gate => {
        this.#check(); this.#continuity(gate.epoch, gate.provisioning); this.#check();
      });
      committed = true; this.#check();
    } catch (error) { s.closed = true; const failure = workerFailure(error);
      if (["storage_unavailable", "storage_format", "history_unknown", "fenced"].includes(failure.code)) s.backing.environment.diagnosticCounters.observe("store_failure", { phase: "prepare", code: "store_unavailable" });
      throw committed ? new V4PoolStoreError(failure.code, "committed", failure.format) : failure; }
    finally { s.active = false; if (s.closed) { s.worker?.close(); this.#cleanup(); } }
  }
  async #journal(key: Uint8Array, expected: Uint8Array | undefined, replacement: Uint8Array | undefined, check: () => void): Promise<Uint8Array | undefined> {
    this.#check(); const state = this.#state, limits = state.backing.limits;
    if (state.active || key.length !== 16 || (expected?.length ?? 0) > limits.maxRecordBytes || (replacement?.length ?? 0) > limits.maxRecordBytes) fail("capacity");
    const resources = state.backing.environment.resources;
    const ref = resources.root.reserve({ owner: credentialOwner(resources, "pool_journal"), accounts: resources.accounts,
      charge: new ResourceVector([BigInt(limits.maxRecordBytes * 4 + 65536), BigInt(limits.maxRecordBytes + 16384), 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n]) });
    state.active = true; const window = new TrustedWindow(state.backing.environment.clock, 120000n);
    try { return await state.worker!.journal({ kind: "journal", epoch: state.epoch, key,
      ...(expected === undefined ? {} : { expected }), ...(replacement === undefined ? {} : { replacement }) }, gate => {
        this.#check(); ref.check(); window.check(); check(); if (gate.epoch !== state.epoch) fail("fenced"); this.#continuity(); check();
      }, { signal: undefined, remainingMS: () => window.remainingMS() });
    } catch (error) { const failure = workerFailure(error); if (failure.writeState === "unknown") { state.poisoned = true; state.worker!.close(); } throw failure; }
    finally {
      const done = () => { ref.release(); state.active = false; this.#cleanup(); };
      if (state.worker!.closed()) void state.worker!.waitCleanup().then(done, done); else done();
    }
  }
  readPoolJournal(key: Uint8Array, check: () => void): Promise<Uint8Array | undefined> { return this.#journal(key, undefined, undefined, check); }
  async comparePoolJournal(key: Uint8Array, expected: Uint8Array | undefined, replacement: Uint8Array, check: () => void): Promise<void> {
    await this.#journal(key, expected, replacement, check);
  }
  async consume(facts: VerifiedPoolSpendFacts, owner: PoolSpendOwner, deadline: TrustedDeadline, admission: ResourceReference, guard: () => void): Promise<void> {
    const s = this.#state, c = s.backing.limits;
    if (!isVerifiedPoolSpendFacts(facts) || typeof guard !== "function" || !deadline.belongsTo(s.backing.environment.clock)) fail("owner_unavailable");
    this.#check(); if (s.active || s.worker === undefined || s.epoch === 0n) fail("capacity");
    if (!s.dependency.reference.sameEnvironment(admission)) fail("owner_unavailable"); facts.check(admission);
    const connect = fixed(owner.connect, 16), carrier = fixed(owner.carrier, 16), generation = quantity(owner.generation);
    const r = s.backing.environment.resources, reference = r.root.reserve({
      owner: credentialOwner(r, "pool_consume"), accounts: r.accounts,
      charge: new ResourceVector([BigInt(c.maxRecordBytes * 2 + 16384) + c.runtimeBytes, BigInt(c.maxRecordBytes + 16384), 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 0n])
    });
    let fields: PoolSpendFields | undefined, projection: Uint8Array | undefined, key: Uint8Array | undefined, committed = false;
    s.active = true;
    try {
      fields = facts.fields(admission);
      if (fields.authority !== s.identity.authority || !s.bindings.some(binding => binding.tenant === fields!.tenant && equalCredential(binding.issuer, fields!.issuer))) fail("owner_unavailable");
      const original = deadline.fork(deadline.cap < fields.activationEnd ? deadline.cap : fields.activationEnd);
      const check = (): void => {
        this.#check(); reference.check(); admission.check(); original.check(); facts.check(admission);
        if (owner.signal?.aborted || guard() !== undefined) fail("owner_unavailable");
      };
      check(); const now = original.sample().requireInterval();
      if (now.lowerMS < fields.issuedAt || fields.initiationEnd > maximum - minimumRetentionMS || now.upperMS > maximum - minimumRetentionMS) fail("configuration_capacity");
      const retainedUntil = (fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS) + minimumRetentionMS;
      key = leaseKey(fields); projection = new Uint8Array(c.maxRecordBytes);
      const body = encodeProjection(projection, fields, s.identity, s.epoch, { connect, carrier, generation }, original.cap, now.upperMS, retainedUntil);
      const epoch = await s.worker.run({ kind: "consume", epoch: s.epoch, key, projection: body, retainedUntil }, gate => {
        check(); if (gate.epoch !== s.epoch) fail("fenced"); this.#continuity(); check();
        if (gate.phase === "commit") owner.spendDispatched?.();
      }, { signal: owner.signal, remainingMS: () => { check(); return original.remainingMS(); } });
      // No query or retry can replace this original successful COMMIT receipt.
      committed = true; owner.spent?.(); if (epoch !== s.epoch) fail("fenced"); check();
    } catch (error) {
      const failure = workerFailure(error);
      if (["storage_unavailable", "storage_format", "history_unknown", "fenced"].includes(failure.code))
        s.backing.environment.diagnosticCounters.observe("store_failure", { phase: "spend", code: "store_unavailable" });
      if (failure.writeState === "unknown") s.backing.environment.diagnosticCounters.observe("spend_unknown", { phase: "spend", code: "spend_unknown" });
      if (failure.code === "spend_conflict") s.backing.environment.diagnosticCounters.observe("reservation_conflict", { phase: "spend", code: "reservation_conflict" });
      if (failure.writeState === "committed") owner.spent?.();
      else if (!committed && failure.writeState === "not_submitted") owner.unspent?.();
      if (failure.writeState === "unknown") { s.poisoned = s.closed = true; s.worker.close(); }
      if (committed) throw new V4PoolStoreError(failure.code, "committed");
      throw failure;
    } finally {
      const cleanup = (): void => {
        fields?.proof.fill(0); projection?.fill(0); key?.fill(0); connect.fill(0); carrier.fill(0); facts.close(); reference.release();
        s.active = false; if (s.closed || s.poisoned || s.worker!.closed()) { s.closed = true; s.worker!.close(); this.#cleanup(); }
      };
      // Logical failure can precede physical SQLite/worker cleanup. Keep both
      // original buffers and the cloned worker request charged through exit.
      if (s.worker.closed() && !s.worker.cleanupComplete()) void s.worker.waitCleanup().then(cleanup);
      else cleanup();
    }
  }
  close(): void { this.#state.closed = true; this.#state.worker?.close(); this.#cleanup(); }
  #cleanup(): void {
    const s = this.#state; if (!s.closed || s.active || s.released || s.worker !== undefined && !s.worker.cleanupComplete()) return;
    s.released = true; s.disk.release(); s.backing.active = false; s.dependency.release(); this.#cleanupResolve?.(); this.#cleanupResolve = undefined;
  }
  cleanupComplete(): boolean { return this.#state.closed && this.#state.released; }
  /** Observes actual worker exit. Dropping this wait never cancels a transaction. */
  waitCleanup(): Promise<void> { return this.#cleanupWait; }
  toJSON(): object { return {}; }
}
export async function openV4SQLitePoolStore(backing: V4SQLitePoolBacking, options: V4SQLitePoolOpenOptions): Promise<V4SQLitePoolStore> {
  const owner = sqliteBackingState(backing); if (owner?.reference === undefined || owner.closed || owner.active) fail("owner_unavailable");
  const identity = Object.freeze({ authority: identityText(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: quantity(options.identity.generation) });
  if (typeof options.continuity?.check !== "function" || typeof options.create !== "boolean" || options.bindings.length < 1 || options.bindings.length > 64) fail("configuration_capacity");
  const continuity = options.continuity.check.bind(options.continuity), bindings = Object.freeze(options.bindings.map(binding => Object.freeze({ tenant: identityText(binding.tenant), issuer: fixed(binding.issuer, 16) })));
  owner.reference.check(); const disk = owner.reference.borrow(); let dependency: EnvironmentDependency | undefined, store: V4SQLitePoolStore | undefined;
  try {
    // Includes the actual worker's bounded heap/code/stack, control descriptor
    // and lifetime task in addition to SQLite cache/file allocations.
    const workerCharge = new ResourceVector([65536n + poolProjectionInspectionBytes, 32n << 20n, 0n, 4097n, 1n, 1n, 0n, 0n, 0n, 0n, 1n]);
    dependency = owner.environment.admitDependency("pool_store", storeCharge(owner.limits).add(workerCharge)); owner.active = true;
    store = new V4SQLitePoolStore(token, { backing: owner, dependency, disk, identity, continuity, bindings, worker: undefined, epoch: 0n, active: false, closed: false, poisoned: false, released: false });
    dependency.onClose(() => store!.close()); await store.initialize(token, options.create); return store;
  } catch (error) {
    store?.close(); if (store !== undefined) await store.waitCleanup();
    else { disk.release(); dependency?.release(); owner.active = false; }
    throw workerFailure(error);
  }
}
for (const constructor of [V4SQLitePoolBacking, V4SQLitePoolStore, V4PoolStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

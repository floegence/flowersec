import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { closeSync, constants, openSync, type Stats } from "node:fs";
import type { EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialOwner, equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedPoolSpendFacts, type VerifiedPoolSpendFacts, type PoolSpendFields } from "../v4/runtime/credentialVerifier.js";
import { registerPoolSpendStore, type PoolSpendOwner, type PoolSpendStore } from "../v4/runtime/poolSpend.js";
import { poolLeaseKey as leaseKey, encodePoolProjection as encodeProjection } from "../v4/runtime/poolRecord.js";
import type { TrustedDeadline } from "../v4/runtime/deadline.js";
import { V4SQLitePoolBacking, V4PoolStoreError, fail, maximum, fixed, quantity, identityText, storeCharge, u64, readU64, missing, syncDirectory,
  sqliteBackingState, sqliteScalar, sqliteExec, sqliteFiles, sqliteConfigure, sqliteCheckpoint, type BackingState,
  type V4SQLitePoolIdentity, type V4SQLitePoolContinuity, type V4SQLitePoolBinding, type V4SQLitePoolOpenOptions } from "./sqliteV4.js";
export { createV4SQLitePoolBacking, createSQLitePoolBacking, V4SQLitePoolBacking, V4PoolStoreError } from "./sqliteV4.js";
export type { V4SQLitePoolLimits, V4SQLitePoolIdentity, V4SQLitePoolContinuity, V4SQLitePoolBinding, V4SQLitePoolOpenOptions, V4PoolStoreFailure } from "./sqliteV4.js";
const token = Symbol("node pool store"), minimumRetentionMS = 604800000n;
// This adapter has one explicit local storage format. It does not identify its
// purpose-limited schema as the Go multi-purpose SQLite store format.
const manifestSQL = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-node-pool'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, spend_rows INTEGER NOT NULL CHECK(spend_rows>=0)) STRICT, WITHOUT ROWID";
const spendSQL = "CREATE TABLE spend (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source=1), state INTEGER NOT NULL CHECK(state=1), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
interface StoreState {
  backing: BackingState; dependency: EnvironmentDependency; disk: ResourceReference; identity: V4SQLitePoolIdentity; continuity: V4SQLitePoolContinuity["check"];
  bindings: readonly V4SQLitePoolBinding[]; database: DatabaseSync | undefined; inode: Stats | undefined; epoch: bigint; active: boolean; closed: boolean; poisoned: boolean;
}
/** Real local, serializable pool once authority. No callback can report commit
 * success. Every successful consume is a FULL-synchronous SQLite transaction. */
export class V4SQLitePoolStore implements PoolSpendStore {
  readonly #state: StoreState;
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerPoolSpendStore(this); Object.freeze(this); }
  #scalar(sql: string, ...args: SQLInputValue[]): SQLOutputValue {
    return sqliteScalar(this.#state.database!, sql, ...args);
  }
  #exec(sql: string, ...args: SQLInputValue[]): void { sqliteExec(this.#state.database!, sql, ...args); }
  #files(): void { const s = this.#state; s.inode = sqliteFiles(s.backing, s.inode); }
  #continuity(provisioning = false): void {
    const s = this.#state;
    if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), s.epoch, provisioning) !== undefined) fail("history_unknown");
  }
  #check(): void {
    const s = this.#state; if (s.closed || s.poisoned || s.database === undefined) fail("closed");
    s.dependency.check(); s.disk.check(); this.#files();
  }
  #fence(): void {
    const s = this.#state; if (readU64(this.#scalar("SELECT epoch FROM manifest WHERE id=1")) !== s.epoch) fail("fenced"); this.#continuity();
  }
  #checkpoint(): void {
    sqliteCheckpoint(this.#state.database!);
  }
  initialize(capability: symbol, create: boolean): void {
    if (capability !== token) fail("owner_unavailable"); const s = this.#state, c = s.backing.limits;
    s.active = true;
    try {
      s.dependency.check(); s.disk.check(); if (create) this.#continuity(true);
      if (create) {
        if (["", "-wal", "-shm", "-journal"].some(suffix => !missing(s.backing.path + suffix))) fail("history_unknown");
        const fd = openSync(s.backing.path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); closeSync(fd);
      } else if (missing(s.backing.path)) fail("history_unknown");
      this.#files();
      s.database = new DatabaseSync(s.backing.path, { allowExtension: false, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false, timeout: 0 });
      sqliteConfigure(s.database, c, create);
      this.#exec("BEGIN IMMEDIATE");
      try {
        if (create) {
          this.#exec(manifestSQL); this.#exec(spendSQL); this.#exec("PRAGMA user_version=1"); s.epoch = 1n;
          this.#exec("INSERT INTO manifest VALUES(1,'flowersec-v4-node-pool',1,?,?,?,?,?,?,?,0)", s.identity.authority, s.identity.storeID, u64(s.identity.generation), u64(s.epoch), c.maxPages, c.maxRecords, c.maxRecordBytes);
        } else {
          this.#validate(); if (s.epoch === maximum) fail("fenced"); this.#continuity(); const old = s.epoch; s.epoch++;
          this.#exec("UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?", u64(s.epoch), u64(old)); if (this.#scalar("SELECT changes()") !== 1) fail("fenced");
        }
        s.dependency.check(); s.disk.check(); this.#continuity();
        try { this.#exec("COMMIT"); } catch { s.poisoned = true; throw new V4PoolStoreError("spent_unknown", "unknown"); }
      } catch (error) { try { this.#exec("ROLLBACK"); } catch { s.poisoned = true; } throw error; }
      if (create) syncDirectory(s.backing.path); this.#check();
    } finally { s.active = false; if (s.closed) this.#cleanup(); }
  }
  #validate(): void {
    const s = this.#state, c = s.backing.limits;
    if (this.#scalar("PRAGMA user_version") !== 1 || this.#scalar("SELECT count(*) FROM sqlite_schema") !== 2) fail("storage_format");
    for (const [name, sql] of [["manifest", manifestSQL], ["spend", spendSQL]] as const) {
      if (this.#scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql.length || this.#scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql) fail("storage_format");
    }
    if (this.#scalar("SELECT count(*) FROM manifest") !== 1 || this.#scalar("SELECT length(authority) FROM manifest WHERE id=1") !== s.identity.authority.length) fail("storage_format");
    const row = s.database!.prepare("SELECT * FROM manifest WHERE id=1").get(); if (row === undefined) fail("storage_format");
    if (row.format !== "flowersec-v4-node-pool" || row.revision !== 1 || row.authority !== s.identity.authority || !(row.instance instanceof Uint8Array) || !equalCredential(row.instance, s.identity.storeID) || readU64(row.generation) !== s.identity.generation ||
      row.max_pages !== c.maxPages || row.max_records !== c.maxRecords || row.max_record_bytes !== c.maxRecordBytes || typeof row.spend_rows !== "number" || row.spend_rows < 0 || row.spend_rows > c.maxRecords || this.#scalar("SELECT count(*) FROM spend") !== row.spend_rows) fail("storage_format");
    s.epoch = readU64(row.epoch); if (s.epoch === 0n) fail("storage_format");
    if (this.#scalar("SELECT count(*) FROM spend WHERE length(projection)>? OR length(projection)<1 OR fence>? OR version<>? OR source<>1 OR state<>1", c.maxRecordBytes, u64(s.epoch), u64(1n)) !== 0) fail("storage_format");
  }
  consume(facts: VerifiedPoolSpendFacts, owner: PoolSpendOwner, deadline: TrustedDeadline, admission: ResourceReference, guard: () => void): void {
    const s = this.#state, c = s.backing.limits;
    if (!isVerifiedPoolSpendFacts(facts) || typeof guard !== "function" || !deadline.belongsTo(s.backing.environment.clock)) fail("owner_unavailable");
    this.#check(); if (s.active) fail("capacity");
    if (!s.dependency.reference.sameEnvironment(admission)) fail("owner_unavailable"); facts.check(admission);
    const connect = fixed(owner.connect, 16), carrier = fixed(owner.carrier, 16), generation = quantity(owner.generation);
    const r = s.backing.environment.resources, reference = r.root.reserve({ owner: credentialOwner(r, "pool_consume"), accounts: r.accounts,
      charge: new ResourceVector([BigInt(c.maxRecordBytes * 2 + 16384) + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]) });
    let fields: PoolSpendFields | undefined, projection: Uint8Array | undefined, key: Uint8Array | undefined, committing = false, committed = false;
    s.active = true;
    try {
      fields = facts.fields(admission);
      if (fields.authority !== s.identity.authority || !s.bindings.some(binding => binding.tenant === fields!.tenant && equalCredential(binding.issuer, fields!.issuer))) fail("owner_unavailable");
      const original = deadline.fork(deadline.cap < fields.activationEnd ? deadline.cap : fields.activationEnd);
      const check = (): void => { this.#check(); reference.check(); admission.check(); original.check(); facts.check(admission); if (guard() !== undefined) fail("owner_unavailable"); };
      check(); const now = original.sample().requireInterval();
      if (now.lowerMS < fields.issuedAt || fields.initiationEnd > maximum - minimumRetentionMS || now.upperMS > maximum - minimumRetentionMS) fail("configuration_capacity");
      const retainedUntil = (fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS) + minimumRetentionMS;
      key = leaseKey(fields); projection = new Uint8Array(c.maxRecordBytes);
      const body = encodeProjection(projection, fields, s.identity, s.epoch, { connect, carrier, generation }, original.cap, now.upperMS, retainedUntil);
      this.#checkpoint(); check(); this.#exec("BEGIN IMMEDIATE");
      try {
        this.#fence(); check();
        if (this.#scalar("SELECT count(*) FROM spend WHERE lease=?", key) !== 0) fail("spend_conflict");
        const rows = this.#scalar("SELECT spend_rows FROM manifest WHERE id=1"); if (typeof rows !== "number" || rows < 0) fail("storage_format"); if (rows >= c.maxRecords) fail("capacity");
        this.#exec("INSERT INTO spend VALUES(?,1,1,?,?,?,?)", key, u64(1n), u64(s.epoch), u64(retainedUntil), body);
        this.#exec("UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1 AND epoch=?", u64(s.epoch)); if (this.#scalar("SELECT changes()") !== 1) fail("fenced");
        check(); committing = true;
        try { this.#exec("COMMIT"); } catch { s.poisoned = true; throw new V4PoolStoreError("spent_unknown", "unknown"); }
        committing = false; committed = true;
      } catch (error) { try { this.#exec("ROLLBACK"); } catch { s.poisoned = true; } throw error; }
      // No query or retry can replace this original successful COMMIT receipt.
      // A late cancellation or expired original deadline cannot activate.
      check();
    } catch (error) {
      if (committing) throw new V4PoolStoreError("spent_unknown", "unknown");
      if (committed) throw new V4PoolStoreError(error instanceof V4PoolStoreError ? error.code : "owner_unavailable", "committed");
      if (error instanceof V4PoolStoreError) throw error;
      // Storage/provider details are never copied into the public diagnostic.
      fail("storage_unavailable");
    } finally {
      fields?.proof.fill(0); projection?.fill(0); key?.fill(0); connect.fill(0); carrier.fill(0); facts.close(); reference.release(); s.active = false; if (s.closed || s.poisoned) { s.closed = true; this.#cleanup(); }
    }
  }
  close(): void { this.#state.closed = true; this.#cleanup(); }
  #cleanup(): void {
    const s = this.#state; if (!s.closed || s.active) return;
    try { s.database?.close(); } catch { return; }
    s.database = undefined; s.disk.release(); s.backing.active = false; s.dependency.release();
  }
  cleanupComplete(): boolean { return this.#state.closed && this.#state.database === undefined; }
  toJSON(): object { return {}; }
}
export function openV4SQLitePoolStore(backing: V4SQLitePoolBacking, options: V4SQLitePoolOpenOptions): V4SQLitePoolStore {
  const owner = sqliteBackingState(backing); if (owner?.reference === undefined || owner.closed || owner.active) fail("owner_unavailable");
  const identity = Object.freeze({ authority: identityText(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: quantity(options.identity.generation) });
  if (typeof options.continuity?.check !== "function" || typeof options.create !== "boolean" || options.bindings.length < 1 || options.bindings.length > 64) fail("configuration_capacity");
  const continuity = options.continuity.check.bind(options.continuity), bindings = Object.freeze(options.bindings.map(binding => Object.freeze({ tenant: identityText(binding.tenant), issuer: fixed(binding.issuer, 16) })));
  owner.reference.check(); const disk = owner.reference.borrow(); let dependency: EnvironmentDependency | undefined, store: V4SQLitePoolStore | undefined;
  try {
    dependency = owner.environment.admitDependency("pool_store", storeCharge(owner.limits)); owner.active = true;
    store = new V4SQLitePoolStore(token, { backing: owner, dependency, disk, identity, continuity, bindings, database: undefined, inode: undefined, epoch: 0n, active: false, closed: false, poisoned: false });
    dependency.onClose(() => store!.close()); store.initialize(token, options.create); return store;
  } catch (error) {
    store?.close(); if (store === undefined) { disk.release(); dependency?.release(); owner.active = false; }
    if (error instanceof V4PoolStoreError) throw error; fail("storage_unavailable");
  }
}
for (const constructor of [V4SQLitePoolBacking, V4SQLitePoolStore, V4PoolStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

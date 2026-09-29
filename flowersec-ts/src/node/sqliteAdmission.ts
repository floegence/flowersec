import { registerServerAdmissionAuthority, type ServerAdmissionAuthority, type AdmissionResponse } from "../v4/runtime/serverAdmissionAuthority.js";
export type { AdmissionResponse } from "../v4/runtime/serverAdmissionAuthority.js";
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { closeSync, constants, openSync, type Stats } from "node:fs";
import type { EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedCredentialClosure, type VerifiedCredentialClosure, type ServerAdmissionFields } from "../v4/runtime/credentialVerifier.js";
import { admissionLeaseKey, encodeParentWinner, encodeAdmission, type ServerAdmissionOwner } from "./admissionRecord.js";
import { randomFillSync } from "node:crypto";
import type { TrustedDeadline } from "../v4/runtime/deadline.js";
import { type V4SQLitePoolBacking, V4PoolStoreError, maximum, fixed, quantity, identityText, storeCharge, u64, readU64, missing, syncDirectory,
  sqliteBackingState, sqliteScalar, sqliteExec, sqliteFiles, sqliteConfigure, sqliteCheckpoint, type BackingState,
  type V4SQLitePoolIdentity, type V4SQLitePoolContinuity, type V4SQLitePoolLimits } from "./sqliteV4.js";
const token = Symbol("node admission store"), minimumRetentionMS = 604800000n;
export type AdmissionStoreFailure = "configuration_capacity" | "storage_unavailable" | "storage_format" | "history_unknown" | "fenced" | "admission_conflict" | "admission_unknown" | "capacity" | "owner_unavailable" | "closed";
export class AdmissionStoreError extends Error {
  constructor(readonly code: AdmissionStoreFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted") { super(code); this.name = "AdmissionStoreError"; }
}
function fail(code: AdmissionStoreFailure): never { throw new AdmissionStoreError(code); }
function failure(error: unknown, state: AdmissionStoreError["writeState"] = "not_submitted"): AdmissionStoreError {
  if (error instanceof AdmissionStoreError) return new AdmissionStoreError(error.code, state === "not_submitted" ? error.writeState : state);
  if (error instanceof V4PoolStoreError && error.code !== "spend_conflict" && error.code !== "spent_unknown") return new AdmissionStoreError(error.code, state);
  return new AdmissionStoreError("storage_unavailable", state);
}
export interface AdmissionAuthorityBinding {
  readonly tenant: string; readonly issuer: Uint8Array; readonly audience: string; readonly serverIdentity: Uint8Array;
}
export interface SQLiteAdmissionOpenOptions {
  readonly identity: V4SQLitePoolIdentity; readonly continuity: V4SQLitePoolContinuity;
  /** Trusted stable service resolution, independent of consumer/peer input. */
  readonly bindings: readonly AdmissionAuthorityBinding[];
  /** All candidate services of a pool parent resolve to this same authority. */
  readonly parentWinnerStore?: SQLiteAdmissionStore;
  readonly create: boolean;
}
/** Must be included in the original Session admission reservation before any
 * durable write. Includes both projections, confirmation row and original FSB. */
export function sqliteAdmissionCharge(c: Pick<V4SQLitePoolLimits, "maxRecordBytes" | "runtimeBytes">): ResourceVector {
  if (!Number.isSafeInteger(c.maxRecordBytes) || c.maxRecordBytes < 8192 || c.maxRecordBytes > 1048576 || c.runtimeBytes <= 0n) fail("configuration_capacity");
  return new ResourceVector([BigInt(c.maxRecordBytes) * 4n + 131072n + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
const manifestSQL = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-node-admission'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, admission_rows INTEGER NOT NULL CHECK(admission_rows>=0), winner_rows INTEGER NOT NULL CHECK(winner_rows>=0)) STRICT, WITHOUT ROWID";
const admissionSQL = "CREATE TABLE admission (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source IN (0,1)), state INTEGER NOT NULL CHECK(state IN (0,1)), admission_count INTEGER NOT NULL CHECK(admission_count=state), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
const winnerSQL = "CREATE TABLE parent_winner (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
interface StoreState {
  backing: BackingState; dependency: EnvironmentDependency; disk: ResourceReference; identity: V4SQLitePoolIdentity; continuity: V4SQLitePoolContinuity["check"];
  bindings: readonly AdmissionAuthorityBinding[]; parent: SQLiteAdmissionStore | undefined; database: DatabaseSync | undefined; inode: Stats | undefined; epoch: bigint; active: boolean; closed: boolean; poisoned: boolean;
}
/** Internal server authority. The original admitted CAS or one bounded read
 * confirming that exact CAS can authorize its unused continuation. Reopen
 * and repeated requests never restore the original invocation. */
export class SQLiteAdmissionStore implements ServerAdmissionAuthority {
  readonly #state: StoreState;
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerServerAdmissionAuthority(this); Object.freeze(this); }
  charge(): ResourceVector { this.#check(); return sqliteAdmissionCharge(this.#state.backing.limits); }
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
      s.dependency.check(); s.disk.check(); if (s.closed) fail("closed");
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
          this.#exec(manifestSQL); this.#exec(admissionSQL); this.#exec(winnerSQL); this.#exec("PRAGMA user_version=1"); s.epoch = 1n;
          this.#exec("INSERT INTO manifest VALUES(1,'flowersec-node-admission',1,?,?,?,?,?,?,?,0,0)", s.identity.authority, s.identity.storeID, u64(s.identity.generation), u64(s.epoch), c.maxPages, c.maxRecords, c.maxRecordBytes);
        } else {
          this.#validate(); if (s.epoch === maximum) fail("fenced"); this.#continuity(); const old = s.epoch; s.epoch++;
          this.#exec("UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?", u64(s.epoch), u64(old)); if (this.#scalar("SELECT changes()") !== 1) fail("fenced");
        }
        s.dependency.check(); s.disk.check(); this.#continuity();
        s.dependency.check(); s.disk.check(); if (s.closed) fail("closed");
        try { this.#exec("COMMIT"); } catch { s.poisoned = true; throw new AdmissionStoreError("admission_unknown", "unknown"); }
      } catch (error) { try { this.#exec("ROLLBACK"); } catch { s.poisoned = true; } throw error; }
      if (create) syncDirectory(s.backing.path); this.#check();
    } finally { s.active = false; if (s.closed) this.#cleanup(); }
  }
  #validate(): void {
    const s = this.#state, c = s.backing.limits;
    if (this.#scalar("PRAGMA user_version") !== 1 || this.#scalar("SELECT count(*) FROM sqlite_schema") !== 3) fail("storage_format");
    for (const [name, sql] of [["manifest", manifestSQL], ["admission", admissionSQL], ["parent_winner", winnerSQL]] as const) {
      if (this.#scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql.length || this.#scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql) fail("storage_format");
    }
    if (this.#scalar("SELECT count(*) FROM manifest") !== 1 || this.#scalar("SELECT length(authority) FROM manifest WHERE id=1") !== s.identity.authority.length) fail("storage_format");
    const row = s.database!.prepare("SELECT * FROM manifest WHERE id=1").get(); if (row === undefined) fail("storage_format");
    if (row.format !== "flowersec-node-admission" || row.revision !== 1 || row.authority !== s.identity.authority || !(row.instance instanceof Uint8Array) || !equalCredential(row.instance, s.identity.storeID) || readU64(row.generation) !== s.identity.generation ||
      row.max_pages !== c.maxPages || row.max_records !== c.maxRecords || row.max_record_bytes !== c.maxRecordBytes || typeof row.admission_rows !== "number" || row.admission_rows < 0 || typeof row.winner_rows !== "number" || row.winner_rows < 0 || row.admission_rows + row.winner_rows > c.maxRecords || this.#scalar("SELECT count(*) FROM parent_winner") !== row.winner_rows || this.#scalar("SELECT count(*) FROM admission") !== row.admission_rows) fail("storage_format");
    if (this.#scalar("SELECT count(*) FROM parent_winner WHERE length(projection)>?", c.maxRecordBytes) !== 0) fail("storage_format");
    s.epoch = readU64(row.epoch); if (s.epoch === 0n) fail("storage_format");
    if (this.#scalar("SELECT count(*) FROM admission WHERE length(projection)>? OR length(projection)<1 OR fence>? OR fence=? OR (state=0 AND version<>?) OR (state=1 AND version<>?)", c.maxRecordBytes, u64(s.epoch), u64(0n), u64(1n), u64(2n)) !== 0) fail("storage_format");
  }
  #capacity(): void {
    const rows = this.#scalar("SELECT admission_rows+winner_rows FROM manifest WHERE id=1");
    if (typeof rows !== "number" || rows < 0) fail("storage_format");
    if (rows >= this.#state.backing.limits.maxRecords) fail("capacity");
  }
  #rollback(): void {
    try { this.#exec("ROLLBACK"); }
    catch {
      // A lost receipt can follow a successful COMMIT. Prove the connection is
      // no longer in a transaction without classifying driver error strings.
      try { this.#exec("BEGIN DEFERRED"); this.#exec("ROLLBACK"); }
      catch { this.#state.poisoned = true; }
    }
  }
  #transaction(check: () => void, write: () => void, confirm?: () => boolean): void {
    this.#checkpoint(); check(); this.#exec("BEGIN IMMEDIATE");
    let submitted = false, committed = false;
    try {
      this.#fence(); check(); write(); check(); submitted = true;
      this.#exec("COMMIT"); committed = true;
    } catch (error) {
      this.#rollback();
      if (!submitted) throw error;
      // Only this still-running invocation retains the original exact CAS and
      // its unused continuation. Reserve/parent writes never use this gate.
      try {
        if (confirm !== undefined) {
          check(); this.#exec("BEGIN IMMEDIATE");
          try { this.#fence(); check(); committed = confirm(); check(); }
          finally { this.#exec("ROLLBACK"); }
        }
      } catch { committed = false; this.#rollback(); }
      if (!committed) throw new AdmissionStoreError("admission_unknown", "unknown");
    }
    try { check(); } catch (error) { throw failure(error, "committed"); }
  }
  #matchesService(f: ServerAdmissionFields): boolean {
    return this.#state.bindings.some(b => b.tenant === f.tenant && equalCredential(b.issuer, f.issuer) &&
      b.audience === f.audience && equalCredential(b.serverIdentity, f.identities[1]!));
  }
  #winner(f: ServerAdmissionFields, key: Uint8Array, projection: Uint8Array, check: () => void): void {
    const s = this.#state;
    this.#check(); if (s.active || s.identity.authority !== f.winnerAuthority || !this.#matchesService(f)) fail("owner_unavailable");
    if (projection.length > s.backing.limits.maxRecordBytes) fail("capacity");
    s.active = true;
    try {
      this.#transaction(() => { this.#check(); check(); this.#check(); }, () => {
        const row = s.database!.prepare("SELECT length(projection) AS size,CASE WHEN length(projection)<=? THEN projection END AS projection FROM parent_winner WHERE lease=?").get(s.backing.limits.maxRecordBytes, key);
        if (row !== undefined) {
          if (!(row.projection instanceof Uint8Array) || row.size !== row.projection.length) fail("storage_format");
          try { if (!equalCredential(row.projection, projection)) fail("admission_conflict"); } finally { row.projection.fill(0); }
          return;
        }
        this.#capacity(); this.#exec("INSERT INTO parent_winner VALUES(?,?)", key, projection);
        this.#exec("UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1");
      });
    } finally { s.active = false; if (s.closed || s.poisoned) { s.closed = true; this.#cleanup(); } }
  }
  admit(closure: VerifiedCredentialClosure, fsb: Uint8Array, context: Uint8Array, owner: ServerAdmissionOwner, deadline: TrustedDeadline,
    admission: ResourceReference, guard: () => void, dispatch: (response: AdmissionResponse) => void): void {
    const s = this.#state, c = s.backing.limits;
    if (!isVerifiedCredentialClosure(closure) || typeof guard !== "function" || typeof dispatch !== "function" || !deadline.belongsTo(s.backing.environment.clock)) fail("owner_unavailable");
    this.#check(); if (s.active) fail("capacity");
    if (!s.dependency.reference.sameEnvironment(admission)) fail("owner_unavailable"); closure.checkPreparation(admission);
    if (!(fsb instanceof Uint8Array) || fsb.length < 1 || fsb.length > 65536 || !(context instanceof Uint8Array) || context.length < 1 || context.length > 2048) fail("configuration_capacity");
    const reference = admission.take(sqliteAdmissionCharge(c));
    let fields: ServerAdmissionFields | undefined, key: Uint8Array | undefined, originalOwner: ServerAdmissionOwner | undefined;
    let originalFSB: Uint8Array | undefined, originalContext: Uint8Array | undefined;
    let reserved: Uint8Array | undefined, target: Uint8Array | undefined, parent: Uint8Array | undefined, reservation: Uint8Array | undefined;
    let writeState: AdmissionStoreError["writeState"] = "not_submitted";
    s.active = true;
    try {
      originalFSB = new Uint8Array(fsb); originalContext = new Uint8Array(context);
      originalOwner = { acceptor: fixed(owner.acceptor, 16), invocation: fixed(owner.invocation, 16), carrier: fixed(owner.carrier, 16), generation: quantity(owner.generation) };
      const signal = owner.signal;
      fields = closure.serverAdmissionFields(originalFSB, originalContext, reference);
      if (!this.#matchesService(fields)) fail("owner_unavailable");
      const parentStore = fields.source === "preauthorized_pool" ? s.parent : undefined;
      const original = deadline.fork(deadline.cap < fields.activationEnd ? deadline.cap : fields.activationEnd);
      const check = (): void => {
        this.#check(); if (parentStore !== undefined) parentStore.#check(); reference.check(); original.check(); deadline.check(); closure.checkPreparation(reference);
        if (signal?.aborted || guard() !== undefined) fail("owner_unavailable");
        // Trusted host hooks can synchronously close the original owner.
        this.#check(); if (parentStore !== undefined) parentStore.#check(); reference.check(); original.check(); deadline.check(); closure.checkPreparation(reference);
        if (signal?.aborted) fail("owner_unavailable");
      };
      check(); const now = original.sample().requireInterval();
      if (now.lowerMS < fields.issuedAt || fields.initiationEnd > maximum - minimumRetentionMS || now.upperMS > maximum - minimumRetentionMS) fail("configuration_capacity");
      const retainedUntil = (fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS) + minimumRetentionMS;
      key = admissionLeaseKey(fields); reserved = new Uint8Array(c.maxRecordBytes); target = new Uint8Array(c.maxRecordBytes); parent = new Uint8Array(c.maxRecordBytes);
      const reservedBody = encodeAdmission(reserved, fields, s.identity, s.epoch, originalOwner, original.cap, now.upperMS, retainedUntil, originalFSB, originalContext, new Uint8Array(), 0n);
      if (reservedBody.length + 48 > c.maxRecordBytes) fail("capacity");
      if (fields.source === "preauthorized_pool") {
        if (s.parent === undefined || !s.parent.#state.dependency.reference.sameEnvironment(reference)) fail("owner_unavailable");
        s.parent.#winner(fields, key, encodeParentWinner(parent, fields), check);
      }
      const lease = key, source = fields.source === "preauthorized_pool" ? 1 : 0;
      this.#transaction(check, () => {
        if (this.#scalar("SELECT count(*) FROM admission WHERE lease=?", lease) !== 0) fail("admission_conflict");
        this.#capacity(); this.#exec("INSERT INTO admission VALUES(?,?,0,0,?,?,?,?)", lease, source, u64(1n), u64(s.epoch), u64(retainedUntil), reservedBody);
        this.#exec("UPDATE manifest SET admission_rows=admission_rows+1 WHERE id=1");
      });
      // Reserve is irrevocable, but it does not grant the continuation.
      writeState = "committed"; check(); reservation = new Uint8Array(32); randomFillSync(reservation);
      if (!reservation.some(value => value !== 0)) fail("storage_unavailable");
      const targetBody = encodeAdmission(target, fields, s.identity, s.epoch, originalOwner, original.cap, now.upperMS, retainedUntil,
        originalFSB, originalContext, reservation, original.sample().requireInterval().upperMS);
      this.#transaction(check, () => {
        this.#exec("UPDATE admission SET state=1,admission_count=1,version=?,projection=? WHERE lease=? AND state=0 AND admission_count=0 AND version=? AND fence=? AND projection=?",
          u64(2n), targetBody, lease, u64(1n), u64(s.epoch), reservedBody);
        if (this.#scalar("SELECT changes()") !== 1) fail("admission_conflict");
      }, () => this.#scalar("SELECT count(*) FROM admission WHERE lease=? AND source=? AND state=1 AND admission_count=1 AND version=? AND fence=? AND retained_until=? AND projection=?",
        lease, source, u64(2n), u64(s.epoch), u64(retainedUntil), targetBody) === 1);
      check();
      // Invoked once within this original local gate. These borrowed bytes are
      // copied by server assembly into its prepaid FSA work before returning.
      if (dispatch(Object.freeze({ serverEpoch: s.epoch, reservationKey: reservation, admissionBinding: fields.admissionBinding })) !== undefined) fail("owner_unavailable");
    } catch (error) {
      if (error instanceof AdmissionStoreError && error.writeState === "unknown") throw error;
      throw failure(error, writeState);
    } finally {
      if (fields !== undefined) { for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0); for (const value of fields.identities) value.fill(0); }
      for (const value of [key, originalFSB, originalContext, reserved, target, parent, reservation, originalOwner?.acceptor, originalOwner?.invocation, originalOwner?.carrier]) value?.fill(0);
      reference.release(); s.active = false; if (s.closed || s.poisoned) { s.closed = true; this.#cleanup(); }
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
export function openSQLiteAdmissionStore(backing: V4SQLitePoolBacking, options: SQLiteAdmissionOpenOptions): SQLiteAdmissionStore {
  const owner = sqliteBackingState(backing); if (owner?.reference === undefined || owner.closed || owner.active) fail("owner_unavailable");
  const identity = Object.freeze({ authority: identityText(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: quantity(options.identity.generation) });
  if (typeof options.continuity?.check !== "function" || typeof options.create !== "boolean" || options.bindings.length < 1 || options.bindings.length > 64) fail("configuration_capacity");
  const continuity = options.continuity.check.bind(options.continuity), bindings = Object.freeze(options.bindings.map(binding => Object.freeze({ tenant: identityText(binding.tenant), issuer: fixed(binding.issuer, 16), audience: identityText(binding.audience), serverIdentity: fixed(binding.serverIdentity, 32) })));
  owner.reference.check(); const disk = owner.reference.borrow(); let dependency: EnvironmentDependency | undefined, store: SQLiteAdmissionStore | undefined;
  try {
    dependency = owner.environment.admitDependency("server_admission_store", storeCharge(owner.limits)); owner.active = true;
    store = new SQLiteAdmissionStore(token, { backing: owner, dependency, disk, identity, continuity, bindings, parent: options.parentWinnerStore, database: undefined, inode: undefined, epoch: 0n, active: false, closed: false, poisoned: false });
    dependency.onClose(() => store!.close()); store.initialize(token, options.create); return store;
  } catch (error) {
    store?.close(); if (store === undefined) { disk.release(); dependency?.release(); owner.active = false; }
    throw failure(error);
  }
}
for (const constructor of [SQLiteAdmissionStore, AdmissionStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

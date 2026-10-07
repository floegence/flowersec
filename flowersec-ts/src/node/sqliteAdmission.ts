import { registerServerAdmissionAuthority, type ServerAdmissionAuthority, type AdmissionResponse } from "../v4/runtime/serverAdmissionAuthority.js";
export type { AdmissionResponse } from "../v4/runtime/serverAdmissionAuthority.js";
import type { SQLInputValue, SQLOutputValue } from "node:sqlite";
import { SQLiteWorkerDatabase, SQLiteWorkerError, sqliteWorkerCharge } from "./sqliteWorkerV4.js";
import type { EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { CredentialWork, credentialWorkCharge, credentialOwner, equalCredential } from "../v4/runtime/credentialSupport.js";
import { isVerifiedCredentialClosure, type VerifiedCredentialClosure, type ServerAdmissionFields } from "../v4/runtime/credentialVerifier.js";
import { admissionLeaseKey, encodeParentWinner, encodeAdmission, validatePersistedAdmission, validatePersistedParentWinner, type ServerAdmissionOwner } from "./admissionRecord.js";
import { randomFillSync } from "node:crypto";
import type { TrustedDeadline } from "../v4/runtime/deadline.js";
import { type V4SQLitePoolBacking, V4PoolStoreError, maximum, fixed, quantity, identityText, storeCharge, u64, readU64, sqliteBackingState, type BackingState, type V4SQLitePoolIdentity, type V4SQLitePoolContinuity, type V4SQLitePoolLimits } from "./sqliteV4.js";
import { isVerifiedRelayClaim, type VerifiedRelayClaim, type RelayCredentialInput } from "../v4/runtime/relayCredentials.js";
import { captureRelayIssuance, clearRelayIssuance, clearRelayFields, relayClaimKey, encodeRelayClaim, validatePersistedRelayIssuance, validatePersistedRelayClaim, type PersistedRelayIssuance } from "./relayRecord.js";
import { isOriginalLiveGrantTransaction, matchesUnsignedCredential, type OriginalLiveGrantTransaction } from "./liveTunnelAuthorityCurrent.js";
import { isOriginalGrantIssuance, type OriginalGrantIssuance } from "./grantIssuerCurrent.js";
import { isRegisteredTunnelParentWinner, type RegisteredTunnelParentWinner } from "./registeredTunnelControl.js";
import { inspectSQLiteStorageHeader, storageFormatProjection, type StorageFormatProjection, type StorageRevision } from "./sqliteFormat.js";
const token = Symbol("node admission store"), minimumRetentionMS = 604800000n;
export type AdmissionStoreFailure = "configuration_capacity" | "storage_unavailable" | "storage_format" | "history_unknown" | "fenced" | "admission_conflict" | "admission_unknown" | "relay_conflict" | "relay_unknown" | "capacity" | "owner_unavailable" | "closed";
export class AdmissionStoreError extends Error {
  constructor(readonly code: AdmissionStoreFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted", readonly format?: StorageFormatProjection) { super(format?.code ?? code); this.name = "AdmissionStoreError"; }
}
function fail(code: AdmissionStoreFailure): never { throw new AdmissionStoreError(code); }
function failure(error: unknown, state: AdmissionStoreError["writeState"] = "not_submitted"): AdmissionStoreError {
  if (error instanceof SQLiteWorkerError)
    return new AdmissionStoreError(error.code, state === "not_submitted" ? error.writeState : state);
  if (error instanceof AdmissionStoreError) return new AdmissionStoreError(error.code, state === "not_submitted" ? error.writeState : state, error.format);
  if (error instanceof V4PoolStoreError && error.code !== "spend_conflict" && error.code !== "spent_unknown") return new AdmissionStoreError(error.code, state, error.format);
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
  /** Original authenticated B registration with the pool authority process. */
  readonly parentWinnerAuthority?: RegisteredTunnelParentWinner;
  readonly create: boolean;
}
/** Must be included in the original Session admission reservation before any
 * durable write. Includes both projections, confirmation row and original FSB. */
export function sqliteAdmissionCharge(c: Pick<V4SQLitePoolLimits, "maxRecordBytes" | "runtimeBytes">): ResourceVector {
  if (!Number.isSafeInteger(c.maxRecordBytes) || c.maxRecordBytes < 8192 || c.maxRecordBytes > 1048576 || c.runtimeBytes <= 0n) fail("configuration_capacity");
  return new ResourceVector([BigInt(c.maxRecordBytes) * 4n + 131072n + c.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
const manifestSQL = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-node-admission'), revision INTEGER NOT NULL CHECK(revision=3), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, admission_rows INTEGER NOT NULL CHECK(admission_rows>=0), winner_rows INTEGER NOT NULL CHECK(winner_rows>=0), relay_rows INTEGER NOT NULL CHECK(relay_rows>=0), issuance_rows INTEGER NOT NULL CHECK(issuance_rows>=0)) STRICT, WITHOUT ROWID";
const liveAuthoritySQL = "CREATE TABLE live_authority (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), invocation BLOB NOT NULL CHECK(length(invocation)=16), candidate BLOB NOT NULL CHECK(length(candidate)=16), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), authority TEXT NOT NULL, signing_key TEXT NOT NULL, proof_draft BLOB NOT NULL CHECK(length(proof_draft) BETWEEN 1 AND 4096), client_draft BLOB NOT NULL CHECK(length(client_draft) BETWEEN 1 AND 65536), server_draft BLOB NOT NULL CHECK(length(server_draft) BETWEEN 1 AND 65536), signers BLOB NOT NULL CHECK(length(signers)=96), recipient BLOB NOT NULL CHECK(length(recipient)=16), incarnation BLOB NOT NULL CHECK(length(incarnation)=16), state INTEGER NOT NULL CHECK(state IN (0,1)), proof BLOB NOT NULL CHECK(length(proof)<=4096), client_grant BLOB NOT NULL CHECK(length(client_grant)<=65536), server_grant BLOB NOT NULL CHECK(length(server_grant)<=65536), CHECK((state=0 AND length(proof)=0 AND length(client_grant)=0 AND length(server_grant)=0) OR (state=1 AND length(proof)>0 AND length(client_grant)>0 AND length(server_grant)>0))) STRICT, WITHOUT ROWID";
const admissionSQL = "CREATE TABLE admission (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source IN (0,1)), state INTEGER NOT NULL CHECK(state IN (0,1)), admission_count INTEGER NOT NULL CHECK(admission_count=state), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
const winnerSQL = "CREATE TABLE parent_winner (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
const relayIssuanceSQL = "CREATE TABLE relay_issuance (lease BLOB NOT NULL CHECK(length(lease) BETWEEN 34 AND 161), candidate BLOB NOT NULL CHECK(length(candidate)=16), side INTEGER NOT NULL CHECK(side IN (0,1)), grant_digest BLOB NOT NULL CHECK(length(grant_digest)=32), grant BLOB NOT NULL CHECK(length(grant) BETWEEN 1 AND 65536), endpoint_certificate BLOB NOT NULL CHECK(length(endpoint_certificate) BETWEEN 1 AND 8192), relay_certificate BLOB NOT NULL CHECK(length(relay_certificate) BETWEEN 1 AND 8192), root BLOB NOT NULL CHECK(length(root) BETWEEN 1 AND 1048576), winner BLOB NOT NULL CHECK(length(winner) BETWEEN 1 AND 1048576), source INTEGER NOT NULL CHECK(source IN (0,1)), winner_authority TEXT NOT NULL, PRIMARY KEY(lease,candidate,side)) STRICT, WITHOUT ROWID";
const relayParentSQL = "CREATE TABLE relay_parent (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), original BLOB NOT NULL CHECK(length(original) BETWEEN 1 AND 1048576), selected BLOB NOT NULL CHECK(length(selected)<=1048576), version BLOB NOT NULL CHECK(length(version)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8)) STRICT, WITHOUT ROWID";
const relayLegSQL = "CREATE TABLE relay_leg (lease BLOB NOT NULL CHECK(length(lease) BETWEEN 34 AND 161), side INTEGER NOT NULL CHECK(side IN (0,1)), claimed INTEGER NOT NULL CHECK(claimed IN (0,1)), projection BLOB NOT NULL CHECK(length(projection)<=1048576), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), PRIMARY KEY(lease,side)) STRICT, WITHOUT ROWID";
export interface RelayActivationOwner { readonly relay: Uint8Array; readonly invocation: Uint8Array; readonly carrier: Uint8Array; readonly generation: bigint; readonly signal?: AbortSignal; }
export function sqliteRelayActivationCharge(c: Pick<V4SQLitePoolLimits, "maxRecordBytes" | "runtimeBytes">): ResourceVector {
  return sqliteAdmissionCharge(c).add(new ResourceVector([BigInt(c.maxRecordBytes) * 4n + 196608n, 0n, 0n, 4n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
}
interface StoreState {
  backing: BackingState;
  dependency: EnvironmentDependency;
  disk: ResourceReference;
  identity: V4SQLitePoolIdentity;
  continuity: V4SQLitePoolContinuity["check"];
  bindings: readonly AdmissionAuthorityBinding[];
  parent: SQLiteAdmissionStore | undefined;
  remoteParent: RegisteredTunnelParentWinner | undefined;
  database: SQLiteWorkerDatabase | undefined;
  released: boolean;
  epoch: bigint;
  active: boolean;
  closed: boolean;
  poisoned: boolean;
}
/** Internal server authority. The original admitted CAS or one bounded read
 * confirming that exact CAS can authorize its unused continuation. Reopen
 * and repeated requests never restore the original invocation. */
export class SQLiteAdmissionStore implements ServerAdmissionAuthority {
  readonly #state: StoreState;
  constructor(capability: symbol, state: StoreState) { if (capability !== token) fail("owner_unavailable"); this.#state = state; registerServerAdmissionAuthority(this); Object.freeze(this); }
  /** Checks actual original authority ownership. Matching authority text or
   * independent databases cannot satisfy this registration. */
  hasOriginalParentWinner(parent: SQLiteAdmissionStore, reference: ResourceReference): boolean {
    this.#check(); parent.#check(); reference.check();
    return this !== parent && this.#state.parent === parent && this.#state.dependency.reference.sameEnvironment(reference) && parent.#state.dependency.reference.sameEnvironment(reference);
  }
  authorityID(): string { this.#check(); return this.#state.identity.authority; }
  /** @internal
   * Read only: match the exact winner already selected by the original relay
   * transaction. Neither this result nor a remote reply carries dispatch rights. */
  async matchOriginalParentWinner(authority: string, key: Uint8Array, projection: Uint8Array, reference: ResourceReference, guard: () => void, signal: AbortSignal, remainingMS: () => bigint): Promise<void> {
    const s = this.#state; this.#check();
    if (s.active || authority !== s.identity.authority || !s.dependency.reference.sameEnvironment(reference) || key.length < 34 || key.length > 161 || projection.length < 1 || projection.length > s.backing.limits.maxRecordBytes) fail("owner_unavailable");
    const check = (): void => { this.#check(); reference.check(); guard(); this.#check(); reference.check(); if (signal.aborted) fail("owner_unavailable"); };
    check(); s.active = true;
    let unobserve: (() => void) | undefined;
    try {
      unobserve = s.database!.observe(signal, () => { check(); return remainingMS(); });
      const row = await s.database!.get("SELECT length(projection) AS size,CASE WHEN length(projection)<=? THEN projection END AS projection FROM parent_winner WHERE lease=?", s.backing.limits.maxRecordBytes, key);
      if (row === undefined) { check(); fail("history_unknown"); }
      if (!(row.projection instanceof Uint8Array) || row.size !== row.projection.length) fail("storage_format");
      try { check(); if (!equalCredential(row.projection, projection)) fail("admission_conflict"); } finally { row.projection.fill(0); }
    } finally {
      unobserve?.(); const cleanup = (): void => { s.active = false; this.#cleanup(); };
      if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(cleanup); else cleanup();
    }
  }
  relayCharge(): ResourceVector { this.#check(); return sqliteRelayActivationCharge(this.#state.backing.limits); }
  charge(): ResourceVector { this.#check(); return sqliteAdmissionCharge(this.#state.backing.limits); }
  async #scalar(sql: string, ...args: SQLInputValue[]): Promise<SQLOutputValue> {
    const row = await this.#state.database!.get(sql, ...args);
    if (row === undefined || Object.keys(row).length !== 1)
      fail("storage_format");
    return Object.values(row)[0]!;
  }
  async #exec(sql: string, ...args: SQLInputValue[]): Promise<void> {
    if (args.length === 0)
      await this.#state.database!.exec(sql);
    else
      await this.#state.database!.run(sql, ...args);
  }
  #continuity(provisioning = false): void {
    const s = this.#state;
    if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), s.epoch, provisioning) !== undefined) fail("history_unknown");
  }
  #check(): void {
    const s = this.#state;
    if (s.closed || s.poisoned || s.database === undefined) fail("closed");
    s.dependency.check();
    s.disk.check();
    if (s.database.closed())
      fail("closed");
  }
  async #fence(): Promise<void> {
    const s = this.#state;
    if (readU64((await this.#scalar("SELECT epoch FROM manifest WHERE id=1"))) !== s.epoch)
      fail("fenced");
    this.#continuity();
  }
  async #checkpoint(): Promise<void> {
    await this.#state.database!.checkpoint();
  }
  async initialize(capability: symbol, create: boolean): Promise<void> {
    if (capability !== token) fail("owner_unavailable");
    const s = this.#state, c = s.backing.limits;
    let observedRevision: StorageRevision = { known: false, value: 0 }, formatPhase: StorageFormatProjection["reason"] = "backend_configuration";
    s.active = true;
    try {
      s.dependency.check();
      s.disk.check();
      if (create) this.#continuity(true);
      s.dependency.check();
      s.disk.check();
      if (s.closed) fail("closed");
      s.database = new SQLiteWorkerDatabase(s.backing.path, c, () => { s.closed = true; this.#cleanup(); });
      await s.database.open(create, true);
      if (!create) {
        const inspectCurrent = async (): Promise<void> => {
          await this.#exec("BEGIN");
          try {
            formatPhase = "manifest_unknown_or_invalid";
            const header = await inspectSQLiteStorageHeader((sql, ...args) => s.database!.get(sql, ...args), manifestSQL, "flowersec-node-admission", 3, s.identity);
            observedRevision = header.observedRevision;
            if (header.refusal !== undefined) throw new AdmissionStoreError("storage_format", "not_submitted", storageFormatProjection("flowersec-node-admission", 3, observedRevision, header.refusal.reason));
            formatPhase = "schema_or_state_invalid";
            await this.#validate();
            if (await this.#scalar("PRAGMA quick_check") !== "ok") throw new AdmissionStoreError("storage_format");
            formatPhase = "backend_configuration";
            if (await this.#scalar("PRAGMA page_size") !== 4096 || await this.#scalar("PRAGMA journal_mode") !== "wal") throw new AdmissionStoreError("storage_format");
            await s.database!.files();
          } finally { await this.#exec("ROLLBACK"); }
        };
        await inspectCurrent();
        formatPhase = "backend_configuration";
        await s.database.admitWrites();
        await s.database.configureCurrent();
      }
      (await this.#exec("BEGIN IMMEDIATE"));
      try {
        if (create) {
          (await this.#exec(manifestSQL));
          (await this.#exec(admissionSQL));
          (await this.#exec(winnerSQL));
          (await this.#exec(relayIssuanceSQL));
          (await this.#exec(relayParentSQL));
          (await this.#exec(relayLegSQL));
          (await this.#exec(liveAuthoritySQL));
          (await this.#exec("PRAGMA user_version=3"));
          s.epoch = 1n;
          (await this.#exec("INSERT INTO manifest VALUES(1,'flowersec-node-admission',3,?,?,?,?,?,?,?,0,0,0,0)", s.identity.authority, s.identity.storeID, u64(s.identity.generation), u64(s.epoch), c.maxPages, c.maxRecords, c.maxRecordBytes));
        }
        else {
          formatPhase = "manifest_unknown_or_invalid";
          const header = await inspectSQLiteStorageHeader((sql, ...args) => s.database!.get(sql, ...args), manifestSQL, "flowersec-node-admission", 3, s.identity);
          observedRevision = header.observedRevision;
          if (header.refusal !== undefined) throw new AdmissionStoreError("storage_format", "not_submitted", storageFormatProjection("flowersec-node-admission", 3, observedRevision, header.refusal.reason));
          formatPhase = "schema_or_state_invalid";
          (await this.#validate());
          if (s.epoch === maximum) fail("fenced");
          this.#continuity();
          const old = s.epoch;
          s.epoch++;
          (await this.#exec("UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?", u64(s.epoch), u64(old)));
          if ((await this.#scalar("SELECT changes()")) !== 1)
            fail("fenced");
        }
        s.dependency.check();
        s.disk.check();
        this.#continuity();
        s.dependency.check();
        s.disk.check();
        if (s.closed) fail("closed");
        try {
          (await this.#exec("COMMIT"));
        }
        catch (error) {
          s.poisoned = true;
          if (error instanceof SQLiteWorkerError && error.writeState === "not_submitted") throw failure(error);
          throw new AdmissionStoreError("admission_unknown", "unknown");
        }
      }
      catch (error) {
        try {
          (await this.#exec("ROLLBACK"));
        }
        catch { s.poisoned = true; }
        throw error;
      }
      if (create)
        await s.database.syncDirectory();
      this.#check();
    }
    catch (error) {
      const projected = failure(error);
      if (["storage_unavailable", "storage_format", "history_unknown", "fenced"].includes(projected.code)) s.backing.environment.diagnosticCounters.observe("store_failure", { phase: "prepare", code: "store_unavailable" });
      if (projected.code === "storage_format" && projected.format === undefined) throw new AdmissionStoreError(projected.code, projected.writeState, storageFormatProjection("flowersec-node-admission", 3, observedRevision, formatPhase));
      throw error;
    }
    finally {
      s.active = false;
      if (s.closed || s.poisoned) { s.closed = true; s.database?.close(); this.#cleanup(); }
    }
  }
  async #validate(): Promise<void> {
    const s = this.#state, c = s.backing.limits;
    if ((await this.#scalar("PRAGMA user_version")) !== 3 || (await this.#scalar("SELECT count(*) FROM sqlite_schema")) !== 7)
      fail("storage_format");
    const tables: readonly (readonly [string, string])[] = [
      ["manifest", manifestSQL], ["admission", admissionSQL], ["parent_winner", winnerSQL],
      ["relay_issuance", relayIssuanceSQL], ["relay_parent", relayParentSQL], ["relay_leg", relayLegSQL],
      ["live_authority", liveAuthoritySQL],
    ];
    for (const [name, sql] of tables) {
      if ((await this.#scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name=?", name)) !== sql.length || (await this.#scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", name)) !== sql)
        fail("storage_format");
    }
    if ((await this.#scalar("SELECT count(*) FROM manifest")) !== 1 || (await this.#scalar("SELECT length(authority) FROM manifest WHERE id=1")) !== s.identity.authority.length)
      fail("storage_format");
    const row = await s.database!.get("SELECT * FROM manifest WHERE id=1");
    if (row === undefined) fail("storage_format");
    if (row.format !== "flowersec-node-admission" || row.revision !== 3 || row.authority !== s.identity.authority || !(row.instance instanceof Uint8Array) || !equalCredential(row.instance, s.identity.storeID) || readU64(row.generation) !== s.identity.generation ||
      row.max_pages !== c.maxPages || row.max_records !== c.maxRecords || row.max_record_bytes !== c.maxRecordBytes || typeof row.admission_rows !== "number" || row.admission_rows < 0 || typeof row.winner_rows !== "number" || row.winner_rows < 0 || typeof row.relay_rows !== "number" || row.relay_rows < 0 || typeof row.issuance_rows !== "number" || row.issuance_rows < 0 || row.admission_rows + row.winner_rows + row.relay_rows + row.issuance_rows > c.maxRecords || (await this.#scalar("SELECT count(*) FROM parent_winner")) !== row.winner_rows || (await this.#scalar("SELECT count(*) FROM admission")) !== row.admission_rows)
      fail("storage_format");
    if ((await this.#scalar("SELECT count(*) FROM parent_winner WHERE length(projection)>?", c.maxRecordBytes)) !== 0)
      fail("storage_format");
    const parentRows = await this.#scalar("SELECT count(*) FROM relay_parent"), legRows = await this.#scalar("SELECT count(*) FROM relay_leg");
    if (typeof parentRows !== "number" || typeof legRows !== "number" || parentRows * 3 !== row.relay_rows || legRows * 3 !== row.relay_rows * 2 ||
      (await this.#scalar("SELECT count(*) FROM relay_issuance")) !== row.issuance_rows ||
      (await this.#scalar("SELECT count(*) FROM relay_parent WHERE length(original)>? OR length(selected)>?", c.maxRecordBytes, c.maxRecordBytes)) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_leg WHERE length(projection)>? OR (claimed=0 AND (version<>? OR length(projection)<>0)) OR (claimed=1 AND (version<>? OR length(projection)=0))", c.maxRecordBytes, u64(1n), u64(2n))) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_issuance WHERE length(root)>? OR length(winner)>?", c.maxRecordBytes, c.maxRecordBytes)) !== 0) fail("storage_format");
    s.epoch = readU64(row.epoch);
    if (s.epoch === 0n) fail("storage_format");
    if ((await this.#scalar("SELECT count(*) FROM admission WHERE length(projection)>? OR length(projection)<1 OR fence>? OR fence=? OR (state=0 AND version<>?) OR (state=1 AND version<>?)", c.maxRecordBytes, u64(s.epoch), u64(0n), u64(1n), u64(2n))) !== 0)
      fail("storage_format");
    // A reopened history must contain both original leg safety slots for each
    // parent and both issuance sides for each original candidate. Aggregate
    // counts alone cannot establish those relationships or their old fences.
    if ((await this.#scalar("SELECT count(*) FROM relay_leg l LEFT JOIN relay_parent p ON p.lease=l.lease WHERE p.lease IS NULL OR l.fence=? OR l.fence>?", u64(0n), u64(s.epoch))) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_parent p WHERE (SELECT count(*) FROM relay_leg l WHERE l.lease=p.lease)<>2 OR NOT EXISTS(SELECT 1 FROM relay_issuance i WHERE i.lease=p.lease)")) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_parent p WHERE ((SELECT sum(l.claimed) FROM relay_leg l WHERE l.lease=p.lease)=0 AND (p.version<>? OR length(p.selected)<>0)) OR ((SELECT sum(l.claimed) FROM relay_leg l WHERE l.lease=p.lease)=1 AND (p.version<>? OR length(p.selected)=0)) OR ((SELECT sum(l.claimed) FROM relay_leg l WHERE l.lease=p.lease)=2 AND (p.version<>? OR length(p.selected)=0))", u64(1n), u64(2n), u64(3n))) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_issuance i LEFT JOIN relay_parent p ON p.lease=i.lease WHERE p.lease IS NULL OR NOT EXISTS(SELECT 1 FROM relay_issuance j WHERE j.lease=i.lease AND j.candidate=i.candidate AND j.side=1-i.side AND j.root=i.root AND j.winner=i.winner AND j.source=i.source AND j.winner_authority=i.winner_authority)")) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_parent p WHERE length(p.selected)>0 AND NOT EXISTS(SELECT 1 FROM relay_issuance i WHERE i.lease=p.lease AND i.root=p.selected)")) !== 0 ||
      (await this.#scalar("SELECT count(*) FROM relay_issuance i JOIN relay_parent p ON p.lease=i.lease WHERE i.source=1 AND (i.winner_authority<>? OR (p.selected=i.root AND NOT EXISTS(SELECT 1 FROM parent_winner w WHERE w.lease=i.lease AND w.projection=i.winner)))", s.identity.authority)) !== 0) fail("storage_format");

    await this.#validateDurableRecords();
    await this.#validateLiveRows();
  }
  async #validateDurableRecords(): Promise<void> {
    const s = this.#state, r = s.backing.environment.resources, maximumBytes = s.backing.limits.maxRecordBytes, workBytes = Math.max(65536, maximumBytes);
    const reference = r.root.reserve({ owner: credentialOwner(r, "relay_reopen_rows"), accounts: r.accounts,
      charge: new ResourceVector([BigInt(maximumBytes) * 6n + 262144n + r.runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]) });
    let workReference: ResourceReference | undefined, work: CredentialWork | undefined, buffer: Uint8Array | undefined;
    let cursorLease = new Uint8Array(), cursorCandidate = new Uint8Array(), cursorSide = -1, rows = 0;
    const check = (): void => { s.dependency.check(); s.disk.check(); reference.check(); if (s.closed) fail("closed"); };
    try {
      workReference = r.root.reserve({ owner: credentialOwner(r, "relay_reopen_projection"), accounts: r.accounts, charge: credentialWorkCharge(workBytes, r.runtimeBytes) });
      if (!workReference.sameEnvironment(reference)) fail("owner_unavailable"); work = new CredentialWork(r, workBytes, workReference); work.prepayParsers(workBytes, 16384, 4); work.prepaySignatures(workBytes, 16384); buffer = new Uint8Array(maximumBytes);
      for (;;) {
        check(); const row = await s.database!.get("SELECT lease,projection FROM parent_winner WHERE lease>? ORDER BY lease LIMIT 1", cursorLease);
        if (row === undefined) break;
        try {
          if (++rows > s.backing.limits.maxRecords || !(row.lease instanceof Uint8Array) || !(row.projection instanceof Uint8Array)) fail("storage_format");
          try { validatePersistedParentWinner(work, row.lease, row.projection, maximumBytes, s.identity.authority); } catch { fail("storage_format"); }
          cursorLease.fill(0); cursorLease = new Uint8Array(row.lease);
        } finally { clearRelayFields(row); }
      }
      cursorLease.fill(0); cursorLease = new Uint8Array(); rows = 0;
      for (;;) {
        check(); const row = await s.database!.get("SELECT * FROM admission WHERE lease>? ORDER BY lease LIMIT 1", cursorLease);
        if (row === undefined) break;
        try {
          if (++rows > s.backing.limits.maxRecords || !(row.lease instanceof Uint8Array) || !(row.projection instanceof Uint8Array) || typeof row.source !== "number" || typeof row.state !== "number") fail("storage_format");
          let winner: Uint8Array | undefined;
          try {
            try { winner = validatePersistedAdmission(work, { lease: row.lease, source: row.source, state: row.state, fence: readU64(row.fence), retainedUntil: readU64(row.retained_until), projection: row.projection }, s.identity, s.epoch, buffer, fields => this.#matchesService(fields)); }
            catch { fail("storage_format"); }
            if (row.source === 1) {
              const parent = s.parent; if (parent === undefined) fail("history_unknown"); parent.#check();
              const stored = await parent.#state.database!.get("SELECT projection FROM parent_winner WHERE lease=?", row.lease);
              if (stored === undefined) fail("history_unknown");
              try { if (!(stored.projection instanceof Uint8Array) || !equalCredential(stored.projection, winner)) fail("storage_format"); } finally { clearRelayFields(stored); }
              parent.#check();
            }
          } finally { winner?.fill(0); }
          cursorLease.fill(0); cursorLease = new Uint8Array(row.lease);
        } finally { clearRelayFields(row); }
      }
      cursorLease.fill(0); cursorLease = new Uint8Array(); rows = 0;
      // One bounded joined row at a time. The original transaction fixes the
      // keyset while every persisted byte remains under admitted backing.
      for (;;) {
        check(); const row = await s.database!.get("SELECT i.*,p.original,p.retained_until FROM relay_issuance i JOIN relay_parent p ON p.lease=i.lease WHERE (i.lease,i.candidate,i.side)>(?,?,?) ORDER BY i.lease,i.candidate,i.side LIMIT 1", cursorLease, cursorCandidate, cursorSide);
        if (row === undefined) break;
        try {
          if (++rows > s.backing.limits.maxRecords) fail("storage_format");
          for (const name of ["lease", "candidate", "grant_digest", "grant", "endpoint_certificate", "relay_certificate", "root", "winner", "original", "retained_until"] as const)
            if (!(row[name] instanceof Uint8Array) || (row[name] as Uint8Array).length > (name === "grant" ? 65536 : name === "endpoint_certificate" || name === "relay_certificate" || name === "original" ? 8192 : maximumBytes)) fail("storage_format");
          if (typeof row.side !== "number" || typeof row.source !== "number" || typeof row.winner_authority !== "string") fail("storage_format");
          try { validatePersistedRelayIssuance(work, row as unknown as PersistedRelayIssuance, buffer); } catch { fail("storage_format"); }
          cursorLease.fill(0); cursorCandidate.fill(0); cursorLease = new Uint8Array(row.lease as Uint8Array); cursorCandidate = new Uint8Array(row.candidate as Uint8Array); cursorSide = row.side;
        } finally { clearRelayFields(row); }
      }
      cursorLease.fill(0); cursorLease = new Uint8Array(); cursorSide = -1; rows = 0;
      for (;;) {
        check(); const row = await s.database!.get("SELECT l.*,p.selected FROM relay_leg l JOIN relay_parent p ON p.lease=l.lease WHERE l.claimed=1 AND (l.lease,l.side)>(?,?) ORDER BY l.lease,l.side LIMIT 1", cursorLease, cursorSide);
        if (row === undefined) break;
        try {
          if (++rows > s.backing.limits.maxRecords || !(row.lease instanceof Uint8Array) || !(row.projection instanceof Uint8Array) || !(row.selected instanceof Uint8Array) || typeof row.side !== "number") fail("storage_format");
          if ((await this.#scalar("SELECT count(*) FROM relay_issuance WHERE lease=? AND side=? AND root=?", row.lease, row.side, row.selected)) !== 1) fail("storage_format");
          const issuance = await s.database!.get("SELECT grant,grant_digest,endpoint_certificate,relay_certificate FROM relay_issuance WHERE lease=? AND side=? AND root=?", row.lease, row.side, row.selected);
          if (issuance === undefined) fail("storage_format");
          try {
            for (const name of ["grant", "grant_digest", "endpoint_certificate", "relay_certificate"] as const) if (!(issuance[name] instanceof Uint8Array)) fail("storage_format");
            try { validatePersistedRelayClaim(work, row.projection, row.side, readU64(row.fence), row.selected,
              issuance as unknown as { grant: Uint8Array; grant_digest: Uint8Array; endpoint_certificate: Uint8Array; relay_certificate: Uint8Array }, buffer); } catch { fail("storage_format"); }
          } finally { clearRelayFields(issuance); }
          cursorLease.fill(0); cursorLease = new Uint8Array(row.lease); cursorSide = row.side;
        } finally { clearRelayFields(row); }
      }
      check();
    } finally { cursorLease.fill(0); cursorCandidate.fill(0); buffer?.fill(0); work?.close(); workReference?.release(); reference.release(); }
  }
  async #capacity(additional = 1): Promise<void> {
    const rows = (await this.#scalar("SELECT admission_rows+winner_rows+relay_rows+issuance_rows+(SELECT count(*) FROM live_authority)+5*(SELECT count(*) FROM live_authority WHERE state=0) FROM manifest WHERE id=1"));
    if (typeof rows !== "number" || rows < 0) fail("storage_format");
    if (rows + additional > this.#state.backing.limits.maxRecords) fail("capacity");
  }
  async #rollback(): Promise<void> {
    try {
      (await this.#exec("ROLLBACK"));
    }
    catch {
      // A lost receipt can follow a successful COMMIT. Prove the connection is
      // no longer in a transaction without classifying driver error strings.
      try {
        (await this.#exec("BEGIN DEFERRED"));
        (await this.#exec("ROLLBACK"));
      }
      catch { this.#state.poisoned = true; }
    }
  }
  async #transaction(check: () => void, write: () => void | Promise<void>, confirm?: () => boolean | Promise<boolean>): Promise<void> {
    try { await this.#transactionOriginal(check, write, confirm); }
    catch (error) {
      const projected = failure(error);
      const counters = this.#state.backing.environment.diagnosticCounters;
      if (["storage_unavailable", "storage_format", "history_unknown", "fenced"].includes(projected.code))
        counters.observe("store_failure", { phase: "spend", code: "store_unavailable" });
      if (projected.writeState === "unknown") counters.observe("spend_unknown", { phase: "spend", code: "spend_unknown" });
      if (["admission_conflict", "relay_conflict"].includes(projected.code)) counters.observe("reservation_conflict", { phase: "spend", code: "reservation_conflict" });
      throw error;
    }
  }
  async #transactionOriginal(check: () => void, write: () => void | Promise<void>, confirm?: () => boolean | Promise<boolean>): Promise<void> {
    (await this.#checkpoint());
    check();
    (await this.#exec("BEGIN IMMEDIATE"));
    let submitted = false, committed = false;
    try {
      (await this.#fence());
      check();
      await write();
      check();
      submitted = true;
      (await this.#exec("COMMIT"));
      committed = true;
      await this.#state.database!.files();
    }
    catch (error) {
      (await this.#rollback());
      if (!submitted || !committed && error instanceof SQLiteWorkerError && error.writeState === "not_submitted") throw error;
      if (committed) throw failure(error, "committed");
      // Only this still-running invocation retains the original exact CAS and
      // its unused continuation. Reserve/parent writes never use this gate.
      try {
        if (confirm !== undefined) {
          check();
          (await this.#exec("BEGIN IMMEDIATE"));
          try {
            (await this.#fence());
            check();
            committed = await confirm();
            check();
          }
          finally {
            (await this.#exec("ROLLBACK"));
          }
        }
      }
      catch {
        committed = false;
        (await this.#rollback());
      }
      if (!committed) throw new AdmissionStoreError("admission_unknown", "unknown");
    }
    try { check(); } catch (error) { throw failure(error, "committed"); }
  }
  #matchesService(f: Omit<ServerAdmissionFields, "admissionBinding">): boolean {
    return this.#state.bindings.some(b => b.tenant === f.tenant && equalCredential(b.issuer, f.issuer) &&
      b.audience === f.audience && equalCredential(b.serverIdentity, f.identities[1]!));
  }
  async #winner(f: ServerAdmissionFields, key: Uint8Array, projection: Uint8Array, check: () => void): Promise<void> {
    const s = this.#state;
    this.#check();
    if (s.active || s.identity.authority !== f.winnerAuthority || !this.#matchesService(f)) fail("owner_unavailable");
    if (projection.length > s.backing.limits.maxRecordBytes) fail("capacity");
    s.active = true;
    try {
      (await this.#transaction(() => { this.#check(); check(); this.#check(); }, async () => {
        const row = await s.database!.get("SELECT length(projection) AS size,CASE WHEN length(projection)<=? THEN projection END AS projection FROM parent_winner WHERE lease=?", s.backing.limits.maxRecordBytes, key);
        if (row !== undefined) {
          if (!(row.projection instanceof Uint8Array) || row.size !== row.projection.length)
            fail("storage_format");
          try {
            if (!equalCredential(row.projection, projection))
              fail("admission_conflict");
          }
          finally {
            row.projection.fill(0);
          }
          return;
        }
        (await this.#capacity());
        (await this.#exec("INSERT INTO parent_winner VALUES(?,?)", key, projection));
        (await this.#exec("UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1"));
      }));
    }
    finally {
      const cleanup = (): void => { s.active = false; if (s.closed || s.poisoned || s.database!.closed()) { s.closed = true; s.database!.close(); this.#cleanup(); } };
      if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(cleanup); else cleanup();
    }
  }
  async admit(closure: VerifiedCredentialClosure, fsb: Uint8Array, context: Uint8Array, owner: ServerAdmissionOwner, deadline: TrustedDeadline, admission: ResourceReference, guard: () => void, dispatch: (response: AdmissionResponse) => void): Promise<void> {
    const s = this.#state, c = s.backing.limits;
    if (!isVerifiedCredentialClosure(closure) || typeof guard !== "function" || typeof dispatch !== "function" || !deadline.belongsTo(s.backing.environment.clock)) fail("owner_unavailable");
    this.#check();
    if (s.active) fail("capacity");
    if (!s.dependency.reference.sameEnvironment(admission)) fail("owner_unavailable");
    closure.checkPreparation(admission);
    if (!(fsb instanceof Uint8Array) || fsb.length < 1 || fsb.length > 65536 || !(context instanceof Uint8Array) || context.length < 1 || context.length > 2048) fail("configuration_capacity");
    const reference = admission.take(sqliteAdmissionCharge(c));
    let fields: ServerAdmissionFields | undefined, key: Uint8Array | undefined, originalOwner: ServerAdmissionOwner | undefined;
    let originalFSB: Uint8Array | undefined, originalContext: Uint8Array | undefined;
    let reserved: Uint8Array | undefined, target: Uint8Array | undefined, parent: Uint8Array | undefined, reservation: Uint8Array | undefined;
    let writeState: AdmissionStoreError["writeState"] = "not_submitted";
    const observations: (() => void)[] = [];
    s.active = true;
    try {
      originalFSB = new Uint8Array(fsb);
      originalContext = new Uint8Array(context);
      originalOwner = { acceptor: fixed(owner.acceptor, 16), invocation: fixed(owner.invocation, 16), carrier: fixed(owner.carrier, 16), generation: quantity(owner.generation) };
      const signal = owner.signal;
      fields = closure.serverAdmissionFields(originalFSB, originalContext, reference);
      if (!this.#matchesService(fields)) fail("owner_unavailable");
      const parentStore = fields.source === "preauthorized_pool" ? s.parent : undefined;
      const remoteParent = fields.source === "preauthorized_pool" ? s.remoteParent : undefined;
      const original = deadline.fork(deadline.cap < fields.activationEnd ? deadline.cap : fields.activationEnd);
      const check = (): void => {
        this.#check(); if (parentStore !== undefined) parentStore.#check(); remoteParent?.check(reference); reference.check(); original.check(); deadline.check(); closure.checkPreparation(reference);
        if (signal?.aborted || guard() !== undefined) fail("owner_unavailable");
        // Trusted host hooks can synchronously close the original owner.
        this.#check(); if (parentStore !== undefined) parentStore.#check(); remoteParent?.check(reference); reference.check(); original.check(); deadline.check(); closure.checkPreparation(reference);
        if (signal?.aborted) fail("owner_unavailable");
      };
      check();
      const remaining = (): bigint => { check(); return original.remainingMS(); };
      observations.push(s.database!.observe(signal, remaining));
      if (parentStore !== undefined) observations.push(parentStore.#state.database!.observe(signal, remaining));
      const now = original.sample().requireInterval();
      if (now.lowerMS < fields.issuedAt || fields.initiationEnd > maximum - minimumRetentionMS || now.upperMS > maximum - minimumRetentionMS) fail("configuration_capacity");
      const retainedUntil = (fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS) + minimumRetentionMS;
      key = admissionLeaseKey(fields);
      reserved = new Uint8Array(c.maxRecordBytes);
      target = new Uint8Array(c.maxRecordBytes);
      parent = new Uint8Array(c.maxRecordBytes);
      const reservedBody = encodeAdmission(reserved, fields, s.identity, s.epoch, originalOwner, original.cap, now.upperMS, retainedUntil, originalFSB, originalContext, new Uint8Array(), 0n);
      if (reservedBody.length + 48 > c.maxRecordBytes) fail("capacity");
      if (fields.source === "preauthorized_pool") {
        const projection = encodeParentWinner(parent, fields);
        if (remoteParent !== undefined) {
          await remoteParent.match(fields.winnerAuthority, key, projection, reference, { ...(signal === undefined ? {} : { signal }), check, remainingMS: remaining });
          check();
        } else {
          if (s.parent === undefined || !s.parent.#state.dependency.reference.sameEnvironment(reference)) fail("owner_unavailable");
          await s.parent.#winner(fields, key, projection, check);
        }
      }
      const lease = key, source = fields.source === "preauthorized_pool" ? 1 : 0;
      (await this.#transaction(check, async () => {
        if ((await this.#scalar("SELECT count(*) FROM admission WHERE lease=?", lease)) !== 0)
          fail("admission_conflict");
        (await this.#capacity());
        (await this.#exec("INSERT INTO admission VALUES(?,?,0,0,?,?,?,?)", lease, source, u64(1n), u64(s.epoch), u64(retainedUntil), reservedBody));
        (await this.#exec("UPDATE manifest SET admission_rows=admission_rows+1 WHERE id=1"));
      }));
      // Reserve is irrevocable, but it does not grant the continuation.
      writeState = "committed";
      check();
      reservation = new Uint8Array(32);
      randomFillSync(reservation);
      if (!reservation.some(value => value !== 0)) fail("storage_unavailable");
      const targetBody = encodeAdmission(target, fields, s.identity, s.epoch, originalOwner, original.cap, now.upperMS, retainedUntil,
        originalFSB, originalContext, reservation, original.sample().requireInterval().upperMS);
      (await this.#transaction(check, async () => {
        (await this.#exec("UPDATE admission SET state=1,admission_count=1,version=?,projection=? WHERE lease=? AND state=0 AND admission_count=0 AND version=? AND fence=? AND projection=?", u64(2n), targetBody, lease, u64(1n), u64(s.epoch), reservedBody));
        if ((await this.#scalar("SELECT changes()")) !== 1)
          fail("admission_conflict");
      }, async () => (await this.#scalar("SELECT count(*) FROM admission WHERE lease=? AND source=? AND state=1 AND admission_count=1 AND version=? AND fence=? AND retained_until=? AND projection=?", lease, source, u64(2n), u64(s.epoch), u64(retainedUntil), targetBody)) === 1));
      check();
      // Invoked once within this original local gate. These borrowed bytes are
      // copied by server assembly into its prepaid FSA work before returning.
      if (dispatch(Object.freeze({ serverEpoch: s.epoch, reservationKey: reservation, admissionBinding: fields.admissionBinding })) !== undefined) fail("owner_unavailable");
    }
    catch (error) {
      if (error instanceof AdmissionStoreError && error.writeState === "unknown") throw error;
      throw failure(error, writeState);
    }
    finally {
      for (const unobserve of observations) unobserve();
      const cleanup = (): void => {
        if (fields !== undefined) {
          for (const value of Object.values(fields)) if (value instanceof Uint8Array) value.fill(0);
          for (const value of fields.identities) value.fill(0);
        }
        for (const value of [key, originalFSB, originalContext, reserved, target, parent, reservation, originalOwner?.acceptor, originalOwner?.invocation, originalOwner?.carrier]) value?.fill(0);
        reference.release(); s.active = false;
        if (s.closed || s.poisoned || s.database!.closed()) { s.closed = true; s.database!.close(); this.#cleanup(); }
      };
      const tails = [s.database, s.parent === undefined ? undefined : s.parent.#state.database].filter((db): db is SQLiteWorkerDatabase => db !== undefined && db.closed() && !db.cleanupComplete());
      if (tails.length !== 0) void Promise.all(tails.map(db => db.waitCleanup())).then(cleanup);
      else cleanup();
    }
  }
  /** Original TxA. The full frozen proof/Grant projections and recipients are
   * durable before application policy or any signer can run. There is no query
   * continuation and a duplicate lease cannot invoke old policy again. */
  async recordLiveTxA(transaction: OriginalLiveGrantTransaction, reservation: ResourceReference, deadline: TrustedDeadline): Promise<void> {
    this.#check(); const s = this.#state, c = s.backing.limits;
    if (s.active || !isOriginalLiveGrantTransaction(transaction)) fail("owner_unavailable");
    const reference = reservation.take(sqliteRelayActivationCharge(c)); s.active = true; let signers: Uint8Array | undefined;
    try {
      const fields = transaction.projection(reference); transaction.check(reference);
      if (fields.authority !== s.identity.authority || !s.bindings.some(binding => binding.tenant === fields.tenant && binding.audience === fields.audience && equalCredential(binding.issuer, fields.issuer) && equalCredential(binding.serverIdentity, fields.identities[1])) || fields.activationDraft.length + fields.grantDrafts[0].length + fields.grantDrafts[1].length + 256 > c.maxRecordBytes) fail("configuration_capacity");
      const now = deadline.sample().requireInterval(), base = fields.initiationEnd > now.upperMS ? fields.initiationEnd : now.upperMS;
      if (base > maximum - minimumRetentionMS || fields.sessionEnd > base + minimumRetentionMS) fail("configuration_capacity");
      const retainedUntil = base + minimumRetentionMS; signers = new Uint8Array(96); signers.set(fields.activationSigner); signers.set(fields.grantSigners[0], 32); signers.set(fields.grantSigners[1], 64);
      const check = (): void => { this.#check(); reference.check(); deadline.check(); transaction.check(reference); };
      await this.#transaction(check, async () => {
        if ((await this.#scalar("SELECT count(*) FROM live_authority WHERE lease=?", fields.lease)) !== 0) fail("relay_conflict"); await this.#capacity(6);
        await this.#exec("INSERT INTO live_authority VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)", fields.lease, fields.invocation, fields.candidate, u64(s.epoch), u64(retainedUntil), fields.authority, fields.signingKeyID,
          fields.activationDraft, fields.grantDrafts[0], fields.grantDrafts[1], signers!, fields.recipient, fields.incarnation, new Uint8Array(), new Uint8Array(), new Uint8Array());
      }); check();
    } finally { signers?.fill(0); const release = (): void => { reference.release(); s.active = false; this.#cleanup(); }; if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(release); else release(); }
  }
  async #validateLiveRows(): Promise<void> {
    const s = this.#state, r = s.backing.environment.resources, c = s.backing.limits;
    const total = await this.#scalar("SELECT admission_rows+winner_rows+relay_rows+issuance_rows+(SELECT count(*) FROM live_authority)+5*(SELECT count(*) FROM live_authority WHERE state=0) FROM manifest WHERE id=1"); if (typeof total !== "number" || total > c.maxRecords) fail("storage_format");
    const reference = r.root.reserve({ owner: credentialOwner(r, "live_reopen"), accounts: r.accounts, charge: credentialWorkCharge(524288, r.runtimeBytes).add(new ResourceVector([131072n + r.runtimeBytes, 0n, 0n, 2n, 0n, 0n, 0n, 0n, 0n, 0n, 0n])) });
    const unsignedBacking: readonly [Uint8Array, Uint8Array] = [new Uint8Array(65536), new Uint8Array(65536)];
    let work: CredentialWork | undefined, cursor = new Uint8Array();
    try {
      work = new CredentialWork(r, 524288, reference); work.prepayParsers(65536, 16384, 4); work.prepaySignatures(65536, 16384); let count = 0;
      for (;;) {
        this.#check(); const row = await s.database!.get("SELECT * FROM live_authority WHERE lease>? ORDER BY lease LIMIT 1", cursor); if (row === undefined) break;
        try {
          if (++count > c.maxRecords || row.authority !== s.identity.authority || typeof row.signing_key !== "string" || typeof row.state !== "number") fail("storage_format");
          for (const name of ["lease", "invocation", "candidate", "fence", "retained_until", "proof_draft", "client_draft", "server_draft", "signers", "recipient", "incarnation", "proof", "client_grant", "server_grant"] as const) if (!(row[name] instanceof Uint8Array)) fail("storage_format");
          const lease = row.lease as Uint8Array, proof = row.proof_draft as Uint8Array, client = row.client_draft as Uint8Array, server = row.server_draft as Uint8Array;
          if (proof.length + client.length + server.length + 256 > c.maxRecordBytes || readU64(row.fence) === 0n || readU64(row.fence) > s.epoch || readU64(row.retained_until) === 0n) fail("storage_format");
          const map = work.parse(proof, "ActivationAuthorization", 4096, 2048, { selectors: { activation_source_profile: "live_authority" } });
          try {
            const signature = map.bytes("signature"), candidate = map.bytes("candidate_selection"), issuer = map.bytes("artifact_issuer_key_id"), leaseID = map.bytes("lease_id"), tenant = new TextEncoder().encode(map.text("tenant_id"));
            try { if (!signature.every(byte => byte === 0) || map.text("authority_id") !== row.authority || map.text("signing_key_id") !== row.signing_key || !equalCredential(candidate, row.candidate as Uint8Array) || lease.length !== tenant.length + 33 || lease[0] !== tenant.length || !equalCredential(lease.subarray(1, 1 + tenant.length), tenant) || !equalCredential(lease.subarray(1 + tenant.length, 17 + tenant.length), issuer) || !equalCredential(lease.subarray(17 + tenant.length), leaseID) || map.uint("session_not_after_ms") > readU64(row.retained_until)) fail("storage_format"); }
            finally { signature.fill(0); candidate.fill(0); issuer.fill(0); leaseID.fill(0); tenant.fill(0); }
          } finally { map.close(); }
          for (const draft of [client, server]) { const map = work.parse(draft, "Grant", 65536); try { const signature = map.bytes("signature"); try { if (!signature.every(byte => byte === 0)) fail("storage_format"); } finally { signature.fill(0); } } finally { map.close(); } }
          if (row.state === 1) {
            if (!matchesUnsignedCredential(work, "ActivationAuthorization", proof, row.proof as Uint8Array, unsignedBacking) || !matchesUnsignedCredential(work, "Grant", client, row.client_grant as Uint8Array, unsignedBacking) || !matchesUnsignedCredential(work, "Grant", server, row.server_grant as Uint8Array, unsignedBacking)) fail("storage_format");
            for (const [side, schema, bytes, offset] of [[-1, "ActivationAuthorization", row.proof, 0], [0, "Grant", row.client_grant, 32], [1, "Grant", row.server_grant, 64]] as const) {
              const map = work.parse(bytes as Uint8Array, schema, schema === "Grant" ? 65536 : 4096, 16384, schema === "Grant" ? {} : { selectors: { activation_source_profile: "live_authority" } });
              try { work.verify(map, (row.signers as Uint8Array).subarray(offset, offset + 32), schema === "Grant" ? {} : { selectors: { activation_source_profile: "live_authority" } }); } finally { map.close(); }
              if (side >= 0 && (await this.#scalar("SELECT count(*) FROM relay_issuance WHERE lease=? AND candidate=? AND side=? AND source=0 AND grant=?", lease, row.candidate as Uint8Array, side, bytes as Uint8Array)) !== 1) fail("storage_format");
            }
          }
          cursor.fill(0); cursor = new Uint8Array(lease);
        } finally { clearRelayFields(row); }
      }
    } finally { cursor.fill(0); for (const bytes of unsignedBacking) bytes.fill(0); work?.close(); reference.release(); }
  }
  /** Commit both original leg grants before their issuance response escapes.
   * The issuer's configured tenant/issuer/service resolution is independent
   * of a relay's received HELLO. A missing registration is never recreated by
   * claim, and no method deletes parent/leg safety history. */
  async recordRelayIssuance(issuance: OriginalGrantIssuance, reservation: ResourceReference, deadline: TrustedDeadline, guard: () => void, live?: OriginalLiveGrantTransaction): Promise<void> {
    const s = this.#state, c = s.backing.limits; this.#check(); if (s.active || !isOriginalGrantIssuance(issuance) || live !== undefined && !isOriginalLiveGrantTransaction(live)) fail("owner_unavailable");
    const reference = reservation.take(sqliteRelayActivationCharge(c)); let record: ReturnType<typeof captureRelayIssuance> | undefined; s.active = true;
    try {
      const { closure, legs } = issuance.original(reference);
      record = captureRelayIssuance(s.backing.environment.resources, closure, legs, reference, c.maxRecordBytes);
      if (!this.#matchesService(record.fields)) fail("owner_unavailable");
      const check = (): void => { this.#check(); reference.check(); deadline.check(); issuance.check(reference); live?.check(reference); if (guard() !== undefined) fail("owner_unavailable"); this.#check(); };
      await this.#transaction(check, async () => {
        if (live !== undefined) {
          const fixed = live.projection(reference), proof = live.proof(reference);
          if (record!.fields.source !== "live_authority" || !equalCredential(record!.lease, fixed.lease) || !equalCredential(record!.candidate, fixed.candidate)) fail("owner_unavailable");
          const row = await s.database!.get("SELECT * FROM live_authority WHERE lease=?", fixed.lease); if (row === undefined) fail("history_unknown");
          try {
            const signers = new Uint8Array(96); signers.set(fixed.activationSigner); signers.set(fixed.grantSigners[0], 32); signers.set(fixed.grantSigners[1], 64);
            try { if (row.state !== 0 || readU64(row.fence) !== s.epoch || row.authority !== fixed.authority || row.signing_key !== fixed.signingKeyID ||
              !equalCredential(row.invocation as Uint8Array, fixed.invocation) || !equalCredential(row.candidate as Uint8Array, fixed.candidate) || !equalCredential(row.proof_draft as Uint8Array, fixed.activationDraft) ||
              !equalCredential(row.client_draft as Uint8Array, fixed.grantDrafts[0]) || !equalCredential(row.server_draft as Uint8Array, fixed.grantDrafts[1]) || !equalCredential(row.signers as Uint8Array, signers) ||
              !equalCredential(row.recipient as Uint8Array, fixed.recipient) || !equalCredential(row.incarnation as Uint8Array, fixed.incarnation)) fail("relay_conflict"); }
            finally { signers.fill(0); }
            const grants = record!.grants;
            if (grants.length !== 2 || grants[0] === undefined || grants[1] === undefined) fail("owner_unavailable");
            live.checkCompleteProjection(reference, [grants[0], grants[1]]);
            await this.#exec("UPDATE live_authority SET state=1,proof=?,client_grant=?,server_grant=? WHERE lease=? AND state=0 AND fence=? AND invocation=?", proof, record!.grants[0]!, record!.grants[1]!, fixed.lease, u64(s.epoch), fixed.invocation);
          } finally { clearRelayFields(row); }
        }
        const row = await s.database!.get("SELECT original,retained_until FROM relay_parent WHERE lease=?", record!.lease);
        if (row === undefined) {
          await this.#capacity(5);
          await this.#exec("INSERT INTO relay_parent VALUES(?,?,?,?,?)", record!.lease, record!.parent, new Uint8Array(), u64(1n), u64(record!.retainedUntil));
          for (let side = 0; side < 2; side++) await this.#exec("INSERT INTO relay_leg VALUES(?,?,0,?,?,?)", record!.lease, side, new Uint8Array(), u64(1n), u64(s.epoch));
          await this.#exec("UPDATE manifest SET relay_rows=relay_rows+3 WHERE id=1");
        } else {
          if (!(row.original instanceof Uint8Array) || !equalCredential(row.original, record!.parent) || readU64(row.retained_until) !== record!.retainedUntil) fail("relay_conflict");
          row.original.fill(0); await this.#capacity(2);
        }
        for (let side = 0; side < 2; side++) {
          if ((await this.#scalar("SELECT claimed FROM relay_leg WHERE lease=? AND side=?", record!.lease, side)) !== 0 || (await this.#scalar("SELECT count(*) FROM relay_issuance WHERE lease=? AND candidate=? AND side=?", record!.lease, record!.candidate, side)) !== 0) fail("relay_conflict");
          await this.#exec("INSERT INTO relay_issuance VALUES(?,?,?,?,?,?,?,?,?,?,?)", record!.lease, record!.candidate, side, record!.grantDigests[side]!, record!.grants[side]!, record!.endpointCertificates[side]!, record!.relayCertificates[side]!, record!.root, record!.winner, record!.fields.source === "preauthorized_pool" ? 1 : 0, record!.fields.winnerAuthority);
        }
        await this.#exec("UPDATE manifest SET issuance_rows=issuance_rows+2 WHERE id=1");
      });
      check();
    } finally {
      if (record !== undefined) clearRelayIssuance(record);
      const release = (): void => { reference.release(); s.active = false; this.#cleanup(); };
      if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(release); else release();
    }
  }
  /** Read only the opposite leg from committed original issuance. Lookup
   * returns public signed material and never recreates a dispatch right. */
  async relayCounterpart(claim: VerifiedRelayClaim, reservation: ResourceReference, deadline: TrustedDeadline): Promise<RelayCredentialInput> {
    const s = this.#state; this.#check(); if (s.active || !isVerifiedRelayClaim(claim)) fail("owner_unavailable");
    const reference = reservation.take(sqliteRelayActivationCharge(s.backing.limits)), fields = claim.fields(reference), lease = relayClaimKey(fields); s.active = true;
    try {
      await this.#fence(); claim.check(reference); deadline.check();
      const row = await s.database!.get("SELECT grant,endpoint_certificate,relay_certificate FROM relay_issuance WHERE lease=? AND candidate=? AND side=?", lease, fields.candidate, 1 - fields.endpointRole);
      this.#check(); claim.check(reference); deadline.check(); if (row === undefined) fail("history_unknown");
      if (!(row.grant instanceof Uint8Array) || row.grant.length < 1 || row.grant.length > 65536 || !(row.endpoint_certificate instanceof Uint8Array) || row.endpoint_certificate.length < 1 || row.endpoint_certificate.length > 8192 || !(row.relay_certificate instanceof Uint8Array) || row.relay_certificate.length < 1 || row.relay_certificate.length > 8192) fail("storage_format");
      return Object.freeze({ grant: row.grant, endpointCertificate: row.endpoint_certificate, relayCertificate: row.relay_certificate });
    } finally {
      clearRelayFields(fields); lease.fill(0);
      const release = (): void => { reference.release(); s.active = false; this.#cleanup(); };
      if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(release); else release();
    }
  }
  /** The original claimed transaction alone owns publish. A duplicate exact
   * row, restored connection or retried invocation cannot receive it. */
  async claimRelay(claim: VerifiedRelayClaim, owner: RelayActivationOwner, deadline: TrustedDeadline, reservation: ResourceReference, guard: () => void, publish: () => Promise<void>): Promise<void> {
    const s = this.#state, c = s.backing.limits; this.#check(); if (s.active || !isVerifiedRelayClaim(claim)) fail("owner_unavailable");
    const reference = reservation.take(sqliteRelayActivationCharge(c)), localOwner = { relay: fixed(owner.relay, 16), invocation: fixed(owner.invocation, 16), carrier: fixed(owner.carrier, 16), generation: quantity(owner.generation) };
    let fields: ReturnType<VerifiedRelayClaim["fields"]> | undefined, lease: Uint8Array | undefined, grant: Uint8Array | undefined, target: Uint8Array | undefined, detach: (() => void) | undefined;
    const buffer = new Uint8Array(c.maxRecordBytes); s.active = true;
    try {
      fields = claim.fields(reference); lease = relayClaimKey(fields); grant = claim.grant(reference);
      const original = deadline.fork(deadline.cap < fields.notAfter ? deadline.cap : fields.notAfter);
      const check = (): void => { this.#check(); reference.check(); deadline.check(); original.check(); claim.check(reference); if (owner.signal?.aborted || guard() !== undefined) fail("owner_unavailable"); this.#check(); reference.check(); };
      detach = s.database!.observe(owner.signal, () => original.remainingMS()); check();
      await this.#transaction(check, async () => {
        const issued = await s.database!.get("SELECT grant_digest,grant,root,winner,source,winner_authority FROM relay_issuance WHERE lease=? AND candidate=? AND side=?", lease!, fields!.candidate, fields!.endpointRole);
        if (issued === undefined) fail("history_unknown");
        for (const name of ["grant_digest", "grant", "root", "winner"] as const) if (!(issued[name] instanceof Uint8Array) || (issued[name] as Uint8Array).length > c.maxRecordBytes && name !== "grant") fail("storage_format");
        const storedGrant = issued.grant as Uint8Array, digest = issued.grant_digest as Uint8Array, root = issued.root as Uint8Array, winner = issued.winner as Uint8Array;
        try {
          if (!equalCredential(storedGrant, grant!) || !equalCredential(digest, fields!.grantDigest)) fail("relay_conflict");
          const parent = await s.database!.get("SELECT original,selected,version FROM relay_parent WHERE lease=?", lease!);
          if (parent === undefined || !(parent.original instanceof Uint8Array) || !(parent.selected instanceof Uint8Array)) fail("history_unknown");
          try {
            const originalParent = claim.parentReference(reference); try { if (!equalCredential(parent.original, originalParent)) fail("relay_conflict"); } finally { originalParent.fill(0); }
            if (parent.selected.length !== 0 && !equalCredential(parent.selected, root)) fail("relay_conflict");
            const version = readU64(parent.version); if (version === maximum) fail("fenced");
            // ParentWinner shares this exact SQLite transaction and original
            // store with endpoint admission. Independent databases cannot act
            // as a replacement authority for the same pool parent.
            if (issued.source === 1) {
              if (issued.winner_authority !== s.identity.authority) fail("owner_unavailable");
              const selected = await s.database!.get("SELECT projection FROM parent_winner WHERE lease=?", lease!);
              if (selected !== undefined) { if (!(selected.projection instanceof Uint8Array) || !equalCredential(selected.projection, winner)) fail("relay_conflict"); selected.projection.fill(0); }
              else { await this.#capacity(); await this.#exec("INSERT INTO parent_winner VALUES(?,?)", lease!, winner); await this.#exec("UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1"); }
            } else if (issued.source !== 0) fail("storage_format");
            if ((await this.#scalar("SELECT claimed FROM relay_leg WHERE lease=? AND side=?", lease!, fields!.endpointRole)) !== 0) fail("relay_conflict");
            target = new Uint8Array(encodeRelayClaim(buffer, fields!, localOwner, s.epoch, root, grant!, original.cap));
            await this.#exec("UPDATE relay_parent SET selected=?,version=? WHERE lease=? AND version=?", root, u64(version + 1n), lease!, u64(version));
            if ((await this.#scalar("SELECT changes()")) !== 1) fail("relay_conflict");
            await this.#exec("UPDATE relay_leg SET claimed=1,projection=?,version=?,fence=? WHERE lease=? AND side=? AND claimed=0 AND version=?", target, u64(2n), u64(s.epoch), lease!, fields!.endpointRole, u64(1n));
            if ((await this.#scalar("SELECT changes()")) !== 1) fail("relay_conflict");
          } finally { parent.original.fill(0); parent.selected.fill(0); }
        } finally { storedGrant.fill(0); digest.fill(0); root.fill(0); winner.fill(0); }
      }, async () => target !== undefined && (await this.#scalar("SELECT count(*) FROM relay_leg WHERE lease=? AND side=? AND claimed=1 AND projection=? AND version=? AND fence=?", lease!, fields!.endpointRole, target, u64(2n), u64(s.epoch))) === 1);
      check(); await publish(); check();
    } catch (error) {
      if (error instanceof AdmissionStoreError && error.code === "admission_unknown") throw new AdmissionStoreError("relay_unknown", "unknown");
      throw error;
    } finally {
      detach?.(); buffer.fill(0); if (fields !== undefined) clearRelayFields(fields); lease?.fill(0); grant?.fill(0); target?.fill(0); for (const value of Object.values(localOwner)) if (value instanceof Uint8Array) value.fill(0);
      const release = (): void => { reference.release(); s.active = false; this.#cleanup(); };
      if (s.database!.closed() && !s.database!.cleanupComplete()) void s.database!.waitCleanup().then(release); else release();
    }
  }
  close(): void { this.#state.closed = true; this.#state.database?.close(); this.#cleanup(); }
  #cleanupResolve: (() => void) | undefined;
  readonly #cleanupWait = new Promise<void>(resolve => { this.#cleanupResolve = resolve; });
  #cleanup(): void {
    const s = this.#state;
    if (!s.closed || s.active || s.released || s.database !== undefined && !s.database.cleanupComplete())
      return;
    s.released = true;
    s.disk.release();
    s.backing.active = false;
    s.dependency.release();
    this.#cleanupResolve?.();
    this.#cleanupResolve = undefined;
  }
  cleanupComplete(): boolean { return this.#state.closed && this.#state.released; }
  waitCleanup(): Promise<void> { return this.#cleanupWait; }
  toJSON(): object { return {}; }
}
export async function openSQLiteAdmissionStore(backing: V4SQLitePoolBacking, options: SQLiteAdmissionOpenOptions): Promise<SQLiteAdmissionStore> {
  const owner = sqliteBackingState(backing);
  if (owner?.reference === undefined || owner.closed || owner.active) fail("owner_unavailable");
  const identity = Object.freeze({ authority: identityText(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: quantity(options.identity.generation) });
  if (typeof options.continuity?.check !== "function" || typeof options.create !== "boolean" || options.bindings.length < 1 || options.bindings.length > 64) fail("configuration_capacity");
  const continuity = options.continuity.check.bind(options.continuity), bindings = Object.freeze(options.bindings.map(binding => Object.freeze({ tenant: identityText(binding.tenant), issuer: fixed(binding.issuer, 16), audience: identityText(binding.audience), serverIdentity: fixed(binding.serverIdentity, 32) })));
  owner.reference.check();
  if (options.parentWinnerAuthority !== undefined && (options.parentWinnerStore !== undefined || !isRegisteredTunnelParentWinner(options.parentWinnerAuthority, owner.reference))) fail("configuration_capacity");
  const disk = owner.reference.borrow();
  let dependency: EnvironmentDependency | undefined, store: SQLiteAdmissionStore | undefined;
  try {
    dependency = owner.environment.admitDependency("server_admission_store", storeCharge(owner.limits).add(sqliteWorkerCharge(owner.limits)));
    owner.active = true;
    store = new SQLiteAdmissionStore(token, { backing: owner, dependency, disk, identity, continuity, bindings, parent: options.parentWinnerStore, remoteParent: options.parentWinnerAuthority, database: undefined, released: false, epoch: 0n, active: false, closed: false, poisoned: false });
    dependency.onClose(() => store!.close());
    await store.initialize(token, options.create);
    return store;
  }
  catch (error) {
    store?.close();
    if (store !== undefined)
      await store.waitCleanup();
    if (store === undefined) {
      disk.release();
      dependency?.release();
      owner.active = false;
    }
    throw failure(error);
  }
}
for (const constructor of [SQLiteAdmissionStore, AdmissionStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

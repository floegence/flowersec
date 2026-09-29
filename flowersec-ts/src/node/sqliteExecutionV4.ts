import { SQLiteExecutionContent, captureContent, contentCharges, contentConfiguration, contentSchemas, type CapturedContentConfig, type V4SQLiteContentConfig } from "./sqliteExecutionContentV4.js";
export type { V4SQLiteContentConfig } from "./sqliteExecutionContentV4.js";
import { ResumeCodec, resumeCodecCharges, type ResumeTargetFacts, type ResumeOutcome, type ResumeRequestFacts } from "../v4/runtime/resumeCodec.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { randomFillSync } from "node:crypto";
import type { V4Checkpoint, V4CheckpointIssuanceOptions } from "../v4/checkpoint.js";
import type { ExecutionTarget } from "../v4/runtime/executionManagementCodec.js";
import { checkpointToken, type CheckpointSessionPolicy, type CheckpointSigningKey, type CheckpointVerificationKey } from "../v4/runtime/checkpointToken.js";
import { timeAdd } from "../v4/runtime/timeArithmetic.js";
import { DatabaseSync, type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { closeSync, constants, openSync, type Stats } from "node:fs";
import type { EnvironmentDependency } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialDigest, equalCredential, credentialOwner } from "../v4/runtime/credentialSupport.js";
import { RPCProtocolError } from "../v4/runtime/rpcFragment.js";
import { captureVolatileExecution, type VolatileExecutionConfig } from "../v4/runtime/volatileExecutions.js";
import { registerExecutionStorage, type ExecutionStorage, type ExecutionRecordFacts } from "../v4/runtime/executionStorage.js";
import type { ServiceContractSnapshot, AdmissionOffer } from "../v4/runtime/serviceContract.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { V4SQLitePoolBacking} from "./sqliteV4.js";
import { V4PoolStoreError, fixed, quantity, identityText, count, maximum, storeCharge, u64, readU64, missing, syncDirectory,
  sqliteBackingState, sqliteScalar, sqliteExec, sqliteFiles, sqliteConfigure, sqliteCheckpoint, type BackingState, type V4SQLitePoolIdentity } from "./sqliteV4.js";

export { V4SQLitePoolBacking as V4SQLiteExecutionBacking, createV4SQLitePoolBacking as createV4SQLiteExecutionBacking } from "./sqliteV4.js";
export type { V4SQLitePoolLimits as V4SQLiteExecutionLimits, V4SQLitePoolIdentity as V4SQLiteExecutionIdentity } from "./sqliteV4.js";
export interface V4DurableExecutionService extends VolatileExecutionConfig { readonly durability: "durable" }
export interface V4SQLiteExecutionContinuity {
  /** Independent host proof of complete history and settlement/fencing of the
   * previous process's actual business work. The file cannot prove this. */
  check(identity: V4SQLitePoolIdentity, service: VolatileExecutionConfig, epoch: bigint, provisioning: boolean): void;
}
export interface V4SQLiteExecutionRegistration {
  readonly encodedBytes: number;
  readonly typeID: number;
  readonly revision: bigint;
  readonly enabled: boolean;
  readonly offers: readonly Readonly<{ notBeforeMS: bigint; notAfterMS: bigint }>[];
}
export type V4SQLiteCheckpointSigningKey = CheckpointSigningKey;
export type V4SQLiteCheckpointVerificationKey = CheckpointVerificationKey;
interface CheckpointLimits {
  readonly maxTokens: number;
  readonly maxTokensPerOperation: number;
  readonly maxTokenBytes: number;
  readonly maxIssuesPerWindow: number;
  readonly windowMS: bigint;
}
/** Recovery keys belong to the trusted application configuration, independent
 * of transport secrets. At most seven retired issuance keys can remain usable
 * for verification; omission explicitly revokes their recovery authority. */
export type V4SQLiteCheckpointConfig = CheckpointLimits & (
  Readonly<{ keyID: Uint8Array; macKey: Uint8Array; signingKey?: never; verificationKeys?: never }> |
  Readonly<{ signingKey: V4SQLiteCheckpointSigningKey; verificationKeys?: readonly V4SQLiteCheckpointVerificationKey[]; keyID?: never; macKey?: never }>
);
interface CapturedCheckpoint extends CheckpointLimits {
  readonly signingKey: CheckpointSigningKey;
  readonly verificationKeys: readonly CheckpointVerificationKey[];
}
function clearCheckpoint(c: CapturedCheckpoint | undefined): void {
  if (c === undefined) return;
  c.signingKey.keyID.fill(0);
  if (c.signingKey.protection === "ed25519") c.signingKey.seed.fill(0); else c.signingKey.macKey.fill(0);
  for (const key of c.verificationKeys) { key.keyID.fill(0); if (key.protection === "ed25519") key.publicKey.fill(0); else key.macKey.fill(0); }
}
function captureCheckpointConfig(input: V4SQLiteCheckpointConfig): CapturedCheckpoint {
  if (input.signingKey !== undefined && (input.keyID !== undefined || input.macKey !== undefined) ||
      input.signingKey === undefined && input.verificationKeys !== undefined) throw new V4ExecutionStoreError("configuration_capacity");
  const limits = { maxTokens: count(input.maxTokens, 1, 8192), maxTokensPerOperation: count(input.maxTokensPerOperation, 1, 64),
    maxTokenBytes: count(input.maxTokenBytes, 128, 4980), maxIssuesPerWindow: count(input.maxIssuesPerWindow, 1, 8192), windowMS: quantity(input.windowMS) };
  const source = input.signingKey ?? { protection: "hmac_sha256" as const, keyID: input.keyID, macKey: input.macKey };
  const previous = input.verificationKeys ?? [];
  if (!Array.isArray(previous) || previous.length > 7 || (source.protection !== "ed25519" && source.protection !== "hmac_sha256")) throw new V4ExecutionStoreError("configuration_capacity");
  const captured: Uint8Array[] = [];
  const copy = (value: Uint8Array, length: number) => { const bytes = fixed(value, length); captured.push(bytes); return bytes; };
  try {
    const keyID = copy(source.keyID!, 16);
    const signingKey: CheckpointSigningKey = Object.freeze(source.protection === "ed25519" ?
      { protection: source.protection, keyID, seed: copy(source.seed, 32) } : { protection: source.protection, keyID, macKey: copy(source.macKey!, 32) });
    const verificationKeys: CheckpointVerificationKey[] = [];
    if (signingKey.protection === "ed25519") {
      const publicKey = ed25519.getPublicKey(signingKey.seed); captured.push(publicKey);
      verificationKeys.push(Object.freeze({ protection: "ed25519", keyID: copy(keyID, 16), publicKey }));
    } else verificationKeys.push(Object.freeze({ protection: "hmac_sha256", keyID: copy(keyID, 16), macKey: copy(signingKey.macKey, 32) }));
    for (const value of previous) {
      const id = copy(value.keyID, 16);
      if (verificationKeys.some(key => equalCredential(key.keyID, id))) throw new V4ExecutionStoreError("configuration_capacity");
      if (value.protection === "ed25519") {
        const publicKey = copy(value.publicKey, 32), point = ed25519.Point.fromBytes(publicKey, false);
        if (point.is0() || !point.isTorsionFree() || !equalCredential(point.toBytes(), publicKey)) throw new V4ExecutionStoreError("configuration_capacity");
        verificationKeys.push(Object.freeze({ protection: value.protection, keyID: id, publicKey }));
      } else if (value.protection === "hmac_sha256") verificationKeys.push(Object.freeze({ protection: value.protection, keyID: id, macKey: copy(value.macKey, 32) }));
      else throw new V4ExecutionStoreError("configuration_capacity");
    }
    return Object.freeze({ ...limits, signingKey, verificationKeys: Object.freeze(verificationKeys) });
  } catch (error) { for (const bytes of captured) bytes.fill(0); throw error; }
}
export interface V4SQLiteExecutionOptions {
  readonly checkpoint?: V4SQLiteCheckpointConfig;
  readonly content?: V4SQLiteContentConfig;
  readonly identity: V4SQLitePoolIdentity;
  readonly continuity: V4SQLiteExecutionContinuity;
  readonly service: VolatileExecutionConfig;
  readonly maxContracts: number;
  readonly create: boolean;
}
export class V4ExecutionStoreError extends Error {
  constructor(readonly code: "configuration_capacity" | "storage_unavailable" | "storage_format" | "history_unknown" | "fenced" | "capacity" | "closed" | "operation_conflict",
    readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted") { super(code); this.name = "V4ExecutionStoreError"; }
}
const capability = Symbol("original SQLite execution store");
const hex = (bytes: Uint8Array): string => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
const manifestSQL = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-node-execution'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL, instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), configuration TEXT NOT NULL CHECK(length(CAST(configuration AS BLOB))<=4096), registry_revision BLOB NOT NULL CHECK(length(registry_revision)=8)) STRICT, WITHOUT ROWID";
const contractsSQL = "CREATE TABLE contracts (digest TEXT PRIMARY KEY CHECK(length(digest)=64), method INTEGER NOT NULL, canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 8192), offers BLOB NOT NULL CHECK(length(offers)<=128 AND length(offers)%16=0), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), revision BLOB NOT NULL CHECK(length(revision)=8)) STRICT, WITHOUT ROWID";
const recordsSQL = "CREATE TABLE executions (key TEXT PRIMARY KEY CHECK(length(CAST(key AS BLOB)) BETWEEN 67 AND 258), facts TEXT NOT NULL CHECK(length(CAST(facts AS BLOB))<=8192), payload BLOB CHECK(payload IS NULL OR length(payload)<=1048576), registration_revision BLOB NOT NULL CHECK(length(registration_revision)=8), deadline BLOB NOT NULL CHECK(length(deadline)=8)) STRICT, WITHOUT ROWID";
const floorsSQL = "CREATE TABLE floors (authority TEXT PRIMARY KEY CHECK(length(authority)=64), floor BLOB NOT NULL CHECK(length(floor)=8)) STRICT, WITHOUT ROWID";
const schemas = [["manifest", manifestSQL], ["contracts", contractsSQL], ["executions", recordsSQL], ["floors", floorsSQL]] as const;
const checkpointSchemas = (maxTokenBytes: number) => [
  ["checkpoints", "CREATE TABLE checkpoints (key TEXT PRIMARY KEY, format TEXT NOT NULL, generation BLOB NOT NULL CHECK(length(generation)=8), target BLOB NOT NULL CHECK(length(target)=32), stream BLOB NOT NULL CHECK(length(stream)=8)) STRICT, WITHOUT ROWID"],
  ["checkpoint_tokens", "CREATE TABLE checkpoint_tokens (digest TEXT PRIMARY KEY CHECK(length(digest)=64), original TEXT NOT NULL, issuer TEXT NOT NULL UNIQUE, generation BLOB NOT NULL CHECK(length(generation)=8), expires BLOB NOT NULL CHECK(length(expires)=8), token BLOB NOT NULL CHECK(length(token) BETWEEN 1 AND TOKEN_LIMIT)) STRICT, WITHOUT ROWID".replace("TOKEN_LIMIT", maxTokenBytes > 4948 ? "4980" : "4948")],
  ["checkpoint_rate", "CREATE TABLE checkpoint_rate (id INTEGER PRIMARY KEY CHECK(id=1), window_start BLOB NOT NULL CHECK(length(window_start)=8), issued INTEGER NOT NULL CHECK(issued>=0)) STRICT, WITHOUT ROWID"],
] as const;
const factFields = ["notification", "streaming", "metadataFinished", "key", "domain", "request", "contract", "cutoff", "historyUntil", "retention", "limit", "cancelMode", "cancelRequested", "resultDigest", "state", "active", "dispatched", "resultBytes", "resultCode", "resultUntil", "error"] as const;
const stringify = (value: unknown): string => JSON.stringify(value, (_key, v) => typeof v === "bigint" ? v.toString() : v);
// Key authority comes only from the current trusted application configuration.
// A stored issuance-key fingerprint is not authority to keep using that key.
// All service, capacity and history settings still compare exactly.
function sameExecutionConfiguration(stored: SQLOutputValue | undefined, expected: string): boolean {
  if (typeof stored !== "string" || stored.length > 4096) return false;
  if (stored === expected) return true;
  try {
    const parsed = JSON.parse(stored);
    if (parsed?.checkpoint === null || typeof parsed?.checkpoint !== "object" || Array.isArray(parsed.checkpoint)) return false;
    if (typeof parsed.checkpoint.keyID !== "string" || !/^[0-9a-f]{32}$/u.test(parsed.checkpoint.keyID) ||
        typeof parsed.checkpoint.macKey !== "string" || !/^[0-9a-f]{64}$/u.test(parsed.checkpoint.macKey)) return false;
    delete parsed.checkpoint.keyID; delete parsed.checkpoint.macKey;
    return stringify(parsed) === expected;
  } catch { return false; }
}
function encodeFacts(facts: ExecutionRecordFacts): string {
  const value: Record<string, unknown> = {};
  for (const key of factFields) value[key] = facts[key] ?? null;
  const encoded = stringify(value);
  if (encoded.length > 8192) throw new V4ExecutionStoreError("capacity");
  return encoded;
}
function decodeFacts(input: SQLOutputValue | undefined, service: VolatileExecutionConfig): ExecutionRecordFacts {
  if (typeof input !== "string" || input.length > 8192) throw new V4ExecutionStoreError("storage_format");
  const value: Record<string, unknown> = JSON.parse(input);
  const bad = (): never => { throw new V4ExecutionStoreError("storage_format"); };
  if (value === null || Array.isArray(value) || Object.keys(value).length !== factFields.length || factFields.some(key => !Object.hasOwn(value, key))) bad();
  for (const key of ["cutoff", "historyUntil", "retention", "resultUntil"] as const) {
    const n = value[key];
    if (n === null && key === "resultUntil") { value[key] = undefined; continue; }
    if (typeof n !== "string" || !/^(0|[1-9][0-9]{0,19})$/u.test(n)) bad();
    const integer = BigInt(n as string); if (integer > maximum) bad(); value[key] = integer;
  }
  for (const key of ["notification", "streaming", "metadataFinished", "cancelMode", "cancelRequested", "active", "dispatched"]) if (typeof value[key] !== "boolean") bad();
  for (const key of ["domain", "request", "contract", "resultDigest"]) if (typeof value[key] !== "string" || !/^[0-9a-f]{64}$/u.test(value[key] as string)) bad();
  if (!service.callerAuthorities.includes(value.domain as string) || typeof value.key !== "string") bad();
  const pieces = (value.key as string).split("\0");
  if (pieces.length !== 3 || pieces[0] !== value.domain || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(pieces[1]!) || !/^[0-9a-f]{64}$/u.test(pieces[2]!) || BigInt("0x" + pieces[2]!.slice(0, 16)) !== value.cutoff) bad();
  for (const key of ["limit", "resultBytes"]) if (!Number.isSafeInteger(value[key]) || Number(value[key]) < 0 || Number(value[key]) > 1048576) bad();
  if (Number(value.resultBytes) > Number(value.limit) || !["accepted", "executing", "completed", "failed", "unknown"].includes(value.state as string)) bad();
  if (value.resultCode === null) value.resultCode = undefined;
  else if (!Number.isSafeInteger(value.resultCode) || Number(value.resultCode) < 1 || Number(value.resultCode) > 0xffffffff) bad();
  if (value.error === null) value.error = undefined;
  else if (!["permission_denied", "resource_exhausted", "service_unavailable", "operation_conflict", "result_expired", "deadline_exceeded", "service_failed", "source_overflow"].includes(value.error as string)) bad();
  if (value.notification && value.streaming || (value.notification || value.streaming) && (value.resultUntil !== undefined || value.resultBytes !== 0) || (value.historyUntil as bigint) < (value.cutoff as bigint)) bad();
  return value as unknown as ExecutionRecordFacts;
}
interface StoreState {
  readonly backing: BackingState;
  readonly dependency: EnvironmentDependency;
  readonly disk: ResourceReference;
  readonly identity: V4SQLitePoolIdentity;
  readonly continuity: V4SQLiteExecutionContinuity["check"];
  readonly service: V4DurableExecutionService;
  readonly maxContracts: number;
  readonly checkpoint: CapturedCheckpoint | undefined;
  readonly content: CapturedContentConfig | undefined;
  readonly configuration: string;
  database: DatabaseSync | undefined;
  inode: Stats | undefined;
  epoch: bigint;
  active: boolean;
  bound: boolean;
  used: boolean;
  closed: boolean;
  poisoned: boolean;
}

/** Purpose-specific transactions over the shared bounded Node SQLite driver.
 * The live execution owner is unchanged; this store owns persisted authority. */
export class V4SQLiteExecutionStore {
  readonly #s: StoreState;
  #recoveryCodec: ResumeCodec | undefined;
  #content: SQLiteExecutionContent | undefined;
  readonly service: V4DurableExecutionService;
  constructor(token: symbol, state: StoreState) {
    if (token !== capability) throw new V4ExecutionStoreError("configuration_capacity");
    this.#s = state; this.service = state.service; Object.freeze(this);
  }
  #scalar(sql: string, ...args: SQLInputValue[]): SQLOutputValue { return sqliteScalar(this.#s.database!, sql, ...args); }
  #exec(sql: string, ...args: SQLInputValue[]): void { sqliteExec(this.#s.database!, sql, ...args); }
  #proof(create = false): void {
    const s = this.#s;
    if (s.continuity(Object.freeze({ ...s.identity, storeID: new Uint8Array(s.identity.storeID) }), s.service, s.epoch, create) !== undefined) throw new V4ExecutionStoreError("history_unknown");
  }
  #check(retained = false): void {
    const s = this.#s;
    if (s.poisoned || s.database === undefined || s.closed && (!retained || !s.bound)) throw new V4ExecutionStoreError("closed");
    s.dependency.reference.checkRetained(); s.disk.checkRetained(); s.inode = sqliteFiles(s.backing, s.inode);
  }
  #fence(): void {
    if (readU64(this.#scalar("SELECT epoch FROM manifest WHERE id=1")) !== this.#s.epoch) throw new V4ExecutionStoreError("fenced");
    this.#proof();
  }
  #transaction<T>(action: () => T, retained = false, guard?: () => void): T {
    const s = this.#s; this.#check(retained);
    if (s.active) throw new V4ExecutionStoreError("capacity");
    s.active = true; let committing = false, committed = false;
    try {
      sqliteCheckpoint(s.database!); this.#check(retained); this.#exec("BEGIN IMMEDIATE");
      try {
        this.#fence(); guard?.(); const result = action(); this.#check(retained); guard?.(); this.#fence();
        committing = true; this.#exec("COMMIT"); committing = false; committed = true; this.#check(retained); return result;
      } catch (error) { try { this.#exec("ROLLBACK"); } catch { if (!committed) s.poisoned = true; } throw error; }
    } catch (error) {
      if (committing || committed) { s.poisoned = true; throw new V4ExecutionStoreError("storage_unavailable", committed ? "committed" : "unknown"); }
      if (error instanceof V4ExecutionStoreError || error instanceof RPCProtocolError) throw error;
      s.poisoned = true; throw new V4ExecutionStoreError("storage_unavailable");
    } finally { s.active = false; this.#cleanup(); }
  }
  initialize(token: symbol, create: boolean): void {
    if (token !== capability) throw new V4ExecutionStoreError("configuration_capacity");
    const s = this.#s; s.active = true;
    try {
      if (s.content !== undefined) {
        const r = s.backing.environment.resources;
        const refs = r.root.reserveBatch(contentCharges(s.content).map((charge, index) => ({ accounts: r.accounts,
          owner: credentialOwner(r, `execution_content_${index}`), charge })));
        try { this.#content = new SQLiteExecutionContent(s.content, refs); } finally { refs.forEach(reference => reference.release()); }
      }
      if (s.checkpoint !== undefined) {
        const r = s.backing.environment.resources;
        const refs = r.root.reserveBatch(resumeCodecCharges(r.runtimeBytes).map(charge => ({ accounts: r.accounts,
          owner: credentialOwner(r, "execution_recovery"), charge })));
        try { this.#recoveryCodec = new ResumeCodec(r.runtimeBytes, refs); } finally { refs.forEach(reference => reference.release()); }
      }
      if (create) {
        this.#proof(true);
        if (["", "-wal", "-shm", "-journal"].some(suffix => !missing(s.backing.path + suffix))) throw new V4ExecutionStoreError("history_unknown");
        const fd = openSync(s.backing.path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); closeSync(fd);
      } else if (missing(s.backing.path)) throw new V4ExecutionStoreError("history_unknown");
      s.inode = sqliteFiles(s.backing);
      s.database = new DatabaseSync(s.backing.path, { allowExtension: false, enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false, timeout: 0 });
      sqliteConfigure(s.database, s.backing.limits, create); this.#exec("BEGIN IMMEDIATE");
      try {
        if (create) {
          for (const [, sql] of [...schemas, ...(s.checkpoint === undefined ? [] : checkpointSchemas(s.checkpoint.maxTokenBytes)), ...(s.content === undefined ? [] : contentSchemas)]) this.#exec(sql);
          s.epoch = 1n; this.#exec("PRAGMA user_version=1");
          if (s.checkpoint !== undefined) this.#exec("INSERT INTO checkpoint_rate VALUES(1,?,0)", u64(0n));
          this.#exec("INSERT INTO manifest VALUES(1,'flowersec-v4-node-execution',1,?,?,?,?,?,?)", s.identity.authority, s.identity.storeID, u64(s.identity.generation), u64(s.epoch), s.configuration, u64(0n));
          for (const authority of s.service.callerAuthorities) this.#exec("INSERT INTO floors VALUES(?,?)", authority, u64(0n));
        } else {
          this.#validate(); this.#proof(); if (s.epoch === maximum) throw new V4ExecutionStoreError("fenced");
          const old = s.epoch++; this.#exec("UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?", u64(s.epoch), u64(old));
          if (this.#scalar("SELECT changes()") !== 1) throw new V4ExecutionStoreError("fenced");
          // The independent proof settled/fenced old real work. Restart can
          // preserve its outcome or mark uncertainty, never issue dispatch.
          this.#content?.validate(s.database!, s.service.maxRecords, value => decodeFacts(value, s.service));
    for (const row of this.#rows()) {
            const facts = decodeFacts(row.facts, s.service);
            if (!facts.active) continue;
            const terminal = facts.resultUntil !== undefined || facts.metadataFinished || facts.state === "completed";
            const settled: ExecutionRecordFacts = { ...facts, active: false,
              state: terminal ? facts.state : facts.dispatched ? "unknown" : "failed",
              error: terminal ? facts.error : "service_unavailable" };
            this.#exec("UPDATE executions SET facts=? WHERE key=?", encodeFacts(settled), facts.key);
          }
        }
        s.dependency.check(); s.disk.check(); this.#proof();
        try { this.#exec("COMMIT"); } catch { s.poisoned = true; throw new V4ExecutionStoreError("storage_unavailable", "unknown"); }
      } catch (error) { try { this.#exec("ROLLBACK"); } catch { s.poisoned = true; } throw error; }
      if (create) syncDirectory(s.backing.path); this.#check();
    } finally { s.active = false; this.#cleanup(); }
  }
  #validate(): void {
    const s = this.#s;
    if (this.#scalar("PRAGMA user_version") !== 1 || this.#scalar("SELECT count(*) FROM sqlite_schema") !== schemas.length + (s.checkpoint === undefined ? 0 : checkpointSchemas(s.checkpoint.maxTokenBytes).length + 1) + (s.content === undefined ? 0 : contentSchemas.length) || this.#scalar("SELECT count(*) FROM manifest") !== 1) throw new V4ExecutionStoreError("storage_format");
    for (const [name, sql] of [...schemas, ...(s.checkpoint === undefined ? [] : checkpointSchemas(s.checkpoint.maxTokenBytes)), ...(s.content === undefined ? [] : contentSchemas)]) {
      if (this.#scalar("SELECT length(sql) FROM sqlite_schema WHERE name=?", name) !== sql.length || this.#scalar("SELECT sql FROM sqlite_schema WHERE name=?", name) !== sql) throw new V4ExecutionStoreError("storage_format");
    }
    const m = s.database!.prepare("SELECT format,revision,CASE WHEN length(authority)<=128 THEN authority END AS authority,instance,generation,epoch,CASE WHEN length(configuration)<=4096 THEN configuration END AS configuration FROM manifest WHERE id=1").get();
    if (m?.format !== "flowersec-v4-node-execution" || m.revision !== 1 || m.authority !== s.identity.authority || !(m.instance instanceof Uint8Array) || !equalCredential(m.instance, s.identity.storeID) || readU64(m.generation) !== s.identity.generation || !sameExecutionConfiguration(m.configuration, s.configuration)) throw new V4ExecutionStoreError("storage_format");
    s.epoch = readU64(m.epoch); if (s.epoch === 0n) throw new V4ExecutionStoreError("storage_format");
    if (Number(this.#scalar("SELECT count(*) FROM contracts")) > s.maxContracts || Number(this.#scalar("SELECT count(*) FROM executions")) > s.service.maxRecords || Number(this.#scalar("SELECT coalesce(sum(length(payload)),0) FROM executions")) > Number(s.service.resultBytes) || Number(this.#scalar("SELECT count(*) FROM floors")) !== s.service.callerAuthorities.length) throw new V4ExecutionStoreError("storage_format");
    for (const authority of s.service.callerAuthorities) readU64(this.#scalar("SELECT floor FROM floors WHERE authority=?", authority));
    if (this.#scalar("SELECT count(*) FROM executions WHERE length(CAST(facts AS BLOB))>8192 OR length(payload)>? OR length(registration_revision)<>8 OR length(deadline)<>8", s.backing.limits.maxRecordBytes) !== 0) throw new V4ExecutionStoreError("storage_format");
    if (s.checkpoint !== undefined) {
      const c = s.checkpoint;
      if (Number(this.#scalar("SELECT count(*) FROM checkpoints")) > s.service.maxRecords ||
          Number(this.#scalar("SELECT count(*) FROM checkpoint_tokens")) > c.maxTokens ||
          this.#scalar("SELECT count(*) FROM checkpoint_rate") !== 1 ||
          Number(this.#scalar("SELECT issued FROM checkpoint_rate WHERE id=1")) > c.maxIssuesPerWindow ||
          this.#scalar("SELECT count(*) FROM checkpoints c LEFT JOIN executions e ON e.key=c.key WHERE e.key IS NULL OR length(CAST(c.format AS BLOB)) NOT BETWEEN 1 AND 128") !== 0 ||
          this.#scalar("SELECT count(*) FROM checkpoint_tokens t LEFT JOIN checkpoints c ON c.key=t.original WHERE c.key IS NULL OR length(t.token)>?", c.maxTokenBytes) !== 0) throw new V4ExecutionStoreError("storage_format");
      readU64(this.#scalar("SELECT window_start FROM checkpoint_rate WHERE id=1"));
      for (const row of s.database!.prepare("SELECT generation,target,stream FROM checkpoints").iterate()) {
        const generation = readU64(row.generation), stream = readU64(row.stream);
        if (!(row.target instanceof Uint8Array) || row.target.length !== 32 || stream >= 1n << 63n ||
            generation === 0n && (stream !== 0n || row.target.some(n => n !== 0)) ||
            generation !== 0n && (stream === 0n || row.target.every(n => n === 0))) throw new V4ExecutionStoreError("storage_format");
      }
      for (const row of s.database!.prepare("SELECT digest,token FROM checkpoint_tokens").iterate()) {
        if (!(row.token instanceof Uint8Array) || hex(sha256(row.token)) !== row.digest) throw new V4ExecutionStoreError("storage_format");
        row.token.fill(0);
      }
    }
    for (const row of this.#rows()) {
      const facts = decodeFacts(row.facts, s.service);
      if (facts.key !== row.key || row.payload !== null && (!(row.payload instanceof Uint8Array) || row.payload.length !== facts.resultBytes || hex(sha256(row.payload)) !== facts.resultDigest)) throw new V4ExecutionStoreError("storage_format");
      if (row.payload instanceof Uint8Array) row.payload.fill(0);
    }
  }
  *#rows(): IterableIterator<Record<string, SQLOutputValue>> {
    let count = 0;
    for (const row of this.#s.database!.prepare("SELECT key,CASE WHEN length(CAST(facts AS BLOB))<=8192 THEN facts END AS facts,CASE WHEN length(payload)<=1048576 THEN payload END AS payload FROM executions ORDER BY key").iterate()) {
      if (++count > this.#s.service.maxRecords) throw new V4ExecutionStoreError("storage_format"); yield row;
    }
  }
  #registration(digest: string): Record<string, SQLOutputValue> {
    const row = this.#s.database!.prepare("SELECT method,CASE WHEN length(canonical)<=8192 THEN canonical END AS canonical,CASE WHEN length(offers)<=128 THEN offers END AS offers,enabled,revision FROM contracts WHERE digest=?").get(digest);
    if (row === undefined || !(row.canonical instanceof Uint8Array) || hex(credentialDigest("service_contract_digest", row.canonical)) !== digest || !(row.offers instanceof Uint8Array) || row.offers.length % 16 !== 0) throw new V4ExecutionStoreError("storage_format");
    return row;
  }
  #contract(contract: ServiceContractSnapshot): Readonly<{ digest: string; canonical: Uint8Array }> {
    if (contract.namespace !== this.service.namespace || contract.semantics !== "execution" || contract.optionalUint(13) !== 1n || contract.optionalText(20) !== undefined && this.#s.checkpoint === undefined || contract.shape === "server_streaming" && contract.streamContentMode() !== "none" && this.#content === undefined || contract.shape === "unary" && contract.uint(10) > BigInt(this.#s.backing.limits.maxRecordBytes) || !contract.sameEnvironment(this.#s.dependency.reference)) throw new V4ExecutionStoreError("configuration_capacity");
    const digest = new Uint8Array(32), buffer = new Uint8Array(8192); contract.copyDigest(digest);
    const size = contract.copyEncoded(buffer); this.#content?.policy(buffer.subarray(0, size)); return { digest: hex(digest), canonical: buffer.subarray(0, size) };
  }
  /** Copy the persisted original body and exact windows for service assembly.
   * Reading does not renew an Offer or grant execution admission. */
  readRegistration(digest: Uint8Array, destination: Uint8Array): V4SQLiteExecutionRegistration {
    this.#check(); this.#fence();
    if (!(digest instanceof Uint8Array) || digest.length !== 32 || !(destination instanceof Uint8Array) || destination.buffer instanceof SharedArrayBuffer) throw new V4ExecutionStoreError("configuration_capacity");
    const row = this.#registration(hex(digest)), canonical = row.canonical as Uint8Array, windows = row.offers as Uint8Array;
    if (destination.length < canonical.length) throw new V4ExecutionStoreError("capacity");
    const offers: { notBeforeMS: bigint; notAfterMS: bigint }[] = [];
    for (let at = 0; at < windows.length; at += 16) {
      const notBeforeMS = readU64(windows.subarray(at, at + 8)), notAfterMS = readU64(windows.subarray(at + 8, at + 16));
      if (notBeforeMS >= notAfterMS) throw new V4ExecutionStoreError("storage_format");
      offers.push(Object.freeze({ notBeforeMS, notAfterMS }));
    }
    const revision = readU64(row.revision);
    if (!Number.isSafeInteger(row.method) || Number(row.method) <= 0 || Number(row.method) > 0xffffffff || row.enabled !== 0 && row.enabled !== 1 || revision === 0n) throw new V4ExecutionStoreError("storage_format");
    this.#check(); this.#fence(); destination.set(canonical);
    return Object.freeze({ encodedBytes: canonical.length, typeID: Number(row.method), revision, enabled: row.enabled === 1, offers: Object.freeze(offers) });
  }
  installContract(contract: ServiceContractSnapshot, offers: readonly Readonly<{ notBeforeMS: bigint; notAfterMS: bigint }>[], expectedRevision: bigint): bigint {
    const s = this.#s, captured = this.#contract(contract);
    if (typeof expectedRevision !== "bigint" || expectedRevision < 0n || expectedRevision >= maximum || offers.length > 8) throw new V4ExecutionStoreError("configuration_capacity");
    const windows = new Uint8Array(offers.length * 16);
    offers.forEach((offer, index) => {
      if (typeof offer.notBeforeMS !== "bigint" || typeof offer.notAfterMS !== "bigint" || offer.notBeforeMS < 0n || offer.notBeforeMS >= offer.notAfterMS || offer.notAfterMS > maximum || offer.notAfterMS - offer.notBeforeMS > contract.uint(16)) throw new V4ExecutionStoreError("configuration_capacity");
      windows.set(u64(offer.notBeforeMS), index * 16); windows.set(u64(offer.notAfterMS), index * 16 + 8);
    });
    return this.#transaction(() => {
      if (readU64(this.#scalar("SELECT registry_revision FROM manifest WHERE id=1")) !== expectedRevision) throw new V4ExecutionStoreError("operation_conflict");
      const found = this.#scalar("SELECT count(*) FROM contracts WHERE digest=?", captured.digest) === 1;
      if (found) {
        const old = this.#registration(captured.digest), bytes = old.offers as Uint8Array, now = s.backing.environment.clock.sample().requireInterval();
        if (!equalCredential(old.canonical as Uint8Array, captured.canonical)) throw new V4ExecutionStoreError("storage_format");
        for (let at = 0; at < bytes.length; at += 16) {
          const before = readU64(bytes.subarray(at, at + 8)), after = readU64(bytes.subarray(at + 8, at + 16));
          if (now.lowerMS < after && !offers.some(next => next.notBeforeMS === before && next.notAfterMS === after)) throw new V4ExecutionStoreError("configuration_capacity");
        }
      } else if (Number(this.#scalar("SELECT count(*) FROM contracts")) >= s.maxContracts || Number(this.#scalar("SELECT count(*) FROM contracts WHERE method=?", contract.typeID)) >= 8) throw new V4ExecutionStoreError("capacity");
      const revision = expectedRevision + 1n;
      this.#exec("INSERT INTO contracts VALUES(?,?,?,?,1,?) ON CONFLICT(digest) DO UPDATE SET offers=excluded.offers,revision=excluded.revision", captured.digest, contract.typeID, captured.canonical, windows, u64(revision));
      this.#exec("UPDATE manifest SET registry_revision=? WHERE id=1", u64(revision)); return revision;
    });
  }
  #adapter(): ExecutionStorage {
    const s = this.#s;
    return Object.freeze({
      bind: (reference: ResourceReference): void => { this.#check(); if (s.used || !reference.sameEnvironment(s.dependency.reference)) throw new V4ExecutionStoreError("configuration_capacity"); s.bound = s.used = true; },
      release: (): void => { s.bound = false; this.#cleanup(); },
      check: (): void => { try { if (s.closed || s.poisoned || s.database === undefined) throw new Error(); s.dependency.reference.checkRetained(); s.disk.checkRetained(); } catch { throw new RPCProtocolError("service_unavailable"); } },
      floors: (): ReadonlyMap<string, bigint> => new Map(s.service.callerAuthorities.map(authority => [authority, readU64(this.#scalar("SELECT floor FROM floors WHERE authority=?", authority))])),
      records: (): Iterable<Readonly<{ facts: ExecutionRecordFacts; payload?: Uint8Array }>> => {
        const original = this;
        return { *[Symbol.iterator]() { original.#check(); for (const row of original.#rows()) {
          const facts = decodeFacts(row.facts, s.service); yield { facts, ...(row.payload instanceof Uint8Array ? { payload: row.payload } : {}) };
        } } };
      },
      checkContract: (contract: ServiceContractSnapshot, offer: AdmissionOffer, maximumWindowMS: bigint): void => {
        this.#check(); this.#fence(); const captured = this.#contract(contract), row = this.#registration(captured.digest);
        this.#content?.policy(captured.canonical);
        offer.copyEncoded(contract, maximumWindowMS, new Uint8Array(256));
        const windows = row.offers as Uint8Array; let found = false;
        for (let at = 0; at < windows.length; at += 16) found ||= readU64(windows.subarray(at, at + 8)) === offer.notBeforeMS && readU64(windows.subarray(at + 8, at + 16)) === offer.notAfterMS;
        if (row.enabled !== 1 || !found || !equalCredential(row.canonical as Uint8Array, captured.canonical)) throw new RPCProtocolError("service_contract_mismatch");
      },
      register: (facts: ExecutionRecordFacts, contract: ServiceContractSnapshot, deadline: bigint, guard: () => void): void => {
        const captured = this.#contract(contract);
        this.#transaction(() => {
          if (this.#scalar("SELECT count(*) FROM executions WHERE key=?", facts.key) !== 0) throw new RPCProtocolError("operation_conflict");
          const row = this.#registration(captured.digest), windows = row.offers as Uint8Array, now = s.backing.environment.clock.sample().requireInterval();
          let found = false;
          for (let at = 0; at < windows.length; at += 16) found ||= readU64(windows.subarray(at, at + 8)) <= now.lowerMS && facts.cutoff <= readU64(windows.subarray(at + 8, at + 16));
          if (row.enabled !== 1 || !found || !equalCredential(row.canonical as Uint8Array, captured.canonical) || now.upperMS >= facts.cutoff || facts.cutoff <= readU64(this.#scalar("SELECT floor FROM floors WHERE authority=?", facts.domain)) || now.upperMS >= deadline || deadline > now.lowerMS + contract.uint(17) || facts.cutoff > now.lowerMS + contract.uint(16)) throw new RPCProtocolError("deadline_exceeded");
          if (Number(this.#scalar("SELECT count(*) FROM executions")) >= s.service.maxRecords) throw new RPCProtocolError("resource_exhausted");
          const content = this.#content?.policy(captured.canonical);
          if (content !== undefined) timeAdd(now.upperMS, content.retention);
          this.#exec("INSERT INTO executions VALUES(?,?,NULL,?,?)", facts.key, encodeFacts(facts), row.revision!, u64(deadline));
          if (content !== undefined) this.#exec("INSERT INTO content_heads VALUES(?,?)", facts.key, u64(now.upperMS));
          const format = contract.optionalText(20);
          if (format !== undefined) this.#exec("INSERT INTO checkpoints VALUES(?,?,?,?,?)", facts.key, format, u64(0n), new Uint8Array(32), u64(0n));
        }, false, guard);
      },
      update: (facts: ExecutionRecordFacts, payload?: Uint8Array): void => {
        try { this.#transaction(() => {
          if (payload !== undefined) {
            if (payload.length > s.backing.limits.maxRecordBytes || payload.length !== facts.resultBytes || Number(this.#scalar("SELECT coalesce(sum(length(payload)),0) FROM executions WHERE key<>?", facts.key)) + payload.length > Number(s.service.resultBytes)) throw new V4ExecutionStoreError("capacity");
            this.#exec("UPDATE executions SET facts=?,payload=? WHERE key=?", encodeFacts(facts), payload, facts.key);
          } else this.#exec("UPDATE executions SET facts=? WHERE key=?", encodeFacts(facts), facts.key);
          if (this.#scalar("SELECT changes()") !== 1) throw new V4ExecutionStoreError("history_unknown");
        }, true); } catch (error) { s.poisoned = true; throw error; }
      },
      issueCheckpoint: (facts: ExecutionRecordFacts, original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void) => this.#issueCheckpoint(facts, original, checkpoint, options, policy, executionCap, guard),
      finishResume: (facts: ExecutionRecordFacts, request: Uint8Array, target: ResumeTargetFacts, policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void) => this.#finishResume(facts, request, target, policy, executionCap, guard),
      saveContent: (facts: ExecutionRecordFacts, position: Uint8Array, payload: Uint8Array, executionCap: bigint, guard: () => void) => this.#transaction(() => {
        const current = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", facts.key), s.service);
        const now = s.backing.environment.clock.sample().requireInterval();
        if (this.#content === undefined || !current.streaming || !current.active || !current.dispatched || current.state !== "executing" || current.cancelRequested ||
            current.request !== facts.request || current.contract !== facts.contract) throw new RPCProtocolError("service_unavailable");
        if (now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
        return this.#content.save(s.database!, current, position, payload, now);
      }, true, guard),
      readContent: (facts: ExecutionRecordFacts, target: ExecutionTarget, position: Uint8Array, destination: Uint8Array, readerType: number, guard: () => void) => {
        const content = this.#content;
        if (content === undefined) throw new RPCProtocolError("service_unavailable");
        return content.deliver(destination, scratch => this.#transaction(() => {
          const current = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", facts.key), s.service);
          const registration = this.#registration(current.contract);
          if (!current.active || !current.dispatched || current.state !== "executing" || current.cancelRequested || current.request !== facts.request || current.contract !== facts.contract || registration.method !== readerType) throw new RPCProtocolError("permission_denied");
          return content.read(s.database!, target, position, scratch, readerType, s.backing.environment.clock.sample().requireInterval(), value => decodeFacts(value, s.service));
        }, true, guard), guard, () => s.backing.environment.clock.sample().requireInterval());
      },
      absence: (key: string, authority: string, cutoff: bigint, guard: () => void): "not_registered" | "history_unknown" => this.#transaction(() => {
        // The independent complete-history proof and the original floor are
        // checked inside the same boundary as first registration and GC.
        if (this.#scalar("SELECT count(*) FROM executions WHERE key=?", key) !== 0) throw new V4ExecutionStoreError("history_unknown");
        return cutoff > readU64(this.#scalar("SELECT floor FROM floors WHERE authority=?", authority)) ? "not_registered" : "history_unknown";
      }, false, guard),
      expireResult: (key: string): void => { this.#transaction(() => {
        const facts = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", key), s.service);
        const now = s.backing.environment.clock.sample().requireInterval();
        if (facts.active || facts.resultUntil !== undefined && now.lowerMS < facts.resultUntil) throw new V4ExecutionStoreError("history_unknown");
        // Keep identity, outcome and digest until history GC. Releasing only the
        // payload does not make this operation eligible for another dispatch.
        this.#exec("UPDATE executions SET payload=NULL WHERE key=?", key);
      }, true); },
      remove: (key: string, authority: string, floor: bigint): void => { this.#transaction(() => {
        const old = readU64(this.#scalar("SELECT floor FROM floors WHERE authority=?", authority));
        if (floor < old) throw new V4ExecutionStoreError("history_unknown");
        if (s.checkpoint !== undefined) {
          // Token expiry is capped by the original history promise. Even a
          // caller bypassing the live GC loop cannot erase usable tokens.
          const now = s.backing.environment.clock.sample().requireInterval();
          if (Number(this.#scalar("SELECT count(*) FROM checkpoint_tokens WHERE original=? AND expires>?", key, u64(now.lowerMS))) !== 0) throw new V4ExecutionStoreError("history_unknown");
          this.#exec("DELETE FROM checkpoint_tokens WHERE original=?", key);
          this.#exec("DELETE FROM checkpoints WHERE key=?", key);
        }
        if (this.#content !== undefined) {
          const now = s.backing.environment.clock.sample().requireInterval();
          if (Number(this.#scalar("SELECT count(*) FROM content_items WHERE key=? AND expires>?", key, u64(now.lowerMS))) !== 0) throw new V4ExecutionStoreError("history_unknown");
          this.#exec("DELETE FROM content_items WHERE key=?", key); this.#exec("DELETE FROM content_heads WHERE key=?", key);
        }
        this.#exec("UPDATE floors SET floor=? WHERE authority=?", u64(floor), authority); this.#exec("DELETE FROM executions WHERE key=?", key);
      }, true); },
    });
  }
  #issueCheckpoint(facts: ExecutionRecordFacts, original: ExecutionTarget, checkpoint: V4Checkpoint, options: V4CheckpointIssuanceOptions,
    policy: CheckpointSessionPolicy, executionCap: bigint, guard: () => void): Readonly<{ facts: ExecutionRecordFacts; payload: Uint8Array }> {
    const s = this.#s, c = s.checkpoint;
    if (c === undefined) throw new RPCProtocolError("service_unavailable");
    let payload: Uint8Array | undefined;
    try {
      const result = this.#transaction(() => {
        const sourceKey = `${original.authority}\0${original.subject}\0${original.operation}`;
        const source = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", sourceKey), s.service);
        const issuing = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", facts.key), s.service);
        if (original.tenant !== s.service.tenant || original.audience !== s.service.audience || original.namespace !== s.service.namespace ||
            sourceKey === facts.key || source.domain !== facts.domain || sourceKey.split("\0")[1] !== facts.key.split("\0")[1] ||
            source.request !== original.requestDigest || source.contract !== original.contractDigest ||
            this.#scalar("SELECT format FROM checkpoints WHERE key=?", sourceKey) !== checkpoint.format ||
            !issuing.active || !issuing.dispatched || issuing.state !== "executing" || issuing.resultUntil !== undefined || issuing.error !== undefined || issuing.request !== facts.request || issuing.contract !== facts.contract) throw new RPCProtocolError("operation_conflict");
        const now = s.backing.environment.clock.sample().requireInterval();
        if (now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
        const duration = [options.durationMS, options.applicationDurationLimitMS, policy.maxIssuedTokenDurationMS].reduce((a, b) => a < b ? a : b);
        const expires = [timeAdd(now.lowerMS, duration), options.historyNotAfterMS, source.historyUntil].reduce((a, b) => a < b ? a : b);
        if (expires <= now.upperMS) throw new RPCProtocolError("deadline_exceeded");
        const generation = readU64(this.#scalar("SELECT generation FROM checkpoints WHERE key=?", sourceKey));
        if (generation === maximum) throw new RPCProtocolError("resource_exhausted");
        if (Number(this.#scalar("SELECT count(*) FROM checkpoint_tokens")) >= c.maxTokens ||
            Number(this.#scalar("SELECT count(*) FROM checkpoint_tokens WHERE original=? AND generation=? AND expires>?", sourceKey, u64(generation), u64(now.lowerMS))) >= c.maxTokensPerOperation) throw new RPCProtocolError("resource_exhausted");
        const start = readU64(this.#scalar("SELECT window_start FROM checkpoint_rate WHERE id=1"));
        const freshWindow = now.lowerMS >= timeAdd(start, c.windowMS);
        const issued = freshWindow ? 0 : Number(this.#scalar("SELECT issued FROM checkpoint_rate WHERE id=1"));
        if (issued >= c.maxIssuesPerWindow) throw new RPCProtocolError("resource_exhausted");
        const nonce = randomFillSync(new Uint8Array(32));
        try { payload = checkpointToken(original, checkpoint, generation, now.lowerMS, expires, nonce, c.signingKey); }
        finally { nonce.fill(0); }
        if (payload.length > Math.min(c.maxTokenBytes, policy.maxTokenBytes, facts.limit, s.backing.limits.maxRecordBytes) ||
            Number(this.#scalar("SELECT coalesce(sum(length(payload)),0) FROM executions")) + payload.length > Number(s.service.resultBytes)) throw new RPCProtocolError("resource_exhausted");
        const digest = hex(sha256(payload));
        const completed: ExecutionRecordFacts = { ...issuing, state: "completed", resultBytes: payload.length, resultCode: undefined,
          resultDigest: digest, resultUntil: timeAdd(now.upperMS, issuing.retention) };
        this.#exec("INSERT INTO checkpoint_tokens VALUES(?,?,?,?,?,?)", digest, sourceKey, facts.key, u64(generation), u64(expires), payload);
        this.#exec("UPDATE checkpoint_rate SET window_start=?,issued=? WHERE id=1", u64(freshWindow ? now.lowerMS : start), issued + 1);
        this.#exec("UPDATE executions SET facts=?,payload=? WHERE key=?", encodeFacts(completed), payload, facts.key);
        return { facts: completed, payload };
      }, true, () => { guard(); if (s.backing.environment.clock.sample().requireInterval().upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded"); });
      payload = undefined; return result;
    } finally { payload?.fill(0); }
  }
  #finishResume(facts: ExecutionRecordFacts, request: Uint8Array, target: ResumeTargetFacts, policy: CheckpointSessionPolicy,
    executionCap: bigint, guard: () => void): Readonly<{ facts: ExecutionRecordFacts; payload: Uint8Array; outcome: ResumeOutcome }> {
    const s = this.#s, c = s.checkpoint, codec = this.#recoveryCodec;
    if (c === undefined || codec === undefined || !/^[0-9a-f]{64}$/u.test(target.transportContextDigest) || /^0+$/u.test(target.transportContextDigest) ||
        target.streamID < 1n || target.streamID >= 1n << 63n) throw new RPCProtocolError("service_unavailable");
    let payload: Uint8Array | undefined, decoded: ResumeRequestFacts | undefined, outcome: ResumeOutcome | undefined;
    try {
      const result = this.#transaction(() => {
        decoded = codec.request(request, c.verificationKeys, Math.min(c.maxTokenBytes, policy.maxTokenBytes));
        const claims = decoded.claims, [authority, subject] = facts.key.split("\0"), sourceKey = `${authority}\0${subject}\0${claims.operation}`;
        const now = s.backing.environment.clock.sample().requireInterval();
        if (claims.tenant !== s.service.tenant || claims.audience !== s.service.audience || claims.namespace !== s.service.namespace || claims.subject !== subject ||
            sourceKey === facts.key || decoded.transportContextDigest !== target.transportContextDigest || decoded.streamID !== target.streamID) throw new RPCProtocolError("permission_denied");
        // A new Session's issuance duration never rewrites an existing token.
        if (claims.issuedAtMS > now.lowerMS || now.upperMS >= claims.expiresAtMS || now.upperMS >= executionCap) throw new RPCProtocolError("deadline_exceeded");
        const current = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", facts.key), s.service);
        if (!current.active || !current.dispatched || current.notification || current.streaming || current.state !== "executing" || current.resultUntil !== undefined ||
            current.error !== undefined || current.request !== facts.request || current.contract !== facts.contract) throw new RPCProtocolError("operation_conflict");
        if (this.#scalar("SELECT count(*) FROM executions WHERE key=?", sourceKey) === 0) outcome = { status: "unknown" };
        else {
          const original = decodeFacts(this.#scalar("SELECT facts FROM executions WHERE key=?", sourceKey), s.service);
          const head = s.database!.prepare("SELECT format,generation FROM checkpoints WHERE key=?").get(sourceKey);
          const digest = hex(sha256(decoded.token));
          const token = s.database!.prepare("SELECT generation,expires,token FROM checkpoint_tokens WHERE original=? AND digest=?").get(sourceKey, digest);
          const matches = original.request === claims.requestDigest && head?.format === claims.checkpoint.format && readU64(head.generation) === claims.generation &&
            claims.generation !== maximum && token?.token instanceof Uint8Array && readU64(token.generation) === claims.generation &&
            readU64(token.expires) === claims.expiresAtMS && equalCredential(token.token, decoded.token);
          if (token?.token instanceof Uint8Array) token.token.fill(0);
          outcome = matches ? { status: "accepted", checkpoint: { format: claims.checkpoint.format, position: new Uint8Array(claims.checkpoint.position) }, generation: claims.generation + 1n } : { status: "rejected" };
        }
        payload = codec.encodeResult(outcome);
        if (payload.length > Math.min(current.limit, s.backing.limits.maxRecordBytes) ||
            Number(this.#scalar("SELECT coalesce(sum(length(payload)),0) FROM executions")) + payload.length > Number(s.service.resultBytes)) throw new RPCProtocolError("resource_exhausted");
        const completed: ExecutionRecordFacts = { ...current, state: "completed", resultBytes: payload.length, resultCode: undefined,
          resultDigest: hex(sha256(payload)), resultUntil: timeAdd(now.upperMS, current.retention) };
        this.#exec("UPDATE executions SET facts=?,payload=? WHERE key=?", encodeFacts(completed), payload, facts.key);
        if (outcome.status === "accepted") {
          this.#exec("UPDATE checkpoints SET generation=?,target=?,stream=? WHERE key=? AND generation=?", u64(outcome.generation!), Uint8Array.from(target.transportContextDigest.match(/../gu)!, b => Number.parseInt(b, 16)), u64(target.streamID), sourceKey, u64(claims.generation));
          if (this.#scalar("SELECT changes()") !== 1) throw new V4ExecutionStoreError("operation_conflict");
          // The original generation is authoritative; all its tokens lose
          // eligibility atomically. Retained execution results remain readable.
          this.#exec("DELETE FROM checkpoint_tokens WHERE original=?", sourceKey);
        }
        return { facts: completed, payload, outcome };
      }, true, () => {
        guard(); const now = s.backing.environment.clock.sample().requireInterval();
        if (now.upperMS >= executionCap || decoded !== undefined && now.upperMS >= decoded.claims.expiresAtMS) throw new RPCProtocolError("deadline_exceeded");
      });
      payload = undefined; outcome = undefined; return result;
    } finally { decoded?.token.fill(0); decoded?.claims.checkpoint.position.fill(0); payload?.fill(0); outcome?.checkpoint?.position.fill(0); }
  }
  register(token: symbol): void { if (token !== capability) throw new V4ExecutionStoreError("configuration_capacity"); registerExecutionStorage(this.service, this.#adapter()); }
  close(): void { this.#s.closed = true; this.#cleanup(); }
  #cleanup(): void {
    const s = this.#s; if (!s.closed || s.active || s.bound) return;
    try { s.database?.close(); } catch { return; }
    s.database = undefined; this.#content?.close(); this.#content = undefined; this.#recoveryCodec?.close(); this.#recoveryCodec = undefined; clearCheckpoint(s.checkpoint); s.disk.release(); s.backing.active = false; s.dependency.release();
  }
  cleanupComplete(): boolean { return this.#s.closed && this.#s.database === undefined; }
  toJSON(): object { return {}; }
}

export function openV4SQLiteExecutionStore(backing: V4SQLitePoolBacking, options: V4SQLiteExecutionOptions): V4SQLiteExecutionStore {
  const owner = sqliteBackingState(backing);
  if (owner.reference === undefined || owner.closed || owner.active) throw new V4ExecutionStoreError("closed");
  const base = captureVolatileExecution(options.service), service = Object.freeze({ ...base, durability: "durable" as const });
  const identity = Object.freeze({ authority: identityText(options.identity.authority), storeID: fixed(options.identity.storeID, 32), generation: quantity(options.identity.generation) });
  const maxContracts = count(options.maxContracts, 1, 1024), c = owner.limits;
  if (typeof options.create !== "boolean" || typeof options.continuity?.check !== "function" || base.maxRecords > c.maxRecords ||
      c.maxPages < 32 + maxContracts * 4 + (base.maxRecords + 1) * (16 + Math.ceil(c.maxRecordBytes / 4096))) throw new V4ExecutionStoreError("configuration_capacity");
  const content = captureContent(options.content);
  const checkpointInput = options.checkpoint;
  const checkpoint = checkpointInput === undefined ? undefined : captureCheckpointConfig(checkpointInput);
  let disk: ResourceReference | undefined, dependency: EnvironmentDependency | undefined, store: V4SQLiteExecutionStore | undefined;
  try {
    const basePages = 32 + maxContracts * 4 + (base.maxRecords + 1) * (16 + Math.ceil(c.maxRecordBytes / 4096));
    const contentPages = content === undefined ? 0 : 4 + (base.maxRecords + 1) * (4 + 4 * content.maxItemsPerOperation + Math.ceil(content.maxBytesPerOperation / 4096));
    const checkpointPages = checkpoint === undefined ? 0 : 8 + (base.maxRecords + 1) * 2 + checkpoint.maxTokens * (4 + Math.ceil(checkpoint.maxTokenBytes / 4096));
    if (c.maxPages < basePages + contentPages + checkpointPages || checkpoint !== undefined &&
        (checkpoint.maxTokensPerOperation > checkpoint.maxTokens || checkpoint.windowMS === 0n)) throw new V4ExecutionStoreError("configuration_capacity");
    const configuration = stringify({ service: base, maxContracts, limits: c, ...(content === undefined ? {} : { content: contentConfiguration(content) }), ...(checkpoint === undefined ? {} : {
      // Persist quotas and history identity, never a fingerprint of mutable
      // independently trusted recovery key configuration. Reopen cannot reset
      // issuance counters, generations, retained tokens or execution facts.
      checkpoint: { maxTokens: checkpoint.maxTokens, maxTokensPerOperation: checkpoint.maxTokensPerOperation,
        maxTokenBytes: checkpoint.maxTokenBytes, maxIssuesPerWindow: checkpoint.maxIssuesPerWindow, windowMS: checkpoint.windowMS } }) });
    if (configuration.length > 4096) { clearCheckpoint(checkpoint); throw new V4ExecutionStoreError("configuration_capacity"); }
    owner.reference.check(); disk = owner.reference.borrow();
    dependency = owner.environment.admitDependency("execution_store", storeCharge(c).add(new ResourceVector([checkpoint === undefined ? 65536n : 135168n, 0n, 0n, 4n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]))); owner.active = true;
    store = new V4SQLiteExecutionStore(capability, { backing: owner, dependency, disk, identity, continuity: options.continuity.check.bind(options.continuity),
      service, maxContracts, checkpoint, content, configuration, database: undefined, inode: undefined, epoch: 0n, active: false, bound: false, used: false, closed: false, poisoned: false });
    dependency.onClose(() => store!.close()); store.initialize(capability, options.create); store.register(capability); return store;
  } catch (error) {
    clearCheckpoint(checkpoint); store?.close(); if (store === undefined) { disk?.release(); dependency?.release(); owner.active = false; }
    if (error instanceof V4ExecutionStoreError) throw error;
    if (error instanceof V4PoolStoreError && ["configuration_capacity", "storage_format", "history_unknown", "fenced", "capacity", "closed"].includes(error.code)) throw new V4ExecutionStoreError(error.code as V4ExecutionStoreError["code"]);
    throw new V4ExecutionStoreError("storage_unavailable");
  }
}
for (const constructor of [V4SQLiteExecutionStore, V4ExecutionStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

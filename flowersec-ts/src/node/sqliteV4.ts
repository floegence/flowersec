import type { DatabaseSync} from "node:sqlite";
import { type SQLInputValue, type SQLOutputValue } from "node:sqlite";
import { closeSync, constants, fsyncSync, lstatSync, openSync, realpathSync, type Stats } from "node:fs";
import { dirname, isAbsolute, normalize } from "node:path";
import type { V4TransportEnvironment } from "../v4/public.js";
import { originalEnvironment, type V4EnvironmentRuntime } from "../v4/runtime/environment.js";
import { ResourceVector, type ResourceReference } from "../v4/runtime/resources.js";
import { credentialOwner } from "../v4/runtime/credentialSupport.js";

export type V4PoolStoreFailure = "configuration_capacity" | "storage_unavailable" | "storage_format" | "history_unknown" | "fenced" | "spend_conflict" | "spent_unknown" | "capacity" | "owner_unavailable" | "closed";
export class V4PoolStoreError extends Error {
  constructor(readonly code: V4PoolStoreFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted") { super(code); this.name = "V4PoolStoreError"; }
}
export function fail(code: V4PoolStoreFailure): never { throw new V4PoolStoreError(code); }
const token = Symbol("node SQLite backing");
export const pageBytes = 4096n, maximum = 0xffffffffffffffffn;
export interface V4SQLitePoolLimits {
  readonly maxPages: number;
  readonly maxRecords: number;
  readonly maxRecordBytes: number;
  readonly runtimeBytes: bigint;
  readonly providerRuntimeBytes: bigint;
  readonly diskOverheadBytes: bigint;
}
export interface V4SQLitePoolIdentity {
  readonly authority: string;
  readonly storeID: Uint8Array;
  readonly generation: bigint;
}
/** Independent trusted host boundary. This bounded synchronous check must prove
 * complete, non-rolled-back history for this stable identity/fence. SQLite
 * cannot establish that fact about its own file. There is no permissive default.
 * This does not perform or report a spend; only the actual SQLite COMMIT does. */
export interface V4SQLitePoolContinuity {
  check(identity: V4SQLitePoolIdentity, epoch: bigint, provisioning: boolean): void;
}
export interface V4SQLitePoolBinding { readonly tenant: string; readonly issuer: Uint8Array }
export interface V4SQLitePoolOpenOptions {
  readonly identity: V4SQLitePoolIdentity;
  readonly continuity: V4SQLitePoolContinuity;
  readonly bindings: readonly V4SQLitePoolBinding[];
  readonly create: boolean;
}
export function count(value: number, min: number, max: number): number { if (!Number.isSafeInteger(value) || value < min || value > max) fail("configuration_capacity"); return value; }
export function quantity(value: bigint): bigint { if (typeof value !== "bigint" || value <= 0n || value > maximum) fail("configuration_capacity"); return value; }
export function identityText(value: string): string { if (typeof value !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,127}$/u.test(value)) fail("configuration_capacity"); return value; }
export function fixed(value: Uint8Array, length: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== length || !value.some(byte => byte !== 0)) fail("configuration_capacity"); return new Uint8Array(value);
}
function limits(c: V4SQLitePoolLimits): V4SQLitePoolLimits {
  return Object.freeze({ maxPages: count(c.maxPages, 16, 1 << 20), maxRecords: count(c.maxRecords, 1, 1 << 20), maxRecordBytes: count(c.maxRecordBytes, 8192, 1 << 20),
    runtimeBytes: quantity(c.runtimeBytes), providerRuntimeBytes: quantity(c.providerRuntimeBytes), diskOverheadBytes: quantity(c.diskOverheadBytes) });
}
function backingCharge(c: V4SQLitePoolLimits): ResourceVector {
  const pages = BigInt(c.maxPages), disk = pages * pageBytes + 32n + pages * (pageBytes + 24n) + (1n + pages / 4096n) * 32768n + c.diskOverheadBytes;
  return new ResourceVector([4096n + c.runtimeBytes, 0n, disk, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function storeCharge(c: V4SQLitePoolLimits): ResourceVector {
  return new ResourceVector([8192n + 64n * 144n + 65n * c.runtimeBytes, BigInt(c.maxPages) * pageBytes * 2n + BigInt(c.maxRecordBytes) * 2n + c.providerRuntimeBytes,
    0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 4n]);
}
export function u64(value: bigint): Uint8Array { if (value < 0n || value > maximum) fail("storage_format"); const result = new Uint8Array(8); new DataView(result.buffer).setBigUint64(0, value); return result; }
export function readU64(value: unknown): bigint {
  if (!(value instanceof Uint8Array) || value.length !== 8) fail("storage_format"); return new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0);
}
export function missing(path: string): boolean { try { lstatSync(path); return false; } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return true; throw error; } }
export function syncDirectory(path: string): void { const fd = openSync(dirname(path), constants.O_RDONLY); try { fsyncSync(fd); } finally { closeSync(fd); } }
export interface BackingState { environment: V4EnvironmentRuntime; path: string; limits: V4SQLitePoolLimits; reference: ResourceReference | undefined; active: boolean; closed: boolean }
const backings = new WeakMap<V4SQLitePoolBacking, BackingState>();
/** Owns the persistent file allocation independently of a live connection.
 * Close never deletes history or refunds its disk. The trusted host may call
 * releaseRemoved only after discharging history obligations and removing files. */
export class V4SQLitePoolBacking {
  constructor(capability: symbol, state: BackingState) { if (capability !== token) fail("owner_unavailable"); backings.set(this, state); Object.freeze(this); }
  close(): void { const state = backings.get(this)!; state.closed = true; state.reference?.seal(); }
  releaseRemoved(): void {
    const state = backings.get(this)!; if (state.reference === undefined) return;
    if (state.active || ["", "-wal", "-shm", "-journal"].some(suffix => !missing(state.path + suffix))) fail("history_unknown");
    state.closed = true; state.reference.release(); state.reference = undefined;
  }
  retainedDiskBytes(): bigint { const state = backings.get(this)!; return state.reference === undefined ? 0n : backingCharge(state.limits).values()[2]!; }
  toJSON(): object { return {}; }
}
export function createV4SQLitePoolBacking(environment: V4TransportEnvironment, path: string, input: V4SQLitePoolLimits): V4SQLitePoolBacking {
  return createSQLitePoolBacking(originalEnvironment(environment), path, input);
}
/** Internal entry used by the original Environment assembler and its tests. */
export function createSQLitePoolBacking(environment: V4EnvironmentRuntime, path: string, input: V4SQLitePoolLimits): V4SQLitePoolBacking {
  const captured = limits(input);
  if (!isAbsolute(path) || normalize(path) !== path || path.length > 4096 || path.includes("\0")) fail("configuration_capacity");
  const parent = dirname(path), stat = lstatSync(parent);
  if (!stat.isDirectory() || realpathSync(parent) !== parent || (stat.mode & 0o022) !== 0) fail("storage_unavailable");
  environment.clock.sample().requireInterval();
  const resources = environment.resources, reference = resources.root.reserve({ owner: credentialOwner(resources, "pool_disk"), accounts: resources.accounts, charge: backingCharge(captured) });
  return new V4SQLitePoolBacking(token, { environment, path, limits: captured, reference, active: false, closed: false });
}

export function sqliteBackingState(backing: V4SQLitePoolBacking): BackingState {
  const state = backings.get(backing); if (state === undefined) fail("owner_unavailable"); return state;
}
export function sqliteScalar(database: DatabaseSync, sql: string, ...args: SQLInputValue[]): SQLOutputValue {
  const row = database.prepare(sql).get(...args);
  if (row === undefined || Object.keys(row).length !== 1) fail("storage_format"); return Object.values(row)[0]!;
}
export function sqliteExec(database: DatabaseSync, sql: string, ...args: SQLInputValue[]): void {
  if (args.length === 0) database.exec(sql); else database.prepare(sql).run(...args);
}
export function sqliteFiles(backing: BackingState, inode?: Stats): Stats {
  const pages = BigInt(backing.limits.maxPages);
  let main: Stats | undefined;
  for (const [suffix, limit] of [["", pages * pageBytes], ["-wal", 32n + pages * (pageBytes + 24n)], ["-shm", (1n + pages / 4096n) * 32768n], ["-journal", 0n]] as const) {
    if (suffix !== "" && missing(backing.path + suffix)) continue;
    const stat = lstatSync(backing.path + suffix);
    if (!stat.isFile() || stat.nlink !== 1 || BigInt(stat.size) > limit || suffix === "-journal") fail("storage_unavailable");
    if (suffix === "") {
      if (inode !== undefined && (inode.dev !== stat.dev || inode.ino !== stat.ino)) fail("history_unknown"); main = stat;
    }
  }
  return main!;
}
export function sqliteConfigure(database: DatabaseSync, c: V4SQLitePoolLimits, create: boolean): void {
  const scalar = (sql: string): SQLOutputValue => sqliteScalar(database, sql);
  database.enableDefensive(true);
  if (create) { database.exec("PRAGMA page_size=4096"); if (scalar("PRAGMA journal_mode=WAL") !== "wal") fail("storage_unavailable"); }
  if (scalar("PRAGMA page_size") !== 4096 || scalar("PRAGMA journal_mode") !== "wal") fail("storage_format");
  for (const [name, value, expected] of [["synchronous", "FULL", 2], ["fullfsync", "ON", 1], ["checkpoint_fullfsync", "ON", 1], ["foreign_keys", "ON", 1],
    ["trusted_schema", "OFF", 0], ["busy_timeout", "0", 0], ["temp_store", "MEMORY", 2], ["cache_spill", "OFF", 0], ["wal_autocheckpoint", "0", 0],
    ["locking_mode", "EXCLUSIVE", "exclusive"], ["cache_size", String(c.maxPages), c.maxPages]] as const) {
    database.exec(`PRAGMA ${name}=${value}`); if (scalar(`PRAGMA ${name}`) !== expected) fail("storage_unavailable");
  }
  if (scalar(`PRAGMA max_page_count=${c.maxPages}`) !== c.maxPages || scalar(`PRAGMA journal_size_limit=${32n + BigInt(c.maxPages) * (pageBytes + 24n)}`) !== Number(32n + BigInt(c.maxPages) * (pageBytes + 24n))) fail("capacity");
}
export function sqliteCheckpoint(database: DatabaseSync): void {
  const row = database.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
  if (row?.busy !== 0 || row.log !== 0 || row.checkpointed !== 0) fail("storage_unavailable");
}
for (const constructor of [V4SQLitePoolBacking, V4PoolStoreError]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

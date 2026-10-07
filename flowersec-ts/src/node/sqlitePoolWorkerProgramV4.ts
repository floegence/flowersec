// Fixed SDK worker entry; imports are bundled into the generated program.
import { parentPort, workerData } from "node:worker_threads";
import type { DatabaseSync } from "node:sqlite";
import { openSQLiteInspection, admitSQLiteWrites } from "./sqliteInspectionV4.js";
import type * as SQLite from "node:sqlite";
import { closeSync, constants, fsyncSync, lstatSync, openSync } from "node:fs";
import { dirname } from "node:path";
import { createHash } from "node:crypto";
import { readPoolStorageValue as readValue, validatePersistedPoolProjection as validateProjection } from "../v4/runtime/poolRecordStorage.js";
import { validatePersistedPoolJournal as validateJournal } from "../v4/runtime/poolJournalStorage.js";
import { topUpErrorProjection as topUpError, type V4TopUpErrorCode } from "../generated/transportV4APIResults.js";
import { inspectSQLiteStorageHeader as inspectHeader, type StorageFormatProjection, type StorageRevision } from "./sqliteFormat.js";
import type { V4PoolStoreFailure } from "./sqliteV4.js";
import type { PoolWorkerConfiguration, PoolWorkerCommand, PoolWorkerGate } from "./sqlitePoolWorkerV4.js";

function poolStorageProgram(): void {
  const port = parentPort!;
  const configuration = workerData as PoolWorkerConfiguration & { activationLabel: string; certificateLabel: string; extension: string };
  const { limits: c, identity, activationLabel, certificateLabel } = configuration;
  const maximum = 0xffffffffffffffffn;
  // This purpose-limited local format is distinct from the Go store format.
  const manifestSQL = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-node-pool'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, spend_rows INTEGER NOT NULL CHECK(spend_rows>=0)) STRICT, WITHOUT ROWID";
  const spendSQL = "CREATE TABLE spend (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source=1), state INTEGER NOT NULL CHECK(state=1), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
  const materialSQL = "CREATE TABLE material_pool (source BLOB PRIMARY KEY CHECK(length(source)=16), snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
  class Failure extends Error { constructor(readonly code: V4PoolStoreFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted", readonly format?: StorageFormatProjection) { super(code); } }
  const fail: (code: V4PoolStoreFailure) => never = (code) => { throw new Failure(code); };
  const digestMap = (label: string): ((bytes: Uint8Array) => Uint8Array) => {
    const digestLabel = Uint8Array.from(label.match(/../gu)!.map(byte => Number.parseInt(byte, 16)));
    return bytes => {
      const size = new Uint8Array(4); new DataView(size.buffer).setUint32(0, bytes.length);
      return createHash("sha256").update(digestLabel).update(size).update(bytes).digest();
    };
  };
  const digestActivation = digestMap(activationLabel), digestCertificate = digestMap(certificateLabel);
  const hash = (bytes: Uint8Array): Uint8Array => createHash("sha256").update(bytes).digest();
  const terminalCode = (value: string): boolean => topUpError(value as V4TopUpErrorCode, "terminal") !== undefined;
  let database: InstanceType<typeof DatabaseSync> | undefined, inode: { dev: number; ino: number } | undefined, epoch = 0n;
  let active = false, closing = false, committed = false;
  let observedRevision: StorageRevision = { known: false, value: 0 }, formatPhase: StorageFormatProjection["reason"] = "backend_configuration";
  let authorization: { id: number; phase: PoolWorkerGate["phase"]; resolve: (allowed: boolean) => void } | undefined;
  const u64 = (value: bigint): Uint8Array => { const result = new Uint8Array(8); new DataView(result.buffer).setBigUint64(0, value); return result; };
  const readU64 = (value: unknown): bigint => { if (!(value instanceof Uint8Array) || value.length !== 8) fail("storage_format"); return new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0); };
  const exec = (sql: string, ...args: SQLite.SQLInputValue[]): void => { if (args.length === 0) database!.exec(sql); else database!.prepare(sql).run(...args); };
  const scalar = (sql: string, ...args: SQLite.SQLInputValue[]): SQLite.SQLOutputValue => {
    const row = database!.prepare(sql).get(...args); if (row === undefined || Object.keys(row).length !== 1) fail("storage_format"); return Object.values(row)[0]!;
  };
  const missing = (path: string): boolean => { try { lstatSync(path); return false; } catch (error) { if ((error as { code?: string }).code === "ENOENT") return true; throw error; } };
  const files = (): void => {
    const pages = BigInt(c.maxPages);
    for (const [suffix, limit] of [["", pages * 4096n], ["-wal", 32n + pages * 4120n], ["-shm", (1n + pages / 4096n) * 32768n], ["-journal", 0n]] as const) {
      if (suffix !== "" && missing(configuration.path + suffix)) continue;
      const stat = lstatSync(configuration.path + suffix);
      if (!stat.isFile() || stat.nlink !== 1 || BigInt(stat.size) > limit || suffix === "-journal") fail("storage_unavailable");
      if (suffix === "") { if (inode !== undefined && (inode.dev !== stat.dev || inode.ino !== stat.ino)) fail("history_unknown"); inode = { dev: stat.dev, ino: stat.ino }; }
    }
  };
  const gate = async (id: number, phase: PoolWorkerGate["phase"], provisioning = false): Promise<void> => {
    if (closing) fail("closed");
    const allowed = await new Promise<boolean>(resolve => { authorization = { id, phase, resolve }; port.postMessage({ type: "gate", id, phase, epoch, provisioning }); });
    if (!allowed || closing) fail("closed");
    files();
  };
  const rollback = (): void => { try { exec("ROLLBACK"); } catch { closing = true; } };
  const commit = (): void => { try { exec("COMMIT"); committed = true; } catch { closing = true; throw new Failure("spent_unknown", "unknown"); } };
  const configure = (create: boolean): void => {
    database!.enableDefensive(true);
    if (create) { exec("PRAGMA page_size=4096"); if (scalar("PRAGMA journal_mode=WAL") !== "wal") fail("storage_unavailable"); }
    if (scalar("PRAGMA page_size") !== 4096 || scalar("PRAGMA journal_mode") !== "wal") fail("storage_format");
    for (const [name, value, expected] of [["synchronous", "FULL", 2], ["fullfsync", "ON", 1], ["checkpoint_fullfsync", "ON", 1], ["foreign_keys", "ON", 1],
      ["trusted_schema", "OFF", 0], ["busy_timeout", "0", 0], ["temp_store", "MEMORY", 2], ["cache_spill", "OFF", 0], ["wal_autocheckpoint", "0", 0],
      ["locking_mode", "EXCLUSIVE", "exclusive"], ["cache_size", String(c.maxPages), c.maxPages]] as const) { exec(`PRAGMA ${name}=${value}`); if (scalar(`PRAGMA ${name}`) !== expected) fail("storage_unavailable"); }
    const walLimit = 32n + BigInt(c.maxPages) * 4120n;
    if (scalar(`PRAGMA max_page_count=${c.maxPages}`) !== c.maxPages || scalar(`PRAGMA journal_size_limit=${walLimit}`) !== Number(walLimit)) fail("capacity");
  };
  const validate = (): void => {
    if (scalar("PRAGMA user_version") !== 1 || scalar("SELECT count(*) FROM sqlite_schema") !== 3) fail("storage_format");
    for (const [name, sql] of [["manifest", manifestSQL], ["spend", spendSQL], ["material_pool", materialSQL]] as const) {
      if (scalar("SELECT length(sql) FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql.length || scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", name) !== sql) fail("storage_format");
    }
    if (scalar("SELECT count(*) FROM manifest") !== 1 || scalar("SELECT length(authority) FROM manifest WHERE id=1") !== identity.authority.length) fail("storage_format");
    const row = database!.prepare("SELECT * FROM manifest WHERE id=1").get();
    if (row === undefined || row.format !== "flowersec-v4-node-pool" || row.revision !== 1 || row.authority !== identity.authority || !(row.instance instanceof Uint8Array) ||
        row.instance.length !== identity.storeID.length || !row.instance.every((byte, index) => byte === identity.storeID[index]) || readU64(row.generation) !== identity.generation ||
        row.max_pages !== c.maxPages || row.max_records !== c.maxRecords || row.max_record_bytes !== c.maxRecordBytes || typeof row.spend_rows !== "number" || row.spend_rows < 0 || row.spend_rows > c.maxRecords || scalar("SELECT count(*) FROM spend") !== row.spend_rows) fail("storage_format");
    if (Number(scalar("SELECT count(*) FROM material_pool")) + row.spend_rows > c.maxRecords ||
        scalar("SELECT count(*) FROM material_pool WHERE length(source)<>16 OR length(snapshot)<1 OR length(snapshot)>?", Math.min(c.maxRecordBytes, 1048576)) !== 0) fail("storage_format");
    epoch = readU64(row.epoch); if (epoch === 0n) fail("storage_format");
    if (scalar("SELECT count(*) FROM spend WHERE length(projection)>? OR length(projection)<1 OR fence>? OR version<>? OR source<>1 OR state<>1", c.maxRecordBytes, u64(epoch), u64(1n)) !== 0) fail("storage_format");
    for (const record of database!.prepare("SELECT lease,fence,retained_until,projection FROM spend ORDER BY lease").iterate()) {
      if (!(record.lease instanceof Uint8Array) || !(record.projection instanceof Uint8Array)) fail("storage_format");
      try { validateProjection(record.lease, record.projection, identity, readU64(record.fence), epoch, readU64(record.retained_until), digestActivation, readValue); }
      catch { fail("storage_format"); }
      finally { record.lease.fill(0); record.projection.fill(0); }
    }
    for (const record of database!.prepare("SELECT source,snapshot FROM material_pool ORDER BY source").iterate()) {
      if (!(record.source instanceof Uint8Array) || !(record.snapshot instanceof Uint8Array)) fail("storage_format");
      try { validateJournal(record.source, record.snapshot, epoch, hash, digestCertificate, terminalCode, readValue); }
      catch { fail("storage_format"); }
      finally { record.source.fill(0); record.snapshot.fill(0); }
    }
  };
  const open = async (id: number, create: boolean): Promise<void> => {
    if (database !== undefined) fail("owner_unavailable");
    if (create) {
      if (["", "-wal", "-shm", "-journal"].some(suffix => !missing(configuration.path + suffix))) fail("history_unknown");
      const fd = openSync(configuration.path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); closeSync(fd);
    } else if (missing(configuration.path)) fail("history_unknown");
    files(); database = openSQLiteInspection(configuration.path, configuration.extension, c.maxPages, c.maxRecordBytes); files();
    if (!create) {
      const inspectCurrent = async (): Promise<void> => {
        exec("BEGIN");
        try {
          formatPhase = "manifest_unknown_or_invalid";
          const header = await inspectHeader((sql, ...args) => database!.prepare(sql).get(...args), manifestSQL, "flowersec-v4-node-pool", 1, identity);
          observedRevision = header.observedRevision;
          if (header.refusal !== undefined) throw new Failure("storage_format", "not_submitted", header.refusal);
          formatPhase = "schema_or_state_invalid";
          validate();
          if (scalar("PRAGMA quick_check") !== "ok") fail("storage_format");
          formatPhase = "backend_configuration";
          if (scalar("PRAGMA page_size") !== 4096 || scalar("PRAGMA journal_mode") !== "wal") fail("storage_format");
          files();
        } finally { exec("ROLLBACK"); }
      };
      await inspectCurrent();
      formatPhase = "backend_configuration";
    }
    admitSQLiteWrites(database, configuration.extension); configure(create); exec("BEGIN IMMEDIATE");
    try {
      if (create) {
        exec(manifestSQL); exec(spendSQL); exec(materialSQL); exec("PRAGMA user_version=1"); epoch = 1n;
        exec("INSERT INTO manifest VALUES(1,'flowersec-v4-node-pool',1,?,?,?,?,?,?,?,0)", identity.authority, identity.storeID, u64(identity.generation), u64(epoch), c.maxPages, c.maxRecords, c.maxRecordBytes);
      } else {
        formatPhase = "manifest_unknown_or_invalid";
        const header = await inspectHeader((sql, ...args) => database!.prepare(sql).get(...args), manifestSQL, "flowersec-v4-node-pool", 1, identity);
        observedRevision = header.observedRevision;
        if (header.refusal !== undefined) throw new Failure("storage_format", "not_submitted", header.refusal);
        formatPhase = "schema_or_state_invalid";
        validate(); if (epoch === maximum) fail("fenced"); await gate(id, "begin"); const old = epoch++;
        exec("UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?", u64(epoch), u64(old)); if (scalar("SELECT changes()") !== 1) fail("fenced");
      }
      await gate(id, "commit", create); commit();
    } catch (error) { rollback(); throw error; }
    if (create) { const fd = openSync(dirname(configuration.path), constants.O_RDONLY); try { fsyncSync(fd); } catch { closing = true; throw new Failure("spent_unknown", "unknown"); } finally { closeSync(fd); } }
    files();
  };
  const journal = async (id: number, command: Extract<PoolWorkerCommand, { kind: "journal" }>): Promise<Uint8Array | undefined> => {
    if (database === undefined || epoch !== command.epoch || command.key.length !== 16 ||
        (command.replacement?.length ?? 0) > c.maxRecordBytes || command.replacement !== undefined && command.replacement.length === 0 ||
        (command.expected?.length ?? 0) > c.maxRecordBytes) fail("owner_unavailable");
    await gate(id, "begin"); exec("BEGIN IMMEDIATE");
    try {
      if (readU64(scalar("SELECT epoch FROM manifest WHERE id=1")) !== epoch) fail("fenced"); await gate(id, "write");
      const row = database!.prepare("SELECT snapshot FROM material_pool WHERE source=?").get(command.key);
      const old = row?.snapshot;
      if (old !== undefined && (!(old instanceof Uint8Array) || old.length < 1 || old.length > c.maxRecordBytes)) fail("storage_format");
      if (command.replacement === undefined) { await gate(id, "commit"); commit(); return old as Uint8Array | undefined; }
      if (command.expected === undefined ? old !== undefined : !(old instanceof Uint8Array) || old.length !== command.expected.length || !old.every((value, index) => value === command.expected![index])) fail("spend_conflict");
      if (old === undefined && Number(scalar("SELECT count(*) FROM material_pool")) + Number(scalar("SELECT count(*) FROM spend")) >= c.maxRecords) fail("capacity");
      exec("INSERT INTO material_pool VALUES(?,?) ON CONFLICT(source) DO UPDATE SET snapshot=excluded.snapshot", command.key, command.replacement);
      await gate(id, "commit"); commit(); return undefined;
    } catch (error) { rollback(); throw error; }
  };
  const consume = async (id: number, command: Extract<PoolWorkerCommand, { kind: "consume" }>): Promise<void> => {
    if (database === undefined || epoch !== command.epoch || command.key.length < 34 || command.key.length > 161 || command.projection.length < 1 || command.projection.length > c.maxRecordBytes || command.retainedUntil < 1n || command.retainedUntil > maximum) fail("owner_unavailable");
    files(); const checkpoint = database.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
    if (checkpoint?.busy !== 0 || checkpoint.log !== 0 || checkpoint.checkpointed !== 0) fail("storage_unavailable");
    await gate(id, "begin"); exec("BEGIN IMMEDIATE");
    try {
      if (readU64(scalar("SELECT epoch FROM manifest WHERE id=1")) !== epoch) fail("fenced"); await gate(id, "write");
      if (scalar("SELECT count(*) FROM spend WHERE lease=?", command.key) !== 0) fail("spend_conflict");
      const rows = scalar("SELECT spend_rows FROM manifest WHERE id=1"); if (typeof rows !== "number" || rows < 0) fail("storage_format"); if (rows >= c.maxRecords) fail("capacity");
      exec("INSERT INTO spend VALUES(?,1,1,?,?,?,?)", command.key, u64(1n), u64(epoch), u64(command.retainedUntil), command.projection);
      exec("UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1 AND epoch=?", u64(epoch)); if (scalar("SELECT changes()") !== 1) fail("fenced");
      await gate(id, "commit"); commit();
    } catch (error) { rollback(); throw error; }
  };
  const cleanup = (): void => { if (!closing || active) return; try { database?.close(); database = undefined; } finally { port.close(); } };
  port.on("message", (message: { type: string; id: number; phase: PoolWorkerGate["phase"]; allowed: boolean; command: PoolWorkerCommand }) => {
    if (message.type === "authorize") {
      if (authorization?.id !== message.id || authorization.phase !== message.phase) { closing = true; authorization?.resolve(false); }
      else { const original = authorization; authorization = undefined; original.resolve(message.allowed === true); }
      return;
    }
    if (message.type === "close") { closing = true; authorization?.resolve(false); authorization = undefined; cleanup(); return; }
    if (message.type !== "command" || active || closing) { closing = true; cleanup(); return; }
    active = true; committed = false;
    void (async () => {
      let result: { type: "result"; id: number; epoch?: bigint; value?: Uint8Array; code?: V4PoolStoreFailure; writeState?: "not_submitted" | "committed" | "unknown"; format?: StorageFormatProjection };
      try {
        if (message.command.kind === "open") await open(message.id, message.command.create);
        else if (message.command.kind === "consume") await consume(message.id, message.command);
        const value = message.command.kind === "journal" ? await journal(message.id, message.command) : undefined;
        result = { type: "result", id: message.id, epoch, ...(value === undefined ? {} : { value }) };
      } catch (error) {
        const damaged = error instanceof Error && "errcode" in error && typeof error.errcode === "number" && [11, 26].includes(error.errcode & 0xff);
        if (damaged) { observedRevision = { known: false, value: 0 }; formatPhase = "manifest_unknown_or_invalid"; }
        const failure = committed && !(error instanceof Failure && error.writeState === "unknown") ? new Failure(error instanceof Failure ? error.code : "storage_unavailable", "committed", error instanceof Failure ? error.format : undefined) : error instanceof Failure ? error : new Failure(damaged ? "storage_format" : "storage_unavailable");
        const format = failure.format ?? (message.command.kind === "open" && failure.code === "storage_format" ? {
          code: "storage_format_incompatible" as const, transactionGroup: "flowersec-v4-node-pool" as const, wireProfile: "flowersec-v4-transport-security" as const,
          observedRevision, requiredRevision: 1, reason: formatPhase, exactConversionAvailable: false as const,
        } : undefined);
        result = { type: "result", id: message.id, code: failure.code, writeState: failure.writeState, ...(format === undefined ? {} : { format }) };
        if (message.command.kind === "open" || failure.writeState !== "not_submitted") closing = true;
      } finally {
        if (message.command.kind === "consume") { message.command.key.fill(0); message.command.projection.fill(0); }
        if (message.command.kind === "journal") { message.command.key.fill(0); message.command.expected?.fill(0); message.command.replacement?.fill(0); }
        active = false;
        // The receipt also hands back the original request after its cloned
        // buffers have been scrubbed; no request cleanup follows publication.
        port.postMessage(result!); cleanup();
      }
    })();
  });
}

poolStorageProgram();

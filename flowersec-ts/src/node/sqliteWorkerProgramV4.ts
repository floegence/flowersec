// Fixed SDK worker entry; generated as a self-contained program at build time.
import { parentPort, workerData } from "node:worker_threads";
import type { DatabaseSync } from "node:sqlite";
import { openSQLiteInspection, admitSQLiteWrites } from "./sqliteInspectionV4.js";
import type * as SQLite from "node:sqlite";
import { closeSync, constants, fsyncSync, lstatSync, openSync } from "node:fs";
import { dirname } from "node:path";
import type { V4SQLitePoolLimits } from "./sqliteV4.js";
import type { Command, Row, StorageFailure } from "./sqliteWorkerV4.js";

function sqliteProgram(): void {
  const port = parentPort!, { path, limits: c, bytes, extension } = workerData as { path: string; limits: V4SQLitePoolLimits; bytes: number; extension: string };
  class Failure extends Error { constructor(readonly code: StorageFailure) { super(code); } }
  const fail = (code: StorageFailure): never => { throw new Failure(code); };
  let db: InstanceType<typeof DatabaseSync> | undefined, inode: { dev: number; ino: number } | undefined, closing = false, inspecting = false;
  const missing = (file: string): boolean => { try { lstatSync(file); return false; } catch (error) { if ((error as { code?: string }).code === "ENOENT") return true; throw error; } };
  const files = (): void => {
    const pages = BigInt(c.maxPages);
    for (const [suffix, limit] of [["", pages * 4096n], ["-wal", 32n + pages * 4120n], ["-shm", (1n + pages / 4096n) * 32768n], ["-journal", 0n]] as const) {
      if (suffix !== "" && missing(path + suffix)) continue;
      const stat = lstatSync(path + suffix);
      if (!stat.isFile() || stat.nlink !== 1 || BigInt(stat.size) > limit || suffix === "-journal") fail("storage_unavailable");
      if (suffix === "") { if (inode !== undefined && (inode.dev !== stat.dev || inode.ino !== stat.ino)) fail("history_unknown"); inode = { dev: stat.dev, ino: stat.ino }; }
    }
  };
  const scalar = (sql: string): SQLite.SQLOutputValue => Object.values(db!.prepare(sql).get()!)[0]!;
  const configure = (create: boolean): void => {
    db!.enableDefensive(true);
    if (create) { db!.exec("PRAGMA page_size=4096"); if (scalar("PRAGMA journal_mode=WAL") !== "wal") fail("storage_unavailable"); }
    if (scalar("PRAGMA page_size") !== 4096 || scalar("PRAGMA journal_mode") !== "wal") fail("storage_format");
    for (const [name, value, expected] of [["synchronous", "FULL", 2], ["fullfsync", "ON", 1], ["checkpoint_fullfsync", "ON", 1], ["foreign_keys", "ON", 1],
      ["trusted_schema", "OFF", 0], ["busy_timeout", "0", 0], ["temp_store", "MEMORY", 2], ["cache_spill", "OFF", 0], ["wal_autocheckpoint", "0", 0],
      ["locking_mode", "EXCLUSIVE", "exclusive"], ["cache_size", String(c.maxPages), c.maxPages]] as const) { db!.exec(`PRAGMA ${name}=${value}`); if (scalar(`PRAGMA ${name}`) !== expected) fail("storage_unavailable"); }
    const wal = 32n + BigInt(c.maxPages) * 4120n;
    if (scalar(`PRAGMA max_page_count=${c.maxPages}`) !== c.maxPages || scalar(`PRAGMA journal_size_limit=${wal}`) !== Number(wal)) fail("capacity");
  };
  const scrub = (value: unknown): void => { if (value instanceof Uint8Array) value.fill(0); else if (Array.isArray(value)) value.forEach(scrub); else if (value !== null && typeof value === "object") Object.values(value).forEach(scrub); };
  port.on("message", (message: { close?: boolean; id: number; command: Command }) => {
    if (message.close) { closing = true; try { db?.close(); } finally { db = undefined; port.close(); } return; }
    const command = message.command; let result: unknown;
    try {
      if (closing) fail("closed");
      if (command.kind === "open") {
        if (db !== undefined) fail("closed");
        if (command.create) {
          if (["", "-wal", "-shm", "-journal"].some(suffix => !missing(path + suffix))) fail("history_unknown");
          const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW, 0o600); closeSync(fd);
        } else if (missing(path)) fail("history_unknown");
        inspecting = !command.create && command.inspectFirst;
        files(); db = openSQLiteInspection(path, extension, c.maxPages, c.maxRecordBytes); files();
        if (!inspecting) { admitSQLiteWrites(db, extension); configure(command.create); }
      } else {
        if (db === undefined) throw new Failure("closed"); files();
        if (command.kind === "admitWrites") {
          if (!inspecting) fail("closed");
          admitSQLiteWrites(db, extension); inspecting = false; files();
        }
        else if (command.kind === "configure") { if (inspecting) fail("closed"); configure(false); }
        else if (command.kind === "directory") { const fd = openSync(dirname(path), constants.O_RDONLY); try { fsyncSync(fd); } finally { closeSync(fd); } }
        else if (command.kind === "checkpoint") { const row = db!.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get(); if (row?.busy !== 0 || row.log !== 0 || row.checkpointed !== 0) fail("storage_unavailable"); }
        else if ("sql" in command) {
          if (command.sql.length > 8192 || command.args.length > 32) fail("capacity");
          if (command.kind === "exec") db!.exec(command.sql);
          else if (command.kind === "run") db!.prepare(command.sql).run(...command.args);
          else {
            const rows: Row[] = []; let used = 0;
            for (const row of db!.prepare(command.sql).iterate(...command.args)) {
              used += 512;
              for (const value of Object.values(row)) used += typeof value === "string" ? value.length * 2 : value instanceof Uint8Array ? value.length : 16;
              if (used > bytes) { scrub(row); scrub(rows); fail("capacity"); }
              rows.push(row); if (command.kind === "get") break;
            }
            result = command.kind === "get" ? rows[0] : rows;
          }
        }
      }
      port.postMessage({ id: message.id, result });
    } catch (error) {
      const damaged = error instanceof Error && "errcode" in error && typeof error.errcode === "number" && [11, 26].includes(error.errcode & 0xff);
      port.postMessage({ id: message.id, code: error instanceof Failure ? error.code : damaged ? "storage_format" : "storage_unavailable", unknown: command.kind === "exec" && command.sql === "COMMIT" });
    } finally { scrub(result); if ("args" in command) scrub(command.args); }
  });
}

sqliteProgram();

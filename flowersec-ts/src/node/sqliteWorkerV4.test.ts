import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Worker } from "node:worker_threads";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import type { SQLiteWorkerError } from "./sqliteWorkerV4.js";
import { SQLiteWorkerDatabase } from "./sqliteWorkerV4.js";

const limits = Object.freeze({ maxPages: 64, maxRecords: 4, maxRecordBytes: 8192,
  runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });

describe("SQLite worker submission custody", () => {
  it("opens, reopens and joins both fixed workers under the source loader", async () => {
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-worker-loader-"));
    // The source loader introduces helpers that cannot survive serializing a
    // function body. Exercise a separate process with the ordinary loader.
    const program = `
      import assert from "node:assert/strict";
      import { join } from "node:path";
      import { SQLiteWorkerDatabase } from "./src/node/sqliteWorkerV4.ts";
      import { PoolStorageWorker } from "./src/node/sqlitePoolWorkerV4.ts";
      const limits = { maxPages: 64, maxRecords: 4, maxRecordBytes: 8192,
        runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n };
      const path = process.argv[1];
      let exits = 0;
      for (const create of [true, false]) {
        const database = new SQLiteWorkerDatabase(join(path, "data.sqlite"), limits, () => exits++);
        try {
          await database.open(create);
          if (create) {
            await database.exec("CREATE TABLE value_store (value INTEGER NOT NULL) STRICT");
            await database.run("INSERT INTO value_store VALUES(?)", 73);
          }
          assert.equal((await database.get("SELECT value FROM value_store")).value, 73);
        } finally { database.close(); await database.waitCleanup(); }
        const pool = new PoolStorageWorker({ path: join(path, "pool.sqlite"), limits,
          identity: { authority: "source-loader", storeID: new Uint8Array(32).fill(7), generation: 1n } }, () => exits++);
        try { assert.equal(await pool.run({ kind: "open", create }, () => {}), create ? 1n : 2n); }
        finally { pool.close(); await pool.waitCleanup(); }
      }
      assert.equal(exits, 4);
    `;
    try {
      await promisify(execFile)(process.execPath, ["--import", "tsx", "--input-type=module", "-e", program, directory], {
        cwd: new URL("../..", import.meta.url), timeout: 10000, maxBuffer: 65536,
      });
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }, 15000);

  it("keeps initial format inspection query-only until admitting writes on the same connection", async () => {
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-worker-readonly-"));
    const path = join(directory, "store.sqlite");
    let exits = 0;
    const created = new SQLiteWorkerDatabase(path, limits, () => { exits++; });
    let reopened: SQLiteWorkerDatabase | undefined;
    try {
      await created.open(true);
      await created.exec("CREATE TABLE values_store (value INTEGER NOT NULL) STRICT");
      await created.run("INSERT INTO values_store VALUES(?)", 7);
      created.close(); await created.waitCleanup();
      reopened = new SQLiteWorkerDatabase(path, limits, () => { exits++; });
      await reopened.open(false, true);
      await reopened.exec("BEGIN");
      expect(await reopened.get("SELECT value FROM values_store")).toMatchObject({ value: 7 });
      await expect(reopened.run("UPDATE values_store SET value=?", 8)).rejects.toMatchObject({ code: "storage_unavailable", writeState: "not_submitted" });
      await reopened.exec("ROLLBACK");
      await expect(reopened.configureCurrent()).rejects.toMatchObject({ code: "closed" });
      await reopened.admitWrites();
      expect(exits).toBe(1);
      expect(await reopened.get("SELECT value FROM values_store")).toMatchObject({ value: 7 });
      await reopened.configureCurrent();
      await reopened.run("UPDATE values_store SET value=?", 9);
      expect(await reopened.get("SELECT value FROM values_store")).toMatchObject({ value: 9 });
    } finally {
      created.close(); reopened?.close();
      await Promise.all([created.waitCleanup(), reopened?.waitCleanup()]);
      rmSync(directory, { recursive: true, force: true });
    }
    expect(exits).toBe(2);
  });

  it("reports a COMMIT that never crosses postMessage as not submitted and rolls it back on actual exit", async () => {
    const directory = mkdtempSync(join(realpathSync(tmpdir()), "flowersec-ts-worker-submit-"));
    const path = join(directory, "store.sqlite");
    let exits = 0;
    const database = new SQLiteWorkerDatabase(path, limits, () => { exits++; });
    let reopened: SQLiteWorkerDatabase | undefined;
    try {
      await database.open(true);
      await database.exec("CREATE TABLE values_store (value INTEGER NOT NULL) STRICT");
      await database.exec("BEGIN IMMEDIATE");
      await database.run("INSERT INTO values_store VALUES(?)", 7);
      const original = Worker.prototype.postMessage;
      let rejected = false;
      const handoff = vi.spyOn(Worker.prototype, "postMessage").mockImplementation(function (this: Worker, ...args: Parameters<Worker["postMessage"]>) {
        const message = args[0] as { command?: { sql?: string } };
        if (!rejected && message.command?.sql === "COMMIT") {
          rejected = true;
          throw new Error("command did not reach the worker");
        }
        return Reflect.apply(original, this, args);
      });
      try {
        await expect(database.exec("COMMIT")).rejects.toMatchObject({ code: "storage_unavailable", writeState: "not_submitted" } satisfies Pick<SQLiteWorkerError, "code" | "writeState">);
        expect(rejected).toBe(true);
      } finally { handoff.mockRestore(); }
      // Logical failure is not physical release. Reopen follows actual exit,
      // preserving the original transaction's rollback and file ownership.
      database.close();
      await database.waitCleanup();
      expect(database.cleanupComplete()).toBe(true);
      expect(exits).toBe(1);
      reopened = new SQLiteWorkerDatabase(path, limits, () => { exits++; });
      await reopened.open(false);
      expect(await reopened.get("SELECT count(*) AS count FROM values_store")).toMatchObject({ count: 0 });
    } finally {
      database.close(); reopened?.close();
      await Promise.all([database.waitCleanup(), reopened?.waitCleanup()]);
      rmSync(directory, { recursive: true, force: true });
    }
  });
});

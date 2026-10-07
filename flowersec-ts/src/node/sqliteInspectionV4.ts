import { DatabaseSync } from "node:sqlite";
import { sqliteInspectionRowBytes } from "./sqliteFormat.js";

function configureConnection(database: DatabaseSync, extension: string, entry: string): void {
  database.enableLoadExtension(true);
  try { database.loadExtension(extension, entry); }
  finally { database.enableLoadExtension(false); }
}

/** Keep the original READWRITE connection through inspection and admission.
 * Exclusive WAL mode uses a private index; query_only prevents inspection
 * writes and NO_CKPT_ON_CLOSE protects an unaccepted WAL on every refusal. */
export function openSQLiteInspection(path: string, extension: string, maxPages: number, maxRecordBytes: number): DatabaseSync {
  // The original provider charge includes this complete record/metadata cap.
  const profile = sqliteInspectionRowBytes(maxRecordBytes) / 1024;
  const database = new DatabaseSync(path, {
    readOnly: false, allowExtension: true, enableForeignKeyConstraints: true,
    enableDoubleQuotedStringLiterals: false, timeout: 0,
  });
  try {
    // Install protection before any statement can read the database header.
    configureConnection(database, extension, `sqlite3_flowersec_inspect${profile}_init`);
    database.exec("PRAGMA locking_mode=EXCLUSIVE; PRAGMA query_only=ON");
    // Bound the cache before the first header/schema/WAL inspection. All values
    // are from the validated local backing configuration, never stored SQL.
    database.exec(`PRAGMA cache_size=${maxPages}; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF`);
    if (database.prepare("PRAGMA locking_mode").get()?.locking_mode !== "exclusive" ||
        database.prepare("PRAGMA query_only").get()?.query_only !== 1) throw new Error("storage_unavailable");
    database.enableDefensive(true);
    database.exec("PRAGMA trusted_schema=OFF");
    return database;
  } catch (error) { database.close(); throw error; }
}

/** The caller has validated the complete current state under this connection. */
export function admitSQLiteWrites(database: DatabaseSync, extension: string): void {
  database.exec("PRAGMA query_only=OFF");
  if (database.prepare("PRAGMA query_only").get()?.query_only !== 0) throw new Error("storage_unavailable");
  configureConnection(database, extension, "sqlite3_flowersec_admit_init");
}

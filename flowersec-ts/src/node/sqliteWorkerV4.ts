import { Worker } from "node:worker_threads";
import { sqliteExtensionPath } from "./sqliteNativeV4.js";
import { sqliteWorkerSource } from "../generated/sqliteWorkers.js";
import type * as SQLite from "node:sqlite";
import type { V4SQLitePoolLimits } from "./sqliteV4.js";
import { ResourceVector } from "../v4/runtime/resources.js";
import { timerChunk } from "../v4/runtime/deadline.js";

export type StorageFailure = "storage_unavailable" | "storage_format" | "history_unknown" | "capacity" | "closed";
export class SQLiteWorkerError extends Error {
  constructor(readonly code: StorageFailure, readonly writeState: "not_submitted" | "unknown" = "not_submitted") { super(code); }
}
export type Command = Readonly<{ kind: "open"; create: boolean; inspectFirst: boolean }> | Readonly<{ kind: "exec" | "get" | "all" | "run"; sql: string; args: readonly SQLite.SQLInputValue[] }> |
  Readonly<{ kind: "files" | "checkpoint" | "directory" | "configure" | "admitWrites" }>;
export type Row = Record<string, SQLite.SQLOutputValue>;
interface Pending { id: number; readonly command: Command; readonly observation: { signal: AbortSignal | undefined; remainingMS: () => bigint } | undefined; committing: boolean; submitted: boolean; resolve: (result: unknown) => void; reject: (error: SQLiteWorkerError) => void; cleanup: () => void }
const resultBytes = (c: V4SQLitePoolLimits): bigint => BigInt(c.maxPages) * 32768n + BigInt(c.maxRecordBytes) * 4n + 65536n;
/** Bounds the worker heap, SQLite result clones, one control descriptor and
 * actual worker lifetime. Each adapter separately retains its original task. */
export function sqliteWorkerCharge(c: V4SQLitePoolLimits): ResourceVector {
  const bytes = resultBytes(c);
  return new ResourceVector([bytes * 2n + 65536n, bytes * 4n + (32n << 20n), 0n, 1n, 1n, 1n, 0n, 0n, 0n, 0n, 1n]);
}
/** SDK-only SQLite driver. SQL is supplied by maintained adapter code, never
 * by a peer, database row, public callback or executable worker injection.
 * There is exactly one command position. Transactions remain owned by
 * the adapter's original asynchronous call across each worker round trip. */
export class SQLiteWorkerDatabase {
  readonly #worker: Worker;
  readonly #cleanup: Promise<void>;
  #pending: Pending | undefined;
  #sequence = 0;
  #closed = false;
  #exited = false;
  #observation: { signal: AbortSignal | undefined; remainingMS: () => bigint } | undefined;
  constructor(path: string, limits: V4SQLitePoolLimits, exited: () => void) {
    const bytes = Number(resultBytes(limits));
    this.#worker = new Worker(sqliteWorkerSource, { eval: true, execArgv: [], name: "flowersec-sqlite", workerData: { path, limits, bytes, extension: sqliteExtensionPath() },
      resourceLimits: { maxOldGenerationSizeMb: Math.ceil(bytes * 3 / 1048576) + 16, maxYoungGenerationSizeMb: 4, codeRangeSizeMb: 4, stackSizeMb: 2 } });
    this.#worker.on("message", (input: unknown) => {
      const p = this.#pending, m = input as { id?: unknown; code?: unknown; result?: unknown; unknown?: unknown } | null;
      if (p === undefined || m === null || typeof m !== "object" || m.id !== p.id) { this.#fail(); return; }
      this.#pending = undefined; p.cleanup();
      if (m.code === undefined) p.resolve(m.result);
      else {
        const code = ["storage_unavailable", "storage_format", "history_unknown", "capacity", "closed"].includes(String(m.code)) ? m.code as StorageFailure : "storage_unavailable";
        p.reject(new SQLiteWorkerError(code, m.unknown === true ? "unknown" : "not_submitted"));
      }
    });
    this.#worker.on("error", () => this.#fail());
    this.#cleanup = new Promise(resolve => this.#worker.once("exit", () => { this.#exited = true; this.#fail(); resolve(); exited(); }));
  }
  observe(signal: AbortSignal | undefined, remainingMS: () => bigint): () => void {
    if (this.#observation !== undefined) throw new SQLiteWorkerError("capacity");
    const observation = this.#observation = { signal, remainingMS };
    return () => { if (this.#observation === observation) this.#observation = undefined; };
  }
  #submit(p: Pending): void {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cancel = (): void => this.#fail(new SQLiteWorkerError("closed"));
    p.cleanup = (): void => { if (timer !== undefined) clearTimeout(timer); p.observation?.signal?.removeEventListener("abort", cancel); };
    try {
      if (p.observation?.signal?.aborted) { cancel(); return; }
      p.observation?.signal?.addEventListener("abort", cancel, { once: true });
      const wake = (): void => { if (this.#pending !== p) return; try { timer = setTimeout(wake, timerChunk(p.observation!.remainingMS())); } catch { cancel(); } };
      if (p.observation !== undefined) wake();
      if (this.#pending === p) {
        p.committing = p.command.kind === "exec" && p.command.sql === "COMMIT";
        this.#worker.postMessage({ id: p.id, command: p.command });
        p.submitted = true;
      }
    } catch { this.#fail(); }
  }
  #run(command: Command): Promise<unknown> {
    if (this.#closed) return Promise.reject(new SQLiteWorkerError("closed"));
    if (this.#pending !== undefined || this.#sequence === Number.MAX_SAFE_INTEGER) return Promise.reject(new SQLiteWorkerError("capacity"));
    return new Promise((resolve, reject) => {
      const observation = this.#observation;
      const p = { id: ++this.#sequence, command, observation, committing: false, submitted: false, resolve, reject, cleanup: (): void => undefined };
      this.#pending = p; this.#submit(p);
    });
  }
  async open(create: boolean, inspectFirst = false): Promise<void> { await this.#run({ kind: "open", create, inspectFirst }); }
  async admitWrites(): Promise<void> { await this.#run({ kind: "admitWrites" }); }
  async configureCurrent(): Promise<void> { await this.#run({ kind: "configure" }); }
  async exec(sql: string): Promise<void> { await this.#run({ kind: "exec", sql, args: [] }); }
  async run(sql: string, ...args: SQLite.SQLInputValue[]): Promise<void> { await this.#run({ kind: "run", sql, args }); }
  async get(sql: string, ...args: SQLite.SQLInputValue[]): Promise<Row | undefined> { return await this.#run({ kind: "get", sql, args }) as Row | undefined; }
  async all(sql: string, ...args: SQLite.SQLInputValue[]): Promise<Row[]> { return await this.#run({ kind: "all", sql, args }) as Row[]; }
  async files(): Promise<void> { await this.#run({ kind: "files" }); }
  async checkpoint(): Promise<void> { await this.#run({ kind: "checkpoint" }); }
  async syncDirectory(): Promise<void> { await this.#run({ kind: "directory" }); }
  #fail(reason = new SQLiteWorkerError("storage_unavailable")): void {
    const pending = this.#pending; this.#pending = undefined;
    if (pending !== undefined) { pending.cleanup(); pending.reject(pending.committing && pending.submitted ? new SQLiteWorkerError("storage_unavailable", "unknown") : reason); }
    this.close();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    const pending = this.#pending; this.#pending = undefined;
    if (pending !== undefined) { pending.cleanup(); pending.reject(new SQLiteWorkerError("closed", pending.committing && pending.submitted ? "unknown" : "not_submitted")); }
    try { this.#worker.postMessage({ close: true }); } catch { /* Actual exit owns cleanup. */ }
  }
  closed(): boolean { return this.#closed; }
  cleanupComplete(): boolean { return this.#exited; }
  waitCleanup(): Promise<void> { return this.#cleanup; }
}

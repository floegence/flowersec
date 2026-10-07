import { Worker } from "node:worker_threads";
import { sqliteExtensionPath } from "./sqliteNativeV4.js";
import { poolStorageWorkerSource } from "../generated/sqliteWorkers.js";
import { wireDomains } from "../v4/runtime/schemaRegistry.js";
import { timerChunk } from "../v4/runtime/deadline.js";
import { V4PoolStoreError, type V4SQLitePoolIdentity, type V4SQLitePoolLimits, type V4PoolStoreFailure } from "./sqliteV4.js";
import { captureStorageFormat, type StorageFormatProjection } from "./sqliteFormat.js";

export interface PoolWorkerConfiguration {
  readonly path: string;
  readonly limits: V4SQLitePoolLimits;
  readonly identity: V4SQLitePoolIdentity;
}
export type PoolWorkerCommand = Readonly<{ kind: "open"; create: boolean }> | Readonly<{ kind: "journal"; epoch: bigint; key: Uint8Array; expected?: Uint8Array; replacement?: Uint8Array }> | Readonly<{
  kind: "consume"; epoch: bigint; key: Uint8Array; projection: Uint8Array; retainedUntil: bigint;
}>;
export interface PoolWorkerGate { readonly epoch: bigint; readonly provisioning: boolean; readonly phase: "begin" | "write" | "commit" }
export class PoolWorkerError extends Error {
  constructor(readonly code: V4PoolStoreFailure, readonly writeState: "not_submitted" | "committed" | "unknown" = "not_submitted", readonly format?: StorageFormatProjection) { super(format?.code ?? code); }
}
const failures = new Set<V4PoolStoreFailure>(["configuration_capacity", "storage_unavailable", "storage_format", "history_unknown", "fenced", "spend_conflict", "spent_unknown", "capacity", "owner_unavailable", "closed"]);
interface Pending {
  readonly id: number; readonly command: PoolWorkerCommand;
  readonly check: (gate: PoolWorkerGate) => void;
  readonly resolve: (epoch: bigint) => void; readonly reject: (error: PoolWorkerError) => void;
  cleanup: () => void; gates: number; epoch?: bigint; committing: boolean; originalError?: PoolWorkerError;
}
/** One storage worker, one original request, and no queued calls. Logical Close
 * seals future commands but keeps the worker and its request charged until exit. */
export class PoolStorageWorker {
  readonly #worker: Worker;
  readonly #exited: Promise<void>;
  #pending: Pending | undefined;
  #journalResult: Uint8Array | undefined;
  #sequence = 0;
  #closed = false;
  #done = false;
  constructor(configuration: PoolWorkerConfiguration, exited: () => void) {
    // The same generated SDK program is used in source and built packages.
    // No filename, callback or executable text comes from the database/peer.
    const activationLabel = wireDomains.find(domain => domain.name === "activation_digest")!.label_bytes;
    const certificateLabel = wireDomains.find(domain => domain.name === "certificate_digest")!.label_bytes;
    this.#worker = new Worker(poolStorageWorkerSource, { eval: true, workerData: { ...configuration, activationLabel, certificateLabel, extension: sqliteExtensionPath() },
      name: "flowersec-pool", execArgv: [], resourceLimits: { maxOldGenerationSizeMb: 16, maxYoungGenerationSizeMb: 4, codeRangeSizeMb: 4, stackSizeMb: 2 } });
    this.#worker.on("message", (message: unknown) => this.#message(message));
    this.#worker.on("error", () => this.#fail());
    this.#exited = new Promise(resolve => this.#worker.once("exit", () => {
      this.#done = this.#closed = true; this.#fail(); resolve(); exited();
    }));
  }
  async journal(command: Extract<PoolWorkerCommand, { kind: "journal" }>, check: Pending["check"], observation?: { signal: AbortSignal | undefined; remainingMS: () => bigint }): Promise<Uint8Array | undefined> {
    this.#journalResult = undefined; await this.run(command, check, observation); const result = this.#journalResult;
    this.#journalResult = undefined; return result;
  }
  run(command: PoolWorkerCommand, check: Pending["check"], observation?: { signal: AbortSignal | undefined; remainingMS: () => bigint }): Promise<bigint> {
    if (this.#closed || this.#done) return Promise.reject(new PoolWorkerError("closed"));
    if (this.#pending !== undefined) return Promise.reject(new PoolWorkerError("capacity"));
    if (this.#sequence === Number.MAX_SAFE_INTEGER) return Promise.reject(new PoolWorkerError("capacity"));
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const cancel = (): void => this.#fail(new PoolWorkerError("owner_unavailable"));
      const cleanup = (): void => { if (timer !== undefined) clearTimeout(timer); observation?.signal?.removeEventListener("abort", cancel); };
      const pending: Pending = { cleanup, id: ++this.#sequence, command, check, resolve, reject, gates: 0, committing: false };
      this.#pending = pending;
      try {
        if (observation?.signal?.aborted) { cancel(); return; }
        observation?.signal?.addEventListener("abort", cancel, { once: true });
        const wake = (): void => {
          if (this.#pending !== pending) return;
          try { timer = setTimeout(wake, timerChunk(observation!.remainingMS())); }
          catch { cancel(); }
        };
        if (observation !== undefined) wake();
        if (this.#pending === pending) this.#worker.postMessage({ type: "command", id: pending.id, command });
      } catch { this.#fail(); }
    });
  }
  #message(input: unknown): void {
    if (input === null || typeof input !== "object") { this.#fail(); return; }
    const message = input as { type?: unknown; id?: unknown; phase?: unknown; epoch?: unknown; provisioning?: unknown; code?: unknown; writeState?: unknown; value?: unknown; format?: unknown };
    const pending = this.#pending;
    if (pending === undefined || message.id !== pending.id) { this.#fail(); return; }
    if (message.type === "gate") {
      const phases = pending.command.kind !== "open" ? ["begin", "write", "commit"] : pending.command.create ? ["commit"] : ["begin", "commit"];
      if (message.phase !== phases[pending.gates] || message.provisioning !== (pending.command.kind === "open" && pending.command.create) || typeof message.epoch !== "bigint" || message.epoch < 1n ||
          message.epoch > 0xffffffffffffffffn || typeof message.provisioning !== "boolean") { this.#fail(); return; }
      const expectedEpoch = pending.command.kind !== "open" ? pending.command.epoch : pending.command.create ? 1n : pending.epoch === undefined ? message.epoch : pending.epoch + 1n;
      if (message.epoch !== expectedEpoch) { this.#fail(); return; }
      pending.epoch = message.epoch; pending.gates++;
      const gate: PoolWorkerGate = { phase: message.phase as PoolWorkerGate["phase"], epoch: message.epoch, provisioning: message.provisioning };
      try {
        if (this.#closed) throw new PoolWorkerError("closed");
        pending.check(gate);
        if (this.#closed || this.#pending !== pending) throw new PoolWorkerError("closed");
        this.#worker.postMessage({ type: "authorize", id: pending.id, phase: gate.phase, allowed: true });
        // postMessage is the irreversible worker handoff. A serialization or
        // closed-port failure before it returns never grants COMMIT permission.
        if (gate.phase === "commit") pending.committing = true;
      } catch (error) {
        pending.originalError = error instanceof PoolWorkerError ? error : error instanceof V4PoolStoreError ? new PoolWorkerError(error.code, error.writeState, error.format) : new PoolWorkerError("owner_unavailable");
        try { this.#worker.postMessage({ type: "authorize", id: pending.id, phase: gate.phase, allowed: false }); }
        catch { this.#fail(); }
      }
      return;
    }
    if (message.type !== "result") { this.#fail(); return; }
    if (message.code !== undefined && (!failures.has(message.code as V4PoolStoreFailure) || !["not_submitted", "committed", "unknown"].includes(String(message.writeState)))) { this.#fail(); return; }
    const format = captureStorageFormat(message.format, "flowersec-v4-node-pool", 1);
    if (message.format !== undefined && (format === undefined || message.code !== "storage_format" || pending.command.kind !== "open")) { this.#fail(); return; }
    if (pending.command.kind === "journal") {
      if (message.value !== undefined && !(message.value instanceof Uint8Array)) { this.#fail(); return; }
      if (pending.command.replacement === undefined && message.value instanceof Uint8Array) this.#journalResult = message.value;
    }
    this.#pending = undefined; pending.cleanup();
    if (message.code !== undefined) {
      const code = failures.has(message.code as V4PoolStoreFailure) ? message.code as V4PoolStoreFailure : "storage_unavailable";
      const state = message.writeState === "unknown" ? "unknown" : message.writeState === "committed" ? "committed" : "not_submitted";
      pending.reject(state === "not_submitted" && pending.originalError !== undefined ? pending.originalError : new PoolWorkerError(code, state, format));
      if (state !== "not_submitted") this.close();
    } else if (typeof message.epoch === "bigint" && message.epoch > 0n && message.epoch <= 0xffffffffffffffffn && message.epoch === pending.epoch && pending.committing) pending.resolve(message.epoch);
    else { pending.reject(new PoolWorkerError("storage_unavailable", pending.committing ? "unknown" : "not_submitted")); this.close(); }
  }
  #fail(reason = new PoolWorkerError("storage_unavailable")): void {
    const pending = this.#pending; this.#pending = undefined;
    if (pending !== undefined) { pending.cleanup(); pending.reject(pending.committing ? new PoolWorkerError("spent_unknown", "unknown") : reason); }
    this.close();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    const pending = this.#pending; this.#pending = undefined;
    if (pending !== undefined) { pending.cleanup(); pending.reject(new PoolWorkerError(pending.committing ? "spent_unknown" : "closed", pending.committing ? "unknown" : "not_submitted")); }
    try { this.#worker.postMessage({ type: "close" }); } catch { /* Exit owns physical cleanup. */ }
  }
  closed(): boolean { return this.#closed; }
  cleanupComplete(): boolean { return this.#done; }
  waitCleanup(): Promise<void> { return this.#exited; }
}

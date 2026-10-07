import type { DiagnosticEvent, DiagnosticFields, DiagnosticSink, DiagnosticSinkOptions } from "../diagnostics.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import type { OperationOptions } from "../../public/contract.js";
import { diagnosticGroup, type DiagnosticGroup, type FixedDiagnosticExecutor } from "./fixedDiagnosticExecutor.js";
import { diagnosticFields, type DiagnosticCounters } from "./diagnosticCounters.js";
import { credentialOwner, type CredentialResources } from "./credentialSupport.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import { hostRandomFill } from "./random.js";
import type { DiagnosticOperation } from "./diagnosticObservation.js";

const bucketMS = 900000, maxIDs = 1024, maxEvents = 4096;
interface Slot { users: number; id: Uint8Array<ArrayBuffer>; assigned: boolean; }
interface Queued { slot: Slot; fields: DiagnosticFields; }
interface Delivery { cancel?: () => void; }
const none: DiagnosticOperation = Object.freeze({ emit: () => {}, close: () => {} });
const completed: V4CleanupStatus = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });

/** Each sink owns its bounded table/queue; the executor owns transferred
 * callback responsibility until the real promise exits, even after Close. */
export class RuntimeDiagnosticSink implements DiagnosticSink {
  readonly #slots: Slot[];
  readonly #queue: Queued[] = [];
  readonly #deliveries = new Set<Delivery>();
  #group: DiagnosticGroup | undefined;
  #lane: FixedDiagnosticExecutor | undefined;
  readonly #sample: number;
  readonly #queueLimit: number;
  readonly #cleanupMS: number;
  readonly #counters: DiagnosticCounters;
  #changed: (() => void) | undefined;
  #callback: DiagnosticSinkOptions["callback"] | undefined;
  #reference: ResourceReference | undefined;
  #bucket = Math.floor(Date.now() / bucketMS);
  #ids = 0;
  #events = 0;
  #closed = false;
  #deadline: number | undefined;
  #timedOut = false;
  readonly #waiters = new Set<(status: V4CleanupStatus) => void>();
  #pump: ReturnType<typeof setTimeout> | undefined;
  #rotation: ReturnType<typeof setTimeout> | undefined;
  #cleanupTimer: ReturnType<typeof setTimeout> | undefined;
  #resolveClose!: (status: V4CleanupStatus) => void;
  readonly #close = new Promise<V4CleanupStatus>(resolve => { this.#resolveClose = resolve; });
  constructor(resources: CredentialResources, config: DiagnosticSinkOptions, cleanupMS: number, counters: DiagnosticCounters, changed: () => void) {
    const slots = config.operationSlots ?? 64, queue = config.queueEvents ?? 64, sample = config.sampleBasisPoints ?? 100;
    const callback = config.callback, runtimeBytes = config.runtimeBytes;
    if (!Number.isSafeInteger(slots) || slots < 1 || slots > maxIDs || !Number.isSafeInteger(queue) || queue < 1 || queue > maxEvents ||
        !Number.isSafeInteger(sample) || sample < 0 || sample > 100 || typeof callback !== "function" || typeof runtimeBytes !== "bigint" || runtimeBytes <= 0n) throw new Error("configuration_capacity");
    this.#sample = sample; this.#queueLimit = queue; this.#cleanupMS = cleanupMS; this.#counters = counters; this.#changed = changed; this.#callback = callback;
    // Queue encoding is at most 512 bytes per event, and never above 2 MiB.
    // The larger charge includes JS metadata and six transferred deliveries.
    const charge = new ResourceVector([BigInt(slots * 128 + queue * 1024 + 6 * 1024 + 2048) + 6n * runtimeBytes, 0n, 0n, BigInt(slots + queue + 8), 0n, 0n, 3n, 0n, 0n, 0n, 0n]);
    if (charge.values()[0]! > 2n * 1024n * 1024n) throw new Error("configuration_capacity");
    const ref = resources.root.reserve({ owner: credentialOwner(resources, "diagnostic_sink"), accounts: resources.accounts, charge });
    let group: DiagnosticGroup | undefined;
    try {
      this.#reference = ref; this.#slots = Array.from({ length: slots }, () => ({ users: 0, id: new Uint8Array(16), assigned: false }));
      this.#group = group = diagnosticGroup(resources.root, resources.accounts, credentialOwner(resources, "diagnostic_service"), resources.runtimeBytes);
      this.#lane = group.executor; this.#armRotation();
    } catch (error) { group?.close(); ref.release(); throw error; }
    Object.freeze(this);
  }
  begin(): DiagnosticOperation {
    if (this.#closed || this.#sample === 0) return none;
    this.#rotate();
    const index = this.#slots.findIndex(value => value.users === 0), slot = this.#slots[index];
    if (slot === undefined) { this.#drop(); return none; }
    if (!this.#assign(slot)) return none;
    slot.users = 1; let closed = false;
    return Object.freeze({
      emit: (fields: Partial<DiagnosticFields>) => { const current = this.#slots[index]; if (!closed && current !== undefined) this.#emit(current, fields); },
      close: () => { if (!closed) { closed = true; const current = this.#slots[index]; if (current !== undefined) this.#release(current); } },
    });
  }
  #release(slot: Slot): void { if (slot.users > 0 && --slot.users === 0) { slot.id.fill(0); slot.assigned = false; } }
  #assign(slot: Slot): boolean {
    if (this.#ids >= maxIDs) { this.#drop(); return false; }
    try { hostRandomFill(slot.id); slot.assigned = true; this.#ids++; return true; }
    catch { slot.id.fill(0); slot.assigned = false; this.#drop(); return false; }
  }
  #drop(): void { this.#counters.observe("diagnostic_drop", { code: "diagnostic_dropped" }); }
  #emit(slot: Slot, input: Partial<DiagnosticFields>): void {
    if (this.#closed) return;
    this.#rotate();
    if (this.#queue.length >= this.#queueLimit) { this.#drop(); return; }
    slot.users++; this.#queue.push({ slot, fields: diagnosticFields(input) });
    if (this.#pump === undefined) this.#pump = setTimeout(() => { this.#pump = undefined; this.#drain(); }, 0);
  }
  #rotate(): void {
    const bucket = Math.floor(Date.now() / bucketMS);
    if (bucket === this.#bucket) return;
    this.#bucket = bucket; this.#ids = this.#events = 0;
    for (const queued of this.#queue.splice(0)) { this.#release(queued.slot); this.#drop(); }
    for (const slot of this.#slots) { slot.id.fill(0); slot.assigned = false; if (slot.users > 0) this.#assign(slot); }
    // Cancel unstarted old-bucket deliveries immediately, clearing their SDK
    // copy. Already delivered external copies belong to the application.
    for (const delivery of [...this.#deliveries]) delivery.cancel?.();
  }
  #armRotation(): void {
    this.#rotation = setTimeout(() => { this.#rotation = undefined; if (!this.#closed) { this.#rotate(); this.#armRotation(); } }, Math.max(1, (this.#bucket + 1) * bucketMS - Date.now()));
  }
  #sampleEvent(): boolean {
    const random = new Uint8Array(4);
    try {
      // Rejection sampling avoids modulo bias; diagnostic entropy is separate
      // from all protocol keys, challenges and application operation IDs.
      for (let attempt = 0; attempt < 8; attempt++) {
        hostRandomFill(random); const value = new DataView(random.buffer).getUint32(0);
        if (value < 4294960000) return value % 10000 < this.#sample;
      }
      this.#drop(); return false;
    } finally { random.fill(0); }
  }
  #drain(): void {
    if (this.#closed) return; this.#rotate();
    for (let queued = this.#queue.shift(); queued !== undefined; queued = this.#queue.shift()) {
      try {
        if (!this.#sampleEvent()) continue;
        if (this.#events >= maxEvents) { this.#drop(); continue; }
        if (!queued.slot.assigned && !this.#assign(queued.slot)) continue;
        let event: DiagnosticEvent | undefined = Object.freeze({ ...queued.fields, correlation_id: Array.from(queued.slot.id, byte => byte.toString(16).padStart(2, "0")).join("") });
        if (JSON.stringify(event).length > 512) { this.#drop(); continue; }
        const bucket = this.#bucket, delivery: Delivery = {};
        this.#deliveries.add(delivery);
        // The event leaves the SDK queue atomically with its original charged
        // delivery slot. No new reservation is made at callback dispatch.
        let cancel: (() => void) | undefined;
        try { cancel = this.#lane!.submit(this.#group!, signal => {
          this.#rotate(); const value = event; event = undefined;
          if (this.#closed || bucket !== this.#bucket || signal.aborted || value === undefined) { this.#drop(); return; }
          try { return Promise.resolve(this.#callback?.(value, Object.freeze({ signal }))).catch(() => this.#drop()); }
          catch { this.#drop(); }
        }, () => { event = undefined; this.#deliveries.delete(delivery); this.#finish(); }); }
        catch { event = undefined; this.#deliveries.delete(delivery); this.#drop(); continue; }
        if (cancel === undefined) { event = undefined; this.#deliveries.delete(delivery); this.#drop(); }
        else { delivery.cancel = cancel; this.#events++; }
      } catch { this.#drop(); }
      finally { this.#release(queued.slot); }
    }
  }
  close(): Promise<V4CleanupStatus> {
    if (this.#closed) return this.#close;
    this.#closed = true; this.#deadline = performance.now() + this.#cleanupMS;
    if (this.#pump !== undefined) clearTimeout(this.#pump); this.#pump = undefined;
    if (this.#rotation !== undefined) clearTimeout(this.#rotation); this.#rotation = undefined;
    for (const queued of this.#queue.splice(0)) this.#release(queued.slot);
    for (const slot of this.#slots) { slot.id.fill(0); slot.assigned = false; }
    for (const delivery of [...this.#deliveries]) delivery.cancel?.();
    this.#group?.close(); this.#finish();
    if (this.#reference !== undefined) this.#cleanupTimer = setTimeout(() => { this.#cleanupTimer = undefined; this.#timedOut = true; this.#counters.observe("cleanup_timeout", { phase: "cleanup", code: "cleanup_incomplete" }); this.#settle(this.cleanupStatus()); this.#changed?.(); }, this.#cleanupMS);
    return this.#close;
  }
  #finish(): void {
    if (!this.#closed || this.#deliveries.size !== 0 || this.#group?.cleanupComplete() === false) return;
    this.#group = undefined; this.#lane = undefined;
    for (const slot of this.#slots) { slot.id.fill(0); slot.id = new Uint8Array(0); }
    this.#slots.length = 0;
    this.#callback = undefined; this.#reference?.release(); this.#reference = undefined;
    if (this.#cleanupTimer !== undefined) clearTimeout(this.#cleanupTimer); this.#cleanupTimer = undefined;
    this.#settle(completed); const changed = this.#changed; this.#changed = undefined; changed?.();
  }
  #settle(status: V4CleanupStatus): void {
    this.#resolveClose(status);
    for (const finish of [...this.#waiters]) finish(status);
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#closed && this.#reference === undefined) return completed;
    return Object.freeze({ status: this.#timedOut || this.#deadline !== undefined && performance.now() >= this.#deadline ? "cleanup_incomplete" : "pending", core_cleanup: this.#closed && this.#queue.length === 0 ? "complete" : "pending", pending_callbacks: BigInt(this.#deliveries.size + this.#queue.length) });
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    if (options?.signal?.aborted) return Promise.reject(new Error("canceled"));
    const current = this.cleanupStatus();
    if (current.status !== "pending") return Promise.resolve(current);
    // Observe the original lifecycle. Only Close seals delivery and starts
    // its cleanup deadline; waiting neither closes nor extends that owner.
    if (options?.signal === undefined) return this.#close;
    if (this.#waiters.size >= 4) return Promise.reject(new Error("resource_exhausted"));
    const signal = options.signal;
    return new Promise<V4CleanupStatus>((resolve, reject) => {
      const finish = (status: V4CleanupStatus): void => { this.#waiters.delete(finish); signal.removeEventListener("abort", canceled); resolve(status); };
      const canceled = (): void => { this.#waiters.delete(finish); signal.removeEventListener("abort", canceled); reject(new Error("canceled")); };
      this.#waiters.add(finish);
      signal.addEventListener("abort", canceled, { once: true });
      const status = this.cleanupStatus(); if (status.status !== "pending") finish(status);
      if (signal.aborted) canceled();
    });
  }
}

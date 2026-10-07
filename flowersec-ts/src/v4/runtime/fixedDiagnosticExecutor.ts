import { ResourceVector, type ResourceAccount, type ResourceOwner, type ResourceReference, type ResourceRoot, type ResourceServiceReference } from "./resources.js";

const services = new WeakMap<ResourceRoot, FixedDiagnosticExecutor>();
export class DiagnosticGroup {
  #closed = false;
  #users = 0;
  #detach: (() => void) | undefined;
  constructor(readonly executor: FixedDiagnosticExecutor, private reference: ResourceReference | undefined) {
    this.#detach = executor.reference.attach(reference!);
  }
  retain(): void { if (this.#closed || this.reference === undefined) throw new Error("closed"); this.reference.check(); this.#users++; }
  release(): void { if (this.#users < 1) throw new Error("owner_unavailable"); this.#users--; this.#cleanup(); }
  close(): void { if (this.#closed) return; this.#closed = true; this.executor.cancelGroup(this); this.#cleanup(); }
  #cleanup(): void {
    if (!this.#closed || this.#users !== 0 || this.reference === undefined) return;
    this.#detach?.(); this.#detach = undefined; this.reference.release(); this.reference = undefined; this.executor.removeGroup(this);
  }
  cleanupComplete(): boolean { return this.reference === undefined; }
}
export function diagnosticGroup(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, runtimeBytes: bigint): DiagnosticGroup {
  const reference = root.reserve({ accounts, owner, charge: new ResourceVector([runtimeBytes + 1024n, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]) });
  let lane = services.get(root);
  try {
    if (lane === undefined) { lane = new FixedDiagnosticExecutor(root); services.set(root, lane); }
    return lane.attach(reference);
  } catch (error) { reference.release(); lane?.cleanup(); throw error; }
}

interface Job {
  readonly group: DiagnosticGroup;
  readonly run: (signal: AbortSignal) => void | Promise<void>;
  readonly finished: () => void;
  readonly abort: AbortController;
  started: boolean;
  canceled: boolean;
}
/** The root's independent two-running/four-ready diagnostic subpool. */
export class FixedDiagnosticExecutor {
  readonly reference: ResourceServiceReference;
  readonly #jobs = new Set<Job>();
  readonly #groups = new Set<DiagnosticGroup>();
  #running = 0;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  constructor(private readonly root: ResourceRoot) {
    this.reference = root.reserveService(new ResourceVector([256n * 1024n, 0n, 0n, 7n, 2n, 2n, 1n, 0n, 0n, 0n, 0n]));
  }
  attach(reference: ResourceReference): DiagnosticGroup {
    if (this.#closed || this.#groups.size >= 1024) throw new Error("resource_exhausted");
    const group = new DiagnosticGroup(this, reference); this.#groups.add(group); return group;
  }
  removeGroup(group: DiagnosticGroup): void { this.#groups.delete(group); this.cleanup(); }
  cleanup(): void { if (this.#groups.size === 0 && this.#jobs.size === 0) { services.delete(this.root); this.close(); } }
  submit(group: DiagnosticGroup, run: Job["run"], finished: Job["finished"]): (() => void) | undefined {
    if (this.#closed || this.#jobs.size - this.#running >= 4) return;
    try { group.retain(); } catch { return; }
    const job: Job = { group, run, finished, abort: new AbortController(), started: false, canceled: false };
    this.#jobs.add(job); this.#schedule();
    return () => this.#cancel(job);
  }
  #cancel(job: Job): void {
    job.canceled = true;
    if (!job.started) this.#finish(job); else this.#schedule();
  }
  #schedule(): void {
    if (this.#timer !== undefined || ![...this.#jobs].some(job =>
      job.started && job.canceled && !job.abort.signal.aborted || !this.#closed && this.#running < 2 && !job.started)) return;
    // A host task, outside transport I/O and SDK producer call chains.
    this.#timer = setTimeout(() => { this.#timer = undefined; this.#drive(); }, 0);
  }
  #drive(): void {
    // Application abort listeners also execute exclusively on this lane.
    for (const job of this.#jobs) if (job.started && job.canceled && !job.abort.signal.aborted) job.abort.abort();
    for (const job of this.#jobs) {
      if (this.#closed || this.#running >= 2) break;
      if (job.started) continue;
      job.started = true; this.#running++;
      void Promise.resolve().then(() => { if (!job.canceled) return job.run(job.abort.signal); }).catch(() => undefined).finally(() => this.#finish(job));
    }
  }
  #finish(job: Job): void {
    if (!this.#jobs.delete(job)) return;
    if (job.started) this.#running--;
    // Publish completion only after the actual callback's group charge returns.
    try { job.group.release(); job.finished(); } finally { this.#schedule(); this.#cleanup(); this.cleanup(); }
  }
  cancelGroup(group: DiagnosticGroup): void {
    for (const job of [...this.#jobs]) if (job.group === group) this.#cancel(job);
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    for (const job of [...this.#jobs]) this.#cancel(job);
    this.#cleanup();
  }
  #cleanup(): void { if (this.#closed && this.#jobs.size === 0) this.reference.release(); }
}

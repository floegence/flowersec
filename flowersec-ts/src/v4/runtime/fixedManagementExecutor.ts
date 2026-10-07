import type { ApplicationGroup } from "./applicationExecutor.js";
import { ResourceError, ResourceVector, type ResourceRoot, type ResourceServiceReference } from "./resources.js";

const NativePromise = Promise;

interface Pending {
  readonly group: ApplicationGroup;
  readonly signal: AbortSignal;
  readonly check: () => void;
  readonly cancel: () => void;
  readonly resolve: (permit: ManagementPermit) => void;
  readonly reject: (error: unknown) => void;
}
/** A running SDK step retains its actual original group until exit. */
export class ManagementPermit {
  #executor: FixedManagementExecutor | undefined;
  constructor(executor: FixedManagementExecutor, readonly group: ApplicationGroup) { this.#executor = executor; Object.freeze(this); }
  release(): void {
    const executor = this.#executor; if (executor === undefined) return;
    this.#executor = undefined; executor.returnPermit(this);
  }
}
/** One root service, two actual running SDK steps, and four bounded ready
 * descriptors. Network waits remain with their original protocol owners.
 * Callers cannot select this lane as an application work class. */
export class FixedManagementExecutor {
  #reference: ResourceServiceReference | undefined;
  readonly #ready: Pending[] = [];
  #running = 0;
  #closed = false;
  #dispatching = false;
  #lastGroup: ApplicationGroup | undefined;
  constructor(root: ResourceRoot) {
    this.#reference = root.reserveService(new ResourceVector([256n * 1024n, 0n, 0n, 7n, 2n, 2n, 0n, 0n, 0n, 0n, 0n]));
  }
  get reference(): ResourceServiceReference {
    if (this.#closed || this.#reference === undefined) throw new Error("closed");
    this.#reference.check(); return this.#reference;
  }
  acquire(group: ApplicationGroup, signal: AbortSignal, check: () => void): Promise<ManagementPermit> {
    try {
      this.reference.check(); group.check(); check();
      if (signal.aborted) throw new Error("canceled");
      if (this.#running < 2 && this.#ready.length === 0) {
        group.retain(); this.#running++;
        const permit = new ManagementPermit(this, group);
        try { group.check(); check(); if (signal.aborted) throw new Error("canceled"); }
        catch (error) { permit.release(); throw error; }
        return NativePromise.resolve(permit);
      }
      if (this.#ready.length >= 4) throw new ResourceError("resource_exhausted");
      group.retain();
      return new NativePromise((resolve, reject) => {
        const pending: Pending = { group, signal, check, resolve, reject, cancel: () => this.#remove(pending, new Error("canceled")) };
        this.#ready.push(pending); signal.addEventListener("abort", pending.cancel, { once: true });
        if (signal.aborted || group.closed || this.#closed) pending.cancel();
        this.#dispatch();
      });
    } catch (error) { return NativePromise.reject(error); }
  }
  #remove(pending: Pending, error: unknown): void {
    const index = this.#ready.indexOf(pending); if (index < 0) return;
    this.#ready.splice(index, 1); pending.signal.removeEventListener("abort", pending.cancel);
    pending.group.release(); pending.reject(error); this.#collect();
  }
  #dispatch(): void {
    if (this.#dispatching || this.#closed) return;
    this.#dispatching = true;
    try {
      while (this.#running < 2 && this.#ready.length > 0 && !this.#closed) {
        const alternate = this.#ready.findIndex(pending => pending.group !== this.#lastGroup), index = alternate < 0 ? 0 : alternate;
        const pending = this.#ready.splice(index, 1)[0]!;
        pending.signal.removeEventListener("abort", pending.cancel);
        try {
          this.reference.check(); pending.group.check(); pending.check();
          if (pending.signal.aborted) throw new Error("canceled");
        } catch (error) { pending.group.release(); pending.reject(error); continue; }
        this.#running++; this.#lastGroup = pending.group;
        pending.resolve(new ManagementPermit(this, pending.group));
      }
    } finally { this.#dispatching = false; this.#collect(); }
  }
  returnPermit(permit: ManagementPermit): void {
    if (this.#running < 1) throw new Error("owner_unavailable");
    this.#running--; permit.group.release(); this.#dispatch(); this.#collect();
  }
  cancelGroup(group: ApplicationGroup): void {
    for (const pending of Array.from(this.#ready)) if (pending.group === group) this.#remove(pending, new Error("closed"));
    if (this.#lastGroup === group) this.#lastGroup = undefined;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const pending of Array.from(this.#ready)) this.#remove(pending, new Error("closed"));
    this.#collect();
  }
  #collect(): void {
    if (this.#closed && !this.#dispatching && this.#running === 0 && this.#ready.length === 0) {
      this.#reference?.release(); this.#reference = undefined; this.#lastGroup = undefined;
    }
  }
}

for (const constructor of [FixedManagementExecutor, ManagementPermit]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

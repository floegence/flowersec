import type { V4CleanupStatus, V4LifecycleResult } from "../../generated/transportV4APIResults.js";
import type { OperationOptions } from "../../public/contract.js";
import type { SessionDrain } from "../drain.js";
import type { TrustedClock } from "./clock.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import { cleanupResult, lifecycleResult } from "./lifecycle.js";
import { ResourceVector, type ResourceRoot, type ResourceAccount, type ResourceOwner, type ResourceReference } from "./resources.js";

const NativePromise = Promise;
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
export function sessionCleanupCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([runtimeBytes + 1280n, 0n, 0n, 1n, 0n, 1n, 1n, 0n, 0n, 0n, 0n]);
}
/** A send encoder still belongs to its original Session, unlike a complete
 * receive candidate already transferred to an independent result owner. */
export class SessionApplicationTail {
  #running = true;
  #cleanup: SessionCleanup | undefined;
  constructor(cleanup: SessionCleanup) { this.#cleanup = cleanup; cleanup.startJob(); cleanup.enterCallback(); }
  callbackExited(): void { if (!this.#running) return; this.#running = false; this.#cleanup!.exitCallback(); }
  finish(): void {
    const cleanup = this.#cleanup; if (cleanup === undefined) return;
    this.callbackExited(); this.#cleanup = undefined; cleanup.finishJob();
  }
}
/** Original close result and remaining application duties, without a Session,
 * stream, provider, cipher or protocol callback. Core admission prepays this
 * cell; after core exit it takes and shrinks that same unique reservation. */
export class SessionCleanup {
  #host: { root: ResourceRoot; accounts: readonly ResourceAccount[]; owner: ResourceOwner; clock: TrustedClock; runtimeBytes: bigint } | undefined;
  #reference: ResourceReference | undefined;
  #closed = false;
  #starting = false;
  #coreComplete = false;
  #corePending = 0;
  #jobs = 0;
  #callbacks = 0;
  #incomplete = false;
  #fault = false;
  #window: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #resolve: ((result: V4LifecycleResult) => void) | undefined;
  readonly closed = new NativePromise<V4LifecycleResult>(resolve => { this.#resolve = resolve; });
  readonly #observers = new Set<() => void>();
  readonly #cleaned = new Set<() => void>();
  #serveCleaned: (() => void) | undefined;
  #controllerCleaned: (() => void) | undefined;
  #coreCleaned: (() => void) | undefined;
  #drain: SessionDrain | undefined;
  constructor(root: ResourceRoot, accounts: readonly ResourceAccount[], owner: ResourceOwner, clock: TrustedClock, runtimeBytes: bigint) {
    this.#host = { root, accounts, owner, clock, runtimeBytes };
  }
  startClose(drain?: SessionDrain): void {
    if (this.#closed) return; this.#closed = true; this.#starting = true; this.#drain = drain;
    try { this.#window = new TrustedWindow(this.#host!.clock, 5000n); this.#tick(); }
    catch { this.#incomplete = true; }
    this.#notify();
  }
  readonly #tick = (): void => {
    this.#timer = undefined;
    try { this.#window!.check(); this.#timer = setTimeout(this.#tick, timerChunk(this.#window!.remainingMS())); }
    catch { this.#incomplete = true; this.#notify(); }
  };
  startJob(): void { if (this.#closed) throw new Error("closed"); this.#jobs++; }
  startApplicationCallback(): SessionApplicationTail { return new SessionApplicationTail(this); }
  enterCallback(): void { this.#callbacks++; }
  exitCallback(): void { this.#callbacks--; }
  markIncomplete(): void { this.#incomplete = true; this.#notify(); }
  finishJob(): void { this.#jobs--; this.#notify(); }
  updateCore(pending: number, fault = false): void {
    this.#starting = false; this.#corePending = pending; if (fault) this.#fault = this.#incomplete = true; this.#notify();
  }
  finishCore(reference: ResourceReference): void {
    if (this.#coreComplete || !this.#closed) throw new Error("owner_unavailable");
    this.#reference = reference;
    reference.shrink(sessionCleanupCharge(this.#host!.runtimeBytes));
    this.#coreComplete = true; this.#corePending = 0;
    const coreCleaned = this.#coreCleaned; this.#coreCleaned = undefined; coreCleaned?.();
    this.#notify();
  }
  coreComplete(): boolean { return this.#coreComplete; }
  onCoreCleanup(callback: () => void): void {
    if (this.#coreComplete) callback();
    else { if (this.#coreCleaned !== undefined) throw new Error("configuration_capacity"); this.#coreCleaned = callback; }
  }
  onCleanup(callback: () => void): void {
    if (this.cleanupStatus().status === "complete") callback();
    else { if (this.#cleaned.size >= 2) throw new Error("configuration_capacity"); this.#cleaned.add(callback); }
  }
  /** The owning Controller prepays this single link. Unlike WaitCleanup, this
   * notification only fires after every original cleanup tail has exited. */
  onControllerCleanup(callback: () => void): void {
    if (this.#controllerCleaned !== undefined) throw new Error("configuration_capacity");
    if (this.cleanupStatus().status === "complete") callback(); else this.#controllerCleaned = callback;
  }
  /** The original Serve position prepays one actual-cleanup link. */
  onServeCleanup(callback: () => void): void {
    if (this.#serveCleaned !== undefined) throw new Error("configuration_capacity");
    if (this.cleanupStatus().status === "complete") callback(); else this.#serveCleaned = callback;
  }
  #projection(): V4CleanupStatus {
    if (this.#coreComplete && this.#jobs === 0) return complete;
    return cleanupResult({ status: this.#incomplete ? "cleanup_incomplete" : "pending", core_cleanup: this.#coreComplete ? "complete" : "pending",
      // SDK jobs can still own a real continuation after their application
      // callback exits. Include those tails in the original cleanup count.
      pending_callbacks: BigInt(this.#corePending + Math.max(this.#callbacks, this.#jobs)) });
  }
  #lifecycle(status: V4CleanupStatus): V4LifecycleResult {
    return lifecycleResult("session", this.#closed ? "session_aborted" : "active", status,
      this.#fault ? "core_cleanup_failed" : status.status === "cleanup_incomplete" ? "deadline_exceeded" : "none");
  }
  lifecycleResult(): V4LifecycleResult { return this.#lifecycle(this.cleanupStatus()); }
  cleanupStatus(): V4CleanupStatus {
    if (this.#window !== undefined && !this.#incomplete) try { this.#window.check(); } catch { this.#incomplete = true; this.#notify(); }
    return this.#projection();
  }
  #notify(): void {
    if (this.#starting) return;
    const status = this.#projection(); this.#drain?.cleanup(status);
    if (status.status === "complete") {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#window = undefined;
      this.#host = undefined; this.#drain = undefined;
      const reference = this.#reference; this.#reference = undefined; reference?.release();
    }
    if (this.#closed && status.status !== "pending") { const resolve = this.#resolve; this.#resolve = undefined; resolve?.(this.#lifecycle(status)); }
    for (const wake of this.#observers) wake();
    if (status.status === "complete") {
      const callbacks = [...this.#cleaned], controller = this.#controllerCleaned, serve = this.#serveCleaned;
      this.#cleaned.clear(); this.#controllerCleaned = undefined; this.#serveCleaned = undefined;
      for (const callback of callbacks) callback(); controller?.(); serve?.();
    }
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    const initial = this.cleanupStatus(); if (initial.status !== "pending") return NativePromise.resolve(initial);
    if (options?.signal?.aborted) return NativePromise.reject(new Error("canceled"));
    if (this.#observers.size >= 32) return NativePromise.reject(new Error("resource_exhausted"));
    const host = this.#host!, reference = host.root.reserve({ accounts: host.accounts, owner: { ...host.owner, kind: "v4_session_cleanup_wait" },
      charge: new ResourceVector([host.runtimeBytes + 256n, 0n, 0n, 1n, 1n, 1n, 1n, 0n, 0n, 0n, 0n]) });
    return new NativePromise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined, window: TrustedWindow | undefined, done = false;
      const finish = (canceled = false, expired = false): void => {
        if (done) return; done = true; this.#observers.delete(wake);
        if (timer !== undefined) clearTimeout(timer); options?.signal?.removeEventListener("abort", abort); reference.release();
        if (canceled) reject(new Error("canceled"));
        else { const status = this.#projection(); resolve(expired && status.status === "pending" ? cleanupResult({ ...status, status: "cleanup_incomplete" }) : status); }
      };
      const abort = (): void => finish(true), wake = (): void => { if (this.#projection().status !== "pending") finish(); };
      const tick = (): void => { try { window!.check(); timer = setTimeout(tick, timerChunk(window!.remainingMS())); } catch { finish(false, true); } };
      this.#observers.add(wake); options?.signal?.addEventListener("abort", abort, { once: true });
      try { window = new TrustedWindow(host.clock, 5000n); if (options?.signal?.aborted) abort(); else { wake(); if (!done) tick(); } }
      catch { finish(false, true); }
    });
  }
}

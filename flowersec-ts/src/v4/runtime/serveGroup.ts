import type { SessionCleanup } from "./sessionCleanup.js";
import type { OperationOptions } from "../../public/contract.js";
import type { V4CleanupStatus } from "../../generated/transportV4APIResults.js";
import { V4Session, type V4SessionOwner } from "../public.js";
import { createSessionDrain, type SessionDrain, type V4DrainOptions, type V4DrainOperation, type V4DrainOutcome } from "../drain.js";
import { ServeError, type ServeCallbacks, type ServeHandleOwner, type AuthenticatedRequestContext, type ApplicationAuthorizationLease, type ServeReleaseContext } from "../serve.js";
import type { V4AuthenticatedContext } from "../streamHandlers.js";
import { TimeError } from "./timeArithmetic.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import type { EnvironmentDependency, V4EnvironmentRuntime } from "./environment.js";
import { ResourceVector } from "./resources.js";
import { cleanupResult } from "./lifecycle.js";

export interface ServeGroupLimits {
  readonly positions: number;
  readonly callbackBytes: bigint;
  readonly handshakeMS: bigint;
  readonly drainMS: bigint;
  readonly cleanupMS: bigint;
}
function completeCleanup(value: V4CleanupStatus): boolean { return value?.status === "complete" && value.core_cleanup === "complete" && value.pending_callbacks === 0n; }
function incompleteCleanup(snapshot?: V4CleanupStatus): V4CleanupStatus {
  const pending = snapshot?.pending_callbacks;
  return cleanupResult({ status: "cleanup_incomplete", core_cleanup: "complete",
    pending_callbacks: typeof pending === "bigint" && pending >= 0n && pending <= 0xffffffffffffffffn ? pending : 0n });
}
function combineOutcome(a: V4DrainOutcome, b: V4DrainOutcome): Exclude<V4DrainOutcome, "pending"> {
  return a === "failed" || b === "failed" ? "failed" : a === "deadline_aborted" || b === "deadline_aborted" ? "deadline_aborted" : "drained";
}
const complete = cleanupResult({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n });
/** Original listener aggregate. Each position stays occupied through native,
 * Session, application authorization and Release tails, including rejection. */
export class ServeGroup<Plan extends object> implements ServeHandleOwner {
  #dependency: EnvironmentDependency | undefined;
  #environment: V4EnvironmentRuntime | undefined;
  readonly #children = new Set<ServeIngress<Plan>>();
  readonly #observers = new Set<() => void>();
  readonly #drain: SessionDrain;
  #callbacks: ServeCallbacks<Plan> | undefined;
  #sealed = false;
  #closing = false;
  #listenerEnded = false;
  #listenerCoreEnded = false;
  #drainStarted = false;
  #startingDrain = false;
  #childOutcome: Exclude<V4DrainOutcome, "pending"> = "drained";
  #sealListener: (() => void) | undefined;
  #abortListener: (() => void) | undefined;
  #cleanupWindow: TrustedWindow | undefined;
  #drainWindow: TrustedWindow | undefined;
  #drainTimer: ReturnType<typeof setTimeout> | undefined;
  #finished = false;
  #cleanupObserved = false;
  #cleanupObserver: (() => void) | undefined;
  #failed = false;
  #waiters = 0;
  #parentSignal: AbortSignal | undefined;
  readonly #parentAbort = () => this.close();
  constructor(environment: V4EnvironmentRuntime, readonly limits: ServeGroupLimits, callbacks: ServeCallbacks<Plan>, signal?: AbortSignal) {
    if (!Number.isSafeInteger(limits.positions) || limits.positions < 1 || limits.positions > 1024 ||
        typeof limits.callbackBytes !== "bigint" || limits.callbackBytes < 1n || limits.callbackBytes > 1n << 30n ||
        [limits.handshakeMS, limits.drainMS, limits.cleanupMS].some(value => typeof value !== "bigint" || value < 1n || value > 600000n)) throw new ServeError("configuration_capacity", complete);
    this.#environment = environment;
    this.limits = Object.freeze({ positions: limits.positions, callbackBytes: limits.callbackBytes, handshakeMS: limits.handshakeMS, drainMS: limits.drainMS, cleanupMS: limits.cleanupMS });
    const n = BigInt(limits.positions), runtime = environment.resources.runtimeBytes;
    this.#dependency = environment.admitDependency("serve", new ResourceVector([16384n + n * (8192n + limits.callbackBytes + runtime), 0n, 0n, 32n + n * 8n, n + 1n, n + 34n, 0n, 0n, 0n, 0n, 0n]));
    this.#callbacks = Object.freeze({ ...callbacks });
    this.#drain = createSessionDrain(() => {
      const ref = this.#dependency!.reference.borrow(); return () => ref.release();
    }, this.cleanupStatus(), () => this.cleanupStatus());
    this.#dependency.onClose(() => this.close());
    this.#parentSignal = signal; signal?.addEventListener("abort", this.#parentAbort, { once: true });
    if (signal?.aborted) this.close();
  }
  get environment(): V4EnvironmentRuntime { if (this.#environment === undefined) throw this.failure("closed"); return this.#environment; }
  get closing(): boolean { return this.#closing; }
  bindListener(seal: () => void, abort: () => void): void {
    if (this.#sealListener !== undefined) throw this.failure("owner_unavailable");
    this.#sealListener = seal; this.#abortListener = abort;
    if (this.#sealed) seal(); if (this.#closing) abort();
  }
  listenerCoreEnded(): void { this.#listenerCoreEnded = true; this.#collect(); }
  listenerEnded(): void { this.#listenerEnded = this.#listenerCoreEnded = true; this.#collect(); }
  begin(closeNative: () => void): ServeIngress<Plan> {
    this.checkIngress();
    if (this.#children.size >= this.limits.positions) throw this.failure("resource_exhausted");
    const child = new ServeIngress(this, closeNative); this.#children.add(child);
    // Native Promise/clock hooks may have sealed ingress during construction.
    try { this.checkIngress(); child.startDeadline(); child.check(); return child; }
    catch (error) { child.abort(); child.finishUnused(); throw error; }
  }
  checkIngress(): void { if (this.#sealed) throw this.failure("closed"); this.#dependency!.check(); }
  failure(code: ConstructorParameters<typeof ServeError>[0]): ServeError { return new ServeError(code, this.cleanupStatus()); }
  callbacks(): ServeCallbacks<Plan> { if (this.#callbacks === undefined) throw this.failure("closed"); return this.#callbacks; }
  changed(): void { this.#collect(); }
  retired(child: ServeIngress<Plan>): void {
    if (this.#drainStarted) this.#childOutcome = combineOutcome(this.#childOutcome, child.drainOutcome() === "pending" ? "failed" : child.drainOutcome());
    this.#children.delete(child); this.#collect();
  }
  drain(options?: V4DrainOptions): V4DrainOperation {
    if (this.#sealed) return this.#drain.operation;
    const duration = options?.timeoutMS ?? this.limits.drainMS;
    if (typeof duration !== "bigint" || duration < 1n || duration > this.limits.drainMS) throw this.failure("configuration_capacity");
    this.#drainStarted = this.#startingDrain = true;
    this.#seal();
    try { this.#drainWindow = new TrustedWindow(this.environment.clock, duration); }
    catch (error) { this.#startingDrain = false; this.#deadline(error); return this.#drain.operation; }
    try {
      for (const child of this.#children) {
        if (this.#closing) break;
        const remaining = this.#drainWindow.remainingMS();
        if (this.#closing) break;
        child.drain(remaining);
      }
    } catch (error) { this.#deadline(error); }
    this.#startingDrain = false;
    const tick = (): void => {
      this.#drainTimer = undefined;
      this.#collect();
      if (this.#finished || this.#closing || this.#drain.operation.status().outcome !== "pending") return;
      try { this.#drainWindow!.check(); this.#drainTimer = setTimeout(tick, Math.min(10, timerChunk(this.#drainWindow!.remainingMS()))); }
      catch (error) { this.#deadline(error); }
    };
    tick(); return this.#drain.operation;
  }
  waitDrain(options?: OperationOptions) { return this.#drain.operation.wait(options); }
  #deadline(error: unknown): void {
    this.#drain.finish(error instanceof TimeError && error.code === "time_expired" ? "deadline_aborted" : "failed"); this.close();
  }
  #seal(): void {
    if (this.#sealed) return; this.#sealed = true;
    this.#sealListener?.();
  }
  #startCleanup(): void {
    if (this.#cleanupWindow !== undefined || this.#finished) return;
    try { this.#cleanupWindow = new TrustedWindow(this.environment.clock, this.limits.cleanupMS); } catch { this.#failed = true; }
  }
  close(): void {
    if (this.#closing || this.#finished) return; this.#closing = true; this.#seal(); this.#startCleanup();
    this.#drain.finish("failed");
    if (this.#drainTimer !== undefined) clearTimeout(this.#drainTimer); this.#drainTimer = undefined;
    this.#abortListener?.(); for (const child of this.#children) child.abort(); this.#collect();
  }
  onCleanup(callback: () => void): void {
    if (this.#cleanupObserved || typeof callback !== "function") throw this.failure("owner_unavailable");
    this.#cleanupObserved = true;
    if (this.#finished) callback(); else this.#cleanupObserver = callback;
  }
  cleanupStatus(): V4CleanupStatus {
    if (this.#finished) return complete;
    let callbacks = 0n, core = this.#listenerCoreEnded;
    for (const child of this.#children) { callbacks += child.pendingCallbacks(); core &&= child.coreEnded; }
    let incomplete = this.#failed || Array.from(this.#children).some(child => child.cleanupIncomplete());
    if (this.#cleanupWindow !== undefined) try { this.#cleanupWindow.check(); } catch { incomplete = true; }
    return cleanupResult({ status: incomplete ? "cleanup_incomplete" : "pending", core_cleanup: core ? "complete" : "pending", pending_callbacks: callbacks });
  }
  #collect(): void {
    if (this.#finished) return;
    if (this.#drainStarted && !this.#startingDrain && this.#drain.operation.status().outcome === "pending") {
      let outcome: V4DrainOutcome = this.#childOutcome, pending = false;
      for (const child of this.#children) {
        const current = child.drainOutcome();
        if (current === "pending") pending = true; else outcome = combineOutcome(outcome, current);
      }
      if (!pending) { this.#startCleanup(); this.#drain.finish(outcome as Exclude<V4DrainOutcome, "pending">); }
    }
    if (!this.#startingDrain && this.#sealed && this.#listenerEnded && this.#children.size === 0) {
      this.#finished = true;
      if (this.#drainTimer !== undefined) clearTimeout(this.#drainTimer); this.#drainTimer = undefined;
      this.#parentSignal?.removeEventListener("abort", this.#parentAbort); this.#parentSignal = undefined;
      this.#sealListener = this.#abortListener = undefined; this.#callbacks = undefined;
      this.#drain.cleanup(complete); this.#drain.finish("failed"); this.#dependency!.release(); this.#dependency = undefined; this.#environment = undefined;
    } else this.#drain.cleanup(this.cleanupStatus());
    for (const wake of this.#observers) wake();
    if (this.#finished) {
      const observer = this.#cleanupObserver; this.#cleanupObserver = undefined;
      observer?.();
    }
  }
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus> {
    if (options?.signal?.aborted) return Promise.reject(this.failure("canceled"));
    const status = this.cleanupStatus(); if (status.status !== "pending") return Promise.resolve(status);
    if (this.#waiters >= 32) return Promise.reject(this.failure("resource_exhausted"));
    const ref = this.#dependency!.reference.borrow(); this.#waiters++;
    return new Promise((resolve, reject) => {
      let done = false, timer: ReturnType<typeof setTimeout> | undefined;
      const finish = (canceled = false, expired = false): void => {
        if (done) return; done = true;
        if (timer !== undefined) clearTimeout(timer); this.#observers.delete(wake);
        options?.signal?.removeEventListener("abort", abort); this.#waiters--; ref.release();
        const current = this.cleanupStatus();
        if (canceled) reject(new ServeError("canceled", current));
        else resolve(expired && current.status === "pending" ? cleanupResult({ ...current, status: "cleanup_incomplete" }) : current);
      };
      const abort = () => finish(true), wake = () => { if (this.cleanupStatus().status !== "pending") finish(); };
      this.#observers.add(wake); options?.signal?.addEventListener("abort", abort, { once: true });
      try {
        const window = new TrustedWindow(this.environment.clock, this.limits.cleanupMS);
        const tick = (): void => { try { window.check(); timer = setTimeout(tick, timerChunk(window.remainingMS())); } catch { finish(false, true); } };
        if (options?.signal?.aborted) abort(); else { wake(); if (!done) tick(); }
      } catch { finish(false, true); }
    });
  }
}

export class ServeIngress<Plan extends object> {
  readonly signal: AbortSignal;
  readonly invocation = Object.freeze({});
  readonly #abort = new AbortController();
  #window: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #callback = false;
  #authorization: ServeReleaseContext["authorization"] = "not_started";
  #context: AuthenticatedRequestContext | undefined;
  #lease: ApplicationAuthorizationLease | undefined;
  #leaseClosed = false;
  #leaseClosing = false;
  #session: (V4SessionOwner & { readonly cleanupOwner: SessionCleanup }) | undefined;
  #published = false;
  #delivered = false;
  #sessionDrain: V4DrainOperation | undefined;
  #drainFailed = false;
  #drainExcluded = false;
  #leaseCleanup: V4CleanupStatus | undefined;
  #releaseCleanup: V4CleanupStatus | undefined;
  #finishing = false;
  #finished = false;
  #cleanupObserved = false;
  #cleanupObserver: (() => void) | undefined;
  #nativeEnded = false;
  get coreEnded(): boolean { return this.#nativeEnded && (this.#session === undefined || this.#session.cleanupStatus().core_cleanup === "complete"); }
  nativeEnded(): void { this.#nativeEnded = true; this.group.changed(); }
  cleanupIncomplete(): boolean { return this.failed || this.#leaseCleanup?.status === "cleanup_incomplete"; }
  failed = false;
  constructor(readonly group: ServeGroup<Plan>, private readonly closeNative: () => void) { this.signal = this.#abort.signal; }
  startDeadline(): void {
    this.#window = new TrustedWindow(this.group.environment.clock, this.group.limits.handshakeMS);
    const tick = (): void => { if (this.#published || this.#finishing) return; try { this.check(); this.#timer = setTimeout(tick, timerChunk(this.#window!.remainingMS())); } catch { this.abort(); } };
    tick();
  }
  check(): void { this.group.checkIngress(); if (this.signal.aborted) throw this.group.failure("canceled"); this.#window?.check(); this.group.checkIngress(); if (this.signal.aborted) throw this.group.failure("canceled"); }
  pendingCallbacks(): bigint { return BigInt(Number(this.#callback) + Number(this.#leaseClosing)) + (this.#session?.cleanupStatus().pending_callbacks ?? 0n) + (this.#leaseCleanup?.pending_callbacks ?? 0n) + (this.#releaseCleanup?.pending_callbacks ?? 0n); }
  async #call<T>(callback: () => T | Promise<T>, cleanup = false): Promise<T> {
    if (this.#callback) throw this.group.failure("owner_unavailable"); this.#callback = true;
    try { if (!cleanup) this.check(); return await callback(); } finally { this.#callback = false; this.group.changed(); }
  }
  async resolveMaterial<T>(callback: () => Promise<T>): Promise<T> { this.check(); const result = await this.#call(callback); this.check(); return result; }
  async authorizeRequest(origin: string): Promise<void> {
    this.check(); const context = Object.freeze({ signal: this.signal, origin, invocation: this.invocation });
    const result = await this.#call(() => this.group.callbacks().authorizeRequest(context)); this.check();
    if (result?.allowed !== true) throw this.group.failure("rejected");
  }
  async authorize(authentication: V4AuthenticatedContext): Promise<Plan> {
    this.check(); if (this.#context !== undefined) throw this.group.failure("owner_unavailable");
    const context = this.#context = Object.freeze({ signal: this.signal, authentication, invocation: this.invocation });
    const handlers = await this.#call(() => this.group.callbacks().resolveHandlers(context)); this.check();
    this.#authorization = "unknown";
    const result = await this.#call(() => this.group.callbacks().authorizeApplication(context, handlers));
    // Capture a late result before checking cancellation, so its lease cannot
    // escape the original invocation's cleanup on cancellation or rejection.
    const lease = result?.lease;
    if (lease !== undefined) {
      const close = lease.close, waitCleanup = lease.waitCleanup;
      if (typeof close !== "function" || typeof waitCleanup !== "function") throw this.group.failure("authorization_unknown");
      this.#lease = Object.freeze({ close: () => close.call(lease), waitCleanup: (options?: OperationOptions) => waitCleanup.call(lease, options) });
    }
    if (result?.decision === "authorized" && this.#lease !== undefined) this.#authorization = "authorized";
    else if (result?.decision === "rejected") this.#authorization = "rejected";
    this.check();
    if (this.#authorization !== "authorized") throw this.group.failure(this.#authorization === "rejected" ? "rejected" : "authorization_unknown");
    return (result as { handlers: Plan }).handlers;
  }
  /** The authenticated assembly invokes this before starting any application
   * reader. The final claim and Drain/Close sealing share this original gate. */
  claim(session: V4SessionOwner & { readonly cleanupOwner: SessionCleanup }): void {
    if (this.#session !== undefined) throw this.group.failure("owner_unavailable"); this.#session = session;
    this.check();
    if (this.#context === undefined || this.#authorization !== "authorized") throw this.group.failure("owner_unavailable");
    this.#published = true; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
  }
  async publish(session: V4SessionOwner & { readonly cleanupOwner: SessionCleanup }): Promise<void> {
    if (this.#session === undefined) this.claim(session);
    if (this.#session !== session || !this.#published || this.#delivered) throw this.group.failure("owner_unavailable");
    return this.publishClaimed();
  }
  async publishClaimed(): Promise<void> {
    if (!this.#published || this.#delivered) return;
    const session = this.#session!;
    // This is the continuation of the original successful claim. A later
    // Drain/Close cannot revoke that one handoff; the Session may be closing.
    const facade = new V4Session(session); this.#delivered = true;
    const result = await this.#call(() => this.group.callbacks().onSession(facade, this.#context!), true);
    if (result?.accepted !== true) { this.abort(); throw this.group.failure("rejected"); }
  }
  drain(duration: bigint): void {
    // A Session that already terminated before this Drain owns cleanup only.
    if (this.#finishing) { this.#drainExcluded = true; return; }
    if (!this.#published) { this.abort(); return; }
    try { this.#sessionDrain = this.#session!.drain({ timeoutMS: duration }); }
    catch (error) {
      if (error instanceof TimeError && error.code === "time_expired") throw error;
      this.#drainFailed = true; this.abort();
    }
  }
  drainOutcome(): V4DrainOutcome {
    if (!this.#published || this.#drainExcluded) return "drained";
    if (this.#drainFailed) return "failed";
    return this.#sessionDrain?.status().outcome ?? (this.#finishing || this.#finished ? "failed" : "pending");
  }
  abort(): void {
    if (this.#finished) return;
    this.#abort.abort(); this.#burnLease(); if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.closeNative(); if (this.#session !== undefined) void this.#session.close().catch(() => { this.failed = true; this.group.changed(); });
  }
  #burnLease(): void {
    if (this.#lease === undefined || this.#leaseClosed) return; this.#leaseClosed = true;
    this.#leaseClosing = true;
    try { this.#lease.close(); } catch { this.#leaseCleanup = cleanupResult({ status: "cleanup_incomplete", core_cleanup: "complete", pending_callbacks: 0n }); } finally { this.#leaseClosing = false; this.group.changed(); }
  }
  finishUnused(): void { if (this.#finishing || this.#finished) return; this.#finished = true; this.group.retired(this); }
  async #observeLease(): Promise<boolean> {
    if (this.#lease === undefined) return true;
    this.#burnLease();
    try {
      const snapshot = await this.#call(() => this.#lease!.waitCleanup(), true);
      if (completeCleanup(snapshot)) { this.#lease = undefined; this.#leaseCleanup = undefined; return true; }
      this.#leaseCleanup = incompleteCleanup(snapshot);
    } catch { this.#leaseCleanup = cleanupResult({ status: "cleanup_incomplete", core_cleanup: "complete", pending_callbacks: 0n }); }
    this.group.changed(); return false;
  }
  /** The listener calls this only after its real native close has completed.
   * Actual Session cleanup remains joined even when a bounded wait times out. */
  async finish(): Promise<void> {
    if (this.#finishing || this.#finished) return; this.#finishing = true; this.nativeEnded();
    this.abort();
    try {
      if (this.#session !== undefined) {
        const session = this.#session;
        if (session.cleanupStatus().status !== "complete") await new Promise<void>(resolve => {
          session.cleanupOwner.onServeCleanup(resolve);
          if (session.cleanupStatus().status === "complete") resolve();
        });
        this.#session = undefined;
      }
      let leaseComplete = await this.#observeLease();
      const context = Object.freeze({ invocation: this.invocation, ...(this.#context === undefined ? {} : { authentication: this.#context.authentication }),
        authorization: this.#authorization, published: this.#published, cleanup: leaseComplete ? complete : this.#leaseCleanup! });
      let releaseComplete = false;
      try {
        const snapshot = await this.#call(() => this.group.callbacks().release(context), true);
        releaseComplete = completeCleanup(snapshot);
        if (!releaseComplete) this.#releaseCleanup = incompleteCleanup(snapshot);
      } catch { this.#releaseCleanup = incompleteCleanup(); }
      // A bounded lease wait is an observation, not actual completion. Reuse
      // this original position/task with one delayed observation at a time;
      // never overlap callbacks or repeat authorization/Release.
      let retryMS = 25;
      while (!leaseComplete) {
        await new Promise<void>(resolve => setTimeout(resolve, retryMS));
        leaseComplete = await this.#observeLease(); retryMS = Math.min(1000, retryMS * 2);
      }
      if (!releaseComplete) { this.failed = true; return; }
      this.#context = undefined; this.#finished = true; this.group.retired(this);
    } catch { this.failed = true; }
    finally { this.group.changed(); }
  }
}

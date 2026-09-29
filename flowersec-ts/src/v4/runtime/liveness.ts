import type { OperationOptions } from "../../public/contract.js";
import { V4LivenessError, type V4LivenessResult, type V4LivenessFailure, type V4AutomaticLivenessPolicy } from "../liveness.js";
import type { ClockMark, TrustedClock } from "./clock.js";
import { TrustedWindow, timerChunk, type TrustedDeadline } from "./deadline.js";
import { TimeError, timeAdd } from "./timeArithmetic.js";

interface Probe {
  readonly nonce: Uint8Array;
  readonly start: ClockMark;
  readonly window: TrustedWindow;
  readonly deadline: TrustedDeadline;
  readonly automatic: boolean;
  readonly signal: AbortSignal | undefined;
  readonly aborted: () => void;
  readonly resolve: (result: V4LivenessResult) => void;
  readonly reject: (error: V4LivenessError) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
  terminal: boolean;
  submitted: boolean;
  complete: boolean;
  tail: boolean;
  epoch: number;
  ticketedAt: ClockMark | undefined;
  completedAt: ClockMark | undefined;
  respondedAt: ClockMark | undefined;
  handoff: ClockMark | undefined;
}
export interface SessionLivenessHooks {
  check(): void;
  available(): boolean;
  stalled(): boolean;
  epoch(): number;
  submit(nonce: Uint8Array, ticket: () => void): Promise<void>;
  fail(code: "liveness_path_unresponsive" | "carrier_failed"): void;
  changed(): void;
}

/** Eight prepaid owners include their real provider tails. Terminal waiters do
 * not recycle a still-borrowed slot. No SDK queue or detached task is created
 * for the ninth caller. The automatic policy protects the eighth position. */
export class SessionLiveness {
  readonly #slots = new Set<Probe>();
  #counter = 0n;
  #closed = false;
  #rekey = false;
  #pumping = false;
  #submitting = false;
  #automatic: Probe | undefined;
  #next: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #started = false;
  #misses = 0;
  constructor(private readonly clock: TrustedClock, private readonly safety: TrustedDeadline, private readonly duration: bigint,
    private readonly policy: V4AutomaticLivenessPolicy | undefined, private readonly hooks: SessionLivenessHooks) {}
  start(): void { if (this.#started || this.#closed) return; this.#started = true; this.#schedule(); }
  probe(options?: OperationOptions): Promise<V4LivenessResult> { return this.#begin(false, options?.signal); }
  #begin(automatic: boolean, signal?: AbortSignal): Promise<V4LivenessResult> {
    let start: ClockMark | undefined;
    const refused = (code: V4LivenessFailure): Promise<V4LivenessResult> => Promise.reject(new V4LivenessError(code,
      { submitted: false, complete: false, elapsedMS: start === undefined ? null : this.#elapsed(start) }));
    if (this.#closed) return refused("closed");
    if (this.#rekey) return refused("rekey_in_progress");
    const ordinary = [...this.#slots].filter(p => !p.automatic).length;
    if (this.#slots.size >= 8 || !automatic && ordinary >= (this.policy === undefined ? 8 : 7) || automatic && this.#automatic !== undefined ||
        this.#counter === (1n << 128n) - 1n) return refused("resource_exhausted");
    if (signal?.aborted) return refused("canceled");
    let window: TrustedWindow, deadline: TrustedDeadline;
    try {
      const sample = this.clock.sample(); start = sample.mark;
      if (start === undefined) return refused("time_unavailable");
      const duration = automatic ? timeAdd(this.policy!.submissionMS, this.policy!.responseMS) : this.duration;
      window = new TrustedWindow(this.clock, duration, start);
      deadline = this.safety.forkAgeAt(sample, duration);
      this.hooks.check();
    } catch (error) { return refused(error instanceof TimeError ? "time_unavailable" : "closed"); }
    const nonce = new Uint8Array(16); let counter = ++this.#counter;
    for (let i = 15; i >= 0; i--) { nonce[i] = Number(counter & 255n); counter >>= 8n; }
    let probe!: Probe;
    const result = new Promise<V4LivenessResult>((resolve, reject) => {
      probe = { nonce, start: start!, window, deadline, automatic, signal, aborted: () => this.#finish(probe, "canceled"), resolve, reject,
        timer: undefined, terminal: false, submitted: false, complete: false, tail: false, epoch: 0,
        ticketedAt: undefined, completedAt: undefined, respondedAt: undefined, handoff: undefined };
    });
    this.#slots.add(probe); if (automatic) this.#automatic = probe;
    signal?.addEventListener("abort", probe.aborted, { once: true });
    if (signal?.aborted) this.#finish(probe, "canceled");
    this.#arm(probe); this.wake();
    return result;
  }
  #elapsed(start: ClockMark, now?: ClockMark): bigint | null {
    try { now ??= this.clock.monotonic(); return now.sameEra(start) && now.milliseconds >= start.milliseconds ? now.milliseconds - start.milliseconds : null; }
    catch { return null; }
  }
  #check(probe: Probe): boolean {
    if (probe.terminal) return false;
    try {
      probe.window.check();
    } catch (error) {
      this.#finish(probe, error instanceof TimeError && error.code === "time_expired" ? "timeout" : "time_unavailable");
      return false;
    }
    try {
      probe.deadline.check(); this.hooks.check();
      if (this.#rekey) { this.#finish(probe, "rekey_in_progress"); return false; }
      if (probe.signal?.aborted) { this.#finish(probe, "canceled"); return false; }
      return true;
    } catch (error) {
      this.#finish(probe, error instanceof TimeError && error.code !== "time_expired" ? "time_unavailable" : "closed");
      return false;
    }
  }
  #arm(probe: Probe): void {
    if (!this.#check(probe)) return;
    try {
      const a = probe.window.remainingMS(), b = probe.deadline.remainingMS();
      probe.timer = setTimeout(() => { probe.timer = undefined; this.#arm(probe); }, timerChunk(a < b ? a : b));
    } catch { if (this.#check(probe)) this.#finish(probe, "time_unavailable"); }
  }
  wake(): void {
    if (this.#pumping || this.#closed) return;
    this.#pumping = true;
    try {
      for (const probe of this.#slots) {
        if (probe.submitted || probe.tail || !this.#check(probe) || !this.hooks.available()) continue;
        if (probe.automatic && this.hooks.stalled()) { this.#finish(probe, "local_stall"); continue; }
        probe.tail = true; this.#submitting = probe.automatic;
        try {
          const tail = this.hooks.submit(probe.nonce, () => {
            probe.submitted = true; probe.epoch = this.hooks.epoch();
            try { probe.ticketedAt = this.clock.monotonic(); }
            catch { this.#finish(probe, "time_unavailable"); }
          });
          void tail.then(() => {
            probe.complete = true;
            try { probe.completedAt = this.clock.monotonic(); }
            catch { this.#finish(probe, "time_unavailable"); }
            if (!probe.terminal && this.#check(probe) && probe.automatic) {
              try {
                const now = probe.completedAt!, elapsed = this.#elapsed(probe.start, now);
                if (elapsed !== null && this.clock.profile.rate.elapsed(elapsed).upperMS <= this.policy!.submissionMS && !this.hooks.stalled()) probe.handoff = now;
              } catch { this.#finish(probe, "time_unavailable"); }
            }
            probe.tail = false; this.#collect(probe);
            if (!probe.terminal) this.hooks.changed();
          }, () => {
            this.#finish(probe, "provider_failed"); this.hooks.fail("carrier_failed");
            probe.tail = false; this.#collect(probe);
          });
        } catch {
          this.#finish(probe, "provider_failed"); this.hooks.fail("carrier_failed");
          probe.tail = false; this.#collect(probe);
        } finally { this.#submitting = false; }
      }
    } finally { this.#pumping = false; }
    this.#schedule();
  }
  /** Called only after outer authentication, schema and sequence commit. */
  pong(nonce: Uint8Array, epoch: number): void {
    for (const probe of this.#slots) {
      if (!probe.terminal && probe.submitted && probe.epoch === epoch && probe.nonce.every((value, i) => value === nonce[i]) && this.#check(probe)) {
        this.#finish(probe); return;
      }
    }
  }
  beginRekey(): void {
    this.#rekey = true; this.#clearSchedule();
    for (const probe of this.#slots) this.#finish(probe, "rekey_in_progress");
  }
  endRekey(completed: boolean): void {
    this.#rekey = false; if (completed) this.#misses = 0;
    this.#next = undefined; this.wake();
  }
  /** Known read/write/resource stalls invalidate a sample, never a peer miss.
   * The original probe's own publication is covered by its submission budget. */
  localStall(): void {
    if (!this.#submitting && this.#automatic !== undefined) this.#finish(this.#automatic, "local_stall");
  }
  #finish(probe: Probe, code?: V4LivenessFailure): void {
    if (probe.terminal) return;
    let now: ClockMark | undefined;
    try { now = this.clock.monotonic(); } catch { /* Elapsed is explicitly unavailable. */ }
    const elapsed = now === undefined ? null : this.#elapsed(probe.start, now);
    if (elapsed === null && code !== "closed" && code !== "provider_failed") code = "time_unavailable";
    if (code === undefined) probe.respondedAt = now;
    probe.terminal = true;
    if (probe.timer !== undefined) clearTimeout(probe.timer); probe.timer = undefined;
    probe.signal?.removeEventListener("abort", probe.aborted);
    const result = Object.freeze({ submitted: probe.submitted, complete: probe.complete, elapsedMS: elapsed });
    if (probe.automatic && !this.#closed) {
      if (code === undefined) this.#misses = 0;
      else if (code === "timeout" && probe.handoff !== undefined && now !== undefined && !this.#rekey && !this.hooks.stalled()) {
        const since = this.#elapsed(probe.handoff, now);
        try { if (since !== null && this.clock.profile.rate.elapsed(since).lowerMS >= this.policy!.responseMS) this.#misses++; }
        catch { /* An unavailable clock cannot establish a miss. */ }
      }
    }
    probe.nonce.fill(0);
    if (code === undefined) probe.resolve(result); else probe.reject(new V4LivenessError(code, result));
    this.#collect(probe);
    if (this.policy !== undefined && this.#misses >= this.policy.missThreshold) this.hooks.fail("liveness_path_unresponsive");
  }
  #collect(probe: Probe): void {
    if (!probe.terminal || probe.tail) return;
    this.#slots.delete(probe);
    if (this.#automatic === probe) { this.#automatic = undefined; this.#next = undefined; }
    this.#schedule(); this.hooks.changed();
  }
  #clearSchedule(): void { if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#next = undefined; }
  #schedule(): void {
    if (this.#closed || !this.#started || this.policy === undefined || this.#rekey || this.#automatic !== undefined || this.#timer !== undefined) return;
    try {
      this.#next ??= new TrustedWindow(this.clock, this.policy.intervalMS);
      this.#timer = setTimeout(() => {
        this.#timer = undefined;
        try { this.#next!.check(); this.#schedule(); }
        catch (error) {
          this.#next = undefined;
          if (error instanceof TimeError && error.code === "time_expired") {
            if (!this.hooks.stalled()) void this.#begin(true).catch(() => undefined);
            this.#schedule();
          }
          // Continuity loss disables this schedule; independent safety gates
          // still own Session convergence. It cannot become a peer miss.
        }
      }, timerChunk(this.#next.remainingMS()));
    } catch { this.#clearSchedule(); }
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true; this.#clearSchedule();
    for (const probe of this.#slots) this.#finish(probe, "closed");
  }
  cleanupComplete(): boolean { return this.#closed && this.#slots.size === 0; }
}

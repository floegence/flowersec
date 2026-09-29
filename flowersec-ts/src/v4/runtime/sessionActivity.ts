import type { TrustedClock } from "./clock.js";
import { TrustedWindow, timerChunk } from "./deadline.js";
import { TimeError, timeAdd, timeQuantity } from "./timeArithmetic.js";
import type { V4AutomaticLivenessPolicy } from "../liveness.js";

export function captureAutomaticLiveness(policy: V4AutomaticLivenessPolicy | undefined): V4AutomaticLivenessPolicy | undefined {
  if (policy === undefined) return undefined;
  const result = Object.freeze({ intervalMS: timeQuantity(policy.intervalMS), submissionMS: timeQuantity(policy.submissionMS),
    responseMS: timeQuantity(policy.responseMS), missThreshold: policy.missThreshold });
  timeAdd(result.submissionMS, result.responseMS);
  if (result.intervalMS === 0n || result.submissionMS === 0n || result.responseMS === 0n ||
      !Number.isSafeInteger(result.missThreshold) || result.missThreshold < 1 || result.missThreshold > 0xffffffff) throw new Error("configuration_capacity");
  return result;
}
export function selectedIdleDuration(signed: bigint, local?: bigint): bigint {
  timeQuantity(signed);
  if (local === undefined) return signed;
  if (timeQuantity(local) === 0n) throw new Error("configuration_capacity");
  return signed === 0n || local < signed ? local : signed;
}

export function qualifySessionActivity(clock: TrustedClock, idle: bigint, probe: bigint, policy: V4AutomaticLivenessPolicy | undefined): void {
  const durations = [probe, ...(idle === 0n ? [] : [idle]), ...(policy === undefined ? [] : [policy.intervalMS, policy.submissionMS, policy.responseMS, timeAdd(policy.submissionMS, policy.responseMS)])];
  for (const duration of durations) {
    if (timeQuantity(duration) <= clock.profile.rate.elapsed(0n).upperMS || clock.profile.rate.deadlineDelta(0n, duration) === 0n) throw new Error("configuration_capacity");
  }
}

/** The Session's prepaid timer starts at its completed publication gate.
 * Activity replaces only the monotonic anchor, after testing the old window.
 * A coalesced/late wake never starts a fresh duration. */
export class SessionIdleWatchdog {
  #window: TrustedWindow | undefined;
  #timer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  constructor(private readonly clock: TrustedClock, private readonly duration: bigint,
    private readonly fail: (code: "idle_timeout" | "time_unavailable") => void) {}
  start(): void {
    if (this.#closed || this.duration === 0n || this.#window !== undefined) return;
    try { this.#window = new TrustedWindow(this.clock, this.duration); this.#arm(); }
    catch { this.#failed("time_unavailable"); }
  }
  check(): void {
    try { this.#window?.check(); }
    catch (error) {
      this.#failed(error instanceof TimeError && error.code === "time_expired" ? "idle_timeout" : "time_unavailable");
      throw error;
    }
  }
  activity(): void {
    if (this.#closed || this.#window === undefined) return;
    try {
      const now = this.clock.monotonic();
      this.#window.checkAt(now);
      this.#window = new TrustedWindow(this.clock, this.duration, now);
    } catch (error) {
      this.#failed(error instanceof TimeError && error.code === "time_expired" ? "idle_timeout" : "time_unavailable");
      throw error;
    }
  }
  #arm(): void {
    if (this.#closed || this.#window === undefined) return;
    this.check();
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      try { this.#arm(); } catch { /* The original failure gate already closed. */ }
    }, timerChunk(this.#window.remainingMS()));
  }
  #failed(code: "idle_timeout" | "time_unavailable"): void {
    if (this.#closed) return;
    this.close(); this.fail(code);
  }
  close(): void { this.#closed = true; if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined; this.#window?.cancel(); }
}

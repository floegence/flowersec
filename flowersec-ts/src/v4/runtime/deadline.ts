import type { ClockMark, ClockSample, TrustedClock} from "./clock.js";
import { isClockSample } from "./clock.js";
import { TimeError, timeAdd, timeFailure, timeQuantity, type TimeFailure } from "./timeArithmetic.js";

const min = (a: bigint, b: bigint): bigint => a < b ? a : b;

// These bounded owners belong to their containing operation's original
// metadata reservation. They start no timer/task and do not allocate an
// alternate timeout service. Terminal facts are monotonic and never reset.
export class TrustedWindow {
  readonly #clock: TrustedClock;
  readonly #start: ClockMark;
  readonly #duration: bigint;
  #terminal: TimeFailure | undefined;
  constructor(clock: TrustedClock, duration: bigint, start = clock.monotonic()) {
    if (!start.belongsTo(clock)) timeFailure("time_owner");
    if (timeQuantity(duration) <= clock.profile.rate.elapsed(0n).upperMS) timeFailure("time_expired");
    this.#clock = clock; this.#start = start; this.#duration = duration;
    Object.freeze(this);
  }
  checkAt(now: ClockMark): void {
    if (this.#terminal !== undefined) timeFailure(this.#terminal);
    if (!this.#start.sameEra(now) || now.milliseconds < this.#start.milliseconds) {
      this.#terminal = "time_continuity"; timeFailure(this.#terminal);
    }
    try {
      if (this.#clock.profile.rate.elapsed(now.milliseconds - this.#start.milliseconds).upperMS >= this.#duration) timeFailure("time_expired");
    } catch (error) {
      this.#terminal = error instanceof TimeError ? error.code : "time_unavailable";
      timeFailure(this.#terminal);
    }
  }
  #sample(): ClockMark {
    if (this.#terminal !== undefined) timeFailure(this.#terminal);
    let now: ClockMark;
    try { now = this.#clock.monotonic(); }
    catch { this.#terminal = "time_continuity"; timeFailure(this.#terminal); }
    this.checkAt(now);
    return now;
  }
  check(): void { this.#sample(); }
  remainingMS(): bigint {
    const now = this.#sample(), delta = this.#clock.profile.rate.deadlineDelta(0n, this.#duration);
    const elapsed = now.milliseconds - this.#start.milliseconds;
    return elapsed >= delta ? 1n : delta - elapsed;
  }
  cancel(): void { this.#terminal ??= "time_cancelled"; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.TrustedWindow"; }
}

// A recoverable deadline always keeps the original absolute cap. Within one
// continuous clock era its monotonic projection can only move earlier. A new
// authenticated anchor cannot resurrect an already terminal operation.
export class TrustedDeadline {
  readonly #clock: TrustedClock;
  #cap: bigint;
  #projection: ClockMark | undefined;
  #until = 0n;
  #terminal: TimeFailure | undefined;
  constructor(clock: TrustedClock, cap: bigint, start?: ClockSample) {
    this.#clock = clock; this.#cap = timeQuantity(cap);
    this.checkAt(start ?? clock.sample());
    Object.freeze(this);
  }
  static ageAt(clock: TrustedClock, start: ClockSample, duration: bigint, parentCap: bigint): TrustedDeadline {
    if (!isClockSample(start) || !start.mark?.belongsTo(clock)) timeFailure("time_owner");
    const original = start.requireInterval();
    return new TrustedDeadline(clock, min(timeAdd(original.lowerMS, duration), timeQuantity(parentCap)), start);
  }
  belongsTo(clock: TrustedClock): boolean { return this.#clock === clock; }
  get cap(): bigint { return this.#cap; }
  checkAt(sample: ClockSample): void {
    if (this.#terminal !== undefined) timeFailure(this.#terminal);
    if (!isClockSample(sample)) timeFailure("time_owner");
    const mark = sample.mark;
    if (mark !== undefined && mark.sameEra(this.#projection) && mark.milliseconds >= this.#until) {
      this.#terminal = "time_expired"; timeFailure(this.#terminal);
    }
    // A genuine monotonic expiry above remains conclusive with no fresh wall
    // envelope. A live owner instead suspends on an unavailable wall sample.
    const value = sample.requireInterval();
    if (mark === undefined || !mark.belongsTo(this.#clock)) timeFailure("time_owner");
    try {
      if (value.upperMS >= this.#cap) timeFailure("time_expired");
      const delta = this.#clock.profile.rate.deadlineDelta(value.upperMS, this.#cap);
      let until = timeAdd(mark.milliseconds, delta);
      if (mark.sameEra(this.#projection)) until = min(until, this.#until);
      this.#projection = mark; this.#until = until;
      if (mark.milliseconds >= until) timeFailure("time_expired");
    } catch (error) {
      this.#terminal = error instanceof TimeError ? error.code : "time_unavailable";
      timeFailure(this.#terminal);
    }
  }
  sample(): ClockSample { const s = this.#clock.sample(); this.checkAt(s); return s; }
  check(): void { this.sample(); }
  remainingMS(): bigint { const s = this.sample(); return this.#until - s.mark!.milliseconds; }
  tighten(cap: bigint): void {
    timeQuantity(cap);
    if (cap > this.#cap) timeFailure("time_owner");
    this.#cap = cap; this.check();
  }
  #inherit(original: TrustedDeadline): void {
    if (this.#clock !== original.#clock) timeFailure("time_owner");
    this.#cap = min(this.#cap, original.#cap);
    if (this.#projection?.sameEra(original.#projection)) this.#until = min(this.#until, original.#until);
    else { this.#projection = original.#projection; this.#until = original.#until; }
  }
  tightenFrom(original: TrustedDeadline): void {
    if (this.#clock !== original.#clock) timeFailure("time_owner");
    if (this === original) { this.check(); return; }
    const sample = original.sample();
    this.#inherit(original); this.checkAt(sample);
  }
  fork(cap: bigint): TrustedDeadline {
    timeQuantity(cap);
    if (cap > this.#cap) timeFailure("time_owner");
    const sample = this.sample(), child = new TrustedDeadline(this.#clock, cap, sample);
    child.#inherit(this); child.checkAt(sample);
    return child;
  }
  forkAgeAt(start: ClockSample, duration: bigint): TrustedDeadline {
    const child = TrustedDeadline.ageAt(this.#clock, start, duration, this.#cap);
    const now = this.sample();
    child.#inherit(this); child.checkAt(now);
    return child;
  }
  tightenAgeAt(start: ClockSample, duration: bigint): void {
    if (duration === 0n) timeFailure("time_owner");
    const child = this.forkAgeAt(start, duration);
    this.#cap = child.#cap; this.#projection = child.#projection; this.#until = child.#until;
  }
  cancel(): void { this.#terminal ??= "time_cancelled"; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.TrustedDeadline"; }
}

// Host wakeups are finite chunks, never proof that a protocol action is legal.
// Every actual action must reenter its original deadline/authorization gate.
export function timerChunk(milliseconds: bigint): number {
  timeQuantity(milliseconds);
  if (milliseconds === 0n) return 1;
  return Number(milliseconds > 2147483647n ? 2147483647n : milliseconds);
}
for (const constructor of [TrustedWindow, TrustedDeadline]) { Object.freeze(constructor.prototype); Object.freeze(constructor); }

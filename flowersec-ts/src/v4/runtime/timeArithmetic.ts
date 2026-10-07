// Full-width L1 time arithmetic. All rounding is outward. These functions do
// not authenticate a clock source or establish the admitted oscillator bound.
export type TimeFailure = "time_rate" | "time_overflow" | "time_interval" | "time_width" | "time_round_trip" |
  "time_anchor_age" | "time_expired" | "time_deadline_unrepresentable" | "time_unavailable" |
  "time_continuity" | "time_contradiction" | "time_pending" | "time_not_proven" | "future_timestamp" | "time_cancelled" | "time_capacity" | "time_owner";
export class TimeError extends Error {
  readonly code: TimeFailure;
  constructor(code: TimeFailure) { super(code); this.name = "TimeError"; this.code = code; }
}
export function timeFailure(code: TimeFailure): never { throw new TimeError(code); }
export const maxTime = (1n << 64n) - 1n;
export function timeQuantity(n: bigint): bigint {
  if (typeof n !== "bigint" || n < 0n || n > maxTime) timeFailure("time_overflow");
  return n;
}
export function timeAdd(a: bigint, b: bigint): bigint {
  timeQuantity(a); timeQuantity(b);
  if (b > maxTime - a) timeFailure("time_overflow");
  return a + b;
}
function quotient(product: bigint, denominator: bigint, ceiling: boolean): bigint {
  if (product < 0n || product >= 1n << 128n || denominator <= 0n) timeFailure("time_overflow");
  return timeQuantity(product / denominator + (ceiling && product % denominator !== 0n ? 1n : 0n));
}
export interface TimeInterval { readonly lowerMS: bigint; readonly upperMS: bigint }
export function interval(lowerMS: bigint, upperMS: bigint, maxWidth: bigint): TimeInterval {
  timeQuantity(lowerMS); timeQuantity(upperMS); timeQuantity(maxWidth);
  if (lowerMS > upperMS) timeFailure("time_interval");
  if (maxWidth === 0n || upperMS - lowerMS > maxWidth) timeFailure("time_width");
  return Object.freeze({ lowerMS, upperMS });
}
const rates = new WeakSet<ClockRate>();
export function isClockRate(value: ClockRate): boolean { return rates.has(value); }
export class ClockRate {
  readonly numerator: bigint;
  readonly denominator: bigint;
  readonly quantizationMS: bigint;
  constructor(numerator: bigint, denominator: bigint, quantizationMS: bigint) {
    timeQuantity(numerator); timeQuantity(denominator); timeQuantity(quantizationMS);
    if (denominator === 0n || numerator >= denominator) timeFailure("time_rate");
    rates.add(this);
    this.numerator = numerator; this.denominator = denominator; this.quantizationMS = quantizationMS;
    Object.freeze(this);
  }
  elapsed(delta: bigint): TimeInterval {
    timeQuantity(delta);
    const lo = delta > this.quantizationMS ? delta - this.quantizationMS : 0n;
    const hi = timeAdd(delta, this.quantizationMS);
    return Object.freeze({ lowerMS: quotient(lo * this.denominator, this.denominator + this.numerator, false),
      upperMS: quotient(hi * this.denominator, this.denominator - this.numerator, true) });
  }
  advance(input: TimeInterval, delta: bigint, maxAge: bigint, maxWidth: bigint): TimeInterval {
    const lower = timeQuantity(input.lowerMS), upper = timeQuantity(input.upperMS);
    if (lower > upper) timeFailure("time_interval");
    const elapsed = this.elapsed(delta);
    if (timeQuantity(maxAge) === 0n || elapsed.upperMS > maxAge) timeFailure("time_anchor_age");
    return interval(timeAdd(lower, elapsed.lowerMS), timeAdd(upper, elapsed.upperMS), maxWidth);
  }
  networkAnchor(timestamp: bigint, sourceError: bigint, delta: bigint, maxRoundTrip: bigint, maxWidth: bigint): TimeInterval {
    timeQuantity(timestamp); timeQuantity(sourceError);
    const elapsed = this.elapsed(delta);
    if (timeQuantity(maxRoundTrip) === 0n || elapsed.upperMS > maxRoundTrip) timeFailure("time_round_trip");
    if (timestamp < sourceError) timeFailure("time_overflow");
    return interval(timestamp - sourceError, timeAdd(timeAdd(timestamp, sourceError), elapsed.upperMS), maxWidth);
  }
  deadlineDelta(upper: bigint, deadline: bigint): bigint {
    timeQuantity(upper); timeQuantity(deadline);
    if (upper >= deadline) timeFailure("time_expired");
    const delta = quotient((deadline - upper) * (this.denominator - this.numerator), this.denominator, false);
    if (delta < this.quantizationMS) timeFailure("time_deadline_unrepresentable");
    return delta - this.quantizationMS;
  }
  proveDelta(lower: bigint, bound: bigint): bigint {
    timeQuantity(lower); timeQuantity(bound);
    if (bound <= lower) return 0n;
    return timeAdd(quotient((bound - lower) * (this.denominator + this.numerator), this.denominator, true), this.quantizationMS);
  }
}
export function checkLowerBound(value: TimeInterval, bound: bigint, claimedPast: boolean): void {
  timeQuantity(bound);
  if (value.lowerMS > value.upperMS) timeFailure("time_unavailable");
  if (bound <= value.lowerMS) return;
  timeFailure(claimedPast && bound > value.upperMS ? "future_timestamp" : "time_pending");
}
export function validBefore(value: TimeInterval, bound: bigint): boolean { return value.lowerMS <= value.upperMS && value.upperMS < bound; }
export function retainedThrough(value: TimeInterval, bound: bigint): boolean { return value.lowerMS <= value.upperMS && value.lowerMS >= bound; }
Object.freeze(ClockRate.prototype); Object.freeze(ClockRate);

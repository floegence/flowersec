import { hostRandomFill, type RandomFill } from "./random.js";
import type { ResourceReference} from "./resources.js";
import { ResourceVector } from "./resources.js";
import type { ClockRate} from "./timeArithmetic.js";
import { TimeError, interval, isClockRate, maxTime, timeFailure, timeQuantity, type TimeFailure, type TimeInterval } from "./timeArithmetic.js";

const clockCapability = Symbol("clock mark");
export interface ClockProfile {
  readonly rate: ClockRate;
  readonly maxWidthMS: bigint;
  readonly maxAgeMS: bigint;
  readonly maxRoundTripMS: bigint;
}
export interface ClockTick { readonly milliseconds: bigint; readonly incarnation: string }
interface MarkState { owner: TrustedClock; era: bigint; milliseconds: bigint; incarnation: string }
const marks = new WeakMap<ClockMark, MarkState>();
export class ClockMark {
  constructor(token: symbol, state: MarkState) {
    if (token !== clockCapability) timeFailure("time_owner");
    marks.set(this, state); Object.freeze(this);
  }
  get milliseconds(): bigint { return marks.get(this)!.milliseconds; }
  sameEra(other: ClockMark | undefined): boolean {
    const a = marks.get(this), b = other === undefined ? undefined : marks.get(other);
    return a !== undefined && b !== undefined && a.owner === b.owner && a.era === b.era && a.incarnation === b.incarnation;
  }
  belongsTo(clock: TrustedClock): boolean { return marks.get(this)?.owner === clock; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ClockMark"; }
}
interface SampleState { mark: ClockMark | undefined; interval: TimeInterval | undefined; error: TimeFailure | undefined }
const samples = new WeakMap<ClockSample, SampleState>();
export function isClockSample(value: ClockSample): boolean { return samples.has(value); }
export class ClockSample {
  constructor(token: symbol, state: SampleState) {
    if (token !== clockCapability) timeFailure("time_owner");
    samples.set(this, state); Object.freeze(this);
  }
  get mark(): ClockMark | undefined { return samples.get(this)!.mark; }
  get interval(): TimeInterval | undefined { return samples.get(this)!.interval; }
  get error(): TimeFailure | undefined { return samples.get(this)!.error; }
  requireInterval(): TimeInterval {
    const s = samples.get(this)!;
    if (s.error !== undefined) timeFailure(s.error);
    if (s.interval === undefined) timeFailure("time_unavailable");
    return s.interval;
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.ClockSample"; }
}
interface Anchor { at: ClockMark; origin: ClockMark; interval: TimeInterval }

export function trustedClockCharge(runtimeBytes: bigint): ResourceVector {
  if (timeQuantity(runtimeBytes) === 0n) timeFailure("time_capacity");
  // Includes the complete clock, source closure, anchor, one original refresh,
  // nonce and bounded arithmetic temporaries in the declared host allowance.
  return new ResourceVector([runtimeBytes, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]);
}

// The source is an independently qualified, bounded host adapter. It must
// report loss of suspend/migration/rate continuity; performance.now alone is
// not such evidence. No carrier or peer timestamp installs a trusted anchor.
export class TrustedClock {
  readonly profile: ClockProfile;
  #source: (() => ClockTick) | undefined;
  #reservation: ResourceReference | undefined;
  #last: ClockTick | undefined;
  #era = 1n;
  #failed = false;
  #closed = false;
  #reading = false;
  #anchor: Anchor | undefined;
  #pending: NetworkTimeRequest | undefined;

  constructor(profile: ClockProfile, source: () => ClockTick, runtimeBytes: bigint, reservation: ResourceReference, private readonly random: RandomFill = hostRandomFill) {
    const rate = profile.rate;
    if (!isClockRate(rate) || typeof source !== "function") timeFailure("time_unavailable");
    const maxWidthMS = timeQuantity(profile.maxWidthMS), maxAgeMS = timeQuantity(profile.maxAgeMS), maxRoundTripMS = timeQuantity(profile.maxRoundTripMS);
    if (maxWidthMS === 0n || maxAgeMS === 0n || maxRoundTripMS === 0n) timeFailure("time_unavailable");
    rate.elapsed(rate.proveDelta(0n, maxWidthMS));
    this.profile = Object.freeze({ rate, maxWidthMS, maxAgeMS, maxRoundTripMS });
    this.#reservation = reservation.take(trustedClockCharge(runtimeBytes));
    this.#source = source;
    Object.freeze(this);
  }
  #breakContinuity(): void {
    this.#anchor = undefined;
    if (this.#era === maxTime) this.#closed = true;
    else this.#era++;
  }
  monotonic(): ClockMark {
    if (this.#closed || this.#reading || this.#source === undefined) timeFailure("time_unavailable");
    this.#reading = true;
    try {
      let milliseconds: bigint, incarnation: string;
      try {
        this.#reservation!.check();
        const tick = this.#source();
        milliseconds = timeQuantity(tick.milliseconds); incarnation = tick.incarnation;
        if (typeof incarnation !== "string" || !/^[0-9a-f]{32}$/u.test(incarnation) || /^0+$/u.test(incarnation) || this.#closed) timeFailure("time_unavailable");
        this.#reservation!.check();
      } catch {
        if (!this.#failed) this.#breakContinuity();
        this.#failed = true;
        return timeFailure("time_unavailable");
      }
      this.#failed = false;
      const previous = this.#last;
      this.#last = Object.freeze({ milliseconds, incarnation });
      if (previous !== undefined && incarnation !== previous.incarnation) this.#breakContinuity();
      else if (previous !== undefined && milliseconds < previous.milliseconds) {
        this.#breakContinuity(); timeFailure("time_continuity");
      }
      if (this.#closed) timeFailure("time_unavailable");
      return new ClockMark(clockCapability, { owner: this, era: this.#era, milliseconds, incarnation });
    } finally { this.#reading = false; this.#cleanup(); }
  }
  #interval(now: ClockMark): TimeInterval {
    const a = this.#anchor;
    if (a === undefined || !now.sameEra(a.origin) || now.milliseconds < a.at.milliseconds) timeFailure("time_unavailable");
    const p = this.profile;
    if (p.rate.elapsed(now.milliseconds - a.origin.milliseconds).upperMS > p.maxAgeMS) timeFailure("time_unavailable");
    return p.rate.advance(a.interval, now.milliseconds - a.at.milliseconds, p.maxAgeMS, p.maxWidthMS);
  }
  sample(): ClockSample {
    let mark: ClockMark | undefined;
    try {
      mark = this.monotonic();
      return new ClockSample(clockCapability, { mark, interval: this.#interval(mark), error: undefined });
    } catch (error) {
      // Preserve the genuine mark on lost wall freshness, so original owners
      // can still prove that an earlier monotonic deadline already expired.
      return new ClockSample(clockCapability, { mark, interval: undefined, error: error instanceof TimeError ? error.code : "time_unavailable" });
    }
  }
  #install(now: ClockMark, origin: ClockMark, value: TimeInterval): void {
    let selected = interval(value.lowerMS, value.upperMS, this.profile.maxWidthMS);
    let previous: TimeInterval | undefined;
    try { previous = this.#interval(now); } catch { /* No usable older envelope. */ }
    if (previous !== undefined) {
      if (selected.upperMS < previous.lowerMS || previous.upperMS < selected.lowerMS) {
        this.#anchor = undefined; timeFailure("time_contradiction");
      }
      selected = interval(selected.lowerMS > previous.lowerMS ? selected.lowerMS : previous.lowerMS,
        selected.upperMS < previous.upperMS ? selected.upperMS : previous.upperMS, this.profile.maxWidthMS);
    }
    this.#anchor = { at: now, origin, interval: selected };
  }
  installTrusted(at: ClockMark, input: TimeInterval): void {
    const value = interval(input.lowerMS, input.upperMS, this.profile.maxWidthMS), now = this.monotonic();
    if (!now.sameEra(at) || at.milliseconds > now.milliseconds) timeFailure("time_continuity");
    const p = this.profile;
    this.#install(now, at, p.rate.advance(value, now.milliseconds - at.milliseconds, p.maxAgeMS, p.maxWidthMS));
  }
  beginNetwork(): NetworkTimeRequest {
    if (this.#closed) timeFailure("time_unavailable");
    if (this.#pending !== undefined) timeFailure("time_capacity");
    const nonce = new Uint8Array(32);
    try { this.random(nonce); } catch { timeFailure("time_unavailable"); }
    const start = this.monotonic();
    if (this.#pending !== undefined || this.#closed) { nonce.fill(0); timeFailure("time_capacity"); }
    const request = new NetworkTimeRequest(clockCapability, this, start, nonce);
    this.#pending = request;
    return request;
  }
  // Only the original request's private state is allowed to release this slot.
  completeNetwork(token: symbol, request: NetworkTimeRequest, state: NetworkState, verified: { timestamp: bigint; sourceError: bigint } | undefined): void {
    if (token !== clockCapability || this.#pending !== request) timeFailure("time_owner");
    this.#pending = undefined;
    try {
      if (verified === undefined) return;
      if (state.cancelled) timeFailure("time_cancelled");
      const now = this.monotonic();
      if (state.start === undefined || !now.sameEra(state.start)) timeFailure("time_continuity");
      const p = this.profile;
      this.#install(now, now, p.rate.networkAnchor(verified.timestamp, verified.sourceError,
        now.milliseconds - state.start.milliseconds, p.maxRoundTripMS, p.maxWidthMS));
    } finally { this.#cleanup(); }
  }
  close(): void {
    this.#closed = true; this.#anchor = undefined;
    this.#pending?.cancel(); this.#cleanup();
  }
  #cleanup(): void {
    if (!this.#closed || this.#reading || this.#pending !== undefined) return;
    this.#source = undefined; this.#last = undefined;
    this.#reservation?.release(); this.#reservation = undefined;
  }
  cleanupComplete(): boolean { return this.#closed && this.#reservation === undefined; }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.TrustedClock"; }
}

interface NetworkState { clock: TrustedClock | undefined; start: ClockMark | undefined; nonce: Uint8Array; cancelled: boolean }
const requests = new WeakMap<NetworkTimeRequest, NetworkState>();
export class NetworkTimeRequest {
  constructor(token: symbol, clock: TrustedClock, start: ClockMark, nonce: Uint8Array) {
    if (token !== clockCapability) timeFailure("time_owner");
    requests.set(this, { clock, start, nonce, cancelled: false }); Object.freeze(this);
  }
  nonce(): Uint8Array {
    const s = requests.get(this)!;
    if (s.clock === undefined) timeFailure("time_owner");
    return s.nonce.slice();
  }
  cancel(): void { requests.get(this)!.cancelled = true; }
  release(): void { this.#finish(undefined); }
  completeVerified(nonce: Uint8Array, timestamp: bigint, sourceError: bigint): void {
    const s = requests.get(this)!;
    try { timeQuantity(timestamp); timeQuantity(sourceError); }
    catch { this.#finish(undefined); timeFailure("time_overflow"); }
    let difference = nonce.byteLength ^ 32;
    for (let i = 0; i < 32; i++) difference |= (nonce[i] ?? 0) ^ s.nonce[i]!;
    if (difference !== 0) { this.#finish(undefined); timeFailure("time_owner"); }
    this.#finish({ timestamp, sourceError });
  }
  #finish(verified: { timestamp: bigint; sourceError: bigint } | undefined): void {
    const s = requests.get(this)!, clock = s.clock;
    if (clock === undefined) timeFailure("time_owner");
    s.clock = undefined; s.nonce.fill(0);
    try { clock.completeNetwork(clockCapability, this, s, verified); }
    finally { s.start = undefined; }
  }
  toJSON(): object { return {}; }
  toString(): string { return "Flowersec.NetworkTimeRequest"; }
}
for (const constructor of [ClockMark, ClockSample, TrustedClock, NetworkTimeRequest]) {
  Object.freeze(constructor.prototype); Object.freeze(constructor);
}

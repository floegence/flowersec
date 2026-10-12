import type { V4EnvironmentClockConfig } from "../v4/runtime/environment.js";
import type { ClockProfile } from "../v4/runtime/clock.js";
import { ClockRate, type TimeInterval } from "../v4/runtime/timeArithmetic.js";

/** Engineering peers pair the initial wall envelope with the exact monotonic
 * tick requested by Environment, after its resource construction has finished. */
function pairedClock(profile: ClockProfile, uncertaintyMS: bigint): V4EnvironmentClockConfig {
  const beginning = performance.now();
  const monotonic = () => BigInt(Math.floor(performance.now() - beginning));
  let paired: TimeInterval | undefined;
  return Object.freeze({
    profile: Object.freeze(profile),
    tick: () => {
      let milliseconds: bigint;
      if (paired === undefined) {
        const before = BigInt(Date.now());
        milliseconds = monotonic();
        const after = BigInt(Date.now());
        if (after < before || after - before > 100n) throw new Error("unavailable engineering clock sample");
        paired = Object.freeze({ lowerMS: before - uncertaintyMS, upperMS: after + uncertaintyMS });
      } else {
        // Environment consumes the wall envelope once. Later ticks neither
        // resample the wall clock nor extend that original anchor's freshness.
        milliseconds = monotonic();
      }
      return { milliseconds, incarnation: "3".repeat(32) };
    },
    initial: () => {
      if (paired === undefined) throw new Error("missing engineering clock sample");
      return paired;
    },
  });
}

export function createCurrentPeerClock(): V4EnvironmentClockConfig {
  return pairedClock({ rate: new ClockRate(100n, 1000000n, 1n), maxWidthMS: 200n, maxAgeMS: 60000n, maxRoundTripMS: 10000n }, 50n);
}

export function createCurrentServerClock(): V4EnvironmentClockConfig {
  return pairedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 60000n, maxRoundTripMS: 100n }, 0n);
}

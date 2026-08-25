import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  artifactLeaseStateV3,
  claimArtifactLeaseV3,
  commitArtifactLeaseSpendV3,
  createArtifactLeaseV3Internal,
  duplicateArtifactLeaseHandleV3,
  retireArtifactLeaseV3,
} from "./artifactLease.js";
import {
  ControllerCycleStateV3,
  ControllerRetryWaitV3,
  aggregateCandidateFailuresV3,
  blockPolicyRefreshTriggersV3,
  endpointKeyV3,
  filterBlockedCandidatesV3,
  selectReplacementCandidatesV3,
  type ControllerClockV3,
} from "./controller.js";
import {
  TransportFailureV3,
  aggregateRetryDispositionsV3,
  controllerBackoffMillisecondsV3,
  snapshotTransportSecurityPolicyV3,
  validateRetryDispositionV3,
} from "./security.js";
import { decodeArtifactV3JSON, type CanonicalArtifactCandidateV3 } from "./artifact.js";

const artifactFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const controllerFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/controller_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  backoff_vectors: readonly Readonly<{ consecutive_failure: number; delay_ms: number }>[];
  retry_after: Readonly<{ valid: readonly number[]; invalid: readonly unknown[] }>;
  scenarios: readonly Readonly<{
    id: string;
    driver: string;
    steps: readonly string[];
    input: Readonly<Record<string, unknown>>;
    expected: Readonly<{
      final_state: string;
      acquisitions: number;
      connect_attempts: number;
      transports_created: number;
      replacement_acquisitions: number;
      replacement_quota_used: number;
      spend_callbacks: number;
      retire_callbacks: number;
      lease_terminal_states: readonly string[];
      retry_delays_ms: readonly number[];
    }>;
  }>[];
}>;
const artifact = decodeArtifactV3JSON(artifactFixture.positive[0]!.artifact_json);
const pinA = pinCandidate("pin-a", "https://a.example/flowersec/webtransport/v3/direct", 1);

describe("transport v3 controller, lease, and retry semantics", () => {
  test("recognizes every executable controller vector driver and accounting schema", () => {
    const supportedDrivers = new Set([
      "admission-spend-boundary",
      "attempt-exhaustion",
      "attempt-saturation",
      "candidate-capability-filter",
      "candidate-failure-aggregation",
      "candidate-security-aggregation",
      "capability-barrier",
      "cycle-reset",
      "cycle-reset-terminal",
      "duplicate-lease-identity",
      "expiry-boundary",
      "failure-ordinal",
      "lease-cancel-race",
      "multi-trigger-replacement",
      "policy-replacement",
      "post-spend-retry",
      "quota-preservation",
      "replacement-expiry",
      "replacement-acquisition",
      "retire-cleanup",
      "retry-after-clock",
      "retry-clock-boundary",
      "source-contract-validation",
    ]);
    const observedDrivers = new Set<string>();
    for (const scenario of controllerFixture.scenarios) {
      if (!supportedDrivers.has(scenario.driver)) {
        throw new Error(`unsupported controller vector driver ${scenario.driver} for ${scenario.id}`);
      }
      observedDrivers.add(scenario.driver);
      expect(scenario.steps.length).toBeGreaterThan(0);
      for (const field of [
        "acquisitions", "connect_attempts", "transports_created", "replacement_acquisitions",
        "replacement_quota_used", "spend_callbacks", "retire_callbacks",
      ] as const) {
        expect(scenario.expected[field], `${scenario.id}.${field}`).toBeGreaterThanOrEqual(0);
      }
      expect(scenario.expected.lease_terminal_states).toHaveLength(
        scenario.expected.spend_callbacks + scenario.expected.retire_callbacks,
      );
      expect(scenario.expected.retry_delays_ms.every((value) =>
        Number.isSafeInteger(value) && value >= 0 && value <= 30_000)).toBe(true);
    }
    expect(observedDrivers).toEqual(supportedDrivers);
  });

  test("implements the shared atomic lease state machine across duplicate handles", async () => {
    const spend = vi.fn(async () => undefined);
    const cleanup = vi.fn(async () => { throw new Error("redacted cleanup failure"); });
    const lease = createArtifactLeaseV3Internal(artifact, spend, cleanup);
    const duplicate = duplicateArtifactLeaseHandleV3(lease);
    const claim = claimArtifactLeaseV3(lease);
    expect(() => claimArtifactLeaseV3(duplicate)).toThrowError(/no longer available/);
    await retireArtifactLeaseV3(claim);
    expect(artifactLeaseStateV3(lease)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
    await expect(commitArtifactLeaseSpendV3(claim)).rejects.toMatchObject({ code: "already_consumed" });

    const consumed = createArtifactLeaseV3Internal(artifact, spend);
    const consumedClaim = claimArtifactLeaseV3(consumed);
    await commitArtifactLeaseSpendV3(consumedClaim);
    expect(artifactLeaseStateV3(consumed)).toBe("consumed");
    expect(spend).toHaveBeenCalledOnce();
  });

  test("matches retry-after and deterministic backoff vectors", () => {
    for (const vector of controllerFixture.backoff_vectors) {
      expect(controllerBackoffMillisecondsV3(vector.consecutive_failure)).toBe(vector.delay_ms);
    }
    for (const value of controllerFixture.retry_after.valid) {
      expect(validateRetryDispositionV3({ kind: "retry_after", absoluteUnixMilliseconds: value }))
        .toEqual({
          kind: "retry_after",
          notBeforeUnixMilliseconds: value,
          absoluteUnixMilliseconds: value,
        });
      expect(validateRetryDispositionV3({ kind: "retry_after", notBeforeUnixMilliseconds: value }))
        .toEqual({
          kind: "retry_after",
          notBeforeUnixMilliseconds: value,
          absoluteUnixMilliseconds: value,
        });
    }
    for (const value of controllerFixture.retry_after.invalid) {
      expect(() => validateRetryDispositionV3({
        kind: "retry_after",
        absoluteUnixMilliseconds: value as number,
      })).toThrowError();
    }
    expect(aggregateRetryDispositionsV3([
      { kind: "retryable" },
      { kind: "retry_after", absoluteUnixMilliseconds: 4_000 },
      { kind: "retry_after", absoluteUnixMilliseconds: 5_000 },
    ])).toEqual({
      kind: "retry_after",
      notBeforeUnixMilliseconds: 5_000,
      absoluteUnixMilliseconds: 5_000,
    });
  });

  test("filters same-endpoint pin-to-CA and every blocked old policy", () => {
    const path = "direct" as const;
    const cycle = new ControllerCycleStateV3();
    const key = endpointKeyV3(path, pinA);
    const changed = pinCandidate("pin-a", pinA.normalized_url, 2);
    const sameEndpointCA: CanonicalArtifactCandidateV3 = { ...pinA, tls: { mode: "ca" } };
    const newEndpointCA: CanonicalArtifactCandidateV3 = {
      ...sameEndpointCA,
      id: "ca-b",
      normalized_url: "https://b.example/flowersec/webtransport/v3/direct",
    };
    const eligible = selectReplacementCandidatesV3(
      path,
      [pinA],
      [sameEndpointCA, changed, newEndpointCA],
      new Set([key]),
      new Set([key]),
      cycle,
    );
    expect(eligible).toEqual([changed, newEndpointCA]);
    expect(filterBlockedCandidatesV3(path, [pinA, sameEndpointCA, changed, newEndpointCA], cycle))
      .toEqual([changed, newEndpointCA]);
  });

  test("aggregates security outcomes independently of completion order", () => {
    const entries = [
      { candidate: pinA, failure: new TransportFailureV3("tls_unsupported") },
      { candidate: pinA, failure: new TransportFailureV3("connection_failed") },
      { candidate: pinA, failure: new TransportFailureV3("tls_failed", "pin_mismatch") },
    ] as const;
    for (const failures of [entries, [...entries].reverse(), [entries[1]!, entries[2]!, entries[0]!]]) {
      expect(aggregateCandidateFailuresV3(failures, false)).toMatchObject({
        code: "transport_security_failed",
        disposition: { kind: "terminal" },
      });
    }
    expect(aggregateCandidateFailuresV3(entries, true)).toBe("policy_refresh");
  });

  test("does not refresh a pin policy for a CA-untrusted pin failure", () => {
    const failure = new TransportFailureV3("tls_failed", "ca_untrusted");
    expect(aggregateCandidateFailuresV3([{ candidate: pinA, failure }], true))
      .toMatchObject({
        code: "transport_security_failed",
        disposition: { kind: "terminal" },
      });
    const cycle = new ControllerCycleStateV3();
    expect(blockPolicyRefreshTriggersV3("direct", [{ candidate: pinA, failure }], cycle))
      .toEqual(new Set());
    expect(cycle.snapshot().replacementUsed).toBe(false);
  });

  test("snapshots only active pins and never constructs an empty pin policy", () => {
    const policy = {
      mode: "pin" as const,
      pins: [
        { ...pinA.tls.mode === "pin" ? pinA.tls.pins[0]! : never(), not_after_unix_s: 10 },
        { ...pinA.tls.mode === "pin" ? pinA.tls.pins[0]! : never(), not_after_unix_s: 20 },
      ],
    };
    expect(snapshotTransportSecurityPolicyV3(policy, 10, ["pin"])).toMatchObject({
      mode: "pin",
      activePins: [{ not_after_unix_s: 20 }],
    });
    expect(() => snapshotTransportSecurityPolicyV3(policy, 20, ["pin"]))
      .toThrowError(expect.objectContaining({ code: "tls_policy_expired" }));
    expect(() => snapshotTransportSecurityPolicyV3(policy, 1, ["ca"]))
      .toThrowError(expect.objectContaining({ code: "tls_unsupported" }));
  });

  test("uses monotonic backoff, wall rechecks, cancellation, and retryNow gates", async () => {
    const clock = new FakeClock(1_000, 0);
    const retry = new ControllerRetryWaitV3(clock);
    const signal = new AbortController();
    const waiting = retry.wait({ kind: "retry_after", absoluteUnixMilliseconds: 5_000 }, 1, signal.signal);
    await clock.nextSleep();
    expect(retry.retryNow()).toBe(false);
    clock.advance(1_000, 250);
    await clock.nextSleep();
    clock.advance(3_000, 0);
    await expect(waiting).resolves.toBe(true);

    const manualClock = new FakeClock(10_000, 0);
    const manual = new ControllerRetryWaitV3(manualClock);
    const manualWait = manual.wait({ kind: "retryable" }, 8, signal.signal);
    await manualClock.nextSleep();
    expect(manual.retryNow()).toBe(true);
    await expect(manualWait).resolves.toBe(true);
  });

  test("saturates monotonic timer deadlines at the safe-integer boundary", async () => {
    let monotonic = Number.MAX_SAFE_INTEGER - 1;
    const delays: number[] = [];
    const retry = new ControllerRetryWaitV3({
      wallNowMilliseconds: () => 0,
      monotonicNowMilliseconds: () => monotonic,
      sleep: async (milliseconds) => {
        delays.push(milliseconds);
        monotonic = Number.MAX_SAFE_INTEGER;
      },
    });
    await expect(retry.wait({ kind: "retryable" }, 1, new AbortController().signal)).resolves.toBe(true);
    expect(delays).toEqual([1]);
  });

  test("uses a 250ms first timer with the default fractional monotonic clock", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    let monotonicReads = 0;
    vi.spyOn(performance, "now").mockImplementation(() =>
      Date.now() - 1_000 + (monotonicReads++ === 0 ? 0.125 : 0.375));
    const timer = vi.spyOn(globalThis, "setTimeout");
    const cancellation = new AbortController();
    try {
      const wait = new ControllerRetryWaitV3().wait(
        { kind: "retryable" },
        1,
        cancellation.signal,
      );
      expect(timer).toHaveBeenCalledWith(expect.any(Function), 250);
      cancellation.abort(new Error("test complete"));
      await expect(wait).resolves.toBe(false);
    } finally {
      vi.restoreAllMocks();
      vi.useRealTimers();
    }
  });
});

function pinCandidate(id: string, normalizedURL: string, lastByte: number): CanonicalArtifactCandidateV3 {
  const bytes = new Uint8Array(32);
  bytes[31] = lastByte;
  return {
    carrier: "webtransport",
    id,
    normalized_url: normalizedURL,
    tls: {
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        not_after_unix_s: 2_000_000_000,
        value_b64u: Buffer.from(bytes).toString("base64url"),
      }],
    },
    wire_profile: "flowersec-direct/3",
  };
}

function never(): never {
  throw new Error("unreachable");
}

class FakeClock implements ControllerClockV3 {
  readonly #sleepers: Array<() => void> = [];
  readonly #observed: Array<() => void> = [];

  constructor(private wall: number, private mono: number) {}
  wallNowMilliseconds(): number { return this.wall; }
  monotonicNowMilliseconds(): number { return this.mono; }
  sleep(_milliseconds: number, signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      this.#sleepers.push(() => {
        signal.removeEventListener("abort", abort);
        resolve();
      });
      this.#observed.shift()?.();
    });
  }
  async nextSleep(): Promise<void> {
    if (this.#sleepers.length > 0) return;
    await new Promise<void>((resolve) => this.#observed.push(resolve));
  }
  advance(wall: number, mono: number): void {
    this.wall += wall;
    this.mono += mono;
    this.#sleepers.shift()?.();
  }
}

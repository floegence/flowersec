import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  artifactLeaseStateV3,
  commitArtifactLeaseSpendV3,
  createArtifactLeaseV3Internal,
  duplicateArtifactLeaseHandleV3,
  type ArtifactLeaseV3,
} from "./artifactLease.js";
import {
  createConnectionControllerV3,
  type ArtifactSourceResultV3,
  type ConnectionControllerV3,
  type LeaseAttemptContextV3,
  type ManagedSessionV3,
} from "./connectionController.js";
import {
  ControllerRetryWaitV3,
  aggregateCandidateFailuresV3,
  saturatingControllerIncrementV3,
  type ControllerClockV3,
} from "./controller.js";
import { decodeArtifactV3JSON, type ArtifactV3 } from "./artifact.js";
import {
  BrowserRuntimeCapabilityRegistryV3,
  createBrowserWebTransportCarrierV3,
} from "./browserRuntime.js";
import { detectNodeRuntimeCapabilityV3 } from "./nodeRuntime.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";
import { readyNativeAdmissionV3 } from "./runtimeAdapters.js";
import { attemptClaimedArtifactLeaseV3, type SessionConnectorRuntimeV3 } from "./sessionConnector.js";
import {
  ConnectErrorV3,
  TransportFailureV3,
} from "./security.js";

type ScenarioExpected = Readonly<{
  final_state: string;
  public_error: string | null;
  disposition: string | null;
  acquisitions: number;
  connect_attempts: number;
  transports_created: number;
  replacement_acquisitions: number;
  replacement_quota_used: number;
  spend_callbacks: number;
  retire_callbacks: number;
  lease_terminal_states: readonly string[];
  retry_delays_ms: readonly number[];
  [key: string]: unknown;
}>;

type ControllerScenario = Readonly<{
  id: string;
  driver: string;
  steps: readonly string[];
  input: Readonly<Record<string, unknown>>;
  expected: ScenarioExpected;
}>;

type ControllerFixture = Readonly<{
  version: number;
  scenarios: readonly ControllerScenario[];
  browser_capability_scenarios: readonly ControllerScenario[];
}>;

type ControllerObservation = Readonly<{
  final_state: string;
  public_error: string | null;
  disposition: string | null;
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

type ScenarioRunner = (scenario: ControllerScenario) => Promise<void>;

const artifactFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/controller_vectors.json", import.meta.url),
  "utf8",
)) as ControllerFixture;
const baseArtifact = decodeArtifactV3JSON(artifactFixture.positive[0]!.artifact_json);

const scenarioRunners: Readonly<Record<string, ScenarioRunner>> = Object.freeze({
  "pin-mismatch-changed-pin-success": runPolicyReplacement,
  "pin-mismatch-same-policy-terminal": runPolicyReplacement,
  "pin-to-ca-filtered": runPolicyReplacement,
  "browser-opaque-exhausted": runPolicyReplacement,
  "mixed-security-opaque-policy-refresh": runPolicyReplacement,
  "all-unsupported": runAllUnsupported,
  "replacement-expired-returns-primary": runReplacementExpired,
  "replacement-expired-before-race-returns-primary": runReplacementExpired,
  "replacement-acquisition-retryable-continues-search": runReplacementAcquisition,
  "post-spend-retry-preserves-quota": runPostSpendRetry,
  "lease-cancellation-first": runLeaseCancellation,
  "lease-delivery-first": runLeaseCancellation,
  "attempt-exhaustion": runAttemptExhaustion,
  "retry-after-and-monotonic-backoff": runRetryAfterController,
  "race-order-independent-security-priority": runSecurityPriority,
  "failure-ordinal-counts-attempt-once": runFailureOrdinal,
  "artifact-expiry-before-race": runExpiryBoundary,
  "artifact-expiry-at-race-end": runExpiryBoundary,
  "artifact-expiry-immediately-before-spend": runExpiryBoundary,
  "artifact-expiry-after-spend": runExpiryBoundary,
  "established-session-termination-resets-cycle": runCycleReset,
  "established-session-terminal-termination-resets-cycle": runTerminalCycleReset,
  "retry-after-wall-clock-forward-jump": runClockBoundary,
  "retry-after-wall-clock-backward-jump": runClockBoundary,
  "retry-after-wall-reread-bounded": runClockBoundary,
  "monotonic-timer-safe-integer-saturation": runClockBoundary,
  "single-ca-untrusted-terminal": runCASecurity,
  "ca-untrusted-dominates-ordinary-failure": runCASecurity,
  "multiple-pin-trigger-endpoints-filtered": runMultiTrigger,
  "retire-cleanup-failure-does-not-retry-lease": runRetireCleanup,
  "ordinary-retry-refresh-preserves-replacement-quota": runQuotaPreservation,
  "attempt-counter-safe-integer-saturation": runAttemptSaturation,
  "capability-snapshot-invalidation-barrier": runCapabilityBarrier,
  "primary-fsa3-reject-consumes-spent": runAdmissionBoundary,
  "primary-fsa3-retryable-consumes-spent": runAdmissionBoundary,
  "replacement-fsa3-reject-consumes-spent": runAdmissionBoundary,
  "replacement-fsa3-retryable-consumes-spent": runAdmissionBoundary,
  "primary-fsh3-failure-consumes-spent": runAdmissionBoundary,
  "replacement-fsh3-failure-consumes-spent": runAdmissionBoundary,
  "artifact-source-repeats-consumed-lease": runDuplicateLease,
  "artifact-source-repeats-retired-lease": runDuplicateLease,
});

const browserScenarioRunners: Readonly<Record<string, ScenarioRunner>> = Object.freeze({
  "concurrent-capability-invalidation-replacement-barrier": runConcurrentCapabilityReplacementBarrier,
});

describe("transport v3 shared controller vectors", () => {
  test("declares an exhaustive production runner map", () => {
    expect(fixture.version).toBe(3);
    expect(Object.keys(scenarioRunners).sort()).toEqual(fixture.scenarios.map(({ id }) => id).sort());
  });

  for (const scenario of fixture.scenarios) {
    test(scenario.id, async () => {
      const runner = scenarioRunners[scenario.id];
      if (runner === undefined) throw new Error(`missing TypeScript controller runner for ${scenario.id}`);
      await runner(scenario);
    });
  }
});

describe("transport v3 browser controller vectors", () => {
  test("declares an exhaustive production runner map", () => {
    expect(Object.keys(browserScenarioRunners).sort())
      .toEqual(fixture.browser_capability_scenarios.map(({ id }) => id).sort());
  });

  for (const scenario of fixture.browser_capability_scenarios) {
    test(scenario.id, async () => {
      const runner = browserScenarioRunners[scenario.id];
      if (runner === undefined) throw new Error(`missing TypeScript browser controller runner for ${scenario.id}`);
      await runner(scenario);
    });
  }
});

async function runPolicyReplacement(scenario: ControllerScenario): Promise<void> {
  const mixed = scenario.input.trigger === "mixed_security_opaque";
  const primary = mixed ? mixedCAPinArtifact(baseArtifact) : singleCandidateArtifact(baseArtifact, "t-pin");
  const replacementPolicy = scenario.input.replacement_policy;
  const replacement = replacementPolicy === "changed_pin"
    ? withChangedPin(primary)
    : replacementPolicy === "ca"
      ? withCandidateCA(primary)
      : primary;
  const tracker = new VectorTracker([primary, replacement], undefined, new Set(), new Set([1]));
  const session = managedSession();
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (context.kind === "replacement") {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established", session };
    }
    if (mixed) {
      const ca = context.candidates.find(({ id }) => id === "w-ca");
      const pin = context.candidates.find(({ id }) => id === "w-pin");
      if (ca === undefined || pin === undefined) throw new Error("mixed fixture candidates missing");
      return { kind: "candidate_failures", failures: [
        { candidate: ca, failure: new TransportFailureV3("tls_failed", "ca_untrusted") },
        { candidate: pin, failure: new TransportFailureV3("connection_failed", "browser_pin_opaque") },
      ] };
    }
    const opaque = scenario.input.trigger === "browser_pin_opaque";
    return { kind: "candidate_failures", failures: [{
      candidate: context.candidates[0]!,
      failure: opaque
        ? new TransportFailureV3("connection_failed", "browser_pin_opaque")
        : new TransportFailureV3("tls_failed", "pin_mismatch"),
    }] };
  }, controllerOptions(scenario.expected.acquisitions));
  await finishControllerScenario(controller, scenario, tracker, session);
}

async function runAllUnsupported(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact]);
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1, 0);
    return { kind: "candidate_failures", failures: context.candidates.slice(0, 2).map((candidate) => ({
      candidate,
      failure: new TransportFailureV3("tls_unsupported"),
    })) };
  }, controllerOptions(scenario.expected.acquisitions));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runReplacementExpired(scenario: ControllerScenario): Promise<void> {
  const changed = withChangedPin(baseArtifact);
  const replacement = scenario.input.expiry_boundary === "before_race"
    ? withInitExpiry(changed, 1)
    : changed;
  const tracker = new VectorTracker([baseArtifact, replacement, baseArtifact], undefined, new Set(), new Set([1]));
  const source = tracker.source();
  let now = 1_900_000_000;
  let finalCandidateIDs: readonly string[] = [];
  const session = managedSession();
  const controller = createConnectionControllerV3({
    acquire: async () => {
      if (tracker.acquisitions === 2) now = 1_900_000_000;
      return await source.acquire();
    },
  }, async (context) => {
    tracker.recordConnector(context, 1);
    if (tracker.connectAttempts === 1) return pinMismatch(context);
    if (tracker.connectAttempts === 2 && scenario.input.expiry_boundary !== "before_race") {
      now = context.artifact.session.init_expire_at_unix_s;
      return ordinaryCandidateFailure(context);
    }
    finalCandidateIDs = context.candidates.map(({ id }) => id);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session };
  }, {
    ...controllerOptions(scenario.expected.acquisitions, tracker.clock),
    nowUnixSeconds: () => now,
  });
  await finishControllerScenario(controller, scenario, tracker, session);
  expect(finalCandidateIDs).not.toContain("t-pin");
}

async function runReplacementAcquisition(scenario: ControllerScenario): Promise<void> {
  const changed = withChangedPin(baseArtifact);
  const tracker = new VectorTracker([baseArtifact, changed], undefined, new Set(), new Set([1]));
  const source = tracker.source();
  let acquisition = 0;
  const session = managedSession();
  const controller = createConnectionControllerV3({
    acquire: async () => {
      acquisition += 1;
      if (acquisition === 2) {
        tracker.acquisitions += 1;
        return {
          kind: "failure" as const,
          code: "connection_failed" as const,
          disposition: { kind: "retryable" as const },
        };
      }
      return await source.acquire();
    },
  }, async (context) => {
    tracker.recordConnector(context, 1);
    if (context.kind === "primary") return pinMismatch(context);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session };
  }, controllerOptions(scenario.expected.acquisitions, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker, session);
}

async function runPostSpendRetry(scenario: ControllerScenario): Promise<void> {
  const changed = withChangedPin(baseArtifact);
  const tracker = new VectorTracker([baseArtifact, changed, changed], undefined, new Set(), new Set([1]));
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (tracker.connectAttempts === 1) return pinMismatch(context);
    if (tracker.connectAttempts === 2) {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "post_spend_failure", error: retryableConnectionFailure() };
    }
    return pinMismatch(context);
  }, controllerOptions(scenario.expected.acquisitions, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runLeaseCancellation(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact]);
  if (scenario.input.linearization_winner === "cancellation") {
    let deliver!: (result: ArtifactSourceResultV3) => void;
    const controller = createConnectionControllerV3({
      acquire: async () => {
        tracker.acquisitions += 1;
        return await new Promise<ArtifactSourceResultV3>((resolve) => { deliver = resolve; });
      },
    }, async () => { throw new Error("connector must not run"); }, controllerOptions(0));
    controller.start();
    await Promise.resolve();
    const closing = controller.close();
    deliver({ kind: "lease", lease: tracker.leases[0]!.lease });
    await closing;
    assertObservation(scenario, tracker.observe(controller));
    return;
  }
  let connectorStarted!: () => void;
  const started = new Promise<void>((resolve) => { connectorStarted = resolve; });
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    connectorStarted();
    await new Promise<void>((resolve) => context.signal.addEventListener("abort", () => resolve(), { once: true }));
    return { kind: "pre_spend_failure", error: retryableConnectionFailure() };
  }, controllerOptions(0));
  controller.start();
  await started;
  await controller.close();
  assertObservation(scenario, tracker.observe(controller));
}

async function runAttemptExhaustion(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([]);
  const source = {
    acquire: async (): Promise<ArtifactSourceResultV3> => {
      tracker.acquisitions += 1;
      return { kind: "failure", code: "connection_failed", disposition: { kind: "retryable" } };
    },
  };
  const controller = createConnectionControllerV3(source, async () => {
    throw new Error("connector must not run");
  }, controllerOptions(numberInput(scenario, "maximum_attempts"), tracker.clock));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runRetryAfterController(scenario: ControllerScenario): Promise<void> {
  const clock = new AdvancingVectorClock(scenario);
  const tracker = new VectorTracker([baseArtifact], clock);
  let acquireCount = 0;
  const controller = createConnectionControllerV3({
    acquire: async () => {
      tracker.acquisitions += 1;
      acquireCount += 1;
      if (acquireCount === 1) return {
        kind: "failure" as const,
        code: "connection_failed",
        disposition: {
          kind: "retry_after" as const,
          absoluteUnixMilliseconds: numberInput(scenario, "retry_after_unix_ms"),
        },
      };
      return { kind: "lease" as const, lease: tracker.leases[0]!.lease };
    },
  }, async (context) => {
    tracker.recordConnector(context, 1);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session: managedSession() };
  }, controllerOptions(0, clock));
  controller.start();
  await clock.waitForSleepCount(1);
  expect(controller.retryNow()).toBe(scenario.expected.retry_now_allowed_before_deadline);
  await waitForControllerState(controller, "connected");
  assertObservation(scenario, tracker.observe(controller));
  await controller.close();
}

async function runSecurityPriority(scenario: ControllerScenario): Promise<void> {
  const permutations = scenario.input.permutations as readonly (readonly string[])[];
  for (const permutation of permutations) {
    const tracker = new VectorTracker([singleCandidateArtifact(baseArtifact, "w-ca")]);
    const controller = createConnectionControllerV3(tracker.source(), async (context) => {
      tracker.recordConnector(context, permutation.length);
      const failures = permutation.map((result) => ({
        candidate: context.candidates[0]!,
        failure: transportFailure(result),
      }));
      const aggregate = aggregateCandidateFailuresV3(failures, false);
      expect(aggregate).toMatchObject({ code: scenario.expected.public_error, disposition: { kind: "terminal" } });
      return { kind: "candidate_failures", failures };
    }, controllerOptions(1));
    await finishControllerScenario(controller, scenario, tracker);
  }
}

async function runFailureOrdinal(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact], new HoldingVectorClock());
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    const resultCount = (scenario.input.candidate_results as readonly string[]).length;
    tracker.recordConnector(context, resultCount);
    return { kind: "candidate_failures", failures: context.candidates.slice(0, resultCount).map((candidate) => ({
      candidate,
      failure: new TransportFailureV3("connection_failed"),
    })) };
  }, controllerOptions(0, tracker.clock));
  let attempt = 0;
  const unsubscribe = controller.subscribe((snapshot) => { attempt = snapshot.attempt; });
  await finishControllerScenario(controller, scenario, tracker);
  unsubscribe();
  expect(attempt).toBe(scenario.expected.failure_ordinal);
}

async function runExpiryBoundary(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact], new HoldingVectorClock());
  const boundary = scenario.input.expiry_boundary;
  let now = boundary === "before_race" ? baseArtifact.session.init_expire_at_unix_s : 1_900_000_000;
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (boundary === "race_end") {
      now = context.artifact.session.init_expire_at_unix_s;
      return ordinaryCandidateFailure(context);
    }
    if (boundary === "before_spend") {
      now = context.artifact.session.init_expire_at_unix_s;
      return {
        kind: "pre_spend_failure",
        error: new ConnectErrorV3("expired_artifact", { kind: "retryable" }),
      };
    }
    if (boundary === "after_spend") {
      await commitArtifactLeaseSpendV3(context.claim);
      now = context.artifact.session.init_expire_at_unix_s;
      return { kind: "post_spend_failure", error: new ConnectErrorV3("expired_artifact", { kind: "retryable" }) };
    }
    return ordinaryCandidateFailure(context);
  }, {
    ...controllerOptions(0, tracker.clock),
    nowUnixSeconds: () => now,
  });
  await finishControllerScenario(controller, scenario, tracker);
}

async function runCycleReset(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact, baseArtifact, baseArtifact]);
  let resolveTermination!: (value: Readonly<{ error: Error }>) => void;
  const firstSession: ManagedSessionV3 = {
    waitTermination: async () => await new Promise((resolve) => { resolveTermination = resolve; }),
    close: async () => undefined,
  };
  const finalSession = managedSession();
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (tracker.connectAttempts === 1) return ordinaryCandidateFailure(context);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session: tracker.connectAttempts === 2 ? firstSession : finalSession };
  }, {
    ...controllerOptions(0, tracker.clock),
    projectSessionFailure: (error: Error) => error as ConnectErrorV3,
  });
  controller.start();
  await waitForControllerState(controller, "connected");
  resolveTermination({ error: new ConnectErrorV3("connection_failed", { kind: "retryable" }) });
  await waitFor(() => tracker.connectAttempts === 3);
  await waitForControllerState(controller, "connected");
  assertObservation(scenario, tracker.observe(controller));
  await controller.close();
}

async function runTerminalCycleReset(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact]);
  let resolveTermination!: (value: Readonly<{ error: Error }>) => void;
  const session: ManagedSessionV3 = {
    waitTermination: async () => await new Promise((resolve) => { resolveTermination = resolve; }),
    close: async () => undefined,
  };
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session };
  }, {
    ...controllerOptions(0, tracker.clock),
    projectSessionFailure: (error: Error) => error as ConnectErrorV3,
  });
  controller.start();
  await waitForControllerState(controller, "connected");
  resolveTermination({ error: new ConnectErrorV3("connection_failed", { kind: "terminal" }) });
  await waitForControllerState(controller, "failed");
  let attempt: number | undefined;
  const unsubscribe = controller.subscribe((snapshot) => { attempt = snapshot.attempt; });
  unsubscribe();
  expect(attempt, scenario.id).toBe(scenario.expected.attempt);
  expect(scenario.expected.failure_ordinal, scenario.id).toBe(1);
  assertObservation(scenario, tracker.observe(controller));
  await controller.close();
}

async function runClockBoundary(scenario: ControllerScenario): Promise<void> {
  const clock = new AdvancingVectorClock(scenario);
  const wait = new ControllerRetryWaitV3(clock);
  const abort = new AbortController();
  const waiting = wait.wait({
    kind: "retry_after",
    absoluteUnixMilliseconds: numberInput(scenario, "retry_after_unix_ms"),
  }, numberInput(scenario, "failure_ordinal"), abort.signal);
  if (scenario.expected.final_state === "waiting") {
    await clock.waitForSleepCount(scenario.expected.retry_delays_ms.length);
  } else {
    await expect(waiting).resolves.toBe(true);
  }
  expect(clock.delays).toEqual(scenario.expected.retry_delays_ms);
  expect(clock.wallNowMilliseconds()).toBe(scenario.expected.wall_end_ms);
  expect(clock.monotonicNowMilliseconds()).toBe(scenario.expected.monotonic_end_ms);
  if (scenario.expected.final_state === "waiting") {
    abort.abort();
    await expect(waiting).resolves.toBe(false);
  }
}

async function runCASecurity(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([singleCandidateArtifact(baseArtifact, "w-ca")]);
  const results = scenario.input.candidate_results as readonly string[];
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, results.length);
    return { kind: "candidate_failures", failures: results.map((result) => ({
      candidate: context.candidates[0]!,
      failure: transportFailure(result),
    })) };
  }, controllerOptions(1));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runMultiTrigger(scenario: ControllerScenario): Promise<void> {
  const primary = twoPinArtifact(baseArtifact);
  const tracker = new VectorTracker([primary, primary], undefined, new Set(), new Set([1]));
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, context.candidates.length);
    return { kind: "candidate_failures", failures: context.candidates.map((candidate) => ({
      candidate,
      failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
    })) };
  }, controllerOptions(2));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runRetireCleanup(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact, baseArtifact], undefined, new Set([0]));
  const session = managedSession();
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (tracker.connectAttempts === 1) return ordinaryCandidateFailure(context);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session };
  }, controllerOptions(0, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker, session);
}

async function runQuotaPreservation(scenario: ControllerScenario): Promise<void> {
  const changed = withChangedPin(baseArtifact);
  const tracker = new VectorTracker([baseArtifact, baseArtifact, changed], undefined, new Set(), new Set([2]));
  const session = managedSession();
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (tracker.connectAttempts === 1) return ordinaryCandidateFailure(context);
    if (tracker.connectAttempts === 2) return pinMismatch(context);
    await commitArtifactLeaseSpendV3(context.claim);
    return { kind: "established", session };
  }, controllerOptions(0, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker, session);
}

async function runAttemptSaturation(scenario: ControllerScenario): Promise<void> {
  const maximum = numberInput(scenario, "maximum_attempts");
  const initial = numberInput(scenario, "initial_attempt");
  expect(maximum).toBe(Number.MAX_SAFE_INTEGER);
  expect(saturatingControllerIncrementV3(initial)).toBe(scenario.expected.attempt);
  expect(scenario.expected.counter_saturated).toBe(true);
}

async function runCapabilityBarrier(scenario: ControllerScenario): Promise<void> {
  const artifact = singleCandidateArtifact(baseArtifact, "t-pin");
  let constructorCalls = 0;
  class UnexpectedWebTransport {
    constructor() {
      constructorCalls += 1;
      throw new Error("the live capability gate must run before WebTransport construction");
    }
  }
  const registry = await BrowserRuntimeCapabilityRegistryV3.create({
    WebSocket: class {},
    WebTransport: UnexpectedWebTransport,
    navigator: {
      userAgentData: {
        async getHighEntropyValues() {
          return { fullVersionList: [{ brand: "Chromium", version: "151.0.7922.34" }] };
        },
      },
    },
  });
  expect(registry.pinEnabled()).toBe(true);

  let releaseDial!: () => void;
  const dialReleased = new Promise<void>((resolve) => { releaseDial = resolve; });
  let signalDialArrived!: () => void;
  const dialArrived = new Promise<void>((resolve) => { signalDialArrived = resolve; });
  const runtime: SessionConnectorRuntimeV3 = {
    capabilitySnapshot: () => registry.snapshot(),
    protocolRuntime: nodeSessionRuntimeV3,
    dial: async (candidate, acquiredArtifact, attemptNow, capability, signal) => {
      signalDialArrived();
      await dialReleased;
      const carrier = await createBrowserWebTransportCarrierV3(
        candidate,
        attemptNow,
        capability,
        registry,
        acquiredArtifact.session.max_inbound_streams + 2,
        signal,
      );
      return readyNativeAdmissionV3(candidate, carrier);
    },
  };
  const tracker = new VectorTracker([artifact]);
  let snapshots = 0;
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, context.candidates.length, 0);
    return await attemptClaimedArtifactLeaseV3(context, runtime);
  }, {
    ...controllerOptions(1),
    capabilitySnapshot: () => {
      snapshots += 1;
      return registry.snapshot();
    },
  });

  controller.start();
  await dialArrived;
  expect(registry.invalidatePinSupport()).toBe(true);
  releaseDial();
  await finishControllerScenario(controller, scenario, tracker);
  expect(snapshots).toBe(1);
  expect(registry.pinEnabled()).toBe(false);
  expect(constructorCalls).toBe(0);
  expect(scenario.expected.capability_rechecked).toBe(true);
}

async function runConcurrentCapabilityReplacementBarrier(scenario: ControllerScenario): Promise<void> {
  const refreshPrimary = browserWebTransportArtifact(baseArtifact, [{
    id: "refresh-pin",
    host: "refresh-primary.example",
    tls: "pin",
  }]);
  const refreshReplacement = browserWebTransportArtifact(withChangedPin(refreshPrimary), [
    { id: "refresh-pin", host: "refresh-primary.example", tls: "existing" },
    { id: "replacement-ca", host: "replacement-ca.example", tls: "ca" },
  ]);
  const stalePrimary = browserWebTransportArtifact(baseArtifact, [
    { id: "stale-blocked", host: "stale-blocked.example", tls: "pin" },
    { id: "stale-invalidator", host: "stale-invalidator.example", tls: "pin" },
  ]);

  type ConstructorCall = Readonly<{ pin: boolean; registryState: "enabled" | "ca_only"; url: string }>;
  const constructorCalls: ConstructorCall[] = [];
  let constructedTransports = 0;
  let registry!: BrowserRuntimeCapabilityRegistryV3;
  class CoordinatedWebTransport {
    readonly ready: Promise<void>;
    constructor(url: string, options?: unknown) {
      constructorCalls.push({ pin: options !== undefined, registryState: registry.pinEnabled() ? "enabled" : "ca_only", url });
      if (url.includes("stale-invalidator.example")) {
        throw new DOMException("unsupported", "NotSupportedError");
      }
      constructedTransports += 1;
      if (url.includes("refresh-primary.example")) {
        this.ready = Promise.reject(new Error("opaque browser pin failure"));
        return;
      }
      if (url.includes("replacement-ca.example")) {
        this.ready = Promise.reject(new Error("ordinary CA transport failure"));
        return;
      }
      throw new Error("the old capability snapshot must fail at the live gate");
    }
    close(): void {}
  }
  registry = await BrowserRuntimeCapabilityRegistryV3.create({
    WebSocket: class {},
    WebTransport: CoordinatedWebTransport,
    navigator: {
      userAgentData: {
        async getHighEntropyValues() {
          return { fullVersionList: [{ brand: "Chromium", version: "151.0.7922.34" }] };
        },
      },
    },
  });
  expect(registry.pinEnabled()).toBe(true);

  let releaseFirstAcquisitions!: () => void;
  const firstAcquisitionsReleased = new Promise<void>((resolve) => { releaseFirstAcquisitions = resolve; });
  let activeAcquisitions = 0;
  let concurrentAcquisitionPeak = 0;
  let acquisitions = 0;
  const acquireFirst = async (lease: ArtifactLeaseV3): Promise<ArtifactSourceResultV3> => {
    acquisitions += 1;
    activeAcquisitions += 1;
    concurrentAcquisitionPeak = Math.max(concurrentAcquisitionPeak, activeAcquisitions);
    try {
      await firstAcquisitionsReleased;
      return { kind: "lease", lease };
    } finally {
      activeAcquisitions -= 1;
    }
  };

  let releasePrimaryRetirement!: () => void;
  const primaryRetirementReleased = new Promise<void>((resolve) => { releasePrimaryRetirement = resolve; });
  let signalPrimaryRetirement!: () => void;
  const primaryRetirementStarted = new Promise<void>((resolve) => { signalPrimaryRetirement = resolve; });
  const spends = [vi.fn(async () => undefined), vi.fn(async () => undefined), vi.fn(async () => undefined)];
  const retires = [
    vi.fn(async () => {
      signalPrimaryRetirement();
      await primaryRetirementReleased;
    }),
    vi.fn(async () => undefined),
    vi.fn(async () => undefined),
  ];
  const leases = [
    createArtifactLeaseV3Internal(refreshPrimary, spends[0]!, retires[0]),
    createArtifactLeaseV3Internal(refreshReplacement, spends[1]!, retires[1]),
    createArtifactLeaseV3Internal(stalePrimary, spends[2]!, retires[2]),
  ];

  const capabilitySnapshots: Array<"enabled" | "ca_only"> = [];
  const snapshot = () => {
    capabilitySnapshots.push(registry.pinEnabled() ? "enabled" : "ca_only");
    return registry.snapshot();
  };
  let connectorAttempts = 0;
  let dialCalls = 0;
  const replacementDialCandidateIDs: string[] = [];
  let oldSnapshotLiveGateFailures = 0;
  const runtime = (stale: boolean): SessionConnectorRuntimeV3 => ({
    capabilitySnapshot: () => registry.snapshot(),
    protocolRuntime: nodeSessionRuntimeV3,
    dial: async (candidate, artifact, attemptNow, capability, signal) => {
      dialCalls += 1;
      if (candidate.id.startsWith("replacement-")) replacementDialCandidateIDs.push(candidate.id);
      if (stale && candidate.id === "stale-invalidator") await primaryRetirementStarted;
      if (stale && candidate.id === "stale-blocked") await waitFor(() => !registry.pinEnabled());
      const callsBefore = constructorCalls.length;
      try {
        const carrier = await createBrowserWebTransportCarrierV3(
          candidate,
          attemptNow,
          capability,
          registry,
          artifact.session.max_inbound_streams + 2,
          signal,
        );
        return readyNativeAdmissionV3(candidate, carrier);
      } catch (error) {
        if (candidate.id === "stale-blocked" && constructorCalls.length === callsBefore &&
            error instanceof TransportFailureV3 && error.code === "tls_unsupported") {
          oldSnapshotLiveGateFailures += 1;
        }
        throw error;
      }
    },
  });

  let refreshAcquisition = 0;
  let replacementAcquisitions = 0;
  const refreshController = createConnectionControllerV3({
    acquire: async () => {
      const index = refreshAcquisition++;
      if (index === 0) return await acquireFirst(leases[0]!);
      if (index !== 1) throw new Error("refresh source exhausted");
      acquisitions += 1;
      replacementAcquisitions += 1;
      return { kind: "lease", lease: leases[1]! };
    },
  }, async (context) => {
    connectorAttempts += 1;
    return await attemptClaimedArtifactLeaseV3(context, runtime(false));
  }, {
    ...controllerOptions(2),
    capabilitySnapshot: snapshot,
  });
  const staleController = createConnectionControllerV3({
    acquire: async () => await acquireFirst(leases[2]!),
  }, async (context) => {
    connectorAttempts += 1;
    return await attemptClaimedArtifactLeaseV3(context, runtime(true));
  }, {
    ...controllerOptions(1),
    capabilitySnapshot: snapshot,
  });

  refreshController.start();
  staleController.start();
  try {
    await waitFor(() => concurrentAcquisitionPeak === 2);
    releaseFirstAcquisitions();
    await primaryRetirementStarted;
    await waitFor(() => !registry.pinEnabled());
    await waitForControllerState(staleController, "failed");
    releasePrimaryRetirement();
    await waitForControllerState(refreshController, "failed");

    const observed = {
      final_state: refreshController.state,
      public_error: refreshController.failure?.code ?? null,
      disposition: controllerDisposition(refreshController),
      acquisitions,
      connect_attempts: dialCalls,
      transports_created: constructedTransports,
      replacement_acquisitions: replacementAcquisitions,
      replacement_quota_used: replacementAcquisitions,
      spend_callbacks: spends.reduce((sum, callback) => sum + callback.mock.calls.length, 0),
      retire_callbacks: retires.reduce((sum, callback) => sum + callback.mock.calls.length, 0),
      lease_terminal_states: leases.map((lease) => artifactLeaseStateV3(lease)),
      retry_delays_ms: [],
      concurrent_acquisition_peak: concurrentAcquisitionPeak,
      controller_connector_attempts: connectorAttempts,
      capability_snapshots: capabilitySnapshots,
      pin_constructor_calls: constructorCalls.filter(({ pin }) => pin).length,
      ca_constructor_calls: constructorCalls.filter(({ pin }) => !pin).length,
      old_snapshot_live_gate_failures: oldSnapshotLiveGateFailures,
      post_invalidation_pin_constructor_calls: constructorCalls.filter(({ pin, registryState }) =>
        pin && registryState === "ca_only").length,
      replacement_dial_candidate_ids: replacementDialCandidateIDs,
      peer_final_state: staleController.state,
      peer_public_error: staleController.failure?.code ?? null,
    };
    expect(observed, scenario.id).toEqual(scenario.expected);
  } finally {
    releaseFirstAcquisitions();
    releasePrimaryRetirement();
    await Promise.all([refreshController.close(), staleController.close()]);
  }
}

async function runAdmissionBoundary(scenario: ControllerScenario): Promise<void> {
  const replacement = scenario.input.phase === "replacement";
  const tracker = new VectorTracker(
    replacement ? [baseArtifact, withChangedPin(baseArtifact)] : [baseArtifact],
    scenario.expected.final_state === "waiting" ? new HoldingVectorClock() : undefined,
    new Set(),
    replacement ? new Set([1]) : new Set(),
  );
  const controller = createConnectionControllerV3(tracker.source(), async (context) => {
    tracker.recordConnector(context, 1);
    if (replacement && context.kind === "primary") return pinMismatch(context);
    await commitArtifactLeaseSpendV3(context.claim);
    return {
      kind: "post_spend_failure",
      error: new ConnectErrorV3("connection_failed", {
        kind: scenario.input.admission_result === "fsa_reject" ? "terminal" : "retryable",
      }),
    };
  }, controllerOptions(0, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker);
}

async function runDuplicateLease(scenario: ControllerScenario): Promise<void> {
  const tracker = new VectorTracker([baseArtifact]);
  const duplicate = duplicateArtifactLeaseHandleV3(tracker.leases[0]!.lease);
  let acquisitions = 0;
  const controller = createConnectionControllerV3({
    acquire: async () => {
      tracker.acquisitions += 1;
      acquisitions += 1;
      return { kind: "lease", lease: acquisitions === 1 ? tracker.leases[0]!.lease : duplicate };
    },
  }, async (context) => {
    tracker.recordConnector(context, 1);
    if (scenario.input.repeated_terminal_state === "consumed") {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "post_spend_failure", error: retryableConnectionFailure() };
    }
    return { kind: "pre_spend_failure", error: retryableConnectionFailure() };
  }, controllerOptions(2, tracker.clock));
  await finishControllerScenario(controller, scenario, tracker);
}

class VectorTracker {
  readonly leases: Array<Readonly<{ lease: ArtifactLeaseV3; spend: ReturnType<typeof vi.fn>; retire: ReturnType<typeof vi.fn> }>>;
  readonly clock: ControllerClockV3 & { delays: number[] };
  acquisitions = 0;
  connectAttempts = 0;
  transportsCreated = 0;
  replacementAcquisitions = 0;
  readonly #replacementIndexes: ReadonlySet<number>;

  constructor(
    artifacts: readonly ArtifactV3[],
    clock: (ControllerClockV3 & { delays: number[] }) | undefined = undefined,
    failingRetireIndexes: ReadonlySet<number> = new Set(),
    replacementIndexes: ReadonlySet<number> = new Set(),
  ) {
    this.clock = clock ?? new ImmediateVectorClock();
    this.#replacementIndexes = replacementIndexes;
    this.leases = artifacts.map((artifact, index) => {
      const spend = vi.fn(async () => undefined);
      const retire = vi.fn(async () => {
        if (failingRetireIndexes.has(index)) throw new Error("deployment cleanup failed");
      });
      return { lease: createArtifactLeaseV3Internal(artifact, spend, retire), spend, retire };
    });
  }

  source() {
    let index = 0;
    return {
      acquire: async (): Promise<ArtifactSourceResultV3> => {
        const lease = this.leases[index];
        if (lease === undefined) throw new Error("vector source exhausted");
        this.acquisitions += 1;
        if (this.#replacementIndexes.has(index)) this.replacementAcquisitions += 1;
        index += 1;
        return { kind: "lease", lease: lease.lease };
      },
    };
  }

  recordConnector(
    _context: LeaseAttemptContextV3,
    candidateAttempts: number,
    transportsCreated: number = candidateAttempts,
  ): void {
    this.connectAttempts += candidateAttempts;
    this.transportsCreated += transportsCreated;
  }

  observe(controller: ReturnType<typeof createConnectionControllerV3>): ControllerObservation {
    let disposition: string | null = null;
    const unsubscribe = controller.subscribe((snapshot) => {
      disposition = snapshot.retryDisposition?.kind ?? null;
    });
    unsubscribe();
    return {
      final_state: controller.state,
      public_error: controller.failure?.code ?? null,
      disposition,
      acquisitions: this.acquisitions,
      connect_attempts: this.connectAttempts,
      transports_created: this.transportsCreated,
      replacement_acquisitions: this.replacementAcquisitions,
      replacement_quota_used: this.replacementAcquisitions,
      spend_callbacks: this.leases.reduce((sum, value) => sum + value.spend.mock.calls.length, 0),
      retire_callbacks: this.leases.reduce((sum, value) => sum + value.retire.mock.calls.length, 0),
      lease_terminal_states: this.leases.map(({ lease }) => artifactLeaseStateV3(lease)),
      retry_delays_ms: [...this.clock.delays],
    };
  }
}

class ImmediateVectorClock implements ControllerClockV3 {
  readonly delays: number[] = [];
  #wall = 0;
  #monotonic = 0;
  wallNowMilliseconds(): number { return this.#wall; }
  monotonicNowMilliseconds(): number { return this.#monotonic; }
  async sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw signal.reason;
    this.delays.push(milliseconds);
    this.#wall += milliseconds;
    this.#monotonic += milliseconds;
  }
}

class HoldingVectorClock implements ControllerClockV3 {
  readonly delays: number[] = [];
  wallNowMilliseconds(): number { return 0; }
  monotonicNowMilliseconds(): number { return 0; }
  async sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    this.delays.push(milliseconds);
    await new Promise<void>((_resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      if (signal.aborted) abort();
    });
  }
}

class AdvancingVectorClock implements ControllerClockV3 {
  readonly delays: number[] = [];
  readonly #wallAdvances: readonly number[];
  readonly #monotonicAdvances: readonly number[];
  #wall: number;
  #monotonic: number;
  #sleepCount = 0;
  readonly #holdAfterLastAdvance: boolean;

  constructor(scenario: ControllerScenario) {
    this.#wall = numberInput(scenario, "wall_start_ms");
    this.#monotonic = numberInput(scenario, "monotonic_start_ms");
    this.#wallAdvances = scenario.input.wall_advances_ms as readonly number[];
    this.#monotonicAdvances = scenario.input.monotonic_advances_ms as readonly number[];
    this.#holdAfterLastAdvance = scenario.expected.final_state === "waiting";
  }

  wallNowMilliseconds(): number { return this.#wall; }
  monotonicNowMilliseconds(): number { return this.#monotonic; }
  async sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw signal.reason;
    this.delays.push(milliseconds);
    const index = this.#sleepCount++;
    this.#wall += this.#wallAdvances[index] ?? milliseconds;
    this.#monotonic += this.#monotonicAdvances[index] ?? milliseconds;
    if (this.#holdAfterLastAdvance && index + 1 === this.#wallAdvances.length) {
      await new Promise<void>((_resolve, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
      });
    }
    await Promise.resolve();
  }

  async waitForSleepCount(count: number): Promise<void> {
    await waitFor(() => this.delays.length >= count);
  }
}

function controllerOptions(maximumAttempts: number, clock: ControllerClockV3 = new ImmediateVectorClock()) {
  return {
    maximumAttempts,
    nowUnixSeconds: () => 1_900_000_000,
    clock,
    capabilitySnapshot: () => detectNodeRuntimeCapabilityV3(),
  };
}

async function finishControllerScenario<Session extends ManagedSessionV3>(
  controller: ConnectionControllerV3<Session>,
  scenario: ControllerScenario,
  tracker: VectorTracker,
  session?: Session,
): Promise<void> {
  controller.start();
  if (scenario.expected.final_state === "connected") {
    await waitForControllerState(controller, "connected");
    expect(controller.currentSession).toBe(session ?? controller.currentSession);
  } else if (scenario.expected.final_state === "waiting") {
    await waitForControllerState(controller, "waiting");
    await waitFor(() => tracker.clock.delays.length >= scenario.expected.retry_delays_ms.length);
  } else {
    await waitForControllerState(controller, scenario.expected.final_state);
  }
  assertObservation(scenario, tracker.observe(controller));
  await controller.close();
}

function assertObservation(scenario: ControllerScenario, observed: ControllerObservation): void {
  const expected: ControllerObservation = {
    final_state: scenario.expected.final_state,
    public_error: scenario.expected.public_error,
    disposition: scenario.expected.disposition,
    acquisitions: scenario.expected.acquisitions,
    connect_attempts: scenario.expected.connect_attempts,
    transports_created: scenario.expected.transports_created,
    replacement_acquisitions: scenario.expected.replacement_acquisitions,
    replacement_quota_used: scenario.expected.replacement_quota_used,
    spend_callbacks: scenario.expected.spend_callbacks,
    retire_callbacks: scenario.expected.retire_callbacks,
    lease_terminal_states: scenario.expected.lease_terminal_states,
    retry_delays_ms: scenario.expected.retry_delays_ms,
  };
  expect(observed, scenario.id).toEqual(expected);
}

function singleCandidateArtifact(input: ArtifactV3, id: string): ArtifactV3 {
  const candidate = input.path.candidates.find((value) => value.id === id);
  if (candidate === undefined) throw new Error(`fixture candidate ${id} is missing`);
  return { ...structuredClone(input), path: { ...structuredClone(input.path), candidates: [structuredClone(candidate)] } };
}

function mixedCAPinArtifact(input: ArtifactV3): ArtifactV3 {
  const output = structuredClone(input) as ArtifactV3;
  output.path.candidates = output.path.candidates
    .filter(({ id }) => id === "w-ca" || id === "w-pin")
    .map((candidate) => structuredClone(candidate));
  return output;
}

function twoPinArtifact(input: ArtifactV3): ArtifactV3 {
  return {
    ...structuredClone(input),
    path: {
      ...structuredClone(input.path),
      candidates: input.path.candidates
        .filter(({ id }) => id === "q-pin" || id === "t-pin")
        .map((candidate) => structuredClone(candidate)),
    },
  };
}

function withChangedPin(input: ArtifactV3): ArtifactV3 {
  const output = structuredClone(input) as ArtifactV3;
  output.path.candidates = output.path.candidates.map((candidate) => candidate.tls.mode !== "pin" ? candidate : {
    ...candidate,
    tls: {
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        not_after_unix_s: 2_100_000_000,
        value_b64u: Buffer.alloc(32, 0x7f).toString("base64url"),
      }],
    },
  });
  return output;
}

function withInitExpiry(input: ArtifactV3, expiry: number): ArtifactV3 {
  const output = structuredClone(input) as ArtifactV3;
  output.session.init_expire_at_unix_s = expiry;
  return output;
}

function withCandidateCA(input: ArtifactV3): ArtifactV3 {
  const output = structuredClone(input) as ArtifactV3;
  output.path.candidates = output.path.candidates.map((candidate) => ({ ...candidate, tls: { mode: "ca" } }));
  return output;
}

function browserWebTransportArtifact(
  input: ArtifactV3,
  candidates: readonly Readonly<{
    id: string;
    host: string;
    tls: "ca" | "pin" | "existing";
  }>[],
): ArtifactV3 {
  const output = structuredClone(input) as ArtifactV3;
  const template = output.path.candidates.find(({ carrier }) => carrier === "webtransport");
  if (template === undefined) throw new Error("WebTransport candidate required");
  output.path.candidates = candidates.map(({ id, host, tls }) => {
    const existing = output.path.candidates.find((candidate) => candidate.id === id);
    return {
      id,
      carrier: "webtransport" as const,
      url: `https://${host}:443/flowersec/webtransport/v3/direct`,
      wire_profile: template.wire_profile,
      tls: tls === "existing" ? (existing ?? template).tls : tls === "ca" ? { mode: "ca" } : template.tls,
    };
  });
  return output;
}

function pinMismatch(context: LeaseAttemptContextV3) {
  const candidate = context.candidates.find(({ id }) => id === "t-pin") ??
    context.candidates.find(({ tls }) => tls.mode === "pin") ?? context.candidates[0]!;
  return {
    kind: "candidate_failures" as const,
    failures: [{ candidate, failure: new TransportFailureV3("tls_failed", "pin_mismatch") }],
  };
}

function ordinaryCandidateFailure(context: LeaseAttemptContextV3) {
  return {
    kind: "candidate_failures" as const,
    failures: [{ candidate: context.candidates[0]!, failure: new TransportFailureV3("connection_failed") }],
  };
}

function retryableConnectionFailure(): ConnectErrorV3 {
  return new ConnectErrorV3("connection_failed", { kind: "retryable" });
}

function transportFailure(result: string): TransportFailureV3 {
  if (result === "ca_untrusted") return new TransportFailureV3("tls_failed", "ca_untrusted");
  if (result === "pin_mismatch") return new TransportFailureV3("tls_failed", "pin_mismatch");
  if (result === "tls_failed") return new TransportFailureV3("tls_failed", "unknown");
  if (result === "tls_unsupported") return new TransportFailureV3("tls_unsupported");
  return new TransportFailureV3("connection_failed");
}

function managedSession(): ManagedSessionV3 {
  return {
    waitTermination: async () => await new Promise<Readonly<{ error: Error }>>(() => undefined),
    close: async () => undefined,
  };
}

function numberInput(scenario: ControllerScenario, key: string): number {
  const value = scenario.input[key];
  if (typeof value !== "number") throw new Error(`${scenario.id}.${key} is not a number`);
  return value;
}

function controllerDisposition(controller: ReturnType<typeof createConnectionControllerV3>): string | null {
  let disposition: string | null = null;
  const unsubscribe = controller.subscribe((snapshot) => {
    disposition = snapshot.retryDisposition?.kind ?? null;
  });
  unsubscribe();
  return disposition;
}

async function waitForControllerState(
  controller: ReturnType<typeof createConnectionControllerV3>,
  state: string,
): Promise<void> {
  try {
    await waitFor(() => controller.state === state);
  } catch {
    throw new Error(`controller reached ${controller.state}, expected ${state} (${controller.failure?.code ?? "no failure"})`);
  }
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for controller vector state");
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

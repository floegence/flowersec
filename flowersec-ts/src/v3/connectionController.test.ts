import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  artifactLeaseStateV3,
  claimArtifactLeaseV3,
  commitArtifactLeaseSpendV3,
  createArtifactLeaseV3Internal,
  duplicateArtifactLeaseHandleV3,
  retireArtifactLeaseV3,
  type ArtifactLeaseV3,
  type ClaimedArtifactLeaseV3,
} from "./artifactLease.js";
import {
  createConnectionControllerV3,
  type LeaseAttemptContextV3,
  type ArtifactSourceResultV3,
  type ManagedSessionV3,
} from "./connectionController.js";
import type { ControllerClockV3 } from "./controller.js";
import { ConnectErrorV3, TransportFailureV3 } from "./security.js";
import { detectNodeRuntimeCapabilityV3 } from "./nodeRuntime.js";
import {
  canonicalizeCandidatesV3,
  decodeArtifactV3JSON,
  type ArtifactV3,
} from "./artifact.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ artifact_json: string }>[] }>;
const primaryArtifact = decodeArtifactV3JSON(fixture.positive[0]!.artifact_json);

type ControllerScenarioExpected = Readonly<{
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

const controllerFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/controller_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ scenarios: readonly Readonly<{
  id: string;
  driver: string;
  input: Readonly<Record<string, unknown>>;
  expected: ControllerScenarioExpected;
}>[] }>;

describe("transport v3 production connection controller", () => {
  test("consumes a spend whose callback outlives caller cancellation", async () => {
    let signalStarted!: () => void;
    const started = new Promise<void>((resolve) => { signalStarted = resolve; });
    let release!: () => void;
    const spend = vi.fn(async (_signal?: AbortSignal) => await new Promise<void>((resolve) => {
      release = resolve;
      signalStarted();
    }));
    const lease = createArtifactLeaseV3Internal(primaryArtifact, spend);
    const claim = claimArtifactLeaseV3(lease);
    const cancellation = new AbortController();
    const commit = commitArtifactLeaseSpendV3(claim, cancellation.signal);
    await started;
    cancellation.abort(new Error("caller stopped"));
    await expect(commit).rejects.toThrow("caller stopped");
    expect(artifactLeaseStateV3(lease)).toBe("consumed");
    release();
    expect(spend).toHaveBeenCalledOnce();
  });

  test("consumes a spend whose callback fails", async () => {
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => {
      throw new Error("durability unavailable");
    });
    const claim = claimArtifactLeaseV3(lease);
    await expect(commitArtifactLeaseSpendV3(claim)).rejects.toThrow("durability unavailable");
    expect(artifactLeaseStateV3(lease)).toBe("consumed");
  });

  test("immediately acquires one changed-pin replacement and establishes", async () => {
    const expected = controllerScenario("pin-mismatch-changed-pin-success").expected;
    const replacementArtifact = withChangedWebTransportPin(primaryArtifact);
    const cleanups = [vi.fn(async () => undefined), vi.fn(async () => undefined)];
    const leases = [
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanups[0]),
      createArtifactLeaseV3Internal(replacementArtifact, async () => undefined, cleanups[1]),
    ];
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "lease",
      lease: leases.shift()!,
    }));
    const session = managedSession();
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => {
      const candidate = context.candidates.find(({ id }) => id === "t-pin")!;
      if (context.kind === "primary") {
        return {
          kind: "candidate_failures" as const,
          failures: [{ candidate, failure: new TransportFailureV3("tls_failed", "pin_mismatch") }],
        };
      }
      expect(context.candidates.map(({ id }) => id)).toEqual(["q-pin", "t-pin", "w-ca", "w-pin"]);
      context.assertArtifactFresh();
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established" as const, session };
    });
    const controller = createConnectionControllerV3({ acquire }, connector, {
      maximumAttempts: expected.acquisitions,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    const controllerSnapshots: Array<{ state: string; attempt: number }> = [];
    controller.subscribe((snapshot) => controllerSnapshots.push({
      state: snapshot.state,
      attempt: snapshot.attempt,
    }));
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    expect(controller.state).toBe(expected.final_state);
    expect(controllerSnapshots.find((snapshot) => snapshot.state === "connected")?.attempt).toBe(2);
    expect(acquire).toHaveBeenCalledTimes(expected.acquisitions);
    expect(connector).toHaveBeenCalledTimes(expected.connect_attempts);
    expect(cleanups[0]).toHaveBeenCalledTimes(expected.retire_callbacks);
    expect(cleanups[1]).not.toHaveBeenCalled();
    await controller.close();
  });

  test("forces the last retryable source failure terminal at attempt exhaustion", async () => {
    const expected = controllerScenario("attempt-exhaustion").expected;
    const observed: string[] = [];
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "failure",
      code: "connection_failed",
      disposition: { kind: "retryable" },
    }));
    const snapshots: Array<{ state: string; disposition?: string }> = [];
    const controller = createConnectionControllerV3({ acquire }, async () => {
      throw new Error("connector must not run");
    }, { maximumAttempts: expected.acquisitions, clock: immediateClock(observed), capabilitySnapshot });
    controller.subscribe((snapshot) => snapshots.push({
      state: snapshot.state,
      ...(snapshot.retryDisposition === undefined ? {} : { disposition: snapshot.retryDisposition.kind }),
    }));
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
    expect(acquire).toHaveBeenCalledTimes(expected.acquisitions);
    expect(observed).toEqual(expected.retry_delays_ms.map((delay) => `sleep:${delay}`));
    expect(snapshots.at(-1)).toEqual({ state: expected.final_state, disposition: expected.disposition });
  });

  test.each([
    [new TransportFailureV3("tls_failed", "pin_mismatch"), "transport_security_failed"],
    [new TransportFailureV3("connection_failed", "browser_pin_opaque"), "connection_failed"],
  ] as const)("retains %s trigger provenance when the replacement attempt budget is exhausted", async (
    trigger,
    expectedCode,
  ) => {
    const cleanup = vi.fn(async () => undefined);
    const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
    const lease = createArtifactLeaseV3Internal(primary, async () => undefined, cleanup);
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({ kind: "lease", lease }));
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => ({
      kind: "candidate_failures" as const,
      failures: [{ candidate: context.candidates[0]!, failure: trigger }],
    }));
    const controller = createConnectionControllerV3({ acquire }, connector, {
      maximumAttempts: 1,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: expectedCode },
      retryDisposition: { kind: "terminal" },
    });
    expect(acquire).toHaveBeenCalledOnce();
    expect(connector).toHaveBeenCalledOnce();
    expect(cleanup).toHaveBeenCalledOnce();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
    expect(controller.retryNow()).toBe(false);
    await controller.close();
  });

  test("retains the replacement source failure when its retry-after exhausts the attempt budget", async () => {
    const observed: string[] = [];
    const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
    const lease = createArtifactLeaseV3Internal(primary, async () => undefined);
    const acquire = vi.fn()
      .mockResolvedValueOnce({ kind: "lease", lease })
      .mockResolvedValueOnce({
        kind: "failure",
        code: "connection_failed",
        disposition: { kind: "retry_after", absoluteUnixMilliseconds: 2_000_000_000_000 },
      });
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => ({
      kind: "candidate_failures" as const,
      failures: [{
        candidate: context.candidates[0]!,
        failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
      }],
    }));
    const controller = createConnectionControllerV3({ acquire }, connector, {
      maximumAttempts: 2,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "connection_failed" },
      retryDisposition: { kind: "terminal" },
    });
    expect(observed).toEqual([]);
    expect(acquire).toHaveBeenCalledTimes(2);
    expect(connector).toHaveBeenCalledOnce();
    expect(controller.retryNow()).toBe(false);
    await controller.close();
  });

  test("lets a synchronous waiting subscriber wake the registered retry", async () => {
    const clock = new HoldingClock();
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "failure",
      code: "connection_failed",
      disposition: { kind: "retryable" },
    }));
    const controller = createConnectionControllerV3({ acquire }, async () => {
      throw new Error("connector must not run");
    }, { maximumAttempts: 2, clock, capabilitySnapshot });
    const retryResults: boolean[] = [];
    controller.subscribe((snapshot) => {
      if (snapshot.state === "waiting") retryResults.push(controller.retryNow());
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "connection_failed" },
      retryDisposition: { kind: "terminal" },
    });
    expect(retryResults).toEqual([true]);
    expect(clock.delays).toEqual([250]);
    expect(acquire).toHaveBeenCalledTimes(2);
    await controller.close();
  });

  test("rejects an unregistered source failure code terminally without retry", async () => {
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "failure",
      code: "deployment_internal_detail",
      disposition: { kind: "retryable" },
    }));
    const controller = createConnectionControllerV3({ acquire }, async () => {
      throw new Error("connector must not run");
    }, { maximumAttempts: 3, clock: immediateClock(), capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(acquire).toHaveBeenCalledOnce();
  });

  test("rejects a thrown source failure with invalid retry-after before scheduling", async () => {
    const observed: string[] = [];
    const connector = vi.fn(async () => { throw new Error("connector must not run"); });
    const controller = createConnectionControllerV3({
      acquire: async () => {
        throw new ConnectErrorV3("connection_failed", {
          kind: "retry_after",
          absoluteUnixMilliseconds: 253_402_300_800_000,
        });
      },
    }, connector, { maximumAttempts: 2, clock: immediateClock(observed), capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(controller.state).toBe("failed");
    expect(connector).not.toHaveBeenCalled();
    expect(observed).toEqual([]);
    await controller.close();
  });

  test.each([
    ["NaN", Number.NaN],
    ["positive Infinity", Number.POSITIVE_INFINITY],
    ["negative Infinity", Number.NEGATIVE_INFINITY],
    ["fractional sub-millisecond time", 0.5],
    ["non-round-trippable integer", Number.MAX_SAFE_INTEGER + 1],
  ])("projects a %s source retry-after to artifact_invalid without scheduling", async (_name, deadline) => {
    const observed: string[] = [];
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "failure",
      code: "connection_failed",
      disposition: { kind: "retry_after", absoluteUnixMilliseconds: deadline },
    }));
    const connector = vi.fn(async () => { throw new Error("connector must not run"); });
    const controller = createConnectionControllerV3({ acquire }, connector, {
      maximumAttempts: 2,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(observed).toEqual([]);
    expect(connector).not.toHaveBeenCalled();
    expect(acquire).toHaveBeenCalledOnce();
    expect(controller.retryNow()).toBe(false);
    await controller.close();
  });

  test("retires a lease from a mixed lease-and-failure source result", async () => {
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const connector = vi.fn(async () => { throw new Error("connector must not run"); });
    const controller = createConnectionControllerV3({
      acquire: async () => ({
        kind: "lease",
        lease,
        code: "connection_failed",
        disposition: { kind: "retryable" },
      } as unknown as ArtifactSourceResultV3),
    }, connector, { capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(connector).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("retires a lease when malformed source reflection throws", async () => {
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const malformed = new Proxy({ kind: "lease", lease }, {
      ownKeys: () => { throw new Error("source reflection failure"); },
    });
    const connector = vi.fn(async () => { throw new Error("connector must not run"); });
    const controller = createConnectionControllerV3({
      acquire: async () => malformed as unknown as ArtifactSourceResultV3,
    }, connector, { capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(connector).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("retires a lease from a mixed failure-and-lease source result", async () => {
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const connector = vi.fn(async () => { throw new Error("connector must not run"); });
    const controller = createConnectionControllerV3({
      acquire: async () => ({
        kind: "failure",
        code: "connection_failed",
        disposition: { kind: "retryable" },
        lease,
      } as unknown as ArtifactSourceResultV3),
    }, connector, { capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
      retryDisposition: { kind: "terminal" },
    });
    expect(connector).not.toHaveBeenCalled();
    expect(artifactLeaseStateV3(lease)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("keeps a post-spend lease consumed and retries with a new primary", async () => {
    const states: string[] = [];
    const first = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const second = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const queue = [first, second];
    const session = managedSession();
    let attempt = 0;
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: queue.shift()! }),
    }, async (context) => {
      context.assertArtifactFresh();
      await commitArtifactLeaseSpendV3(context.claim);
      if (attempt++ === 0) {
        return {
          kind: "post_spend_failure",
          error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
        };
      }
      return { kind: "established", session };
    }, {
      maximumAttempts: 2,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(states),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    expect(artifactLeaseStateV3(first)).toBe("consumed");
    expect(artifactLeaseStateV3(second)).toBe("consumed");
    expect(states).toContain("sleep:250");
    await controller.close();
  });

  test("terminalizes a blocked old-pin primary with native security provenance", async () => {
    await expectBlockedPrimaryAfterSpentReplacementRetry(
      new TransportFailureV3("tls_failed", "pin_mismatch"),
      "transport_security_failed",
    );
  });

  test("terminalizes a blocked old-pin primary with browser opaque provenance", async () => {
    await expectBlockedPrimaryAfterSpentReplacementRetry(
      new TransportFailureV3("connection_failed", "browser_pin_opaque"),
      "connection_failed",
    );
  });

  test("counts a completed candidate race once and survives retire cleanup failure", async () => {
    const observed: string[] = [];
    const cleanup = vi.fn(async () => { throw new Error("deployment cleanup failed"); });
    const first = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const second = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const session = managedSession();
    let attempts = 0;
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: attempts === 0 ? first : second }),
    }, async (context) => {
      attempts += 1;
      if (attempts === 1) {
        return {
          kind: "candidate_failures",
          failures: context.candidates.slice(0, 3).map((candidate) => ({
            candidate,
            failure: new TransportFailureV3("connection_failed"),
          })),
        };
      }
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established", session };
    }, {
      maximumAttempts: 2,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    expect(observed).toEqual(["sleep:250"]);
    expect(cleanup).toHaveBeenCalledOnce();
    expect(artifactLeaseStateV3(first)).toBe("retired");
    await controller.close();
  });

  test("allows an ordinary retry before one immediate changed-pin refresh", async () => {
    const replacement = withChangedWebTransportPin(primaryArtifact);
    const leases = [primaryArtifact, primaryArtifact, replacement].map((artifact) =>
      createArtifactLeaseV3Internal(artifact, async () => undefined));
    const kinds: string[] = [];
    const observed: string[] = [];
    const session = managedSession();
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: leases.shift()! }),
    }, async (context) => {
      kinds.push(context.kind);
      if (kinds.length === 1) {
        return { kind: "candidate_failures", failures: [{
          candidate: context.candidates[0]!,
          failure: new TransportFailureV3("connection_failed"),
        }] };
      }
      if (kinds.length === 2) {
        return { kind: "candidate_failures", failures: [{
          candidate: context.candidates.find(({ id }) => id === "t-pin")!,
          failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
        }] };
      }
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established", session };
    }, {
      maximumAttempts: 3,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    expect(kinds).toEqual(["primary", "primary", "replacement"]);
    expect(observed).toEqual(["sleep:250"]);
    await controller.close();
  });

  test("does not close an established Session when its artifact and pins later expire", async () => {
    let now = 1_900_000_000;
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const session = managedSession();
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease }),
    }, async (context) => {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established", session };
    }, { nowUnixSeconds: () => now, capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    now = Number.MAX_SAFE_INTEGER;
    await Promise.resolve();
    expect(controller.state).toBe("connected");
    expect(controller.currentSession).toBe(session);
    await controller.close();
  });

  test("projects an unexpected session termination rejection as terminal", async () => {
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const session: ManagedSessionV3 = {
      waitTermination: async () => { throw new Error("carrier lifecycle failed"); },
      close: async () => undefined,
    };
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease }),
    }, async (context) => {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established" as const, session };
    }, { maximumAttempts: 1, nowUnixSeconds: () => 1_900_000_000, capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);
    await waitForControllerState(controller, "failed");
    expect(controller.failure).toEqual({ phase: "session", code: "connection_failed" });
    await controller.close();
  });

  test("rejects a duplicate lease identity after the original handle is retired", async () => {
    const original = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const duplicate = duplicateArtifactLeaseHandleV3(original);
    const queue = [original, duplicate];
    const connector = vi.fn(async () => ({
      kind: "pre_spend_failure" as const,
      error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
    }));
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: queue.shift()! }),
    }, connector, {
      maximumAttempts: 2,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "artifact", code: "artifact_invalid" },
    });
    expect(connector).toHaveBeenCalledOnce();
    expect(artifactLeaseStateV3(original)).toBe("retired");
  });

  test("keeps a replacement post-spend failure consumed and never reacquires replacement quota", async () => {
    const expected = controllerScenario("post-spend-retry-preserves-quota").expected;
    const observed: string[] = [];
    const replacement = withChangedWebTransportPin(primaryArtifact);
    const first = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const second = createArtifactLeaseV3Internal(replacement, async () => undefined);
    const third = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const queue = [first, second, third];
    const kinds: string[] = [];
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: queue.shift()! }),
    }, async (context) => {
      kinds.push(context.kind);
      if (kinds.length === 1) {
        return { kind: "candidate_failures", failures: [{
          candidate: context.candidates.find(({ id }) => id === "t-pin")!,
          failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
        }] };
      }
      if (kinds.length === 2) {
        await commitArtifactLeaseSpendV3(context.claim);
        return {
          kind: "post_spend_failure",
          error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
        };
      }
      return { kind: "candidate_failures", failures: [{
        candidate: context.candidates.find(({ id }) => id === "q-pin")!,
        failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
      }] };
    }, {
      maximumAttempts: expected.acquisitions + 1,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: expected.public_error },
    });
    expect(kinds).toEqual(["primary", "replacement", "primary"]);
    expect(kinds).toHaveLength(expected.connect_attempts);
    expect(kinds.filter((kind) => kind === "replacement")).toHaveLength(expected.replacement_acquisitions);
    expect(observed).toEqual(expected.retry_delays_ms.map((delay) => `sleep:${delay}`));
    expect([first, second, third].map(artifactLeaseStateV3)).toEqual(expected.lease_terminal_states);
    expect(artifactLeaseStateV3(second)).toBe("consumed");
    expect(queue).toHaveLength(0);
  });

  test("preserves native security provenance before an opaque trigger after replacement retry", async () => {
    const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
    const replacement = withChangedWebTransportPin(primary);
    const opaquePrimary = singleCandidateArtifact(primaryArtifact, "q-pin");
    const leases = [primary, replacement, opaquePrimary].map((artifact) =>
      createArtifactLeaseV3Internal(artifact, async () => undefined));
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "lease",
      lease: leases.shift()!,
    }));
    let calls = 0;
    const controller = createConnectionControllerV3({ acquire }, async (context) => {
      calls += 1;
      if (calls === 1) {
        return {
          kind: "candidate_failures" as const,
          failures: [{
            candidate: context.candidates[0]!,
            failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
          }],
        };
      }
      if (calls === 2) {
        await commitArtifactLeaseSpendV3(context.claim);
        return {
          kind: "post_spend_failure" as const,
          error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
        };
      }
      return {
        kind: "candidate_failures" as const,
        failures: [{
          candidate: context.candidates[0]!,
          failure: new TransportFailureV3("connection_failed", "browser_pin_opaque"),
        }],
      };
    }, {
      maximumAttempts: 3,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: "transport_security_failed" },
      retryDisposition: { kind: "terminal" },
    });
    expect(acquire).toHaveBeenCalledTimes(3);
    expect(calls).toBe(3);
  });

  test("keeps TLS security precedence for mixed CA and opaque failures after replacement retry", async () => {
    const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
    const replacement = withChangedWebTransportPin(primary);
    const leases = [primary, replacement, primaryArtifact].map((artifact) =>
      createArtifactLeaseV3Internal(artifact, async () => undefined));
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "lease",
      lease: leases.shift()!,
    }));
    let calls = 0;
    const controller = createConnectionControllerV3({ acquire }, async (context) => {
      calls += 1;
      if (calls === 1) {
        return {
          kind: "candidate_failures" as const,
          failures: [{
            candidate: context.candidates[0]!,
            failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
          }],
        };
      }
      if (calls === 2) {
        await commitArtifactLeaseSpendV3(context.claim);
        return {
          kind: "post_spend_failure" as const,
          error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
        };
      }
      const opaque = context.candidates.find(({ id }) => id === "q-pin")!;
      const ca = context.candidates.find(({ id }) => id === "w-ca")!;
      return {
        kind: "candidate_failures" as const,
        failures: [
          { candidate: opaque, failure: new TransportFailureV3("connection_failed", "browser_pin_opaque") },
          { candidate: ca, failure: new TransportFailureV3("tls_failed", "ca_untrusted") },
        ],
      };
    }, {
      maximumAttempts: 3,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: "transport_security_failed" },
      retryDisposition: { kind: "terminal" },
    });
    expect(acquire).toHaveBeenCalledTimes(3);
    expect(calls).toBe(3);
  });

  test("makes a non-expiry replacement pre-spend failure terminal", async () => {
    const replacement = withChangedWebTransportPin(primaryArtifact);
    const first = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    const secondCleanup = vi.fn(async () => undefined);
    const second = createArtifactLeaseV3Internal(replacement, async () => undefined, secondCleanup);
    const queue = [first, second];
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => {
      if (context.kind === "primary") {
        return { kind: "candidate_failures" as const, failures: [{
          candidate: context.candidates.find(({ id }) => id === "t-pin")!,
          failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
        }] };
      }
      return {
        kind: "pre_spend_failure" as const,
        error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
      };
    });
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
      kind: "lease", lease: queue.shift()!,
    }));
    const controller = createConnectionControllerV3({ acquire }, connector, {
      maximumAttempts: 3,
      nowUnixSeconds: () => 1_900_000_000,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: "transport_security_failed" },
      retryDisposition: { kind: "terminal" },
    });
    expect(acquire).toHaveBeenCalledTimes(2);
    expect(connector).toHaveBeenCalledTimes(2);
    expect(artifactLeaseStateV3(second)).toBe("retired");
    expect(secondCleanup).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("executes primary and replacement FSA3/FSH3 post-spend vectors", async () => {
    const scenarios = controllerFixture.scenarios.filter(({ driver }) => driver === "admission-spend-boundary");
    expect(scenarios.map(({ id }) => id).sort()).toEqual([
      "primary-fsa3-reject-consumes-spent",
      "primary-fsa3-retryable-consumes-spent",
      "primary-fsh3-failure-consumes-spent",
      "replacement-fsa3-reject-consumes-spent",
      "replacement-fsa3-retryable-consumes-spent",
      "replacement-fsh3-failure-consumes-spent",
    ]);
    for (const scenario of scenarios) {
      const input = scenario.input as Readonly<{ phase: "primary" | "replacement"; admission_result: string }>;
      const expected = scenario.expected;
      const artifacts = input.phase === "replacement"
        ? [primaryArtifact, withChangedWebTransportPin(primaryArtifact)]
        : [primaryArtifact];
      const leases = artifacts.map((artifact) => createArtifactLeaseV3Internal(artifact, async () => undefined));
      const queue = [...leases];
      const kinds: string[] = [];
      const clock = new HoldingClock();
      const snapshots: Array<{ state: string; code?: string; disposition?: string }> = [];
      const controller = createConnectionControllerV3({
        acquire: async () => ({ kind: "lease", lease: queue.shift()! }),
      }, async (context) => {
        kinds.push(context.kind);
        if (input.phase === "replacement" && context.kind === "primary") {
          return { kind: "candidate_failures", failures: [{
            candidate: context.candidates.find(({ id }) => id === "t-pin")!,
            failure: new TransportFailureV3("tls_failed", "pin_mismatch"),
          }] };
        }
        await commitArtifactLeaseSpendV3(context.claim);
        const terminal = input.admission_result === "fsa_reject";
        return {
          kind: "post_spend_failure",
          error: new ConnectErrorV3("connection_failed", { kind: terminal ? "terminal" : "retryable" }),
        };
      }, {
        nowUnixSeconds: () => 1_900_000_000,
        clock,
        capabilitySnapshot,
      });
      controller.subscribe((snapshot) => snapshots.push({
        state: snapshot.state,
        ...(snapshot.failure === undefined ? {} : { code: snapshot.failure.code }),
        ...(snapshot.retryDisposition === undefined ? {} : { disposition: snapshot.retryDisposition.kind }),
      }));
      controller.start();
      await waitForControllerState(controller, expected.final_state);
      if (expected.final_state === "waiting") await clock.waitForSleepCount(expected.retry_delays_ms.length);

      expect(kinds).toHaveLength(expected.connect_attempts);
      expect(kinds.filter((kind) => kind === "replacement")).toHaveLength(expected.replacement_acquisitions);
      expect(leases.map(artifactLeaseStateV3)).toEqual(expected.lease_terminal_states);
      expect(clock.delays).toEqual(expected.retry_delays_ms);
      expect(snapshots.at(-1)).toMatchObject({
        state: expected.final_state,
        code: expected.public_error,
        disposition: expected.disposition,
      });
      await controller.close();
    }
  });

  test("drains and retires a lease delivered after close wins", async () => {
    const expected = controllerScenario("lease-cancellation-first").expected;
    let deliver!: (result: ArtifactSourceResultV3) => void;
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const controller = createConnectionControllerV3({
      acquire: async () => await new Promise<ArtifactSourceResultV3>((resolve) => { deliver = resolve; }),
    }, async () => { throw new Error("connector must not run"); }, { capabilitySnapshot });
    controller.start();
    await Promise.resolve();
    const closing = controller.close();
    deliver({ kind: "lease", lease });
    await closing;
    expect(controller.state).toBe(expected.final_state);
    expect(artifactLeaseStateV3(lease)).toBe(expected.lease_terminal_states[0]);
    expect(cleanup).toHaveBeenCalledTimes(expected.retire_callbacks);
  });

  test("drains an invalid late source result after cancellation", async () => {
    let deliver!: (result: unknown) => void;
    const controller = createConnectionControllerV3({
      acquire: async () => await new Promise<ArtifactSourceResultV3>((resolve) => {
        deliver = resolve as unknown as (result: unknown) => void;
      }),
    }, async () => { throw new Error("connector must not run"); }, { capabilitySnapshot });
    controller.start();
    await Promise.resolve();
    const closing = controller.close();
    deliver(null);
    await closing;
    expect(controller.state).toBe("closed");
  });

  test("does not acquire after a connecting subscriber closes synchronously", async () => {
    const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => {
      throw new Error("acquisition must not start after close");
    });
    const connector = vi.fn(async () => {
      throw new Error("connector must not run");
    });
    const controller = createConnectionControllerV3({ acquire }, connector, { capabilitySnapshot });
    const states: string[] = [];
    let subscriberClose: Promise<void> | undefined;
    controller.subscribe((snapshot) => {
      states.push(snapshot.state);
      if (snapshot.state === "connecting") subscriberClose = controller.close();
    });

    controller.start();
    const repeatedClose = controller.close();

    expect(subscriberClose).toBe(repeatedClose);
    await repeatedClose;
    expect(states).toEqual(["idle", "connecting", "closed"]);
    expect(controller.state).toBe("closed");
    expect(acquire).not.toHaveBeenCalled();
    expect(connector).not.toHaveBeenCalled();
  });

  test("returns one close promise when a closed subscriber closes synchronously", async () => {
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    let finishSessionClose!: () => void;
    const sessionClose = vi.fn(async () => await new Promise<void>((resolve) => {
      finishSessionClose = resolve;
    }));
    const session: ManagedSessionV3 = {
      waitTermination: async () => await new Promise<Readonly<{ error: Error }>>(() => undefined),
      close: sessionClose,
    };
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease }),
    }, async (context) => {
      await commitArtifactLeaseSpendV3(context.claim);
      return { kind: "established", session };
    }, { nowUnixSeconds: () => 1_900_000_000, capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(session);

    let closedNotifications = 0;
    let subscriberClose: Promise<void> | undefined;
    controller.subscribe((snapshot) => {
      if (snapshot.state !== "closed") return;
      closedNotifications += 1;
      subscriberClose = controller.close();
    });
    const closing = controller.close();

    expect(subscriberClose).toBe(closing);
    expect(controller.close()).toBe(closing);
    expect(closedNotifications).toBe(1);
    expect(sessionClose).toHaveBeenCalledOnce();
    let settled = false;
    void closing.then(() => { settled = true; });
    await Promise.resolve();
    expect(settled).toBe(false);
    finishSessionClose();
    await closing;
    expect(settled).toBe(true);
    expect(sessionClose).toHaveBeenCalledOnce();
  });

  test("closes an established session delivered after controller close wins", async () => {
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined);
    let markConnectorStarted!: () => void;
    const connectorStarted = new Promise<void>((resolve) => { markConnectorStarted = resolve; });
    const close = vi.fn(async () => undefined);
    const session: ManagedSessionV3 = {
      waitTermination: async () => await new Promise<Readonly<{ error: Error }>>(() => undefined),
      close,
    };
    let resolveConnector!: (result: { kind: "established"; session: ManagedSessionV3 }) => void;
    const connector = async () => await new Promise<{ kind: "established"; session: ManagedSessionV3 }>((resolve) => {
      resolveConnector = resolve;
      markConnectorStarted();
    });
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease" as const, lease }),
    }, connector, { capabilitySnapshot });
    controller.start();
    await connectorStarted;
    const closing = controller.close();
    resolveConnector({ kind: "established", session });
    await closing;
    expect(close).toHaveBeenCalledOnce();
  });

  test("records the A pin digest before an expired B and filters it on the next primary", async () => {
    const leases = [
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined),
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined),
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined),
    ];
    let now = 1_900_000_000;
    let acquisitions = 0;
    const seen: Array<{ kind: string; candidates: string[] }> = [];
    const controller = createConnectionControllerV3({
      acquire: async () => {
        acquisitions += 1;
        if (acquisitions === 2) now = primaryArtifact.session.init_expire_at_unix_s;
        else if (acquisitions === 3) now = 1_900_000_000;
        return { kind: "lease", lease: leases.shift()! };
      },
    }, async (context) => {
      seen.push({ kind: context.kind, candidates: context.candidates.map(({ id }) => id) });
      if (context.kind === "primary" && seen.length === 1) {
        const candidate = context.candidates.find(({ id }) => id === "t-pin")!;
        return { kind: "candidate_failures", failures: [{ candidate, failure: new TransportFailureV3("tls_failed", "pin_mismatch") }] };
      }
      const candidate = context.candidates[0]!;
      return { kind: "candidate_failures", failures: [{ candidate, failure: new TransportFailureV3("connection_failed") }] };
    }, {
      maximumAttempts: 3,
      nowUnixSeconds: () => now,
      clock: immediateClock(),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
    expect(seen).toEqual([
      { kind: "primary", candidates: ["q-pin", "t-pin", "w-ca", "w-pin"] },
      { kind: "primary", candidates: ["q-pin", "w-ca", "w-pin"] },
    ]);
    await controller.close();
  });

  test("records the A pin digest before a race-end expired B", async () => {
    const expected = controllerScenario("replacement-expired-returns-primary").expected;
    const observed: string[] = [];
    const replacement = withChangedWebTransportPin(primaryArtifact);
    const leases = [
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined),
      createArtifactLeaseV3Internal(replacement, async () => undefined),
      createArtifactLeaseV3Internal(primaryArtifact, async () => undefined),
    ];
    let now = 1_900_000_000;
    let primaryCount = 0;
    const seen: Array<{ kind: string; candidates: string[] }> = [];
    const controller = createConnectionControllerV3({
      acquire: async () => {
        primaryCount += 1;
        if (primaryCount === 3) now = 1_900_000_000;
        return { kind: "lease", lease: leases.shift()! };
      },
    }, async (context) => {
      seen.push({ kind: context.kind, candidates: context.candidates.map(({ id }) => id) });
      const candidate = context.candidates.find(({ id }) => id === "t-pin") ?? context.candidates[0]!;
      if (context.kind === "primary" && seen.length === 1) {
        return { kind: "candidate_failures", failures: [{ candidate, failure: new TransportFailureV3("tls_failed", "pin_mismatch") }] };
      }
      if (context.kind === "replacement") now = replacement.session.init_expire_at_unix_s;
      return { kind: "candidate_failures", failures: [{ candidate, failure: new TransportFailureV3("connection_failed") }] };
    }, {
      maximumAttempts: 3,
      nowUnixSeconds: () => now,
      clock: immediateClock(observed),
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
    expect(seen).toEqual([
      { kind: "primary", candidates: ["q-pin", "t-pin", "w-ca", "w-pin"] },
      { kind: "replacement", candidates: ["q-pin", "t-pin", "w-ca", "w-pin"] },
      { kind: "primary", candidates: ["q-pin", "w-ca", "w-pin"] },
    ]);
    expect(primaryCount).toBe(expected.acquisitions);
    expect(seen).toHaveLength(expected.connect_attempts);
    expect(observed).toEqual(expected.retry_delays_ms.map((delay) => `sleep:${delay}`));
    await controller.close();
  });

  test("filters a same-endpoint pin-to-CA replacement before the B race", async () => {
    const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
    const oldPin = primary.path.candidates[0]!;
    const replacement = {
      ...primary,
      path: {
        ...primary.path,
        candidates: [{ ...oldPin, tls: { mode: "ca" as const } }],
      },
    } as ArtifactV3;
    canonicalizeCandidatesV3(replacement.path.kind, replacement.path.candidates);
    const cleanups = [vi.fn(async () => undefined), vi.fn(async () => undefined)];
    const leases = [
      createArtifactLeaseV3Internal(primary, async () => undefined, cleanups[0]),
      createArtifactLeaseV3Internal(replacement, async () => undefined, cleanups[1]),
    ];
    const connector = vi.fn(async (context) => ({
      kind: "candidate_failures" as const,
      failures: [{ candidate: context.candidates[0]!, failure: new TransportFailureV3("tls_failed", "pin_mismatch") }],
    }));
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease: leases.shift()! }),
    }, connector, {
      maximumAttempts: 2,
      nowUnixSeconds: () => 1_900_000_000,
      capabilitySnapshot,
    });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
    expect(connector).toHaveBeenCalledOnce();
    expect(cleanups[0]).toHaveBeenCalledOnce();
    expect(cleanups[1]).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("executes same-pin and browser-opaque replacement terminal vectors", async () => {
    for (const id of ["pin-mismatch-same-policy-terminal", "browser-opaque-exhausted"] as const) {
      const scenario = controllerScenario(id);
      const expected = scenario.expected;
      const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
      const cleanups = [vi.fn(async () => undefined), vi.fn(async () => undefined)];
      const leases = [
        createArtifactLeaseV3Internal(primary, async () => undefined, cleanups[0]),
        createArtifactLeaseV3Internal(primary, async () => undefined, cleanups[1]),
      ];
      const acquire = vi.fn(async () => ({ kind: "lease" as const, lease: leases.shift()! }));
      const connector = vi.fn(async (context: LeaseAttemptContextV3) => ({
        kind: "candidate_failures" as const,
        failures: [{
          candidate: context.candidates[0]!,
          failure: id === "browser-opaque-exhausted"
            ? new TransportFailureV3("connection_failed", "browser_pin_opaque")
            : new TransportFailureV3("tls_failed", "pin_mismatch"),
        }],
      }));
      const controller = createConnectionControllerV3({ acquire }, connector, {
        maximumAttempts: expected.acquisitions,
        nowUnixSeconds: () => 1_900_000_000,
        capabilitySnapshot,
      });
      controller.start();
      await expect(controller.waitForSession()).rejects.toMatchObject({
        code: "failed",
        failure: { phase: "connect", code: expected.public_error },
      });
      expect(controller.state).toBe(expected.final_state);
      expect(acquire).toHaveBeenCalledTimes(expected.acquisitions);
      expect(connector).toHaveBeenCalledTimes(expected.connect_attempts);
      expect(cleanups.reduce((count, cleanup) => count + cleanup.mock.calls.length, 0))
        .toBe(expected.retire_callbacks);
    }
  });

  test("executes the all-unsupported candidate aggregation vector without transport creation", async () => {
    const expected = controllerScenario("all-unsupported").expected;
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    const transportsCreated = 0;
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => ({
      kind: "candidate_failures" as const,
      failures: context.candidates.slice(0, 2).map((candidate) => ({
        candidate,
        failure: new TransportFailureV3("tls_unsupported"),
      })),
    }));
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease }),
    }, connector, { maximumAttempts: expected.acquisitions, capabilitySnapshot });
    controller.start();
    await expect(controller.waitForSession()).rejects.toMatchObject({
      code: "failed",
      failure: { phase: "connect", code: expected.public_error },
    });
    expect(connector).toHaveBeenCalledTimes(expected.connect_attempts);
    expect(transportsCreated).toBe(expected.transports_created);
    expect(cleanup).toHaveBeenCalledTimes(expected.retire_callbacks);
    expect(artifactLeaseStateV3(lease)).toBe(expected.lease_terminal_states[0]);
  });

  test("executes delivery-first cancellation and waits for retirement cleanup", async () => {
    const expected = controllerScenario("lease-delivery-first").expected;
    const cleanup = vi.fn(async () => undefined);
    const lease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
    let started!: () => void;
    const connecting = new Promise<void>((resolve) => { started = resolve; });
    const connector = vi.fn(async (context: LeaseAttemptContextV3) => {
      started();
      await new Promise<void>((resolve) => context.signal.addEventListener("abort", () => resolve(), { once: true }));
      return {
        kind: "pre_spend_failure" as const,
        error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
      };
    });
    const controller = createConnectionControllerV3({
      acquire: async () => ({ kind: "lease", lease }),
    }, connector, { capabilitySnapshot });
    controller.start();
    await connecting;
    await controller.close();
    expect(controller.state).toBe(expected.final_state);
    expect(connector).toHaveBeenCalledTimes(expected.connect_attempts);
    expect(cleanup).toHaveBeenCalledTimes(expected.retire_callbacks);
    expect(artifactLeaseStateV3(lease)).toBe(expected.lease_terminal_states[0]);
  });

  test("lets a source perform cancellation-first claim and retirement", async () => {
    let lateLease!: ArtifactLeaseV3;
    let lateClaim!: ClaimedArtifactLeaseV3;
    const cleanup = vi.fn(async () => undefined);
    const controller = createConnectionControllerV3({
      acquire: async ({ signal }) => await new Promise<ArtifactSourceResultV3>((_resolve, reject) => {
        signal.addEventListener("abort", async () => {
          lateLease = createArtifactLeaseV3Internal(primaryArtifact, async () => undefined, cleanup);
          lateClaim = claimArtifactLeaseV3(lateLease);
          await retireArtifactLeaseV3(lateClaim);
          reject(signal.reason);
        }, { once: true });
      }),
    }, async () => { throw new Error("connector must not run"); }, { capabilitySnapshot });
    controller.start();
    await controller.close();
    expect(artifactLeaseStateV3(lateLease)).toBe("retired");
    expect(cleanup).toHaveBeenCalledOnce();
  });
});

function withChangedWebTransportPin(input: ArtifactV3): ArtifactV3 {
  const clone = structuredClone(input) as ArtifactV3;
  const candidates = clone.path.candidates.map((candidate) => candidate.id !== "t-pin" ? candidate : {
    ...candidate,
    tls: {
      mode: "pin" as const,
      pins: [{
        algorithm: "sha-256" as const,
        not_after_unix_s: 2_100_000_000,
        value_b64u: Buffer.alloc(32, 0x7f).toString("base64url"),
      }],
    },
  });
  const artifact = { ...clone, path: { ...clone.path, candidates } } as ArtifactV3;
  canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates);
  return artifact;
}

function singleCandidateArtifact(input: ArtifactV3, id: string): ArtifactV3 {
  const candidate = input.path.candidates.find((value) => value.id === id);
  if (candidate === undefined) throw new Error(`fixture candidate ${id} is missing`);
  const artifact = { ...input, path: { ...input.path, candidates: [candidate] } } as ArtifactV3;
  canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates);
  return artifact;
}

function managedSession(): ManagedSessionV3 {
  return {
    waitTermination: async () => await new Promise<Readonly<{ error: Error }>>(() => undefined),
    close: async () => undefined,
  };
}

function immediateClock(observed: string[] = []): ControllerClockV3 {
  let wall = 0;
  let monotonic = 0;
  return {
    wallNowMilliseconds: () => wall,
    monotonicNowMilliseconds: () => monotonic,
    sleep: async (milliseconds, signal) => {
      if (signal.aborted) throw signal.reason;
      observed.push(`sleep:${milliseconds}`);
      wall += milliseconds;
      monotonic += milliseconds;
    },
  };
}

function capabilitySnapshot() {
  return detectNodeRuntimeCapabilityV3();
}

function controllerScenario(id: string) {
  const scenario = controllerFixture.scenarios.find((value) => value.id === id);
  if (scenario === undefined) throw new Error(`controller vector ${id} is missing`);
  return scenario;
}

async function expectBlockedPrimaryAfterSpentReplacementRetry(
  trigger: TransportFailureV3,
  expectedCode: "transport_security_failed" | "connection_failed",
): Promise<void> {
  const primary = singleCandidateArtifact(primaryArtifact, "t-pin");
  const replacement = withChangedWebTransportPin(primary);
  const cleanups = [
    vi.fn(async () => undefined),
    vi.fn(async () => undefined),
    vi.fn(async () => undefined),
  ];
  const spends = [
    vi.fn(async () => undefined),
    vi.fn(async () => undefined),
    vi.fn(async () => undefined),
  ];
  const leases = [primary, replacement, primary].map((artifact, index) =>
    createArtifactLeaseV3Internal(artifact, spends[index]!, cleanups[index]));
  const queue = [...leases];
  const acquire = vi.fn(async (): Promise<ArtifactSourceResultV3> => ({
    kind: "lease",
    lease: queue.shift()!,
  }));
  const connector = vi.fn(async (context: LeaseAttemptContextV3) => {
    if (context.kind === "primary") {
      return {
        kind: "candidate_failures" as const,
        failures: [{ candidate: context.candidates[0]!, failure: trigger }],
      };
    }
    await commitArtifactLeaseSpendV3(context.claim);
    return {
      kind: "post_spend_failure" as const,
      error: new ConnectErrorV3("connection_failed", { kind: "retryable" }),
    };
  });
  const controller = createConnectionControllerV3({ acquire }, connector, {
    maximumAttempts: 3,
    nowUnixSeconds: () => 1_900_000_000,
    clock: immediateClock(),
    capabilitySnapshot,
  });
  controller.start();
  await expect(controller.waitForSession()).rejects.toMatchObject({
    code: "failed",
    failure: { phase: "connect", code: expectedCode },
    retryDisposition: { kind: "terminal" },
  });
  expect(acquire).toHaveBeenCalledTimes(3);
  expect(connector).toHaveBeenCalledTimes(2);
  expect(spends[0]).not.toHaveBeenCalled();
  expect(spends[1]).toHaveBeenCalledOnce();
  expect(spends[2]).not.toHaveBeenCalled();
  expect(cleanups[0]).toHaveBeenCalledOnce();
  expect(cleanups[1]).not.toHaveBeenCalled();
  expect(cleanups[2]).toHaveBeenCalledOnce();
  expect(leases.map(artifactLeaseStateV3)).toEqual(["retired", "consumed", "retired"]);
  await controller.close();
}

async function waitForControllerState(
  controller: ReturnType<typeof createConnectionControllerV3>,
  state: string,
): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (controller.state !== state) {
    if (Date.now() >= deadline) throw new Error(`controller did not reach ${state}`);
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
}

class HoldingClock implements ControllerClockV3 {
  readonly delays: number[] = [];
  readonly #sleepers: Array<{ resolve: () => void; reject: (error: unknown) => void; signal: AbortSignal }> = [];

  wallNowMilliseconds(): number { return 1_900_000_000_000; }
  monotonicNowMilliseconds(): number { return 0; }
  sleep(milliseconds: number, signal: AbortSignal): Promise<void> {
    this.delays.push(milliseconds);
    return new Promise<void>((resolve, reject) => {
      const abort = () => reject(signal.reason);
      signal.addEventListener("abort", abort, { once: true });
      this.#sleepers.push({
        resolve: () => { signal.removeEventListener("abort", abort); resolve(); },
        reject: (error) => { signal.removeEventListener("abort", abort); reject(error); },
        signal,
      });
      if (signal.aborted) abort();
    });
  }

  async waitForSleepCount(count: number): Promise<void> {
    const deadline = Date.now() + 2_000;
    while (this.delays.length < count) {
      if (Date.now() >= deadline) throw new Error(`expected ${count} retry sleeps, got ${this.delays.length}`);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }
}

import { readFileSync } from "node:fs";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  createConnectionControllerV2,
  type ArtifactSource,
  type ArtifactSourceResult,
  type ConnectionController,
  type ConnectionState,
} from "./connectionController.js";
import { SDK_DEFAULTS } from "./defaults.js";
import type { ArtifactLeaseV2 } from "./v2/artifactLease.js";
import { SessionError, type SessionV2 } from "./v2/contract.js";

type ControllerScenario = Readonly<{
  name: string;
  events: readonly string[];
  states: readonly ConnectionState[];
  retry_at_unix_ms?: number;
  artifact_acquisitions?: number;
  scheduler_count?: number;
  max_in_flight_attempts?: number;
  retry_now_results?: readonly boolean[];
  close_calls?: number;
  cleanup_calls?: number;
  policy?: Readonly<{ max_attempts: number }>;
}>;

type ControllerVectors = Readonly<{
  version: number;
  states: readonly ConnectionState[];
  retry_dispositions: readonly string[];
  defaults: Readonly<{
    initial_delay_ms: number;
    max_delay_ms: number;
    factor: number;
    jitter_ratio: number;
    attempt_limit: number | null;
  }>;
  backoff_vectors: readonly Readonly<{ consecutive_failure: number; delay_ms: number }>[];
  scenarios: readonly ControllerScenario[];
  invariants: Readonly<{
    one_shot_artifact_controller: string;
    fresh_artifact_per_attempt: boolean;
    single_scheduler: boolean;
    single_in_flight_attempt: boolean;
    start_idempotent: boolean;
    close_idempotent: boolean;
    retry_now_outside_waiting: boolean;
    retry_after_bypass: boolean;
    subordinate_close_failure_propagates: boolean;
    public_retry_configuration: readonly string[];
    old_stream_migration: boolean;
    rpc_replay: boolean;
    write_replay: boolean;
    cross_session_exactly_once: boolean;
  }>;
}>;

const vectors = JSON.parse(readFileSync(
  new URL("../../testdata/transport_v2/connection_controller_vectors.json", import.meta.url),
  "utf8",
)) as ControllerVectors;

afterEach(() => vi.useRealTimers());

describe("shared ConnectionController lifecycle vectors", () => {
  test("binds defaults, backoff, dispositions, and invariants to the implementation", () => {
    expect(vectors.version).toBe(2);
    expect(vectors.states).toEqual(["idle", "connecting", "connected", "waiting", "failed", "closed"]);
    expect(vectors.retry_dispositions).toEqual(["terminal", "retryable", "retry_after"]);
    expect(vectors.defaults).toEqual({
      initial_delay_ms: SDK_DEFAULTS.connectionController.initialDelayMs,
      max_delay_ms: SDK_DEFAULTS.connectionController.maxDelayMs,
      factor: SDK_DEFAULTS.connectionController.factor,
      jitter_ratio: SDK_DEFAULTS.connectionController.jitterRatio,
      attempt_limit: SDK_DEFAULTS.connectionController.defaultAttemptLimit,
    });
    expect(vectors.backoff_vectors).toEqual([1, 2, 3, 8, 20].map((consecutive_failure) => ({
      consecutive_failure,
      delay_ms: Math.min(
        vectors.defaults.max_delay_ms,
        vectors.defaults.initial_delay_ms * (vectors.defaults.factor ** (consecutive_failure - 1)),
      ),
    })));
    expect(vectors.invariants).toEqual({
      one_shot_artifact_controller: "forbidden",
      fresh_artifact_per_attempt: true,
      single_scheduler: true,
      single_in_flight_attempt: true,
      start_idempotent: true,
      close_idempotent: true,
      retry_now_outside_waiting: false,
      retry_after_bypass: false,
      subordinate_close_failure_propagates: false,
      public_retry_configuration: ["maximum_attempts"],
      old_stream_migration: false,
      rpc_replay: false,
      write_replay: false,
      cross_session_exactly_once: false,
    });
    expect(vectors.scenarios.every((scenario) => scenario.events.length > 0)).toBe(true);
  });

  test.each(vectors.scenarios)("executes $name", async (scenario) => {
    switch (scenario.name) {
      case "connect_and_replace_after_termination":
        await connectAndReplace(scenario);
        break;
      case "retry_now_wakes_existing_wait":
        await retryNowWakesExistingWait(scenario);
        break;
      case "repeated_start_is_idempotent":
        await repeatedStartIsIdempotent(scenario);
        break;
      case "start_after_close_stays_closed":
        await startAfterCloseStaysClosed(scenario);
        break;
      case "retry_now_outside_waiting_returns_false":
        await retryNowOutsideWaitingReturnsFalse(scenario);
        break;
      case "retry_after_is_authoritative":
        await retryAfterIsAuthoritative(scenario);
        break;
      case "terminal_failure":
        await terminalFailure(scenario);
        break;
      case "explicit_attempt_exhaustion":
        await explicitAttemptExhaustion(scenario);
        break;
      case "close_cancels_single_attempt":
        await closeCancelsSingleAttempt(scenario);
        break;
      case "repeated_close_is_idempotent":
        await repeatedCloseIsIdempotent(scenario);
        break;
      case "close_waits_for_owned_cleanup":
        await closeWaitsForOwnedCleanup(scenario);
        break;
      case "subordinate_close_failure_is_ignored":
        await subordinateCloseFailureIsIgnored(scenario);
        break;
      default:
        throw new Error(`unimplemented ConnectionController vector: ${scenario.name}`);
    }
  });
});

async function connectAndReplace(vector: ControllerScenario): Promise<void> {
  vi.useFakeTimers();
  const leases = [lease(), lease()];
  const first = session("session-1");
  const second = session("session-2");
  const acquired: ArtifactLeaseV2[] = [];
  let acquisition = 0;
  const controller = createConnectionControllerV2(
    source(async () => ({ kind: "lease", lease: leases[acquisition++]! })),
    async (value) => {
      acquired.push(value);
      return value === leases[0] ? first.value : second.value;
    },
  );
  const states = observedStates(controller);

  controller.start();
  expect(await controller.waitForSession()).toBe(first.value);
  const oldStream = await first.value.openStream("old-operation");
  await oldStream.write(Uint8Array.of(1));
  await first.value.rpc.call(7, { request: "old" }, (payload) => payload);
  await first.value.rpc.notify(8, { notify: "old" });

  first.terminate(new SessionError("closed"));
  await flush();
  await vi.advanceTimersByTimeAsync(250);
  expect(await controller.waitForSession()).toBe(second.value);

  expect(states.values).toEqual(vector.states);
  expect(acquired).toEqual(leases);
  expect(first.openStream).toHaveBeenCalledOnce();
  expect(first.rpcCall).toHaveBeenCalledOnce();
  expect(first.rpcNotify).toHaveBeenCalledOnce();
  expect(second.openStream).not.toHaveBeenCalled();
  expect(second.rpcCall).not.toHaveBeenCalled();
  expect(second.rpcNotify).not.toHaveBeenCalled();
  states.stop();
  await controller.close();
}

async function retryNowWakesExistingWait(vector: ControllerScenario): Promise<void> {
  vi.useFakeTimers();
  const connected = session("session-1");
  let acquisition = 0;
  let inFlight = 0;
  let maximumInFlight = 0;
  const controller = createConnectionControllerV2(
    source(async () => {
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      await Promise.resolve();
      inFlight -= 1;
      acquisition += 1;
      return acquisition === 1
        ? { kind: "failure", code: "unavailable", disposition: { kind: "retryable" } }
        : { kind: "lease", lease: lease() };
    }),
    async () => connected.value,
  );
  const states = observedStates(controller);

  controller.start();
  controller.start();
  await flush();
  expect(controller.state).toBe("waiting");
  expect(controller.retryNow()).toBe(true);
  await flush();
  expect(await controller.waitForSession()).toBe(connected.value);

  expect(states.values).toEqual(vector.states);
  expect(acquisition).toBe(2);
  expect(maximumInFlight).toBe(vector.max_in_flight_attempts);
  expect(vector.scheduler_count).toBe(1);
  expect(controller.retryNow()).toBe(false);
  states.stop();
  await controller.close();
}

async function repeatedStartIsIdempotent(vector: ControllerScenario): Promise<void> {
  let acquisitions = 0;
  const controller = createConnectionControllerV2(
    source(async ({ signal }) => await new Promise<ArtifactSourceResult>((_resolve, reject) => {
      acquisitions += 1;
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    })),
    async () => session("unused").value,
  );
  controller.start();
  controller.start();
  await flush();
  expect(acquisitions).toBe(vector.max_in_flight_attempts);
  expect(vector.scheduler_count).toBe(1);
  await controller.close();
}

async function startAfterCloseStaysClosed(vector: ControllerScenario): Promise<void> {
  let acquisitions = 0;
  const controller = createConnectionControllerV2(
    source(async () => {
      acquisitions += 1;
      return { kind: "failure", code: "unused", disposition: { kind: "terminal" } };
    }),
    async () => session("unused").value,
  );
  await controller.close();
  controller.start();
  await flush();
  expect(controller.state).toBe("closed");
  expect(acquisitions).toBe(vector.artifact_acquisitions);
  expect(vector.scheduler_count).toBe(0);
}

async function retryNowOutsideWaitingReturnsFalse(vector: ControllerScenario): Promise<void> {
  const results: boolean[] = [];
  const controller = createConnectionControllerV2(
    source(async ({ signal }) => await new Promise<ArtifactSourceResult>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    })),
    async () => session("unused").value,
  );
  results.push(controller.retryNow());
  controller.start();
  await flush();
  results.push(controller.retryNow());
  await controller.close();
  results.push(controller.retryNow());
  expect(results).toEqual(vector.retry_now_results);
}

async function retryAfterIsAuthoritative(vector: ControllerScenario): Promise<void> {
  const retryAt = vector.retry_at_unix_ms;
  if (retryAt === undefined) throw new Error("retry_after vector is missing retry_at_unix_ms");
  vi.useFakeTimers({ now: retryAt - 4_000 });
  let acquisition = 0;
  const connected = session("session-1");
  const controller = createConnectionControllerV2(
    source(async () => {
      acquisition += 1;
      return acquisition === 1
        ? {
            kind: "failure",
            code: "rate_limited",
            disposition: { kind: "retry_after", notBeforeUnixMilliseconds: retryAt },
          }
        : { kind: "lease", lease: lease() };
    }),
    async () => connected.value,
  );
  const states = observedStates(controller);

  controller.start();
  await flush();
  expect(controller.retryNow()).toBe(vector.retry_now_results?.[0]);
  await vi.advanceTimersByTimeAsync(3_999);
  expect(acquisition).toBe(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(await controller.waitForSession()).toBe(connected.value);

  expect(states.values).toEqual(vector.states);
  states.stop();
  await controller.close();
}

async function terminalFailure(vector: ControllerScenario): Promise<void> {
  let acquisitions = 0;
  const controller = createConnectionControllerV2(
    source(async () => {
      acquisitions += 1;
      return { kind: "failure", code: "unsupported", disposition: { kind: "terminal" } };
    }),
    async () => session("unused").value,
  );
  const states = observedStates(controller);

  controller.start();
  await flush();

  expect(states.values).toEqual(vector.states);
  expect(acquisitions).toBe(vector.artifact_acquisitions);
  await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
  states.stop();
  await controller.close();
}

async function explicitAttemptExhaustion(vector: ControllerScenario): Promise<void> {
  vi.useFakeTimers();
  let acquisitions = 0;
  const controller = createConnectionControllerV2(
    source(async () => {
      acquisitions += 1;
      return { kind: "failure", code: "unavailable", disposition: { kind: "retryable" } };
    }),
    async () => session("unused").value,
    { maximumAttempts: vector.policy?.max_attempts },
  );
  const states = observedStates(controller);

  controller.start();
  await flush();
  await vi.advanceTimersByTimeAsync(250);
  await flush();

  expect(states.values).toEqual(vector.states);
  expect(acquisitions).toBe(vector.artifact_acquisitions);
  expect(controller.state).toBe("failed");
  states.stop();
  await controller.close();
}

async function closeCancelsSingleAttempt(vector: ControllerScenario): Promise<void> {
  let inFlight = 0;
  let maximumInFlight = 0;
  let observedAbort = false;
  const controller = createConnectionControllerV2(
    source(async ({ signal }) => await new Promise<ArtifactSourceResult>((_resolve, reject) => {
      inFlight += 1;
      maximumInFlight = Math.max(maximumInFlight, inFlight);
      signal.addEventListener("abort", () => {
        observedAbort = true;
        inFlight -= 1;
        reject(signal.reason);
      }, { once: true });
    })),
    async () => session("unused").value,
  );
  const states = observedStates(controller);

  controller.start();
  await flush();
  await controller.close();

  expect(states.values).toEqual(vector.states);
  expect(observedAbort).toBe(true);
  expect(inFlight).toBe(0);
  expect(maximumInFlight).toBe(vector.max_in_flight_attempts);
  states.stop();
}

async function repeatedCloseIsIdempotent(vector: ControllerScenario): Promise<void> {
  let cleanups = 0;
  const controller = createConnectionControllerV2(
    source(async ({ signal }) => await new Promise<ArtifactSourceResult>((_resolve, reject) => {
      signal.addEventListener("abort", () => {
        cleanups += 1;
        reject(signal.reason);
      }, { once: true });
    })),
    async () => session("unused").value,
  );
  controller.start();
  await flush();
  const first = controller.close();
  const second = controller.close();
  expect(first).toBe(second);
  await Promise.all([first, second]);
  expect(vector.close_calls).toBe(2);
  expect(cleanups).toBe(vector.cleanup_calls);
}

async function closeWaitsForOwnedCleanup(vector: ControllerScenario): Promise<void> {
  let resolveConnect!: (value: SessionV2) => void;
  const pending = new Promise<SessionV2>((resolve) => { resolveConnect = resolve; });
  const late = session("late");
  const controller = createConnectionControllerV2(
    source(async () => ({ kind: "lease", lease: lease() })),
    async () => await pending,
  );
  controller.start();
  await flush();
  let closed = false;
  const closing = controller.close().then(() => { closed = true; });
  await flush();
  expect(closed).toBe(false);
  resolveConnect(late.value);
  await closing;
  expect(late.close).toHaveBeenCalledTimes(vector.cleanup_calls ?? 0);
}

async function subordinateCloseFailureIsIgnored(vector: ControllerScenario): Promise<void> {
  const connected = session("connected");
  connected.close.mockRejectedValueOnce(new Error("subordinate close failed"));
  const controller = createConnectionControllerV2(
    source(async () => ({ kind: "lease", lease: lease() })),
    async () => connected.value,
  );
  controller.start();
  await expect(controller.waitForSession()).resolves.toBe(connected.value);
  await expect(controller.close()).resolves.toBeUndefined();
  expect(connected.close).toHaveBeenCalledTimes(vector.cleanup_calls ?? 0);
}

function source(acquire: ArtifactSource["acquire"]): ArtifactSource {
  return { acquire };
}

function lease(): ArtifactLeaseV2 {
  return {} as ArtifactLeaseV2;
}

function observedStates(controller: ConnectionController): Readonly<{
  values: ConnectionState[];
  stop(): void;
}> {
  const values: ConnectionState[] = [];
  const stop = controller.subscribe((snapshot) => values.push(snapshot.state));
  return { values, stop };
}

function session(name: string): Readonly<{
  value: SessionV2;
  openStream: ReturnType<typeof vi.fn>;
  rpcCall: ReturnType<typeof vi.fn>;
  rpcNotify: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  terminate(error: SessionError): void;
}> {
  let terminate!: (value: Readonly<{ error: SessionError }>) => void;
  const termination = new Promise<Readonly<{ error: SessionError }>>((resolve) => { terminate = resolve; });
  const stream = {
    kind: `${name}-stream`,
    terminalError: undefined,
    read: vi.fn(async () => null),
    write: vi.fn(async (data: Uint8Array) => data.byteLength),
    closeWrite: vi.fn(async () => undefined),
    reset: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
  };
  const openStream = vi.fn(async () => stream);
  const rpcCall = vi.fn(async (_type: number, payload: unknown) => ({ ok: true as const, payload }));
  const rpcNotify = vi.fn(async () => undefined);
  const value = {
    rpc: {
      call: rpcCall,
      notify: rpcNotify,
      onNotify: vi.fn(() => () => undefined),
    },
    openStream,
    acceptStream: vi.fn(),
    rekey: vi.fn(),
    probeLiveness: vi.fn(),
    waitTermination: async () => await termination,
    close: vi.fn(async () => undefined),
  } satisfies SessionV2;
  return { value, openStream, rpcCall, rpcNotify, close: value.close, terminate: (error) => terminate({ error }) };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 8; index++) await Promise.resolve();
}

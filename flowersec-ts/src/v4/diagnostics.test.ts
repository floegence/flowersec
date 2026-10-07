import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiagnosticCounters, diagnosticFailure } from "./runtime/diagnosticCounters.js";
import { DiagnosticActivity } from "./runtime/diagnosticObservation.js";
import { RuntimeDiagnosticSink } from "./runtime/diagnosticSink.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import type { DiagnosticEvent, DiagnosticSinkOptions } from "./diagnostics.js";

function fixture(options: DiagnosticSinkOptions) {
  const limit = new ResourceVector(Array<bigint>(11).fill(100000000n));
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 4, reservations: 64, references: 128,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const accounts = [root.account("tenant", "1".repeat(32), limit), root.account("environment", "2".repeat(32), limit)];
  const resources = { root, accounts, runtimeBytes: 1024n, owner: { tenant: "1".repeat(32), environment: "2".repeat(32), kind: "diagnostic", backing: "3".repeat(32) } };
  const counters = new DiagnosticCounters(), sink = new RuntimeDiagnosticSink(resources, options, 25, counters, () => {});
  return { root, sink, counters, close: async () => { await sink.close(); for (const account of accounts) account.close(); root.close(); } };
}

describe("production diagnostic sink ownership", () => {
  beforeEach(() => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-04T12:00:00Z"));
    let nextID = 0;
    // Independent deterministic entropy at the host boundary, never the
    // protocol RNG. Four-byte zero samples pass the real 1% predicate.
    vi.spyOn(globalThis.crypto, "getRandomValues").mockImplementation(input => {
      const bytes = input as Uint8Array; bytes.fill(bytes.byteLength === 16 ? ++nextID : 0); return input;
    });
  });
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

  it("preserves the original retry bucket and publishes one failure event", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const observer = { counters: f.counters, begin: () => f.sink.begin() };
    try {
      for (const [ordinal, bucket] of [[1n, "1"], [3n, "2_3"], [7n, "4_7"], [8n, "8_plus"]] as const) {
        const activity = new DiagnosticActivity(observer, "material", true, ordinal);
        activity.phase("handshake"); activity.failure(new Error("authentication_failed"), true);
        activity.failure(new Error("authentication_failed"), true);
        await vi.advanceTimersByTimeAsync(5);
        const current = events.splice(0);
        expect(current).toHaveLength(4);
        expect(current.every(event => event.attempt_bucket === bucket)).toBe(true);
        expect(current.filter(event => event.state === "failed")).toHaveLength(1);
        expect(new Set(current.map(event => event.correlation_id)).size).toBe(1);
      }
      expect(f.counters.snapshot("connection_attempt").total).toBe(4n);
      expect(f.counters.snapshot("connection_failure").total).toBe(4n);
      expect(f.counters.snapshot("identity_rejection").total).toBe(4n);
    } finally { await f.close(); }
  });

  it("delivers on its executor lane with independent rotating IDs and exact fields", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const session = f.sink.begin(), operation = f.sink.begin();
    try {
      session.emit({ state: "ready" }); operation.emit({ phase: "application" });
      expect(events).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(5);
      expect(events).toHaveLength(2);
      expect(events[0]!.correlation_id).not.toBe(events[1]!.correlation_id);
      expect(Object.keys(events[0]!).sort()).toEqual(["state", "phase", "code", "duration_bucket", "attempt_bucket", "retry_disposition", "correlation_id"].sort());
      expect(events[0]!.correlation_id).toMatch(/^[0-9a-f]{32}$/u);
      expect(new TextEncoder().encode(JSON.stringify(events[0])).length).toBeLessThanOrEqual(512);
      const previous = events[0]!.correlation_id;
      vi.setSystemTime(new Date("2026-10-04T12:15:00Z"));
      session.emit({ state: "ready" }); await vi.advanceTimersByTimeAsync(5);
      expect(events.at(-1)!.correlation_id).not.toBe(previous);
    } finally { session.close(); operation.close(); await f.close(); }
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });

  it("purges old queued events without disclosing a cross-bucket mapping", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const operation = f.sink.begin();
    try {
      operation.emit({ phase: "material" });
      vi.setSystemTime(new Date("2026-10-04T12:15:00Z"));
      operation.emit({ phase: "application" }); await vi.advanceTimersByTimeAsync(5);
      expect(events.map(event => event.phase)).toEqual(["application"]);
      expect(f.counters.snapshot("diagnostic_drop").total).toBe(1n);
    } finally { operation.close(); await f.close(); }
  });

  it("keeps an unpublished candidate's outcome when its Session closes first", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const activity = new DiagnosticActivity({ counters: f.counters, begin: () => f.sink.begin() }, "material", true, 2n);
    try {
      activity.holdPublication(); activity.event({ state: "ready" }); activity.close();
      activity.failure(new Error("initialization_failed"), true); activity.finishPublication();
      await vi.advanceTimersByTimeAsync(5);
      expect(f.counters.snapshot("connection_failure").total).toBe(1n);
      expect(events.map(event => event.state)).toEqual(["starting", "ready", "failed", "closed"]);
      expect(events.every(event => event.attempt_bucket === "2_3")).toBe(true);
      expect(new Set(events.map(event => event.correlation_id)).size).toBe(1);
    } finally { activity.finishPublication(); activity.close(); await f.close(); }
  });

  it("retains only finite failure facts until the original publication exits", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const activity = new DiagnosticActivity({ counters: f.counters, begin: () => f.sink.begin() }, "application");
    const error = new Error("canceled"), failure = diagnosticFailure(error);
    // The store/provider may keep or mutate its own exception after returning.
    // Diagnostic tails carry only the already projected scalar facts.
    Object.defineProperty(error, "message", { get: () => { throw new Error("late error access"); } });
    try {
      activity.holdPublication(); activity.failureFacts(failure);
      await vi.advanceTimersByTimeAsync(5);
      expect(events.map(event => event.state)).toEqual(["starting", "failed"]);
      expect(events.at(-1)!.code).toBe("cancelled");
      activity.failureFacts(diagnosticFailure(new Error("deadline_exceeded")));
      activity.finishPublication(); activity.finishPublication(); activity.close();
      await vi.advanceTimersByTimeAsync(5);
      expect(events.map(event => event.state)).toEqual(["starting", "failed", "closed"]);
      expect(new Set(events.map(event => event.correlation_id)).size).toBe(1);
    } finally { activity.finishPublication(); activity.close(); await f.close(); }
  });

  it("retains actual callback charge beyond bounded Close and cancels outside Close", async () => {
    let release!: () => void, entered = false, canceled = false, closing = false;
    const tail = new Promise<void>(resolve => { release = resolve; });
    const f = fixture({ runtimeBytes: 1024n, callback: (_event, { signal }) => {
      entered = true; signal.addEventListener("abort", () => { expect(closing).toBe(false); canceled = true; }); return tail;
    } });
    const operation = f.sink.begin(); operation.emit({ state: "ready" });
    await vi.advanceTimersByTimeAsync(5); expect(entered).toBe(true);
    closing = true; const closed = f.sink.close(); closing = false;
    expect(canceled).toBe(false);
    await vi.advanceTimersByTimeAsync(30);
    expect(await closed).toMatchObject({ status: "cleanup_incomplete", pending_callbacks: 1n });
    expect(canceled).toBe(true); expect(f.root.snapshot().reservations).toBeGreaterThan(0);
    release(); await vi.advanceTimersByTimeAsync(5);
    expect(f.sink.cleanupStatus().status).toBe("complete");
    operation.close(); await f.close(); expect(f.root.snapshot().cleanupComplete).toBe(true);
  });

  it("observes cleanup without closing a live sink or starting its deadline", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, callback: event => { events.push(event); } });
    const abort = new AbortController(), operation = f.sink.begin();
    let observed = false;
    const wait = f.sink.waitCleanup().then(status => { observed = true; return status; });
    const canceled = f.sink.waitCleanup({ signal: abort.signal });
    operation.emit({ state: "ready" }); await vi.advanceTimersByTimeAsync(100);
    expect(observed).toBe(false); expect(f.sink.cleanupStatus().status).toBe("pending");
    expect(events).toHaveLength(1);
    abort.abort(); await expect(canceled).rejects.toThrow("canceled");
    operation.emit({ phase: "application" }); await vi.advanceTimersByTimeAsync(5);
    expect(events).toHaveLength(2); expect(f.counters.snapshot("cleanup_timeout").total).toBe(0n);
    operation.close(); await f.sink.close(); expect((await wait).status).toBe("complete"); await f.close();
  });

  it("bounds IDs, queued events and sampling without sampling counters", async () => {
    const events: DiagnosticEvent[] = [], f = fixture({ runtimeBytes: 1024n, operationSlots: 1, queueEvents: 2, callback: event => { events.push(event); } });
    const operation = f.sink.begin(), rejected = f.sink.begin();
    try {
      for (let n = 0; n < 10; n++) { operation.emit({ state: "ready" }); f.counters.observe("connection_attempt"); }
      await vi.advanceTimersByTimeAsync(5);
      expect(events).toHaveLength(2); expect(f.counters.snapshot("diagnostic_drop").total).toBe(9n);
      expect(f.counters.snapshot("connection_attempt").total).toBe(10n);
    } finally { operation.close(); rejected.close(); await f.close(); }
    const zero = fixture({ runtimeBytes: 1024n, sampleBasisPoints: 0, callback: event => { events.push(event); } });
    zero.sink.begin().emit({ state: "ready" }); await vi.advanceTimersByTimeAsync(5); expect(events).toHaveLength(2); await zero.close();
  });

  it("enforces per-bucket cumulative ID and event limits after slots recycle", async () => {
    let delivered = 0;
    const f = fixture({ runtimeBytes: 1024n, operationSlots: 1, queueEvents: 4, callback: () => { delivered++; } });
    try {
      const operation = f.sink.begin();
      for (let batch = 0; batch < 1024; batch++) {
        for (let event = 0; event < 4; event++) operation.emit({ state: "ready" });
        await vi.advanceTimersByTimeAsync(5);
      }
      expect(delivered).toBe(4096);
      operation.emit({ state: "ready" }); await vi.advanceTimersByTimeAsync(5);
      expect(delivered).toBe(4096);
      operation.close();
      for (let id = 1; id < 1024; id++) f.sink.begin().close();
      const before = f.counters.snapshot("diagnostic_drop").total;
      f.sink.begin().close(); expect(f.counters.snapshot("diagnostic_drop").total).toBe(before + 1n);
      vi.setSystemTime(new Date("2026-10-04T12:15:00Z"));
      const next = f.sink.begin(); next.emit({ state: "ready" }); next.close();
      await vi.advanceTimersByTimeAsync(5); expect(delivered).toBe(4097);
    } finally { await f.close(); }
  });

  it("reclaims canceled cleanup wait positions without attaching latent reactions", async () => {
    let release!: () => void;
    const tail = new Promise<void>(resolve => { release = resolve; });
    const f = fixture({ runtimeBytes: 1024n, callback: () => tail });
    const operation = f.sink.begin(); operation.emit({ state: "ready" }); await vi.advanceTimersByTimeAsync(5);
    for (let n = 0; n < 32; n++) {
      const abort = new AbortController(), wait = f.sink.waitCleanup({ signal: abort.signal });
      abort.abort(); await expect(wait).rejects.toThrow("canceled");
    }
    release(); await vi.advanceTimersByTimeAsync(5); operation.close(); await f.close();
    expect(f.root.snapshot().cleanupComplete).toBe(true);
  });
});

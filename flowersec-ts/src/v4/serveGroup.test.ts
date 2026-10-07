import { describe, expect, it, vi } from "vitest";
import { createSessionDrain, type V4DrainOutcome } from "./drain.js";
import type { V4SessionOwner } from "./public.js";
import type { SessionCleanup } from "./runtime/sessionCleanup.js";
import { ServeGroup } from "./runtime/serveGroup.js";
import { V4EnvironmentRuntime } from "./runtime/environment.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { ClockRate, TimeError } from "./runtime/timeArithmetic.js";
import type { ServeCallbacks, AuthorizeApplicationResult, ApplicationAuthorizationLease } from "./serve.js";
const complete = Object.freeze({ status: "complete", core_cleanup: "complete", pending_callbacks: 0n } as const);
const authentication = Object.freeze({ tenant: "tenant", audience: "service", localRole: "server", localSubject: "server", peerSubject: "client", peerIdentityDigest: "1".repeat(64) } as const);
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(yes => { resolve = yes; }); return { promise, resolve }; }
function setup(overrides: Partial<ServeCallbacks<object>> = {}, onTick?: () => void) {
  const limit = new ResourceVector([512n << 20n, 0n, 0n, 5000000n, 5000000n, 2000n, 2000n, 2000n, 2000n, 2000n, 2000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 16, reservations: 256, references: 512,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const start = performance.now();
  const environment = new V4EnvironmentRuntime({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: "2".repeat(32), runtimeBytes: 1024n,
    namespaces: 1, sources: 1, acquisitions: 1, materials: 1, sessions: 1, acquireMS: 10000n, cleanupMS: 10,
    clock: { profile: { rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
      tick: () => { onTick?.(); return { milliseconds: BigInt(Math.floor(performance.now() - start)), incarnation: "3".repeat(32) }; }, initial: () => ({ lowerMS: 1000n, upperMS: 1000n }) },
    random: bytes => { crypto.getRandomValues(bytes); } });
  const lease = { close: vi.fn(), waitCleanup: vi.fn(async () => complete) }, handlers = Object.freeze({});
  const callbacks: ServeCallbacks<object> = { authorizeRequest: vi.fn(() => ({ allowed: true })), resolveHandlers: vi.fn(() => handlers),
    authorizeApplication: vi.fn(() => ({ decision: "authorized" as const, handlers, lease })), onSession: vi.fn(() => ({ accepted: true })), release: vi.fn(() => complete), ...overrides };
  const group = new ServeGroup(environment, { positions: 1, callbackBytes: 1024n, handshakeMS: 1000n, drainMS: 1000n, cleanupMS: 15n }, callbacks);
  const seal = vi.fn(), abort = vi.fn(); group.bindListener(seal, abort);
  return { root, environment, group, callbacks, lease, handlers, seal, abort, async close() {
    group.close(); group.listenerEnded(); expect((await group.waitCleanup()).status).toBe("complete");
    expect(environment.cleanupStatus().status).toBe("pending"); await environment.close(); expect(root.snapshot().reservations).toBe(0);
  } };
}
describe("original Serve aggregate", () => {
  it("keeps authorization and Release in one bounded invocation", async () => {
    const f = setup(), nativeClose = vi.fn(), ingress = f.group.begin(nativeClose);
    try {
      await ingress.authorizeRequest("https://example.com"); expect(await ingress.authorize(authentication)).toBe(f.handlers);
      expect(() => f.group.begin(vi.fn())).toThrow("resource_exhausted");
      expect(f.callbacks.resolveHandlers).toHaveBeenCalledWith(expect.objectContaining({ authentication }));
      await ingress.finish(); expect(f.lease.close).toHaveBeenCalledTimes(1); expect(f.lease.waitCleanup).toHaveBeenCalledTimes(1);
      expect(f.callbacks.release).toHaveBeenCalledWith(expect.objectContaining({ invocation: ingress.invocation, authorization: "authorized", published: false }));
      expect(nativeClose).toHaveBeenCalledTimes(1);
    } finally { await f.close(); }
  });
  it("burns a lease returned after cancellation and retains the callback charge", async () => {
    const result = deferred<AuthorizeApplicationResult>(), entered = deferred<void>();
    const f = setup({ authorizeApplication: async () => { entered.resolve(); return result.promise; } });
    const ingress = f.group.begin(vi.fn()), authorization = ingress.authorize(authentication), rejected = expect(authorization).rejects.toThrow("closed");
    await entered.promise; f.group.close(); f.group.listenerEnded();
    expect(f.group.cleanupStatus().pending_callbacks).toBe(1n); expect((await f.group.waitCleanup()).status).toBe("cleanup_incomplete");
    expect(f.root.snapshot().reservations).toBeGreaterThan(3);
    result.resolve({ decision: "authorized", handlers: f.handlers, lease: f.lease }); await rejected;
    await ingress.finish(); expect(f.lease.close).toHaveBeenCalledTimes(1); await f.close();
  });
  it("joins the actual Release tail and keeps its position occupied", async () => {
    const released = deferred<typeof complete>(), entered = deferred<void>();
    const f = setup({ release: async () => { entered.resolve(); return released.promise; } });
    const ingress = f.group.begin(vi.fn()); await ingress.authorize(authentication);
    const finishing = ingress.finish(); await entered.promise;
    expect(f.group.cleanupStatus()).toMatchObject({ pending_callbacks: 1n }); expect(() => f.group.begin(vi.fn())).toThrow("resource_exhausted");
    f.group.close(); f.group.listenerCoreEnded();
    expect(f.group.cleanupStatus()).toMatchObject({ core_cleanup: "complete", pending_callbacks: 1n });
    expect((await f.group.waitCleanup()).status).toBe("cleanup_incomplete");
    released.resolve(complete); await finishing; await f.close();
  });
  it("settles unknown authorization through Release without publishing", async () => {
    const f = setup({ authorizeApplication: () => { throw new Error("secret application error"); } });
    const ingress = f.group.begin(vi.fn()); await expect(ingress.authorize(authentication)).rejects.toThrow("secret application error");
    await ingress.finish(); expect(f.callbacks.onSession).not.toHaveBeenCalled();
    expect(f.callbacks.release).toHaveBeenCalledWith(expect.objectContaining({ authorization: "unknown", published: false })); await f.close();
  });
  it("releases a denied request without invoking identity or application callbacks", async () => {
    const f = setup({ authorizeRequest: () => ({ allowed: false }) }); const ingress = f.group.begin(vi.fn());
    await expect(ingress.authorizeRequest("")).rejects.toThrow("rejected"); await ingress.finish();
    expect(f.callbacks.authorizeApplication).not.toHaveBeenCalled(); expect(f.callbacks.release).toHaveBeenCalledWith(expect.objectContaining({ authorization: "not_started" })); await f.close();
  });
  it("does not let canceled cleanup waits cancel the aggregate", async () => {
    const f = setup(), cancel = new AbortController(), waiting = f.group.waitCleanup({ signal: cancel.signal });
    const failure = expect(waiting).rejects.toMatchObject({ code: "canceled" }); cancel.abort(); await failure;
    expect(f.seal).not.toHaveBeenCalled(); const ingress = f.group.begin(vi.fn()); await ingress.finish(); await f.close();
  });
  it("seals ingress on Drain and retains native cleanup until the listener ends", async () => {
    const f = setup(), ingress = f.group.begin(vi.fn()); const drain = f.group.drain({ timeoutMS: 500n });
    expect(f.group.drain()).toBe(drain); expect(f.seal).toHaveBeenCalledTimes(1); expect(ingress.signal.aborted).toBe(true);
    expect(() => f.group.begin(vi.fn())).toThrow("closed"); await ingress.finish(); expect(drain.status()).toMatchObject({ outcome: "drained", cleanup_status: { core_cleanup: "pending" } });
    f.group.listenerEnded(); expect((await drain.wait()).outcome).toBe("drained"); await f.close();
  });
  it("captures the original lease methods before application mutation", async () => {
    const original = vi.fn(), lease: ApplicationAuthorizationLease = { close: original, waitCleanup: async () => complete };
    const f = setup({ authorizeApplication: (_context, handlers) => ({ decision: "authorized", handlers, lease }) });
    const ingress = f.group.begin(vi.fn()); await ingress.authorize(authentication);
    lease.close = () => { throw new Error("mutated"); }; await ingress.finish(); expect(original).toHaveBeenCalledTimes(1); await f.close();
  });
  it("re-observes an incomplete lease without repeating Release or freeing its position", async () => {
    let done = false;
    const lease = { close: vi.fn(), waitCleanup: vi.fn(async () => done ? complete : { status: "cleanup_incomplete", core_cleanup: "complete", pending_callbacks: 1n } as const) };
    const f = setup({ authorizeApplication: (_context, handlers) => ({ decision: "authorized", handlers, lease }) });
    const ingress = f.group.begin(vi.fn()); await ingress.authorize(authentication);
    const finishing = ingress.finish();
    await expect.poll(() => f.callbacks.release).toHaveBeenCalledTimes(1);
    expect(f.group.cleanupStatus()).toMatchObject({ status: "cleanup_incomplete", pending_callbacks: 1n });
    expect(() => f.group.begin(vi.fn())).toThrow("resource_exhausted");
    f.group.close(); f.group.listenerCoreEnded();
    expect((await f.group.waitCleanup()).status).toBe("cleanup_incomplete");
    done = true; await finishing;
    expect(lease.close).toHaveBeenCalledTimes(1); expect(lease.waitCleanup.mock.calls.length).toBeGreaterThan(1);
    expect(f.callbacks.release).toHaveBeenCalledTimes(1); await f.close();
  });
  for (const outcome of ["drained", "deadline_aborted", "failed"] as const) {
    it(`preserves a published child's ${outcome} Drain outcome independently of cleanup`, async () => {
      const f = setup(), ingress = f.group.begin(vi.fn()), cleanup = deferred<void>();
      let cleaned = false;
      const childDrain = createSessionDrain(() => () => undefined, complete);
      const child = {
        info: () => ({}), cleanupStatus: () => cleaned ? complete : { status: "pending", core_cleanup: "complete", pending_callbacks: 1n },
        close: async () => { childDrain.finish("failed"); }, drain: () => childDrain.operation,
        cleanupOwner: { onServeCleanup: (callback: () => void) => { void cleanup.promise.then(callback); } },
      } as unknown as V4SessionOwner & { cleanupOwner: SessionCleanup };
      await ingress.authorize(authentication); await ingress.publish(child);
      const drain = f.group.drain(); childDrain.finish(outcome);
      const finishing = ingress.finish(); f.group.listenerCoreEnded();
      expect(drain.status().outcome).toBe(outcome);
      expect(f.group.cleanupStatus()).toMatchObject({ core_cleanup: "complete", pending_callbacks: 1n });
      cleaned = true; cleanup.resolve(); await finishing; f.group.listenerEnded();
      expect((await drain.wait()).outcome).toBe(outcome); await f.close();
    });
  }
  for (const seal of ["drain", "close"] as const) {
    it(`acknowledges the original READY claim after ${seal} seals admission`, async () => {
      const f = setup(), ingress = f.group.begin(vi.fn()), childDrain = createSessionDrain(() => () => undefined, complete);
      const child = { info: () => ({}), cleanupStatus: () => complete,
        drain: () => childDrain.operation, close: vi.fn(async () => { childDrain.finish("failed"); }) } as unknown as V4SessionOwner & { cleanupOwner: SessionCleanup };
      try {
        await ingress.authorize(authentication); ingress.claim(child);
        if (seal === "drain") f.group.drain(); else f.group.close();
        await expect(ingress.publishClaimed()).resolves.toBeUndefined();
        expect(f.callbacks.onSession).toHaveBeenCalledTimes(1);
        await ingress.publishClaimed(); expect(f.callbacks.onSession).toHaveBeenCalledTimes(1);
        await ingress.finish();
        expect(f.callbacks.release).toHaveBeenCalledWith(expect.objectContaining({ authorization: "authorized", published: true }));
        expect(f.lease.close).toHaveBeenCalledTimes(1);
      } finally { await f.close(); }
    });
  }
  it("retains a claimed handoff callback through Close until its actual acknowledgment", async () => {
    const entered = deferred<void>(), acknowledged = deferred<{ accepted: true }>();
    const f = setup({ onSession: async () => { entered.resolve(); return acknowledged.promise; } });
    const ingress = f.group.begin(vi.fn());
    const child = { info: () => ({}), cleanupStatus: () => complete, close: vi.fn(async () => undefined) } as unknown as V4SessionOwner & { cleanupOwner: SessionCleanup };
    try {
      await ingress.authorize(authentication); ingress.claim(child);
      const publishing = ingress.publishClaimed(); await entered.promise;
      f.group.close(); f.group.listenerEnded();
      expect(f.group.cleanupStatus().pending_callbacks).toBe(1n);
      expect(f.callbacks.release).not.toHaveBeenCalled();
      acknowledged.resolve({ accepted: true }); await expect(publishing).resolves.toBeUndefined();
      await ingress.finish(); expect(f.lease.close).toHaveBeenCalledTimes(1); expect(f.callbacks.release).toHaveBeenCalledTimes(1);
    } finally { acknowledged.resolve({ accepted: true }); await ingress.finish(); await f.close(); }
  });
  it("keeps Close during Drain as forced termination", async () => {
    const f = setup(), ingress = f.group.begin(vi.fn());
    const childDrain = createSessionDrain(() => () => undefined, complete);
    const child = { info: () => ({}), cleanupStatus: () => complete,
      drain: () => childDrain.operation, close: async () => { childDrain.finish("failed"); } } as unknown as V4SessionOwner & { cleanupOwner: SessionCleanup };
    await ingress.authorize(authentication); await ingress.publish(child);
    const drain = f.group.drain(); expect(drain.status().outcome).toBe("pending");
    f.group.close(); expect((await drain.wait()).outcome).toBe("failed" satisfies V4DrainOutcome);
    await ingress.finish(); await f.close(); expect(drain.status().outcome).toBe("failed");
  });
  it("reports a child deadline exhausted during Drain startup", async () => {
    const f = setup(), ingress = f.group.begin(vi.fn());
    const child = { info: () => ({}), cleanupStatus: () => complete,
      drain: () => { throw new TimeError("time_expired"); }, close: async () => undefined } as unknown as V4SessionOwner & { cleanupOwner: SessionCleanup };
    await ingress.authorize(authentication); await ingress.publish(child);
    const drain = f.group.drain({ timeoutMS: 500n });
    expect((await drain.wait()).outcome).toBe("deadline_aborted");
    await ingress.finish(); await f.close();
  });
  it("seals ingress before a trusted clock hook can reenter Drain", async () => {
    let probe: (() => void) | undefined;
    const f = setup({}, () => { const current = probe; probe = undefined; current?.(); });
    let nested: ReturnType<typeof f.group.drain> | undefined;
    probe = () => {
      expect(() => f.group.checkIngress()).toThrow("closed");
      nested = f.group.drain({ timeoutMS: 0n });
    };
    const drain = f.group.drain({ timeoutMS: 500n });
    expect(nested).toBe(drain); expect(drain.status().outcome).toBe("drained");
    expect(f.seal).toHaveBeenCalledTimes(1); await f.close();
  });

});

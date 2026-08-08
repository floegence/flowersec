import { afterEach, describe, expect, test, vi } from "vitest";

import { createConnectionControllerV2 } from "./connectionController.js";
import type { ArtifactSource, ArtifactSourceResult } from "./connectionController.js";
import { ConnectError } from "./public/connectError.js";
import type { ArtifactLeaseV2 } from "./v2/artifactLease.js";
import { SessionError } from "./v2/contract.js";
import type { SessionV2 } from "./v2/contract.js";

afterEach(() => vi.useRealTimers());

describe("ConnectionController", () => {
  test("uses a fresh lease and a new one-shot session for every attempt", async () => {
    vi.useFakeTimers();
    const leases = [lease(), lease()];
    let acquisition = 0;
    const connected = session();
    const controller = createConnectionControllerV2(
      source(async () => ({ kind: "lease", lease: leases[acquisition++]! })),
      vi.fn(async (_lease) => {
        if (acquisition === 1) throw new ConnectError("connection_failed");
        return connected.value;
      }),
      { maximumAttempts: 2 },
    );

    controller.start();
    await flush();
    expect(controller.state).toBe("waiting");
    await vi.advanceTimersByTimeAsync(250);
    await expect(controller.waitForSession()).resolves.toBe(connected.value);
    expect(acquisition).toBe(2);
    await controller.close();
  });

  test("replaces a terminated session with a fresh artifact without replaying operations", async () => {
    vi.useFakeTimers();
    const firstLease = lease();
    const secondLease = lease();
    const first = session();
    const second = session();
    let terminateFirst!: (error: SessionError) => void;
    first.termination = new Promise((resolve) => {
      terminateFirst = (error) => resolve({ error });
    });
    let acquisition = 0;
    const acquiredLeases: ArtifactLeaseV2[] = [];
    const controller = createConnectionControllerV2(
      source(async () => ({
        kind: "lease",
        lease: [firstLease, secondLease][acquisition++]!,
      })),
      async (acquired) => {
        acquiredLeases.push(acquired);
        return acquired === firstLease ? first.value : second.value;
      },
    );

    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(first.value);
    const oldStream = await first.value.openStream("old");
    await oldStream.write(new Uint8Array([1]));
    await first.value.rpc.notify(1, { old: true });

    terminateFirst(new SessionError("closed"));
    await vi.advanceTimersByTimeAsync(250);
    await expect(controller.waitForSession()).resolves.toBe(second.value);

    expect(acquiredLeases).toEqual([firstLease, secondLease]);
    expect(first.value.openStream).toHaveBeenCalledOnce();
    expect(first.value.rpc.notify).toHaveBeenCalledOnce();
    expect(second.value.openStream).not.toHaveBeenCalled();
    expect(second.value.rpc.notify).not.toHaveBeenCalled();
    await controller.close();
  });

  test("retryNow skips local backoff but never an absolute retry_after deadline", async () => {
    vi.useFakeTimers({ now: 1_000 });
    let acquisition = 0;
    const connected = session();
    const controller = createConnectionControllerV2(
      source(async () => {
        acquisition += 1;
        if (acquisition === 1) {
          return {
            kind: "failure",
            code: "rate_limited",
            disposition: { kind: "retry_after", notBeforeUnixMilliseconds: 2_000 },
          };
        }
        return { kind: "lease", lease: lease() };
      }),
      async () => connected.value,
    );

    controller.start();
    await flush();
    expect(controller.retryNow()).toBe(false);
    await vi.advanceTimersByTimeAsync(999);
    expect(acquisition).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    await expect(controller.waitForSession()).resolves.toBe(connected.value);
    await controller.close();
  });

  test("close waits for an abort-ignoring one-shot attempt and retires its late session", async () => {
    let resolveConnect!: (value: SessionV2) => void;
    const pending = new Promise<SessionV2>((resolve) => { resolveConnect = resolve; });
    const late = session();
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
    expect(late.close).toHaveBeenCalledOnce();
    expect(controller.state).toBe("closed");
  });

  test("close waits for an abort-ignoring artifact acquisition", async () => {
    let resolveAcquire!: (result: ArtifactSourceResult) => void;
    const pending = new Promise<ArtifactSourceResult>((resolve) => { resolveAcquire = resolve; });
    const controller = createConnectionControllerV2(
      source(async () => await pending),
      async () => session().value,
    );
    controller.start();
    await flush();

    let closed = false;
    const closing = controller.close().then(() => { closed = true; });
    await flush();
    expect(closed).toBe(false);
    resolveAcquire({ kind: "lease", lease: lease() });
    await closing;
    expect(controller.state).toBe("closed");
  });

  test("fails closed when an artifact source replays a lease", async () => {
    vi.useFakeTimers();
    const replayed = lease();
    let calls = 0;
    const controller = createConnectionControllerV2(
      source(async () => ({ kind: "lease", lease: replayed })),
      async () => {
        calls += 1;
        throw new ConnectError("connection_failed");
      },
      { maximumAttempts: 2 },
    );

    controller.start();
    await flush();
    await vi.advanceTimersByTimeAsync(250);
    await flush();
    expect(controller.state).toBe("failed");
    expect(controller.failure).toEqual({ phase: "artifact", code: "reused_artifact_lease" });
    expect(calls).toBe(1);
    await controller.close();
  });

  test("stops immediately on a terminal artifact result", async () => {
    const controller = createConnectionControllerV2(
      source(async () => ({
        kind: "failure",
        code: "unsupported",
        disposition: { kind: "terminal" },
      })),
      async () => session().value,
    );
    controller.start();
    await flush();
    expect(controller.state).toBe("failed");
    await expect(controller.waitForSession()).rejects.toMatchObject({ code: "failed" });
    await controller.close();
  });

  test("normalizes malformed artifact source results to a terminal failure", async () => {
    const controller = createConnectionControllerV2(
      source(async () => null as never),
      async () => session().value,
    );
    controller.start();
    await flush();
    expect(controller.failure).toEqual({ phase: "artifact", code: "artifact_source_failed" });
    expect(controller.state).toBe("failed");
    await controller.close();
  });

  test("does not accept a malformed one-shot session", async () => {
    const controller = createConnectionControllerV2(
      source(async () => ({ kind: "lease", lease: lease() })),
      async () => ({ close: vi.fn() } as never),
    );
    controller.start();
    await flush();
    expect(controller.state).toBe("failed");
    expect(controller.failure).toEqual({ phase: "connect", code: "connection_failed" });
    await controller.close();
  });

  test("cancels a waiter without changing controller lifecycle", async () => {
    let resolveAcquire!: (result: ArtifactSourceResult) => void;
    const controller = createConnectionControllerV2(
      source(async () => await new Promise<ArtifactSourceResult>((resolve) => { resolveAcquire = resolve; })),
      async () => session().value,
    );
    controller.start();
    const waiter = new AbortController();
    const waiting = controller.waitForSession({ signal: waiter.signal });
    waiter.abort(new Error("caller canceled"));
    await expect(waiting).rejects.toMatchObject({ code: "canceled" });
    resolveAcquire({ kind: "failure", code: "canceled", disposition: { kind: "terminal" } });
    await controller.close();
  });

  test("marks a terminal session error failed instead of scheduling a replacement", async () => {
    vi.useFakeTimers();
    const connected = session();
    connected.termination = Promise.resolve({ error: new SessionError("operation_failed") });
    const acquire = vi.fn(async () => ({ kind: "lease" as const, lease: lease() }));
    const controller = createConnectionControllerV2({ acquire }, async () => connected.value);
    controller.start();
    await flush();
    await flush();
    expect(controller.state).toBe("failed");
    expect(acquire).toHaveBeenCalledOnce();
    await controller.close();
  });

  test("isolates subscriber failures from connection lifecycle", async () => {
    const connected = session();
    const controller = createConnectionControllerV2(
      source(async () => ({ kind: "lease", lease: lease() })),
      async () => connected.value,
    );
    let notifications = 0;
    const unsubscribe = controller.subscribe(() => {
      notifications += 1;
      if (notifications > 1) throw new Error("observer failed");
    });
    controller.start();
    await expect(controller.waitForSession()).resolves.toBe(connected.value);
    expect(controller.state).toBe("connected");
    unsubscribe();
    await controller.close();
  });
});

function source(acquire: ArtifactSource["acquire"]): ArtifactSource {
  return { acquire };
}

function lease(): ArtifactLeaseV2 {
  return {} as ArtifactLeaseV2;
}

function session(): {
  value: SessionV2;
  close: ReturnType<typeof vi.fn>;
  termination: Promise<Readonly<{ error: SessionError }>>;
} {
  const close = vi.fn(async () => undefined);
  let termination: Promise<Readonly<{ error: SessionError }>> = new Promise(() => undefined);
  const rpc = {
    call: vi.fn(),
    notify: vi.fn(async () => undefined),
    onNotify: vi.fn(() => () => undefined),
  };
  const stream = {
    kind: "old",
    terminalError: undefined,
    read: vi.fn(async () => null),
    write: vi.fn(async (data: Uint8Array) => data.byteLength),
    closeWrite: vi.fn(async () => undefined),
    reset: vi.fn(async () => undefined),
    close: vi.fn(async () => undefined),
  };
  const value = {
    rpc,
    openStream: vi.fn(async () => stream),
    acceptStream: vi.fn(),
    rekey: vi.fn(),
    probeLiveness: vi.fn(),
    waitTermination: async () => await termination,
    close,
  } satisfies SessionV2;
  return { value, close, get termination() { return termination; }, set termination(value) { termination = value; } };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 8; index++) await Promise.resolve();
}

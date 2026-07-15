import { afterEach, describe, expect, test, vi } from "vitest";

import { createReconnectManager } from "./index.js";
import { registerClientTermination, type ClientTermination } from "../client-connect/termination.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function makeDummyClient(label: string, onClose: () => void) {
  let closed = false;
  return {
    label,
    closeCalls: 0,
    client: {
      path: "tunnel" as const,
      rpc: {} as any,
      openStream: async () => {
        throw new Error("not implemented");
      },
      ping: async () => {},
      close: () => {
        closed = true;
        onClose();
      },
      // Helpful for tests.
      get closed() {
        return closed;
      },
    },
  };
}

function deferredTermination() {
  let resolve!: (termination: ClientTermination) => void;
  const promise = new Promise<ClientTermination>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("reconnect manager", () => {
  test("retries connect failures and eventually connects", async () => {
    const mgr = createReconnectManager();

    let attempts = 0;
    const connectOnce = async () => {
      attempts += 1;
      if (attempts < 3) throw new Error("dial failed");
      const d = makeDummyClient(`c${attempts}`, () => {});
      return d.client as any;
    };

    await mgr.connect({
      connectOnce: async ({ signal, observer }) => {
        if (signal.aborted) throw new Error("canceled");
        return await connectOnce({ signal, observer } as any);
      },
      autoReconnect: { enabled: true, maxAttempts: 5, initialDelayMs: 0, maxDelayMs: 0, factor: 1 },
    });

    const st = mgr.state();
    expect(st.status).toBe("connected");
    expect(st.client).toBeTruthy();
    expect(attempts).toBe(3);
  });

  test("auto reconnects on peer websocket close and uses fresh connectOnce", async () => {
    const mgr = createReconnectManager();

    let created = 0;
    let lastObserver: any = null;
    let closed = 0;

    const connectOnce = async ({ observer }: any) => {
      created += 1;
      lastObserver = observer;
      const d = makeDummyClient(`c${created}`, () => {
        closed += 1;
      });
      return d.client as any;
    };

    await mgr.connect({
      connectOnce: async ({ signal, observer }) => {
        if (signal.aborted) throw new Error("canceled");
        return await connectOnce({ observer });
      },
      autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    });

    expect(mgr.state().status).toBe("connected");
    expect(created).toBe(1);

    // Trigger reconnect.
    lastObserver?.onWsClose?.("peer_or_error", 1006);

    // Wait a tick for the async reconnect loop to run.
    await new Promise((r) => setTimeout(r, 0));

    expect(created).toBe(2);
    expect(closed).toBeGreaterThanOrEqual(1);
    expect(mgr.state().status).toBe("connected");
  });

  test("auto reconnects once on internal session termination", async () => {
    const mgr = createReconnectManager();
    const terminations: Array<ReturnType<typeof deferredTermination>> = [];
    let created = 0;

    await mgr.connect({
      connectOnce: async () => {
        created += 1;
        const d = makeDummyClient(`c${created}`, () => {});
        const termination = deferredTermination();
        terminations.push(termination);
        registerClientTermination(d.client as any, termination.promise);
        return d.client as any;
      },
      autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    });

    terminations[0]!.resolve({ error: new Error("rpc read failed") });
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(created).toBe(2);
    expect(mgr.state().status).toBe("connected");
  });

  test("explicit disconnect ignores later session termination", async () => {
    const mgr = createReconnectManager();
    const termination = deferredTermination();
    let created = 0;

    await mgr.connect({
      connectOnce: async () => {
        created += 1;
        const d = makeDummyClient(`c${created}`, () => {});
        registerClientTermination(d.client as any, termination.promise);
        return d.client as any;
      },
      autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    });

    mgr.disconnect();
    termination.resolve({ error: new Error("late close") });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(created).toBe(1);
    expect(mgr.state().status).toBe("disconnected");
  });

  test("stale client termination does not affect a newer connection", async () => {
    const mgr = createReconnectManager();
    const firstTermination = deferredTermination();
    let firstCreated = 0;
    let secondCreated = 0;
    let secondClient: any;
    const firstConfig = {
      connectOnce: async () => {
        firstCreated += 1;
        const d = makeDummyClient(`first-${firstCreated}`, () => {});
        registerClientTermination(d.client as any, firstTermination.promise);
        return d.client as any;
      },
      autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    };
    const secondConfig = {
      connectOnce: async () => {
        secondCreated += 1;
        secondClient = makeDummyClient(`second-${secondCreated}`, () => {}).client as any;
        return secondClient;
      },
      autoReconnect: { enabled: true, maxAttempts: 3, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    };

    await mgr.connect(firstConfig);
    await mgr.connect(secondConfig);
    firstTermination.resolve({ error: new Error("stale close") });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(firstCreated).toBe(1);
    expect(secondCreated).toBe(1);
    expect(mgr.state().client).toBe(secondClient);
    expect(mgr.state().status).toBe("connected");
  });

  test("connectIfNeeded keeps healthy connection without hard reconnect", async () => {
    const mgr = createReconnectManager();

    let created = 0;
    let closed = 0;
    const connectOnce = async () => {
      created += 1;
      const d = makeDummyClient(`c${created}`, () => {
        closed += 1;
      });
      return d.client as any;
    };

    const cfg = {
      connectOnce: async ({ signal }: any) => {
        if (signal.aborted) throw new Error("canceled");
        return await connectOnce();
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
    };

    await mgr.connect(cfg);
    expect(created).toBe(1);

    await mgr.connectIfNeeded(cfg);
    expect(created).toBe(1);
    expect(closed).toBe(0);
    expect(mgr.state().status).toBe("connected");
  });

  test("connectIfNeeded reuses an unexpected-disconnect retry loop during backoff", async () => {
    vi.useFakeTimers();
    const mgr = createReconnectManager();
    const events: string[] = [];
    let attempts = 0;
    let connectedObserver: any = null;

    const cfg = {
      connectOnce: async ({ observer }: any) => {
        attempts += 1;
        connectedObserver = observer;
        if (attempts === 2) throw new Error("reconnect dial failed");
        return makeDummyClient(`c${attempts}`, () => {}).client as any;
      },
      observer: {
        onDiagnosticEvent: (event: any) => events.push(`${event.code}:${event.attempt_seq}`),
      },
      autoReconnect: {
        enabled: true,
        maxAttempts: 3,
        initialDelayMs: 100,
        maxDelayMs: 100,
        factor: 1,
        jitterRatio: 0,
      },
    };

    await mgr.connect(cfg);
    connectedObserver?.onWsClose?.("peer_or_error", 1006);
    await vi.waitFor(() => {
      expect(attempts).toBe(2);
    });

    const reused = mgr.connectIfNeeded(cfg);
    await vi.advanceTimersByTimeAsync(99);
    expect(attempts).toBe(2);

    await vi.advanceTimersByTimeAsync(1);
    await reused;

    expect(attempts).toBe(3);
    expect(mgr.state().status).toBe("connected");
    expect(events).toContain("reconnect_attempt:2");
    expect(events).toContain("reconnect_retry_attempt:3");
  });

  test("connectIfNeeded reuses a loop when a connecting subscriber reenters", async () => {
    const mgr = createReconnectManager();
    let attempts = 0;
    let resolveConnect!: (client: any) => void;
    const connected = new Promise<any>((resolve) => {
      resolveConnect = resolve;
    });
    const cfg = {
      connectOnce: async () => {
        attempts += 1;
        return await connected;
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, factor: 1 },
    };
    let reentered: Promise<void> | undefined;
    const unsubscribe = mgr.subscribe((state) => {
      if (state.status === "connecting" && reentered == null) {
        reentered = mgr.connectIfNeeded(cfg);
      }
    });

    const initial = mgr.connect(cfg);
    await vi.waitFor(() => expect(attempts).toBe(1));
    resolveConnect(makeDummyClient("connected", () => {}).client as any);

    await initial;
    await reentered;
    unsubscribe();
    expect(attempts).toBe(1);
    expect(mgr.state().status).toBe("connected");
  });

  test("connectIfNeeded reuses a registered loop when connectOnce reenters synchronously", async () => {
    const mgr = createReconnectManager();
    let attempts = 0;
    let reentered: Promise<void> | undefined;
    const cfg = {
      connectOnce: async () => {
        attempts += 1;
        reentered ??= mgr.connectIfNeeded(cfg);
        return makeDummyClient("connected", () => {}).client as any;
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, factor: 1 },
    };

    await mgr.connect(cfg);
    await reentered;
    expect(attempts).toBe(1);
    expect(mgr.state().status).toBe("connected");
  });

  test("uses fake timers and deterministic random for jittered retry scheduling", async () => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(1);

    const mgr = createReconnectManager();
    const events: string[] = [];
    let attempts = 0;

    const p = mgr.connect({
      connectOnce: async () => {
        attempts += 1;
        if (attempts < 2) throw new Error("dial failed");
        return makeDummyClient(`c${attempts}`, () => {}).client as any;
      },
      observer: {
        onDiagnosticEvent: (event) => events.push(`${event.code}:${event.attempt_seq}`),
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 100, maxDelayMs: 100, factor: 1, jitterRatio: 0.5 },
    });

    await vi.waitFor(() => {
      expect(attempts).toBe(1);
    });
    expect(mgr.state().status).toBe("connecting");

    await vi.advanceTimersByTimeAsync(149);
    expect(attempts).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    await p;

    expect(attempts).toBe(2);
    expect(mgr.state().status).toBe("connected");
    await vi.runAllTimersAsync();
    expect(events).toContain("reconnect_attempt:1");
    expect(events).toContain("reconnect_scheduled:1");
    expect(events).toContain("reconnect_retry_attempt:2");
    expect(events).toContain("reconnect_connected:2");
  });

  test("reports reconnect exhausted without expanding the stable state set", async () => {
    const mgr = createReconnectManager();
    const statuses: string[] = [];
    const events: string[] = [];
    const reasons: string[] = [];

    mgr.subscribe((state) => statuses.push(state.status));

    await expect(
      mgr.connect({
        connectOnce: async () => {
          throw new Error("dial failed");
        },
        observer: {
          onDiagnosticEvent: (event) => {
            events.push(event.code);
            if (event.code === "reconnect_exhausted") reasons.push(event.result);
          },
        },
        autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 0, maxDelayMs: 0, factor: 1, jitterRatio: 0 },
      })
    ).rejects.toThrow("dial failed");

    expect(mgr.state().status).toBe("error");
    expect(new Set(statuses)).toEqual(new Set(["disconnected", "connecting", "error"]));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(events).toContain("reconnect_exhausted");
    expect(reasons).toEqual(["fail"]);
  });

  test("uses configured backoff delay before retrying", async () => {
    vi.useFakeTimers();
    const mgr = createReconnectManager();
    let attempts = 0;

    const p = mgr.connect({
      connectOnce: async () => {
        attempts += 1;
        throw new Error("dial failed");
      },
      autoReconnect: { enabled: true, maxAttempts: 2, initialDelayMs: 25, maxDelayMs: 25, factor: 1, jitterRatio: 0 },
    });
    const result = p.then(
      () => null,
      (error: unknown) => error,
    );

    await vi.waitFor(() => {
      expect(attempts).toBe(1);
    });

    await vi.advanceTimersByTimeAsync(24);
    expect(attempts).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    await expect(result).resolves.toMatchObject({ message: "dial failed" });
    expect(attempts).toBe(2);
  });
});

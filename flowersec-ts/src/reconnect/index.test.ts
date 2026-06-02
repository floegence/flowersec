import { afterEach, describe, expect, test, vi } from "vitest";

import { createReconnectManager } from "./index.js";

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
    const rejected = expect(p).rejects.toThrow("dial failed");

    await vi.waitFor(() => {
      expect(attempts).toBe(1);
    });

    await vi.advanceTimersByTimeAsync(24);
    expect(attempts).toBe(1);

    await vi.advanceTimersByTimeAsync(1);
    await rejected;
    expect(attempts).toBe(2);
  });
});

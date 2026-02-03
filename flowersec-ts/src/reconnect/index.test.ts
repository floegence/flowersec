import { describe, expect, test } from "vitest";

import { createReconnectManager } from "./index.js";

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
});


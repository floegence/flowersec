import { describe, expect, test, vi } from "vitest";
import { NoopObserver, normalizeObserver, nowSeconds, withObserverContext } from "./observer.js";

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("observability", () => {
  test("normalizeObserver fills missing handlers and dispatches asynchronously", async () => {
    const onConnect = vi.fn();
    const obs = normalizeObserver({ onConnect });

    obs.onConnect("tunnel", "ok", undefined, 1);
    obs.onAttach("ok", undefined);
    obs.onHandshake("tunnel", "ok", undefined, 1);
    obs.onWsClose("local");
    obs.onWsError("error");
    obs.onRpcCall("ok", 0.01);
    obs.onRpcNotify();

    expect(onConnect).not.toHaveBeenCalled();
    await flushMicrotasks();
    expect(onConnect).toHaveBeenCalledTimes(1);
  });

  test("normalizeObserver returns NoopObserver for undefined", () => {
    const obs = normalizeObserver(undefined);
    expect(obs).toBe(NoopObserver);
  });

  test("nowSeconds falls back to Date.now without performance", () => {
    const original = (globalThis as any).performance;
    let restored = false;
    try {
      Object.defineProperty(globalThis, "performance", { value: undefined, configurable: true });
    } catch {
      // If we cannot override, at least ensure nowSeconds returns a number.
      const v = nowSeconds();
      expect(typeof v).toBe("number");
      return;
    }

    const v = nowSeconds();
    expect(v).toBeGreaterThan(0);

    Object.defineProperty(globalThis, "performance", { value: original, configurable: true });
    restored = true;
    expect(restored).toBe(true);
  });

  test("diagnostic events inherit attempt_seq and correlation context", async () => {
    const onDiagnosticEvent = vi.fn();
    const obs = normalizeObserver(
      withObserverContext(
        {
          onDiagnosticEvent,
        },
        {
          attemptSeq: 3,
          traceId: "trace-0001",
          sessionId: "session-0001",
        }
      ),
      { path: "direct" }
    );

    obs.onHandshake("direct", "fail", "timeout", 0.1);
    await flushMicrotasks();

    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        namespace: "connect",
        path: "direct",
        stage: "handshake",
        code_domain: "error",
        code: "timeout",
        result: "fail",
        attempt_seq: 3,
        trace_id: "trace-0001",
        session_id: "session-0001",
      })
    );
  });

  test("overflow keeps a diagnostics_overflow event", async () => {
    const onDiagnosticEvent = vi.fn();
    const obs = normalizeObserver(
      withObserverContext(
        {
          onDiagnosticEvent,
        },
        {
          maxQueuedItems: 4,
        }
      )
    );

    for (let i = 0; i < 10; i += 1) {
      obs.onWsClose("local");
    }
    await flushMicrotasks();

    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        code_domain: "event",
        code: "diagnostics_overflow",
        result: "skip",
      })
    );
  });

  test("terminal diagnostics survive queue saturation", async () => {
    const onDiagnosticEvent = vi.fn();
    const obs = normalizeObserver(
      withObserverContext(
        {
          onDiagnosticEvent,
        },
        {
          maxQueuedItems: 4,
        }
      ),
      { path: "tunnel" }
    );

    for (let i = 0; i < 8; i += 1) {
      obs.onWsClose("local");
    }
    obs.onHandshake("tunnel", "fail", "timeout", 0.1);
    for (let i = 0; i < 8; i += 1) {
      await flushMicrotasks();
    }

    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "handshake",
        code_domain: "error",
        code: "timeout",
        result: "fail",
      })
    );
  });

  test("elapsed_ms is measured from attempt start", async () => {
    const onDiagnosticEvent = vi.fn();
    const start = nowSeconds() * 1000 - 250;
    const obs = normalizeObserver(
      withObserverContext(
        {
          onDiagnosticEvent,
        },
        {
          attemptStartMs: start,
        }
      ),
      { path: "direct" }
    );

    obs.onHandshake("direct", "ok", undefined, 0.01);
    await flushMicrotasks();

    expect(onDiagnosticEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        elapsed_ms: expect.any(Number),
      })
    );
    const last = onDiagnosticEvent.mock.calls.at(-1)?.[0] as { elapsed_ms: number } | undefined;
    expect(last?.elapsed_ms ?? 0).toBeGreaterThanOrEqual(200);
  });
});

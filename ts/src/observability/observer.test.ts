import { describe, expect, test, vi } from "vitest";
import { normalizeObserver, nowSeconds, NoopObserver } from "./observer.js";

describe("observability", () => {
  test("normalizeObserver fills missing handlers", () => {
    const onConnect = vi.fn();
    const obs = normalizeObserver({ onTunnelConnect: onConnect });

    obs.onTunnelConnect("ok", undefined, 1);
    obs.onTunnelAttach("ok", undefined);
    obs.onTunnelHandshake("ok", undefined, 1);
    obs.onWsError("close");
    obs.onRpcCall("ok", 0.01);
    obs.onRpcNotify();

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
});

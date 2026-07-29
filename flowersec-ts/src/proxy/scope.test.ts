import { describe, expect, it } from "vitest";

import { assertProxyRuntimeScopeV2 } from "./scope.js";

describe("proxy.runtime@2 scope", () => {
  it("normalizes and freezes service-worker configuration", () => {
    const scope = assertProxyRuntimeScopeV2({
      version: 2,
      mode: "service_worker",
      appBasePath: "/app/",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      limits: { timeoutMs: 3_000, maxBodyBytes: 4096 },
    });
    expect(scope).toEqual({
      mode: "service_worker",
      appBasePath: "/app/",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      limits: { timeoutMs: 3_000, maxBodyBytes: 4096 },
    });
    expect(Object.isFrozen(scope)).toBe(true);
    expect(Object.isFrozen(scope.serviceWorker)).toBe(true);
  });

  it.each([
    { version: 1, mode: "controller_bridge", controllerBridge: { allowedOrigins: ["https://app.example"] } },
    { mode: "controller_bridge", controllerBridge: { allowedOrigins: ["https://app.example/path"] } },
    { mode: "controller_bridge", controllerBridge: { allowedOrigins: [] } },
    { mode: "service_worker", serviceWorker: { scriptUrl: "/sw.js", scope: "/" }, unknown: true },
    { mode: "service_worker", serviceWorker: { scriptUrl: "/sw.js", scope: "/" }, limits: { maxBodyBytes: 0 } },
  ])("rejects invalid or legacy payload %#", (payload) => {
    expect(() => assertProxyRuntimeScopeV2(payload)).toThrow(/proxy\.runtime@2/u);
  });
});

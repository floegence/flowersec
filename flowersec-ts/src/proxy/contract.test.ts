import fs from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, expectTypeOf, it } from "vitest";

import type { ByteStreamV2, SessionV2 } from "../v2/contract.js";
import {
  PROXY_RUNTIME_SCOPE_V2,
  assertProxyRuntimeScopeV2,
  createProxyRuntime,
  createProxyServiceWorkerScript,
  createServiceWorkerControllerGuard,
  disableUpstreamServiceWorkerRegister,
  installWebSocketPatch,
  registerProxyAppWindow,
  registerProxyAppWindowWithServiceWorkerControl,
  registerProxyControllerWindow,
  registerServiceWorkerAndEnsureControl,
  type ProxyRuntime,
  type ProxyRuntimeOptions,
  type ProxyRuntimeScopeV2,
} from "./index.js";

describe("proxy v2 public contract", () => {
  it("exports only SessionV2-based runtime and browser bridge entrypoints", () => {
    expect(PROXY_RUNTIME_SCOPE_V2).toEqual({ name: "proxy.runtime", version: 2 });
    expectTypeOf<ProxyRuntimeOptions["session"]>().toEqualTypeOf<SessionV2>();
    expectTypeOf<Awaited<ReturnType<ProxyRuntime["openWebSocketStream"]>>["stream"]>()
      .toEqualTypeOf<ByteStreamV2>();

    expect(createProxyRuntime).toBeTypeOf("function");
    expect(createProxyServiceWorkerScript).toBeTypeOf("function");
    expect(createServiceWorkerControllerGuard).toBeTypeOf("function");
    expect(disableUpstreamServiceWorkerRegister).toBeTypeOf("function");
    expect(installWebSocketPatch).toBeTypeOf("function");
    expect(registerProxyAppWindow).toBeTypeOf("function");
    expect(registerProxyAppWindowWithServiceWorkerControl).toBeTypeOf("function");
    expect(registerProxyControllerWindow).toBeTypeOf("function");
    expect(registerServiceWorkerAndEnsureControl).toBeTypeOf("function");
  });

  it("accepts the strict proxy.runtime@2 scope and rejects v1", () => {
    const scope = assertProxyRuntimeScopeV2({
      mode: "controller_bridge",
      controllerBridge: { allowedOrigins: ["https://app.example"] },
      limits: { maxBodyBytes: 1024 },
    });
    expectTypeOf(scope).toEqualTypeOf<ProxyRuntimeScopeV2>();
    expect(scope.mode).toBe("controller_bridge");

    expect(() => assertProxyRuntimeScopeV2({
      version: 1,
      mode: "controller_bridge",
      controllerBridge: { allowedOrigins: ["https://app.example"] },
    })).toThrow(/proxy\.runtime@2/u);
  });

  it("contains no maintained proxy v1 wire compatibility", () => {
    for (const file of ["runtime.ts", "windowBridge.ts"]) {
      const source = fs.readFileSync(fileURLToPath(new URL(file, import.meta.url)), "utf8");
      expect(source).not.toContain("chunk_credit_v1");
      expect(source).not.toContain('"flowersec-proxy:window_fetch"');
    }
  });
});

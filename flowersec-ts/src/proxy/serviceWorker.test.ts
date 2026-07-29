import { describe, expect, it } from "vitest";

import { createProxyServiceWorkerScript } from "./serviceWorker.js";

describe("proxy service worker generator", () => {
  it("emits a v2 registration and bounded response-credit bridge", () => {
    const script = createProxyServiceWorkerScript({
      passthrough: { paths: ["/proxy-sw.js"], prefixes: ["/assets/"] },
      runtimeRegistrationToken: "runtime-token",
      runtimeClientPathPrefix: "/boot/",
      injectHTML: { mode: "external_script", scriptUrl: "/inject.js", runtimeGlobal: "__runtime" },
    });
    expect(script).toContain("@floegence/flowersec-core/proxy v2");
    expect(script).toContain("chunk_credit_v2");
    expect(script).toContain("flowersec-proxy:register-runtime");
    expect(script).toContain("runtime-token");
    expect(script).not.toContain("proxy.runtime@1");
    expect(script).not.toContain("Yamux");
  });

  it("rejects unsafe or unbounded generator inputs", () => {
    expect(() => createProxyServiceWorkerScript({ maxRequestBodyBytes: 0 })).toThrow();
    expect(() => createProxyServiceWorkerScript({ runtimeRegistrationToken: " bad " })).toThrow();
    expect(() => createProxyServiceWorkerScript({ injectHTML: { mode: "inline_module" } })).toThrow();
  });
});

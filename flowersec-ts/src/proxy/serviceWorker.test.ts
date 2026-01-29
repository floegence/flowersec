import { describe, expect, it } from "vitest";

import { createProxyServiceWorkerScript } from "./serviceWorker.js";

describe("createProxyServiceWorkerScript", () => {
  it("contains the runtime registration and fetch bridge markers", () => {
    const s = createProxyServiceWorkerScript();
    expect(s).toContain("flowersec-proxy:register-runtime");
    expect(s).toContain("flowersec-proxy:fetch");
    expect(s).toContain("flowersec-proxy:response_meta");
    expect(s).toContain("flowersec-proxy:abort");
  });

  it("supports path prefix stripping", () => {
    const s = createProxyServiceWorkerScript({ proxyPathPrefix: "/apps/code/", stripProxyPathPrefix: true });
    expect(s).toContain('const PROXY_PATH_PREFIX = "/apps/code/";');
    expect(s).toContain("STRIP_PROXY_PATH_PREFIX");
    expect(s).toContain("url.pathname.slice(PROXY_PATH_PREFIX.length)");
  });

  it("can inject a proxy bootstrap into HTML responses", () => {
    const s = createProxyServiceWorkerScript({
      proxyPathPrefix: "/apps/code/",
      injectHTML: { proxyModuleUrl: "/assets/flowersec-proxy.js", runtimeGlobal: "__flowersecProxyRuntime" }
    });
    expect(s).toContain("INJECT_HTML");
    expect(s).toContain("/assets/flowersec-proxy.js");
    expect(s).toContain("installWebSocketPatch");
    expect(s).toContain("disableUpstreamServiceWorkerRegister");
    expect(s).toContain("text/html");
  });
});

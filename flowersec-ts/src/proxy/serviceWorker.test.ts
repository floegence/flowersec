import { describe, expect, it } from "vitest";

import { createProxyServiceWorkerScript } from "./serviceWorker.js";

describe("createProxyServiceWorkerScript", () => {
  it("contains the runtime registration and fetch bridge markers", () => {
    const s = createProxyServiceWorkerScript();
    expect(s).toContain("flowersec-proxy:register-runtime");
    expect(s).toContain("flowersec-proxy:fetch");
    expect(s).toContain("flowersec-proxy:response_meta");
    expect(s).toContain("flowersec-proxy:abort");
    expect(s).toContain("event.waitUntil(self.skipWaiting())");
  });

  it("defaults to same-origin only proxying (safe)", () => {
    const s = createProxyServiceWorkerScript();
    expect(s).toContain("const SAME_ORIGIN_ONLY = true;");
    expect(s).toContain("url.origin !== self.location.origin");
  });

  it("supports passthrough paths and prefixes", () => {
    const s = createProxyServiceWorkerScript({
      passthrough: { paths: ["/_sw.js", "/v1/channel/init/entry"], prefixes: ["/assets/", "/api/"] },
    });
    expect(s).toContain("PASSTHROUGH_PATHS");
    expect(s).toContain("/_sw.js");
    expect(s).toContain("/assets/");
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
    expect(s).toContain('const INJECT_MODE = "inline_module";');
    expect(s).toContain("/assets/flowersec-proxy.js");
    expect(s).toContain("installWebSocketPatch");
    expect(s).toContain("disableUpstreamServiceWorkerRegister");
    expect(s).toContain("text/html");
  });

  it("can inject an external script into HTML responses (CSP-friendly)", () => {
    const s = createProxyServiceWorkerScript({
      injectHTML: {
        mode: "external_script",
        scriptUrl: "/_proxy/inject.js",
        excludePathPrefixes: ["/_proxy/"],
      },
    });
    expect(s).toContain('const INJECT_MODE = "external_script";');
    expect(s).toContain('const INJECT_SCRIPT_URL = "/_proxy/inject.js";');
    expect(s).toContain("data-flowersec-runtime-global");
    expect(s).toContain("INJECT_EXCLUDE_PREFIXES");
    expect(s).toContain("shouldSkipInject");
  });

  it("strips validator headers and sets no-store when injecting HTML", () => {
    const s = createProxyServiceWorkerScript({
      injectHTML: { proxyModuleUrl: "/assets/flowersec-proxy.js" },
    });
    expect(s).toContain("content-length");
    expect(s).toContain("etag");
    expect(s).toContain('headers.set("Cache-Control", "no-store")');
  });
});

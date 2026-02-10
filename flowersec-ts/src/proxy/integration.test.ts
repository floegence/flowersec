import { describe, expect, it } from "vitest";

import { createProxyIntegrationServiceWorkerScript, type ProxyIntegrationPlugin } from "./integration.js";

describe("proxy integration script composition", () => {
  it("merges plugin forward message types and conflict hints", () => {
    const plugin: ProxyIntegrationPlugin = {
      name: "redeven-plugin",
      forwardFetchMessageTypes: ["redeven:proxy_fetch"],
      serviceWorkerConflictPolicy: {
        keepScriptPathSuffixes: ["/out/vs/workbench/contrib/webview/browser/pre/service-worker.js"],
      },
    };

    const script = createProxyIntegrationServiceWorkerScript({
      baseOptions: {
        forwardFetchMessageTypes: ["custom:fetch"],
      },
      plugins: [plugin],
    });

    expect(script).toContain("custom:fetch");
    expect(script).toContain("redeven:proxy_fetch");
    expect(script).toContain("CONFLICT_HINT_KEEP_SCRIPT_SUFFIXES");
    expect(script).toContain("/out/vs/workbench/contrib/webview/browser/pre/service-worker.js");
  });

  it("applies plugin option extenders in order", () => {
    const plugins: ProxyIntegrationPlugin[] = [
      {
        name: "a",
        extendServiceWorkerScriptOptions: (opts) => ({
          ...opts,
          passthrough: { prefixes: ["/a/"] },
        }),
      },
      {
        name: "b",
        extendServiceWorkerScriptOptions: (opts) => ({
          ...opts,
          passthrough: {
            prefixes: [...(opts.passthrough?.prefixes ?? []), "/b/"],
          },
        }),
      },
    ];

    const script = createProxyIntegrationServiceWorkerScript({ plugins });
    expect(script).toContain("/a/");
    expect(script).toContain("/b/");
  });
});

import { describe, expect, it } from "vitest";

describe("proxy bootstrap public integration", () => {
  it("exports only artifact-based proxy bootstrap helpers", async () => {
    const proxy = await import("../proxy/index.js");

    expect(proxy.connectArtifactProxyBrowser).toBeTypeOf("function");
    expect(proxy.connectArtifactProxyControllerBrowser).toBeTypeOf("function");
    expect(proxy).not.toHaveProperty("connectTunnelProxyBrowser");
    expect(proxy).not.toHaveProperty("connectTunnelProxyControllerBrowser");
  });
});

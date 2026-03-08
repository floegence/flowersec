import { afterEach, describe, expect, it, vi } from "vitest";

const connectTunnelBrowserMock = vi.fn();
const registerProxyIntegrationMock = vi.fn();

vi.mock("../browser/connect.js", () => ({
  connectTunnelBrowser: connectTunnelBrowserMock,
}));

vi.mock("../proxy/integration.js", () => ({
  registerProxyIntegration: registerProxyIntegrationMock,
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("proxy bootstrap public integration", () => {
  it("exposes one-shot tunnel + proxy bootstrap from the public proxy entry", async () => {
    const client = { close: vi.fn() };
    const runtime = { dispose: vi.fn() };
    const integrationDispose = vi.fn().mockResolvedValue(undefined);

    connectTunnelBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockResolvedValue({ runtime, dispose: integrationDispose });

    const proxy = await import("../proxy/index.js");
    const out = await proxy.connectTunnelProxyBrowser({ tunnel_url: "ws://example.invalid" } as any, {
      connect: { signal: undefined },
      profile: "codeserver",
      serviceWorker: {
        scriptUrl: "/_proxy/sw.js",
        scope: "/",
        expectedScriptPathSuffix: "/_proxy/sw.js",
      },
    });

    expect(out.client).toBe(client);
    expect(out.runtime).toBe(runtime);
    expect(registerProxyIntegrationMock).toHaveBeenCalledWith({
      client,
      profile: "codeserver",
      runtime: undefined,
      serviceWorker: {
        scriptUrl: "/_proxy/sw.js",
        scope: "/",
        expectedScriptPathSuffix: "/_proxy/sw.js",
      },
      plugins: undefined,
    });

    await out.dispose();
    expect(integrationDispose).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });
});

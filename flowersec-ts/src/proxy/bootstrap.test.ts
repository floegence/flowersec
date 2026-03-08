import { afterEach, describe, expect, it, vi } from "vitest";

const connectTunnelBrowserMock = vi.fn();
const registerProxyIntegrationMock = vi.fn();

vi.mock("../browser/connect.js", () => ({
  connectTunnelBrowser: connectTunnelBrowserMock,
}));

vi.mock("./integration.js", () => ({
  registerProxyIntegration: registerProxyIntegrationMock,
}));

afterEach(() => {
  vi.clearAllMocks();
});

describe("connectTunnelProxyBrowser", () => {
  it("returns client + runtime and disposes both layers", async () => {
    const client = { close: vi.fn() };
    const runtime = { dispose: vi.fn() };
    const integrationDispose = vi.fn().mockResolvedValue(undefined);

    connectTunnelBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockResolvedValue({ runtime, dispose: integrationDispose });

    const { connectTunnelProxyBrowser } = await import("./bootstrap.js");
    const out = await connectTunnelProxyBrowser({ tunnel_url: "ws://example.invalid" } as any, {
      serviceWorker: { scriptUrl: "/proxy-sw.js" },
    });

    expect(out.client).toBe(client);
    expect(out.runtime).toBe(runtime);
    expect(connectTunnelBrowserMock).toHaveBeenCalledTimes(1);
    expect(registerProxyIntegrationMock).toHaveBeenCalledWith({
      client,
      profile: undefined,
      runtime: undefined,
      serviceWorker: { scriptUrl: "/proxy-sw.js" },
      plugins: undefined,
    });

    await out.dispose();
    expect(integrationDispose).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it("closes the client when proxy registration fails", async () => {
    const client = { close: vi.fn() };
    const err = new Error("register failed");

    connectTunnelBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockRejectedValue(err);

    const { connectTunnelProxyBrowser } = await import("./bootstrap.js");
    await expect(
      connectTunnelProxyBrowser({ tunnel_url: "ws://example.invalid" } as any, {
        serviceWorker: { scriptUrl: "/proxy-sw.js" },
      })
    ).rejects.toThrow("register failed");

    expect(client.close).toHaveBeenCalledTimes(1);
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";

const connectTunnelBrowserMock = vi.fn();
const registerProxyIntegrationMock = vi.fn();
const createProxyRuntimeMock = vi.fn();
const registerProxyControllerWindowMock = vi.fn();

vi.mock("../browser/connect.js", () => ({
  connectTunnelBrowser: connectTunnelBrowserMock,
}));

vi.mock("./integration.js", () => ({
  registerProxyIntegration: registerProxyIntegrationMock,
}));

vi.mock("./runtime.js", () => ({
  createProxyRuntime: (...args: unknown[]) => createProxyRuntimeMock(...args),
}));

vi.mock("./controllerWindow.js", () => ({
  registerProxyControllerWindow: (...args: unknown[]) => registerProxyControllerWindowMock(...args),
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
      runtimeGlobalKey: "__flowersecProxyRuntime",
      serviceWorker: { scriptUrl: "/proxy-sw.js" },
    });

    expect(out.client).toBe(client);
    expect(out.runtime).toBe(runtime);
    expect(connectTunnelBrowserMock).toHaveBeenCalledTimes(1);
    expect(registerProxyIntegrationMock).toHaveBeenCalledWith({
      client,
      runtimeGlobalKey: "__flowersecProxyRuntime",
      serviceWorker: { scriptUrl: "/proxy-sw.js" },
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

  it("connects a controller runtime and disposes both controller + client", async () => {
    const client = { close: vi.fn() };
    const runtime = { runtime: true };
    const controllerDispose = vi.fn();

    connectTunnelBrowserMock.mockResolvedValue(client);
    createProxyRuntimeMock.mockReturnValue(runtime);
    registerProxyControllerWindowMock.mockReturnValue({ dispose: controllerDispose });

    const { connectTunnelProxyControllerBrowser } = await import("./bootstrap.js");
    const out = await connectTunnelProxyControllerBrowser({ tunnel_url: "ws://example.invalid" } as any, {
      allowedOrigins: ["https://app.example.test"],
      runtime: { maxWsFrameBytes: 1024 },
    });

    expect(out.client).toBe(client);
    expect(out.runtime).toBe(runtime);
    expect(createProxyRuntimeMock).toHaveBeenCalledWith({
      client,
      maxWsFrameBytes: 1024,
    });
    expect(registerProxyControllerWindowMock).toHaveBeenCalledWith({
      runtime,
      allowedOrigins: ["https://app.example.test"],
    });

    out.dispose();
    expect(controllerDispose).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });
});

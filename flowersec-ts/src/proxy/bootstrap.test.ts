import { afterEach, describe, expect, it, vi } from "vitest";

const connectBrowserMock = vi.fn();
const connectTunnelBrowserMock = vi.fn();
const registerProxyIntegrationMock = vi.fn();
const createProxyRuntimeMock = vi.fn();
const registerProxyControllerWindowMock = vi.fn();

vi.mock("../browser/connect.js", () => ({
  connectBrowser: connectBrowserMock,
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

function makeArtifact(scopeVersion = 1) {
  return {
    v: 1,
    transport: "tunnel",
    tunnel_grant: {
      tunnel_url: "wss://example.invalid/tunnel",
      channel_id: "chan_art_1",
      channel_init_expire_at_unix_s: 123,
      idle_timeout_seconds: 30,
      role: 1,
      token: "tok",
      e2ee_psk_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      allowed_suites: [1],
      default_suite: 1,
    },
    scoped: [
      {
        scope: "proxy.runtime",
        scope_version: scopeVersion,
        critical: false,
        payload: {
          mode: "service_worker",
          serviceWorker: {
            scriptUrl: "/proxy-sw.js",
            scope: "/",
          },
          preset: {
            presetId: "default",
          },
          limits: {
            maxBodyBytes: 2048,
          },
        },
      },
    ],
  };
}

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

  it("preserves shared integration-core errors for artifact bootstrap helpers too", async () => {
    const client = { close: vi.fn() };
    const err = new Error("register failed");

    connectBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockRejectedValue(err);

    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");
    await expect(connectArtifactProxyBrowser(makeArtifact() as any)).rejects.toThrow("register failed");

    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it("connects proxy browser from an artifact runtime scope", async () => {
    const client = { close: vi.fn() };
    const runtime = { dispose: vi.fn() };
    const integrationDispose = vi.fn().mockResolvedValue(undefined);

    connectBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockResolvedValue({ runtime, dispose: integrationDispose });

    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");
    const out = await connectArtifactProxyBrowser(makeArtifact() as any, {
      runtimeGlobalKey: "__flowersecProxyRuntime",
    });

    expect(out.client).toBe(client);
    expect(connectBrowserMock).toHaveBeenCalledWith(makeArtifact(), {});
    expect(registerProxyIntegrationMock).toHaveBeenCalledWith({
      client,
      runtimeGlobalKey: "__flowersecProxyRuntime",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      preset: expect.objectContaining({ preset_id: "default" }),
      runtime: { maxBodyBytes: 2048 },
    });
  });

  it("keeps grant helper and artifact helper on the same integration-core option shape", async () => {
    const tunnelClient = { close: vi.fn() };
    const artifactClient = { close: vi.fn() };
    const integrationDispose = vi.fn().mockResolvedValue(undefined);

    connectTunnelBrowserMock.mockResolvedValueOnce(tunnelClient);
    connectBrowserMock.mockResolvedValueOnce(artifactClient);
    registerProxyIntegrationMock.mockResolvedValue({ runtime: { runtime: true }, dispose: integrationDispose });

    const { connectTunnelProxyBrowser, connectArtifactProxyBrowser } = await import("./bootstrap.js");
    const tunnelHandle = await connectTunnelProxyBrowser({ tunnel_url: "ws://example.invalid" } as any, {
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      runtimeGlobalKey: "__flowersecProxyRuntime",
      runtime: { maxBodyBytes: 2048 },
    });
    const artifactHandle = await connectArtifactProxyBrowser(makeArtifact() as any, {
      runtimeGlobalKey: "__flowersecProxyRuntime",
    });

    const [grantCall, artifactCall] = registerProxyIntegrationMock.mock.calls;
    expect(grantCall?.[0]).toEqual({
      client: tunnelClient,
      runtimeGlobalKey: "__flowersecProxyRuntime",
      runtime: { maxBodyBytes: 2048 },
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
    });
    expect(artifactCall?.[0]).toEqual({
      client: artifactClient,
      runtimeGlobalKey: "__flowersecProxyRuntime",
      runtime: { maxBodyBytes: 2048 },
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      preset: expect.objectContaining({ preset_id: "default" }),
    });

    await tunnelHandle.dispose();
    await artifactHandle.dispose();
  });

  it("fails fast when artifact proxy runtime scope is missing or unsupported", async () => {
    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");

    await expect(
      connectArtifactProxyBrowser({
        ...makeArtifact(),
        scoped: [],
      } as any)
    ).rejects.toThrow("missing proxy.runtime@1 scope");

    await expect(connectArtifactProxyBrowser(makeArtifact(2) as any)).rejects.toThrow("unsupported proxy.runtime scope_version: 2");
    expect(connectBrowserMock).not.toHaveBeenCalled();
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

  it("connects a controller runtime from artifact scope and uses allowed origins from the scope", async () => {
    const client = { close: vi.fn() };
    const runtime = { runtime: true };
    const controllerDispose = vi.fn();

    connectBrowserMock.mockResolvedValue(client);
    createProxyRuntimeMock.mockReturnValue(runtime);
    registerProxyControllerWindowMock.mockReturnValue({ dispose: controllerDispose });

    const { connectArtifactProxyControllerBrowser } = await import("./bootstrap.js");
    const out = await connectArtifactProxyControllerBrowser({
      ...makeArtifact(),
      scoped: [
        {
          scope: "proxy.runtime",
          scope_version: 1,
          critical: false,
          payload: {
            mode: "controller_bridge",
            controllerBridge: {
              allowedOrigins: ["https://app.example.test"],
            },
            preset: {
              presetId: "default",
            },
            limits: {
              maxWsFrameBytes: 4096,
            },
          },
        },
      ],
    } as any);

    expect(out.client).toBe(client);
    expect(createProxyRuntimeMock).toHaveBeenCalledWith({
      client,
      maxWsFrameBytes: 4096,
    });
    expect(registerProxyControllerWindowMock).toHaveBeenCalledWith({
      runtime,
      allowedOrigins: ["https://app.example.test"],
    });
  });

  it("keeps grant controller helper and artifact controller helper on the same controller-core semantics", async () => {
    const tunnelClient = { close: vi.fn() };
    const artifactClient = { close: vi.fn() };
    const runtime1 = { runtime: 1 };
    const runtime2 = { runtime: 2 };
    const controllerDispose = vi.fn();

    connectTunnelBrowserMock.mockResolvedValueOnce(tunnelClient);
    connectBrowserMock.mockResolvedValueOnce(artifactClient);
    createProxyRuntimeMock.mockReturnValueOnce(runtime1).mockReturnValueOnce(runtime2);
    registerProxyControllerWindowMock.mockReturnValue({ dispose: controllerDispose });

    const { connectTunnelProxyControllerBrowser, connectArtifactProxyControllerBrowser } = await import("./bootstrap.js");
    const tunnelHandle = await connectTunnelProxyControllerBrowser({ tunnel_url: "ws://example.invalid" } as any, {
      allowedOrigins: ["https://app.example.test"],
      runtime: { maxWsFrameBytes: 4096 },
    });
    const artifactHandle = await connectArtifactProxyControllerBrowser({
      ...makeArtifact(),
      scoped: [
        {
          scope: "proxy.runtime",
          scope_version: 1,
          critical: false,
          payload: {
            mode: "controller_bridge",
            controllerBridge: {
              allowedOrigins: ["https://app.example.test"],
            },
            preset: {
              presetId: "default",
            },
            limits: {
              maxWsFrameBytes: 4096,
            },
          },
        },
      ],
    } as any);

    expect(createProxyRuntimeMock).toHaveBeenNthCalledWith(1, {
      client: tunnelClient,
      maxWsFrameBytes: 4096,
    });
    expect(createProxyRuntimeMock).toHaveBeenNthCalledWith(2, {
      client: artifactClient,
      maxWsFrameBytes: 4096,
    });
    expect(registerProxyControllerWindowMock).toHaveBeenNthCalledWith(1, {
      runtime: runtime1,
      allowedOrigins: ["https://app.example.test"],
    });
    expect(registerProxyControllerWindowMock).toHaveBeenNthCalledWith(2, {
      runtime: runtime2,
      allowedOrigins: ["https://app.example.test"],
    });

    tunnelHandle.dispose();
    artifactHandle.dispose();
  });
});

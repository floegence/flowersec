import { afterEach, describe, expect, it, vi } from "vitest";

const connectBrowserMock = vi.fn();
const registerProxyIntegrationMock = vi.fn();
const createProxyRuntimeMock = vi.fn();
const registerProxyControllerWindowMock = vi.fn();

vi.mock("../browser/connect.js", () => ({
  connectBrowser: connectBrowserMock,
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

describe("artifact proxy bootstrap", () => {
  it("connects a service-worker runtime from artifact scope and disposes both layers", async () => {
    const client = { close: vi.fn() };
    const runtime = { runtime: true };
    const integrationDispose = vi.fn().mockResolvedValue(undefined);
    connectBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockResolvedValue({ runtime, dispose: integrationDispose });

    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");
    const artifact = makeArtifact(serviceWorkerScope());
    const handle = await connectArtifactProxyBrowser(artifact as any, {
      runtimeGlobalKey: "__flowersecProxyRuntime",
    });

    expect(handle.client).toBe(client);
    expect(handle.runtime).toBe(runtime);
    expect(connectBrowserMock).toHaveBeenCalledWith(artifact, {});
    expect(registerProxyIntegrationMock).toHaveBeenCalledWith({
      client,
      runtimeGlobalKey: "__flowersecProxyRuntime",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      preset: expect.objectContaining({ preset_id: "default" }),
      runtime: { maxBodyBytes: 2048 },
    });

    await handle.dispose();
    expect(integrationDispose).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it("closes the connected client when service-worker registration fails", async () => {
    const client = { close: vi.fn() };
    connectBrowserMock.mockResolvedValue(client);
    registerProxyIntegrationMock.mockRejectedValue(new Error("register failed"));

    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");
    await expect(connectArtifactProxyBrowser(makeArtifact(serviceWorkerScope()) as any)).rejects.toThrow("register failed");
    expect(client.close).toHaveBeenCalledTimes(1);
  });

  it("rejects missing and unsupported runtime scopes before connecting", async () => {
    const { connectArtifactProxyBrowser } = await import("./bootstrap.js");
    await expect(connectArtifactProxyBrowser(makeArtifact() as any)).rejects.toThrow("missing proxy.runtime@1 scope");
    await expect(connectArtifactProxyBrowser(makeArtifact({ ...serviceWorkerScope(), scope_version: 2 }) as any))
      .rejects.toThrow("unsupported proxy.runtime scope_version: 2");
    expect(connectBrowserMock).not.toHaveBeenCalled();
  });

  it("connects a controller bridge from artifact scope and disposes the controller and client", async () => {
    const client = { close: vi.fn() };
    const runtime = { runtime: true };
    const controllerDispose = vi.fn();
    connectBrowserMock.mockResolvedValue(client);
    createProxyRuntimeMock.mockReturnValue(runtime);
    registerProxyControllerWindowMock.mockReturnValue({ dispose: controllerDispose });

    const { connectArtifactProxyControllerBrowser } = await import("./bootstrap.js");
    const handle = await connectArtifactProxyControllerBrowser(makeArtifact(controllerScope()) as any, {
      capabilityNonce: "bridge_tok",
      runtime: { maxWsBufferedAmountBytes: 8192 },
    });

    expect(createProxyRuntimeMock).toHaveBeenCalledWith({
      client,
      maxWsFrameBytes: 4096,
      maxWsBufferedAmountBytes: 8192,
    });
    expect(registerProxyControllerWindowMock).toHaveBeenCalledWith({
      runtime,
      allowedOrigins: ["https://app.example.test"],
      capabilityNonce: "bridge_tok",
    });

    handle.dispose();
    expect(controllerDispose).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
  });
});

function makeArtifact(scope?: Record<string, unknown>) {
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
    scoped: scope == null ? [] : [scope],
  };
}

function serviceWorkerScope(): Record<string, unknown> {
  return {
    scope: "proxy.runtime",
    scope_version: 1,
    critical: false,
    payload: {
      mode: "service_worker",
      serviceWorker: { scriptUrl: "/proxy-sw.js", scope: "/" },
      preset: {
        presetId: "default",
        snapshot: {
          v: 1,
          preset_id: "default",
          limits: {},
        },
      },
      limits: { maxBodyBytes: 2048 },
    },
  };
}

function controllerScope(): Record<string, unknown> {
  return {
    scope: "proxy.runtime",
    scope_version: 1,
    critical: false,
    payload: {
      mode: "controller_bridge",
      controllerBridge: { allowedOrigins: ["https://app.example.test"] },
      preset: {
        presetId: "default",
        snapshot: {
          v: 1,
          preset_id: "default",
          limits: {},
        },
      },
      limits: { maxWsFrameBytes: 4096 },
    },
  };
}

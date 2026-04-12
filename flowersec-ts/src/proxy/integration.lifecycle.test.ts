import { afterEach, describe, expect, test, vi } from "vitest";

const {
  createProxyRuntimeMock,
  ensureServiceWorkerRuntimeRegisteredMock,
  resolveProxyPresetMock,
  registerServiceWorkerAndEnsureControlMock,
} = vi.hoisted(() => ({
  createProxyRuntimeMock: vi.fn(),
  ensureServiceWorkerRuntimeRegisteredMock: vi.fn(),
  resolveProxyPresetMock: vi.fn(),
  registerServiceWorkerAndEnsureControlMock: vi.fn(),
}));

vi.mock("./runtime.js", () => ({
  createProxyRuntime: (...args: unknown[]) => createProxyRuntimeMock(...args),
  ensureServiceWorkerRuntimeRegistered: (...args: unknown[]) => ensureServiceWorkerRuntimeRegisteredMock(...args),
}));

vi.mock("./preset.js", async () => {
  const actual = await vi.importActual("./preset.js");
  return {
    ...actual,
    resolveProxyPreset: (...args: unknown[]) => resolveProxyPresetMock(...args),
  };
});

vi.mock("./registerServiceWorker.js", () => ({
  registerServiceWorkerAndEnsureControl: (...args: unknown[]) => registerServiceWorkerAndEnsureControlMock(...args),
}));

type ControllerChangeHandler = () => void;

function installProxyIntegrationEnv(args: { href?: string; controllerScriptURL?: string | null }) {
  const controllerHandlers = new Set<ControllerChangeHandler>();
  const replace = vi.fn();
  const reload = vi.fn();
  const getRegistrations = vi.fn().mockResolvedValue([]);
  const controllerPostMessage = vi.fn((_msg: unknown, transfer?: Transferable[]) => {
    const port = transfer?.[0] as MessagePort | undefined;
    port?.postMessage({ type: "flowersec-proxy:register-runtime-ack", ok: true });
    port?.close();
  });

  const serviceWorker = {
    controller: args.controllerScriptURL == null ? null : { scriptURL: args.controllerScriptURL, postMessage: controllerPostMessage },
    addEventListener: vi.fn((type: string, handler: ControllerChangeHandler) => {
      if (type === "controllerchange") controllerHandlers.add(handler);
    }),
    removeEventListener: vi.fn((type: string, handler: ControllerChangeHandler) => {
      if (type === "controllerchange") controllerHandlers.delete(handler);
    }),
    getRegistrations,
  };

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { serviceWorker },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: {
        href: args.href ?? "https://app.example.test/workbench",
        replace,
        reload,
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
    },
  });

  return { serviceWorker, controllerHandlers, replace, reload, getRegistrations, controllerPostMessage };
}

afterEach(() => {
  vi.clearAllMocks();
  delete (globalThis as Record<string, unknown>).__flowersecRuntime;
  delete (globalThis as { navigator?: unknown }).navigator;
  delete (globalThis as { window?: unknown }).window;
});

describe("registerProxyIntegration", () => {
  test("wires preset limits, runtime globals, plugin hooks, and cleanup", async () => {
    const env = installProxyIntegrationEnv({
      controllerScriptURL: "https://app.example.test/proxy-sw.js",
    });
    const runtime = { dispose: vi.fn() };
    const onRegistered = vi.fn();
    const onDisposed = vi.fn().mockResolvedValue(undefined);

    resolveProxyPresetMock.mockReturnValue({
      v: 1,
      preset_id: "default",
      deprecated: false,
      limits: {
        max_json_frame_bytes: 11,
        max_chunk_bytes: 22,
        max_body_bytes: 33,
        max_ws_frame_bytes: 44,
        timeout_ms: 55,
      },
    });
    createProxyRuntimeMock.mockReturnValue(runtime);
    ensureServiceWorkerRuntimeRegisteredMock.mockResolvedValue(undefined);
    registerServiceWorkerAndEnsureControlMock.mockResolvedValue(undefined);

    const { registerProxyIntegration } = await import("./integration.js");
    const handle = await registerProxyIntegration({
      client: {
        path: "tunnel",
        rpc: {},
        openStream: vi.fn(),
        ping: vi.fn(),
        close: vi.fn(),
      } as any,
      runtimeGlobalKey: "__flowersecRuntime",
      serviceWorker: {
        scriptUrl: "/proxy-sw.js",
        expectedScriptPathSuffix: "/proxy-sw.js",
      },
      plugins: [
        {
          name: "scope-plugin",
          mutateOptions: (opts) => ({
            ...opts,
            serviceWorker: {
              ...opts.serviceWorker,
              scope: "/proxy/",
            },
          }),
          onRegistered,
          onDisposed,
        },
      ],
    });

    expect(registerServiceWorkerAndEnsureControlMock).toHaveBeenCalledWith({
      scriptUrl: "/proxy-sw.js",
      scope: "/proxy/",
      repairQueryKey: "_flowersec_sw_repair",
      maxRepairAttempts: 2,
      controllerTimeoutMs: 8000,
    });
    expect(ensureServiceWorkerRuntimeRegisteredMock).toHaveBeenCalledWith({ timeoutMs: 8000 });
    expect(createProxyRuntimeMock).toHaveBeenCalledWith({
      client: expect.any(Object),
      maxJsonFrameBytes: 11,
      maxChunkBytes: 22,
      maxBodyBytes: 33,
      maxWsFrameBytes: 44,
      timeoutMs: 55,
    });
    expect(onRegistered).toHaveBeenCalledWith(
      expect.objectContaining({
        runtime,
        preset: expect.objectContaining({ preset_id: "default" }),
        options: expect.objectContaining({
          serviceWorker: expect.objectContaining({ scope: "/proxy/" }),
        }),
      })
    );
    expect((globalThis as Record<string, unknown>).__flowersecRuntime).toBe(runtime);
    expect(env.serviceWorker.addEventListener).toHaveBeenCalledWith("controllerchange", expect.any(Function));

    await handle.dispose();

    expect(runtime.dispose).toHaveBeenCalledTimes(1);
    expect(onDisposed).toHaveBeenCalledTimes(1);
    expect(env.serviceWorker.removeEventListener).toHaveBeenCalledWith("controllerchange", expect.any(Function));
    expect((globalThis as Record<string, unknown>).__flowersecRuntime).toBeUndefined();
  });

  test("allows plugins to ignore controller mismatches during registration", async () => {
    installProxyIntegrationEnv({
      controllerScriptURL: "https://app.example.test/other-sw.js",
    });
    createProxyRuntimeMock.mockReturnValue({ dispose: vi.fn() });
    resolveProxyPresetMock.mockReturnValue({
      v: 1,
      preset_id: "default",
      deprecated: false,
      limits: {
        max_json_frame_bytes: 1,
        max_chunk_bytes: 2,
        max_body_bytes: 3,
        max_ws_frame_bytes: 4,
      },
    });
    registerServiceWorkerAndEnsureControlMock.mockResolvedValue(undefined);
    ensureServiceWorkerRuntimeRegisteredMock.mockResolvedValue(undefined);

    const onControllerMismatch = vi.fn().mockReturnValue("ignore");
    const { registerProxyIntegration } = await import("./integration.js");
    const handle = await registerProxyIntegration({
      client: {
        path: "tunnel",
        rpc: {},
        openStream: vi.fn(),
        ping: vi.fn(),
        close: vi.fn(),
      } as any,
      serviceWorker: {
        scriptUrl: "/proxy-sw.js",
        expectedScriptPathSuffix: "/proxy-sw.js",
        repair: {
          controllerTimeoutMs: 1,
        },
        monitor: { enabled: false },
      },
      plugins: [
        {
          name: "ignore-mismatch",
          onControllerMismatch,
        },
      ],
    });

    expect(onControllerMismatch).toHaveBeenCalledWith({
      expectedScriptPathSuffix: "/proxy-sw.js",
      actualScriptURL: "https://app.example.test/other-sw.js",
      stage: "register",
    });

    await handle.dispose();
  });

  test("repairs navigation when the controller drifts after registration", async () => {
    const env = installProxyIntegrationEnv({
      href: "https://app.example.test/workbench",
      controllerScriptURL: "https://app.example.test/proxy-sw.js",
    });
    createProxyRuntimeMock.mockReturnValue({ dispose: vi.fn() });
    resolveProxyPresetMock.mockReturnValue({
      v: 1,
      preset_id: "default",
      deprecated: false,
      limits: {
        max_json_frame_bytes: 1,
        max_chunk_bytes: 2,
        max_body_bytes: 3,
        max_ws_frame_bytes: 4,
      },
    });
    registerServiceWorkerAndEnsureControlMock.mockResolvedValue(undefined);
    ensureServiceWorkerRuntimeRegisteredMock.mockResolvedValue(undefined);

    const { registerProxyIntegration } = await import("./integration.js");
    const handle = await registerProxyIntegration({
      client: {
        path: "tunnel",
        rpc: {},
        openStream: vi.fn(),
        ping: vi.fn(),
        close: vi.fn(),
      } as any,
      serviceWorker: {
        scriptUrl: "/proxy-sw.js",
        expectedScriptPathSuffix: "/proxy-sw.js",
        repair: {
          queryKey: "_k",
          maxAttempts: 2,
          strategy: "replace",
        },
        monitor: {
          throttleMs: 0,
        },
      },
    });

    env.serviceWorker.controller = { scriptURL: "https://app.example.test/other-sw.js" };
    for (const handler of env.controllerHandlers) handler();
    await Promise.resolve();

    expect(env.replace).toHaveBeenCalledWith("https://app.example.test/workbench?_k=1");

    await handle.dispose();
  });
});

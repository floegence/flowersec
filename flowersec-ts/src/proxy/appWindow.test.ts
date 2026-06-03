import { afterEach, describe, expect, test, vi } from "vitest";

const createServiceWorkerControllerGuardMock = vi.fn();

vi.mock("./controllerGuard.js", () => ({
  createServiceWorkerControllerGuard: (...args: unknown[]) => createServiceWorkerControllerGuardMock(...args),
}));

afterEach(() => {
  vi.clearAllMocks();
  delete (globalThis as any).window;
});

describe("registerProxyAppWindowWithServiceWorkerControl", () => {
  test("registers the service worker, ensures control, then installs the app bridge", async () => {
    const register = vi.fn().mockResolvedValue(undefined);
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    const postMessage = vi.fn();

    (globalThis as any).window = {
      navigator: {
        serviceWorker: {
          register,
          addEventListener,
          removeEventListener,
        },
      },
      parent: { postMessage },
      top: { postMessage },
    };

    const ensure = vi.fn().mockResolvedValue(undefined);
    const dispose = vi.fn();
    createServiceWorkerControllerGuardMock.mockReturnValue({ ensure, dispose });

    const { registerProxyAppWindowWithServiceWorkerControl } = await import("./appWindow.js");
    const out = await registerProxyAppWindowWithServiceWorkerControl({
      controllerOrigin: "https://controller.example.test",
      serviceWorker: {
        scriptUrl: "/proxy-sw.js",
        scope: "/",
        expectedScriptPathSuffix: "/proxy-sw.js",
      },
    });

    expect(register).toHaveBeenCalledWith("/proxy-sw.js", { scope: "/" });
    expect(createServiceWorkerControllerGuardMock).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedScriptPathSuffix: "/proxy-sw.js",
      })
    );
    expect(ensure).toHaveBeenCalledTimes(1);
    expect(dispose).toHaveBeenCalledTimes(1);

    out.dispose();
    expect(removeEventListener).toHaveBeenCalledWith("message", expect.any(Function));
  });
});

describe("registerProxyAppWindow", () => {
  test("forwards fetch bridge messages with capability nonce when configured", async () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    const postMessage = vi.fn();
    const targetWindow = {
      navigator: {
        serviceWorker: {
          addEventListener,
          removeEventListener,
        },
      },
      parent: { postMessage },
      top: { postMessage },
    };

    const { registerProxyAppWindow } = await import("./appWindow.js");
    const handle = registerProxyAppWindow({
      controllerOrigin: "https://controller.example.test",
      controllerWindow: targetWindow.parent as any,
      targetWindow: targetWindow as any,
      capabilityNonce: "bridge_tok",
    });

    const listener = addEventListener.mock.calls.find((call) => call[0] === "message")?.[1] as (event: MessageEvent) => void;
    expect(listener).toBeTypeOf("function");
    const port = {} as MessagePort;
    const req = { id: "req-1", method: "GET", path: "/", headers: [] };
    listener({
      data: { type: "flowersec-proxy:window_fetch", req },
      ports: [port],
    } as unknown as MessageEvent);

    expect(postMessage).toHaveBeenCalledWith(
      {
        type: "flowersec-proxy:fetch",
        req,
        capabilityNonce: "bridge_tok",
      },
      "https://controller.example.test",
      [port],
    );

    handle.dispose();
    expect(removeEventListener).toHaveBeenCalledWith("message", listener);
  });

  test("forwards websocket opens with capability nonce when configured", async () => {
    const addEventListener = vi.fn();
    const postMessage = vi.fn((_message: unknown, _origin: string, transfer?: Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      queueMicrotask(() => {
        port?.postMessage({ type: "flowersec-proxy:ws_open_ack", protocol: "demo" });
      });
    });
    const targetWindow = {
      navigator: {
        serviceWorker: {
          addEventListener,
          removeEventListener: vi.fn(),
        },
      },
      parent: { postMessage },
      top: { postMessage },
    };

    const { registerProxyAppWindow } = await import("./appWindow.js");
    const handle = registerProxyAppWindow({
      controllerOrigin: "https://controller.example.test",
      controllerWindow: targetWindow.parent as any,
      targetWindow: targetWindow as any,
      capabilityNonce: "bridge_tok",
    });

    await handle.runtime.openWebSocketStream("/ws", { protocols: ["demo"] });

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "flowersec-proxy:ws_open",
        path: "/ws",
        protocols: ["demo"],
        capabilityNonce: "bridge_tok",
      }),
      "https://controller.example.test",
      expect.arrayContaining([expect.any(MessagePort)]),
    );

    handle.dispose();
  });
});

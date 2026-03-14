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

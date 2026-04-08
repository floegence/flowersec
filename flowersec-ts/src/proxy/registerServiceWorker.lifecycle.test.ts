import { afterEach, describe, expect, test, vi } from "vitest";

import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";

type ControllerChangeHandler = () => void;

function installServiceWorkerEnv(args: { href: string; controllerScriptURL?: string | null }) {
  const controllerHandlers = new Set<ControllerChangeHandler>();
  const register = vi.fn().mockResolvedValue(undefined);
  const replaceState = vi.fn();
  const replace = vi.fn();
  const reload = vi.fn();

  const serviceWorker = {
    controller: args.controllerScriptURL == null ? null : { scriptURL: args.controllerScriptURL },
    register,
    ready: Promise.resolve(undefined),
    addEventListener: vi.fn((type: string, handler: ControllerChangeHandler) => {
      if (type === "controllerchange") controllerHandlers.add(handler);
    }),
    removeEventListener: vi.fn((type: string, handler: ControllerChangeHandler) => {
      if (type === "controllerchange") controllerHandlers.delete(handler);
    }),
  };

  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { serviceWorker },
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: {
        href: args.href,
        replace,
        reload,
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
    },
  });
  Object.defineProperty(globalThis, "history", {
    configurable: true,
    value: { replaceState },
  });
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { title: "Flowersec Proxy" },
  });

  return { serviceWorker, controllerHandlers, register, replaceState, replace, reload };
}

afterEach(() => {
  delete (globalThis as { navigator?: unknown }).navigator;
  delete (globalThis as { window?: unknown }).window;
  delete (globalThis as { history?: unknown }).history;
  delete (globalThis as { document?: unknown }).document;
});

describe("registerServiceWorkerAndEnsureControl", () => {
  test("cleans repair query state when the page is already controlled", async () => {
    const env = installServiceWorkerEnv({
      href: "https://app.example.test/workbench?_flowersec_sw_repair=1#editor",
      controllerScriptURL: "https://app.example.test/proxy-sw.js",
    });

    await registerServiceWorkerAndEnsureControl({
      scriptUrl: "/proxy-sw.js",
    });

    expect(env.register).toHaveBeenCalledWith("/proxy-sw.js", { scope: "/" });
    expect(env.replaceState).toHaveBeenCalledWith(null, "Flowersec Proxy", "/workbench#editor");
  });

  test("waits for controllerchange before resolving and then cleans the repair query", async () => {
    const env = installServiceWorkerEnv({
      href: "https://app.example.test/workbench?_flowersec_sw_repair=2",
      controllerScriptURL: null,
    });

    const promise = registerServiceWorkerAndEnsureControl({
      scriptUrl: "/proxy-sw.js",
      controllerTimeoutMs: 100,
    });

    while (env.serviceWorker.addEventListener.mock.calls.length === 0) {
      await Promise.resolve();
    }
    env.serviceWorker.controller = { scriptURL: "https://app.example.test/proxy-sw.js" };
    for (const handler of env.controllerHandlers) handler();
    await promise;

    expect(env.serviceWorker.addEventListener).toHaveBeenCalledWith("controllerchange", expect.any(Function));
    expect(env.serviceWorker.removeEventListener).toHaveBeenCalledWith("controllerchange", expect.any(Function));
    expect(env.replaceState).toHaveBeenCalledWith(null, "Flowersec Proxy", "/workbench");
  });

  test("throws once repair attempts are exhausted and control never arrives", async () => {
    const env = installServiceWorkerEnv({
      href: "https://app.example.test/workbench",
      controllerScriptURL: null,
    });

    await expect(
      registerServiceWorkerAndEnsureControl({
        scriptUrl: "/proxy-sw.js",
        controllerTimeoutMs: 1,
        maxRepairAttempts: 0,
      })
    ).rejects.toThrow("Service Worker is installed but not controlling this page");

    expect(env.replace).not.toHaveBeenCalled();
    expect(env.reload).not.toHaveBeenCalled();
  });
});

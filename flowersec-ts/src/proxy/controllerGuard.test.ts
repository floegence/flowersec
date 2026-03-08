import { afterEach, describe, expect, it, vi } from "vitest";

import { createServiceWorkerControllerGuard } from "./controllerGuard.js";

type FakeRegistration = {
  active?: { scriptURL?: string | null } | null;
  waiting?: { scriptURL?: string | null } | null;
  installing?: { scriptURL?: string | null } | null;
  unregister: ReturnType<typeof vi.fn>;
};

function createServiceWorkerContainer(args: {
  controllerScriptURL?: string;
  registrations?: FakeRegistration[];
}) {
  let controllerScriptURL = String(args.controllerScriptURL ?? "").trim();
  const listeners = new Set<() => void>();
  const registrations = args.registrations ?? [];

  return {
    get controller() {
      if (controllerScriptURL === "") return null;
      return { scriptURL: controllerScriptURL };
    },
    setController(scriptURL: string) {
      controllerScriptURL = String(scriptURL ?? "").trim();
    },
    emitControllerChange() {
      for (const listener of Array.from(listeners)) listener();
    },
    addEventListener(_type: string, listener: () => void) {
      listeners.add(listener);
    },
    removeEventListener(_type: string, listener: () => void) {
      listeners.delete(listener);
    },
    async getRegistrations() {
      return registrations;
    },
  };
}

function createFakeWindow(args: { href?: string; serviceWorker?: ReturnType<typeof createServiceWorkerContainer> }) {
  const replace = vi.fn();
  const reload = vi.fn();
  return {
    location: {
      href: args.href ?? "https://example.test/app",
      replace,
      reload,
    },
    navigator: {
      serviceWorker: args.serviceWorker,
    },
    setTimeout,
    clearTimeout,
  } as unknown as Window & {
    location: {
      href: string;
      replace: ReturnType<typeof vi.fn>;
      reload: ReturnType<typeof vi.fn>;
    };
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("createServiceWorkerControllerGuard", () => {
  it("passes when the target window is already controlled by the expected script", async () => {
    const sw = createServiceWorkerContainer({ controllerScriptURL: "https://example.test/_proxy/sw.js" });
    const win = createFakeWindow({ serviceWorker: sw });

    const guard = createServiceWorkerControllerGuard({
      targetWindow: win,
      expectedScriptPathSuffix: "/_proxy/sw.js",
    });

    await expect(guard.ensure()).resolves.toBeUndefined();
    guard.dispose();
  });

  it("repairs through the navigation window and preserves keep-listed service workers", async () => {
    const keepReg = {
      active: { scriptURL: "https://example.test/keep/sw.js" },
      unregister: vi.fn(),
    } satisfies FakeRegistration;
    const dropReg = {
      active: { scriptURL: "https://example.test/drop/sw.js" },
      unregister: vi.fn().mockResolvedValue(true),
    } satisfies FakeRegistration;

    const childSW = createServiceWorkerContainer({
      controllerScriptURL: "https://example.test/other/sw.js",
      registrations: [keepReg, dropReg],
    });
    const childWin = createFakeWindow({ href: "https://example.test/frame", serviceWorker: childSW });
    const navWin = createFakeWindow({ href: "https://example.test/app?x=1", serviceWorker: childSW });

    const guard = createServiceWorkerControllerGuard({
      targetWindow: childWin,
      navigationWindow: navWin,
      expectedScriptPathSuffix: "/_proxy/sw.js",
      repair: { queryKey: "_repair", maxAttempts: 2, controllerTimeoutMs: 0 },
      conflicts: {
        keepScriptPathSuffixes: ["/keep/sw.js"],
      },
    });

    await expect(guard.ensure()).rejects.toThrow("Proxy Service Worker is installed but not controlling the target window");
    expect(keepReg.unregister).not.toHaveBeenCalled();
    expect(dropReg.unregister).toHaveBeenCalledTimes(1);
    expect(navWin.location.replace).toHaveBeenCalledWith("https://example.test/app?x=1&_repair=1");
    guard.dispose();
  });

  it("supports ignore on mismatch", async () => {
    const sw = createServiceWorkerContainer({ controllerScriptURL: "https://example.test/other/sw.js" });
    const win = createFakeWindow({ serviceWorker: sw });

    const guard = createServiceWorkerControllerGuard({
      targetWindow: win,
      expectedScriptPathSuffix: "/_proxy/sw.js",
      repair: { controllerTimeoutMs: 0 },
      onControllerMismatch: () => "ignore",
    });

    await expect(guard.ensure()).resolves.toBeUndefined();
    expect(win.location.replace).not.toHaveBeenCalled();
    expect(win.location.reload).not.toHaveBeenCalled();
    guard.dispose();
  });

  it("throttles monitor-triggered repair", async () => {
    const sw = createServiceWorkerContainer({ controllerScriptURL: "https://example.test/_proxy/sw.js" });
    const win = createFakeWindow({ serviceWorker: sw });

    const guard = createServiceWorkerControllerGuard({
      targetWindow: win,
      expectedScriptPathSuffix: "/_proxy/sw.js",
      repair: { queryKey: "_repair", maxAttempts: 2, controllerTimeoutMs: 0 },
      monitor: { enabled: true, throttleMs: 10_000 },
    });

    await guard.ensure();
    sw.setController("https://example.test/other/sw.js");
    sw.emitControllerChange();
    sw.emitControllerChange();

    await Promise.resolve();
    await Promise.resolve();

    expect(win.location.replace).toHaveBeenCalledTimes(1);
    expect(win.location.replace).toHaveBeenCalledWith("https://example.test/app?_repair=1");
    guard.dispose();
  });
});

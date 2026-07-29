import { afterEach, describe, expect, it } from "vitest";

import { createServiceWorkerControllerGuard } from "./controllerGuard.js";
import { disableUpstreamServiceWorkerRegister } from "./disableUpstreamServiceWorkerRegister.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";

const savedGlobals = new Map<PropertyKey, PropertyDescriptor | undefined>();

function setGlobal(name: PropertyKey, value: unknown): void {
  if (!savedGlobals.has(name)) savedGlobals.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
}

afterEach(() => {
  for (const [name, descriptor] of savedGlobals) {
    if (descriptor === undefined) delete (globalThis as Record<PropertyKey, unknown>)[name];
    else Object.defineProperty(globalThis, name, descriptor);
  }
  savedGlobals.clear();
});

class TestServiceWorkerContainer extends EventTarget {
  controller: Readonly<{ scriptURL: string }> | null = null;
  readonly registrations: Array<Readonly<{
    active?: Readonly<{ scriptURL: string }>;
    unregister(): Promise<boolean>;
  }>> = [];
  readonly registerCalls: Array<Readonly<{ scriptUrl: string; scope: string }>> = [];
  readonly ready = Promise.resolve({} as ServiceWorkerRegistration);

  async register(scriptUrl: string, options?: RegistrationOptions): Promise<ServiceWorkerRegistration> {
    this.registerCalls.push({ scriptUrl, scope: options?.scope ?? "" });
    return {} as ServiceWorkerRegistration;
  }

  async getRegistrations(): Promise<readonly ServiceWorkerRegistration[]> {
    return this.registrations as unknown as readonly ServiceWorkerRegistration[];
  }
}

function testWindow(container: TestServiceWorkerContainer | undefined, href = "https://app.example/workbench") {
  const replacements: string[] = [];
  let reloads = 0;
  const target = {
    navigator: container === undefined ? {} : { serviceWorker: container },
    location: {
      href,
      replace(value: string) { replacements.push(value); },
      reload() { reloads++; },
    },
  } as unknown as Window;
  return { target, replacements, reloads: () => reloads };
}

describe("proxy browser control", () => {
  it("accepts the expected controller and removes listeners on dispose", async () => {
    const container = new TestServiceWorkerContainer();
    container.controller = { scriptURL: "https://app.example/proxy-sw.js" };
    const { target } = testWindow(container);
    const guard = createServiceWorkerControllerGuard({
      targetWindow: target,
      expectedScriptPathSuffix: "/proxy-sw.js",
    });
    await guard.ensure();
    guard.dispose();
    guard.dispose();
    await expect(guard.ensure()).rejects.toThrow("disposed");
    expect(() => createServiceWorkerControllerGuard({ targetWindow: target, expectedScriptPathSuffix: " " })).toThrow(TypeError);
  });

  it("cleans conflicting registrations before a bounded repair navigation", async () => {
    const container = new TestServiceWorkerContainer();
    container.controller = { scriptURL: "not-a-url/legacy-sw.js" };
    let unregistered = 0;
    container.registrations.push(
      { active: { scriptURL: "https://app.example/legacy-sw.js" }, unregister: async () => { unregistered++; return true; } },
      { active: { scriptURL: "https://app.example/keep-sw.js" }, unregister: async () => true },
    );
    const { target, replacements } = testWindow(container);
    const contexts: string[] = [];
    const guard = createServiceWorkerControllerGuard({
      targetWindow: target,
      navigationWindow: target,
      expectedScriptPathSuffix: "/proxy-sw.js",
      repair: { controllerTimeoutMs: 1, queryKey: "repair", maxAttempts: 2 },
      conflicts: { keepScriptPathSuffixes: ["/keep-sw.js"] },
      onControllerMismatch(context) { contexts.push(`${context.stage}:${context.actualScriptURL}`); },
    });

    await expect(guard.ensure()).rejects.toThrow("navigation started");
    expect(contexts).toEqual(["ensure:not-a-url/legacy-sw.js"]);
    expect(unregistered).toBe(1);
    expect(replacements[0]).toContain("repair=1");
    guard.dispose();
  });

  it("supports ignored mismatches and fails closed without service workers", async () => {
    const container = new TestServiceWorkerContainer();
    const { target } = testWindow(container);
    const ignored = createServiceWorkerControllerGuard({
      targetWindow: target,
      expectedScriptPathSuffix: "/proxy-sw.js",
      repair: { controllerTimeoutMs: 1 },
      onControllerMismatch: () => "ignore",
    });
    await ignored.ensure();
    ignored.dispose();

    const unavailable = createServiceWorkerControllerGuard({
      targetWindow: testWindow(undefined).target,
      expectedScriptPathSuffix: "/proxy-sw.js",
    });
    await expect(unavailable.ensure()).rejects.toThrow("unavailable");
  });

  it("registers once and observes a controllerchange without navigation", async () => {
    const container = new TestServiceWorkerContainer();
    setGlobal("navigator", { serviceWorker: container });
    setGlobal("location", {
      href: "https://app.example/workbench",
      replace: () => { throw new Error("unexpected navigation"); },
    });
    queueMicrotask(() => {
      container.controller = { scriptURL: "https://app.example/proxy-sw.js" };
      container.dispatchEvent(new Event("controllerchange"));
    });

    await registerServiceWorkerAndEnsureControl({ scriptUrl: " /proxy-sw.js ", scope: " /app/ ", controllerTimeoutMs: 50 });
    expect(container.registerCalls).toEqual([{ scriptUrl: "/proxy-sw.js", scope: "/app/" }]);
  });

  it("bounds registration policy and repairs only within the configured attempt limit", async () => {
    const container = new TestServiceWorkerContainer();
    const replacements: string[] = [];
    setGlobal("navigator", { serviceWorker: container });
    setGlobal("location", {
      href: "https://app.example/workbench?repair=0",
      replace: (value: string) => replacements.push(value),
    });
    await expect(registerServiceWorkerAndEnsureControl({
      scriptUrl: "/proxy-sw.js",
      controllerTimeoutMs: 1,
      repairQueryKey: "repair",
      maxRepairAttempts: 2,
    })).rejects.toThrow("navigation started");
    expect(replacements[0]).toContain("repair=1");

    setGlobal("location", { href: "https://app.example/workbench?repair=2", replace: () => undefined });
    await expect(registerServiceWorkerAndEnsureControl({
      scriptUrl: "/proxy-sw.js",
      controllerTimeoutMs: 1,
      repairQueryKey: "repair",
      maxRepairAttempts: 2,
    })).rejects.toThrow("did not take control");
    await expect(registerServiceWorkerAndEnsureControl({ scriptUrl: " ", controllerTimeoutMs: 1 })).rejects.toThrow(TypeError);
    await expect(registerServiceWorkerAndEnsureControl({ scriptUrl: "/proxy-sw.js", controllerTimeoutMs: 0 })).rejects.toThrow(TypeError);
  });

  it("temporarily disables upstream registration and restores the original method", async () => {
    const container = new TestServiceWorkerContainer();
    setGlobal("navigator", { serviceWorker: container });
    const original = container.register;
    const handle = disableUpstreamServiceWorkerRegister();
    await expect(container.register("/upstream-sw.js")).rejects.toThrow("disabled");
    handle.restore();
    expect(container.register).not.toBe(original);
    await expect(container.register("/restored-sw.js", { scope: "/" })).resolves.toBeDefined();
    expect(container.registerCalls).toEqual([{ scriptUrl: "/restored-sw.js", scope: "/" }]);
  });
});

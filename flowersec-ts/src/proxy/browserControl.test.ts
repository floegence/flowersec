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
    scope?: string;
    active?: Readonly<{ scriptURL: string }>;
    unregister(): Promise<boolean>;
  }>> = [];
  readonly registerCalls: Array<Readonly<{ scriptUrl: string; scope: string }>> = [];
  readonly ready = Promise.resolve({} as ServiceWorkerRegistration);

  async register(scriptUrl: string, options?: RegistrationOptions): Promise<ServiceWorkerRegistration> {
    this.registerCalls.push({ scriptUrl, scope: options?.scope ?? "" });
    const container = this;
    return { scope: new URL(options?.scope ?? "/", "https://app.example/").href,
      get active() { return container.controller; } } as ServiceWorkerRegistration;
  }

  async getRegistrations(): Promise<readonly ServiceWorkerRegistration[]> {
    return this.registrations as unknown as readonly ServiceWorkerRegistration[];
  }
  async getRegistration(): Promise<ServiceWorkerRegistration | undefined> {
    return this.registrations.find(item => item.active === this.controller) as ServiceWorkerRegistration | undefined;
  }
}

function testWindow(container: TestServiceWorkerContainer | undefined, href = "https://app.example/workbench") {
  const replacements: string[] = [];
  let reloads = 0;
  const target = {
    navigator: container === undefined ? {} : { serviceWorker: container },
    history: { state: null, replaceState(_state: unknown, _title: string, url: URL) { target.location.href = url.href; } },
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
    container.controller = { scriptURL: "https://app.example/legacy-sw.js" };
    let unregistered = 0;
    container.registrations.push(
      { scope: "https://app.example/", active: container.controller, unregister: async () => { unregistered++; return true; } },
      { scope: "https://app.example/mail/", active: { scriptURL: "https://app.example/mail/sw.js" }, unregister: async () => { throw new Error("unrelated registration"); } },
    );
    const { target, replacements } = testWindow(container);
    const contexts: string[] = [];
    const guard = createServiceWorkerControllerGuard({
      targetWindow: target,
      navigationWindow: target,
      registration: { scope: "/", scriptUrl: "/proxy-sw.js" },
      expectedScriptPathSuffix: "/proxy-sw.js",
      repair: { controllerTimeoutMs: 1, queryKey: "repair", maxAttempts: 2 },
      conflicts: { keepScriptPathSuffixes: ["/keep-sw.js"] },
      onControllerMismatch(context) { contexts.push(`${context.stage}:${context.actualScriptURL}`); },
    });

    await expect(guard.ensure()).rejects.toThrow("navigation started");
    expect(contexts).toEqual(["ensure:https://app.example/legacy-sw.js"]);
    expect(unregistered).toBe(1);
    expect(replacements[0]).toContain("repair=1");
    guard.dispose();
  });

  it("persists a reload attempt across guard instances and clears it after recovery", async () => {
    const container = new TestServiceWorkerContainer();
    const { target, reloads } = testWindow(container);
    const options = { targetWindow: target, expectedScriptPathSuffix: "/sw.js", repair: { strategy: "reload", maxAttempts: 1, controllerTimeoutMs: 1 } } as const;
    const first = createServiceWorkerControllerGuard(options);
    await expect(first.ensure()).rejects.toThrow("navigation started");
    first.dispose();
    const second = createServiceWorkerControllerGuard(options);
    await expect(second.ensure()).rejects.toThrow("mismatch persists");
    expect(reloads()).toBe(1);
    container.controller = { scriptURL: "https://app.example/sw.js" };
    await second.ensure();
    expect(target.location.href).not.toContain("_flowersec_sw_repair");
    second.dispose();
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

  it("bounds registration and activation before a worker is ready", async () => {
    const container = new TestServiceWorkerContainer();
    setGlobal("navigator", { serviceWorker: container });
    setGlobal("location", { href: "https://app.example/workbench" });
    Object.defineProperty(container, "ready", { value: new Promise(() => {}) });
    const attempt = () => registerServiceWorkerAndEnsureControl({ scriptUrl: "/sw.js", controllerTimeoutMs: 5, maxRepairAttempts: 0 });
    await expect(attempt()).rejects.toThrow("did not take control");
    container.register = () => new Promise(() => {});
    await expect(attempt()).rejects.toThrow("did not take control");
  });

  it("bounds registration policy and repairs only within the configured attempt limit", async () => {
    const container = new TestServiceWorkerContainer();
    const replacements: string[] = [];
    container.controller = { scriptURL: "https://app.example/old-sw.js" };
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

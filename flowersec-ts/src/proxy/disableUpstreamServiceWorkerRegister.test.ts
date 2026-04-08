import { afterEach, describe, expect, test, vi } from "vitest";

import { disableUpstreamServiceWorkerRegister } from "./disableUpstreamServiceWorkerRegister.js";

afterEach(() => {
  delete (globalThis as { navigator?: unknown }).navigator;
});

describe("disableUpstreamServiceWorkerRegister", () => {
  test("blocks subsequent upstream register calls", () => {
    const originalRegister = vi.fn();
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {
        serviceWorker: {
          register: originalRegister,
        },
      },
    });

    disableUpstreamServiceWorkerRegister();

    expect(() => (globalThis as { navigator: { serviceWorker: { register: () => void } } }).navigator.serviceWorker.register()).toThrow(
      "service worker register is disabled by flowersec-proxy runtime"
    );
    expect(originalRegister).not.toHaveBeenCalled();
  });

  test("tolerates missing or non-writable register implementations", () => {
    const readonlyRegister = vi.fn();
    const serviceWorker = {};
    Object.defineProperty(serviceWorker, "register", {
      configurable: true,
      enumerable: true,
      value: readonlyRegister,
      writable: false,
    });
    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: { serviceWorker },
    });

    expect(() => disableUpstreamServiceWorkerRegister()).not.toThrow();
    expect((serviceWorker as { register: unknown }).register).toBe(readonlyRegister);

    Object.defineProperty(globalThis, "navigator", {
      configurable: true,
      value: {},
    });
    expect(() => disableUpstreamServiceWorkerRegister()).not.toThrow();
  });
});

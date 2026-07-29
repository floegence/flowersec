export function disableUpstreamServiceWorkerRegister(): Readonly<{ restore(): void }> {
  const serviceWorker = globalThis.navigator?.serviceWorker;
  if (serviceWorker === undefined || typeof serviceWorker.register !== "function") return Object.freeze({ restore: () => undefined });
  const original = serviceWorker.register.bind(serviceWorker);
  const replacement = async (): Promise<ServiceWorkerRegistration> => {
    throw new Error("upstream service worker registration is disabled by the Flowersec proxy runtime");
  };
  try {
    Object.defineProperty(serviceWorker, "register", { configurable: true, value: replacement });
  } catch {
    return Object.freeze({ restore: () => undefined });
  }
  return Object.freeze({
    restore: () => {
      try {
        Object.defineProperty(serviceWorker, "register", { configurable: true, value: original });
      } catch {
        // Best effort restoration during page teardown.
      }
    },
  });
}

// disableUpstreamServiceWorkerRegister blocks upstream apps from registering their own Service Worker.
//
// This is required for runtime-mode proxying where a proxy SW must control the app scope.
export function disableUpstreamServiceWorkerRegister(): void {
  try {
    const sw = (globalThis as any).navigator?.serviceWorker;
    if (!sw || typeof sw.register !== "function") return;

    const blocked = () => {
      throw new Error("service worker register is disabled by flowersec-proxy runtime");
    };
    // Best-effort. Some environments may not allow overriding the property.
    try {
      sw.register = blocked;
    } catch {
      // Ignore.
    }
  } catch {
    // Ignore.
  }
}


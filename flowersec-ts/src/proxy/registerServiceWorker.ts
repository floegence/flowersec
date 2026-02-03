export type RegisterServiceWorkerOptions = Readonly<{
  scriptUrl: string;
  scope?: string;
  // Optional query key to trigger a "soft navigation" repair when a hard reload causes
  // the current page load to be uncontrolled by the installed Service Worker.
  repairQueryKey?: string;
  maxRepairAttempts?: number;
  controllerTimeoutMs?: number;
}>;

function parseRepairAttemptFromHref(href: string, queryKey: string): number {
  try {
    const u = new URL(href);
    const raw = String(u.searchParams.get(queryKey) ?? "").trim();
    const n = raw ? Number(raw) : 0;
    if (!Number.isFinite(n) || n < 0) return 0;
    return Math.min(9, Math.floor(n));
  } catch {
    return 0;
  }
}

function buildHrefWithRepairAttempt(href: string, queryKey: string, attempt: number): string {
  const u = new URL(href);
  u.searchParams.set(queryKey, String(Math.max(0, Math.floor(attempt))));
  return u.toString();
}

function buildHrefWithoutRepairQueryParam(href: string, queryKey: string): string {
  const u = new URL(href);
  u.searchParams.delete(queryKey);
  const search = u.searchParams.toString();
  return u.pathname + (search ? `?${search}` : "") + u.hash;
}

function waitForController(timeoutMs: number): Promise<boolean> {
  if (navigator.serviceWorker.controller) return Promise.resolve(true);
  const ms = Math.max(0, Math.floor(timeoutMs));

  return new Promise((resolve) => {
    let done = false;
    let t: number | null = null;

    function finish(ok: boolean) {
      if (done) return;
      done = true;
      if (t != null) window.clearTimeout(t);
      navigator.serviceWorker.removeEventListener("controllerchange", onChange);
      resolve(ok);
    }

    function onChange() {
      finish(true);
    }

    navigator.serviceWorker.addEventListener("controllerchange", onChange);

    // Avoid race: controller can become available before/after the listener registration.
    if (navigator.serviceWorker.controller) {
      finish(true);
      return;
    }

    if (ms > 0) {
      t = window.setTimeout(() => finish(Boolean(navigator.serviceWorker.controller)), ms);
    }
  });
}

// registerServiceWorkerAndEnsureControl registers a Service Worker and ensures the current page load is controlled.
//
// In DevTools hard reload flows, the SW may be installed but not control the current page load.
// When this happens, we perform a limited "soft navigation" repair to recover control.
export async function registerServiceWorkerAndEnsureControl(opts: RegisterServiceWorkerOptions): Promise<void> {
  const scriptUrl = String(opts.scriptUrl ?? "").trim();
  if (!scriptUrl) throw new Error("scriptUrl is required");

  if (globalThis.navigator?.serviceWorker == null) {
    throw new Error("service worker is not available in this environment");
  }

  const scope = String(opts.scope ?? "/").trim() || "/";
  const queryKey = String(opts.repairQueryKey ?? "_flowersec_sw_repair").trim() || "_flowersec_sw_repair";
  const maxRepairAttempts = Math.max(0, Math.floor(opts.maxRepairAttempts ?? 2));
  const controllerTimeoutMs = Math.max(0, Math.floor(opts.controllerTimeoutMs ?? 2_000));

  await navigator.serviceWorker.register(scriptUrl, { scope });
  await navigator.serviceWorker.ready;

  const attempt = parseRepairAttemptFromHref(window.location.href, queryKey);
  if (navigator.serviceWorker.controller) {
    if (attempt > 0) {
      try {
        const next = buildHrefWithoutRepairQueryParam(window.location.href, queryKey);
        history.replaceState(null, document.title, next);
      } catch {
        // ignore
      }
    }
    return;
  }

  const controlled = await waitForController(controllerTimeoutMs);
  if (controlled) {
    if (attempt > 0) {
      try {
        const next = buildHrefWithoutRepairQueryParam(window.location.href, queryKey);
        history.replaceState(null, document.title, next);
      } catch {
        // ignore
      }
    }
    return;
  }

  if (attempt < maxRepairAttempts) {
    try {
      const next = buildHrefWithRepairAttempt(window.location.href, queryKey, attempt + 1);
      window.location.replace(next);
    } catch {
      window.location.reload();
    }
    // Navigation will interrupt JS; keep pending so callers don't proceed with dependent work.
    await new Promise(() => {});
  }

  throw new Error("Service Worker is installed but not controlling this page");
}

// Test-only exports (not re-exported from the public proxy entrypoint).
export const __testOnly = {
  parseRepairAttemptFromHref,
  buildHrefWithRepairAttempt,
  buildHrefWithoutRepairQueryParam,
};


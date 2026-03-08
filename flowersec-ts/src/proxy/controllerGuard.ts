export type ServiceWorkerControllerGuardMonitorOptions = Readonly<{
  enabled?: boolean;
  throttleMs?: number;
}>;

export type ServiceWorkerControllerGuardRepairOptions = Readonly<{
  queryKey?: string;
  maxAttempts?: number;
  controllerTimeoutMs?: number;
  strategy?: "replace" | "reload";
}>;

export type ServiceWorkerControllerGuardConflictPolicy = Readonly<{
  keepScriptPathSuffixes?: readonly string[];
  uninstallOnMismatch?: boolean;
}>;

export type ServiceWorkerControllerGuardMismatchContext = Readonly<{
  expectedScriptPathSuffix: string;
  actualScriptURL: string;
  stage: "ensure" | "monitor";
}>;

export type ServiceWorkerControllerGuardOptions = Readonly<{
  targetWindow?: Window;
  navigationWindow?: Window;
  expectedScriptPathSuffix: string;
  repair?: ServiceWorkerControllerGuardRepairOptions;
  monitor?: ServiceWorkerControllerGuardMonitorOptions;
  conflicts?: ServiceWorkerControllerGuardConflictPolicy;
  onControllerMismatch?: (ctx: ServiceWorkerControllerGuardMismatchContext) => "repair" | "ignore" | void;
}>;

export type ServiceWorkerControllerGuardHandle = Readonly<{
  ensure: () => Promise<void>;
  dispose: () => void;
}>;

type ServiceWorkerLike = Readonly<{
  scriptURL?: string | null;
}>;

type ServiceWorkerRegistrationLike = Readonly<{
  active?: ServiceWorkerLike | null;
  waiting?: ServiceWorkerLike | null;
  installing?: ServiceWorkerLike | null;
  unregister?: () => Promise<boolean | void>;
}>;

type ServiceWorkerContainerLike = Readonly<{
  controller?: ServiceWorkerLike | null;
  addEventListener?: (type: string, listener: () => void) => void;
  removeEventListener?: (type: string, listener: () => void) => void;
  getRegistrations?: () => Promise<readonly ServiceWorkerRegistrationLike[]>;
}>;

type ControllerWindowLike = Readonly<{
  location: {
    href: string;
    replace: (href: string) => void;
    reload: () => void;
  };
  navigator?: {
    serviceWorker?: ServiceWorkerContainerLike;
  };
  setTimeout: typeof globalThis.setTimeout;
  clearTimeout: typeof globalThis.clearTimeout;
}>;

function dedupeStrings(values: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = String(value ?? "").trim();
    if (normalized === "" || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  return out;
}

function resolveWindow(raw: Window | undefined, label: string): ControllerWindowLike {
  const candidate = (raw ?? globalThis.window) as Window | undefined;
  if (candidate == null) {
    throw new Error(`${label} is not available in this environment`);
  }
  return candidate as unknown as ControllerWindowLike;
}

function getServiceWorker(targetWindow: ControllerWindowLike): ServiceWorkerContainerLike | null {
  return targetWindow.navigator?.serviceWorker ?? null;
}

function parseRepairAttemptFromHref(href: string, queryKey: string): number {
  try {
    const url = new URL(href);
    const raw = String(url.searchParams.get(queryKey) ?? "").trim();
    const n = raw === "" ? 0 : Number(raw);
    if (!Number.isFinite(n) || n < 0) return 0;
    return Math.min(9, Math.floor(n));
  } catch {
    return 0;
  }
}

function buildHrefWithRepairAttempt(href: string, queryKey: string, attempt: number): string {
  const url = new URL(href);
  url.searchParams.set(queryKey, String(Math.max(0, Math.floor(attempt))));
  return url.toString();
}

function isServiceWorkerScriptPathSuffix(raw: string, suffix: string): boolean {
  const script = String(raw ?? "").trim();
  const wanted = String(suffix ?? "").trim();
  if (script === "" || wanted === "") return false;
  try {
    return new URL(script).pathname.endsWith(wanted);
  } catch {
    return script.endsWith(wanted);
  }
}

async function waitForControllerSuffix(targetWindow: ControllerWindowLike, suffix: string, timeoutMs: number): Promise<boolean> {
  const sw = getServiceWorker(targetWindow);
  if (sw == null) return false;

  const isMatch = () => isServiceWorkerScriptPathSuffix(String(sw.controller?.scriptURL ?? ""), suffix);
  if (isMatch()) return true;

  const ms = Math.max(0, Math.floor(timeoutMs));
  return await new Promise<boolean>((resolve) => {
    let done = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      if (timer != null) targetWindow.clearTimeout(timer);
      sw.removeEventListener?.("controllerchange", onChange);
      resolve(ok);
    };

    const onChange = () => {
      if (isMatch()) finish(true);
    };

    sw.addEventListener?.("controllerchange", onChange);
    if (isMatch()) {
      finish(true);
      return;
    }

    if (ms > 0) {
      timer = targetWindow.setTimeout(() => finish(isMatch()), ms);
    } else {
      finish(isMatch());
    }
  });
}

async function uninstallConflictingServiceWorkers(
  targetWindow: ControllerWindowLike,
  conflicts: ServiceWorkerControllerGuardConflictPolicy | undefined
): Promise<void> {
  if (conflicts?.uninstallOnMismatch === false) return;

  const sw = getServiceWorker(targetWindow);
  if (sw == null || typeof sw.getRegistrations !== "function") return;

  const keepSuffixes = dedupeStrings(conflicts?.keepScriptPathSuffixes ?? []);
  const regs = await sw.getRegistrations();
  for (const reg of regs) {
    const script = String(reg?.active?.scriptURL ?? reg?.waiting?.scriptURL ?? reg?.installing?.scriptURL ?? "").trim();
    if (script === "") continue;

    let shouldKeep = false;
    for (const suffix of keepSuffixes) {
      if (isServiceWorkerScriptPathSuffix(script, suffix)) {
        shouldKeep = true;
        break;
      }
    }
    if (shouldKeep) continue;

    try {
      await reg.unregister?.();
    } catch {
      // Best effort cleanup.
    }
  }
}

function triggerRepairNavigation(
  navigationWindow: ControllerWindowLike,
  repair: ServiceWorkerControllerGuardRepairOptions | undefined
): boolean {
  const queryKey = String(repair?.queryKey ?? "_flowersec_sw_repair").trim() || "_flowersec_sw_repair";
  const maxAttempts = Math.max(0, Math.floor(repair?.maxAttempts ?? 2));
  const strategy = repair?.strategy ?? "replace";

  const attempt = parseRepairAttemptFromHref(navigationWindow.location.href, queryKey);
  if (attempt >= maxAttempts) return false;

  if (strategy === "reload") {
    navigationWindow.location.reload();
    return true;
  }

  const next = buildHrefWithRepairAttempt(navigationWindow.location.href, queryKey, attempt + 1);
  navigationWindow.location.replace(next);
  return true;
}

export function createServiceWorkerControllerGuard(
  opts: ServiceWorkerControllerGuardOptions
): ServiceWorkerControllerGuardHandle {
  const targetWindow = resolveWindow(opts.targetWindow, "targetWindow");
  const navigationWindow = resolveWindow(opts.navigationWindow ?? opts.targetWindow, "navigationWindow");
  const expectedScriptPathSuffix = String(opts.expectedScriptPathSuffix ?? "").trim();
  if (expectedScriptPathSuffix === "") {
    throw new Error("expectedScriptPathSuffix must be non-empty");
  }

  const controllerTimeoutMs = Math.max(0, Math.floor(opts.repair?.controllerTimeoutMs ?? 8_000));
  const monitorEnabled = opts.monitor?.enabled ?? true;
  const monitorThrottleMs = Math.max(0, Math.floor(opts.monitor?.throttleMs ?? 10_000));

  let disposed = false;
  let monitorHandler: (() => void) | null = null;
  let lastMonitorRepairAt = 0;

  const handleMismatch = async (stage: "ensure" | "monitor"): Promise<"ignored" | "repaired" | "skipped"> => {
    const actualScriptURL = String(getServiceWorker(targetWindow)?.controller?.scriptURL ?? "").trim();
    const ctx: ServiceWorkerControllerGuardMismatchContext = {
      expectedScriptPathSuffix,
      actualScriptURL,
      stage,
    };

    const action = opts.onControllerMismatch?.(ctx);
    if (action === "ignore") return "ignored";

    await uninstallConflictingServiceWorkers(targetWindow, opts.conflicts);
    return triggerRepairNavigation(navigationWindow, opts.repair) ? "repaired" : "skipped";
  };

  const attachMonitor = () => {
    if (!monitorEnabled || monitorHandler != null) return;
    const currentSW = getServiceWorker(targetWindow);
    if (currentSW == null) return;

    monitorHandler = () => {
      const actualScriptURL = String(currentSW.controller?.scriptURL ?? "").trim();
      if (isServiceWorkerScriptPathSuffix(actualScriptURL, expectedScriptPathSuffix)) return;

      const now = Date.now();
      if (monitorThrottleMs > 0 && now - lastMonitorRepairAt <= monitorThrottleMs) return;
      lastMonitorRepairAt = now;

      void handleMismatch("monitor");
    };
    currentSW.addEventListener?.("controllerchange", monitorHandler);
  };

  return {
    ensure: async () => {
      if (disposed) throw new Error("controller guard is already disposed");
      if (getServiceWorker(targetWindow) == null) {
        throw new Error("service worker is not available in the target window");
      }
      const ok = await waitForControllerSuffix(targetWindow, expectedScriptPathSuffix, controllerTimeoutMs);
      if (!ok) {
        const outcome = await handleMismatch("ensure");
        if (outcome !== "ignored") {
          throw new Error("Proxy Service Worker is installed but not controlling the target window");
        }
        return;
      }
      attachMonitor();
    },
    dispose: () => {
      if (disposed) return;
      disposed = true;
      if (monitorHandler != null) {
        getServiceWorker(targetWindow)?.removeEventListener?.("controllerchange", monitorHandler);
      }
      monitorHandler = null;
    },
  };
}

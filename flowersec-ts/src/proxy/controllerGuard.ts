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
  onControllerMismatch?: (context: ServiceWorkerControllerGuardMismatchContext) => "repair" | "ignore" | void;
}>;

export type ServiceWorkerControllerGuardHandle = Readonly<{
  ensure(): Promise<void>;
  dispose(): void;
}>;

function serviceWorkerContainer(target: Window): ServiceWorkerContainer | undefined {
  try {
    return target.navigator?.serviceWorker;
  } catch {
    return undefined;
  }
}
function scriptMatches(scriptURL: string | undefined, suffix: string): boolean {
  if (scriptURL === undefined || scriptURL === "") return false;
  try {
    return new URL(scriptURL).pathname.endsWith(suffix);
  } catch {
    return scriptURL.endsWith(suffix);
  }
}

async function removeConflicts(
  container: ServiceWorkerContainer,
  expected: string,
  policy: ServiceWorkerControllerGuardConflictPolicy | undefined,
): Promise<void> {
  if (policy?.uninstallOnMismatch === false || typeof container.getRegistrations !== "function") return;
  const keep = [expected, ...(policy?.keepScriptPathSuffixes ?? [])];
  for (const registration of await container.getRegistrations()) {
    const script = registration.active?.scriptURL ?? registration.waiting?.scriptURL ?? registration.installing?.scriptURL;
    if (script !== undefined && !keep.some((suffix) => scriptMatches(script, suffix))) {
      await registration.unregister().catch(() => false);
    }
  }
}

function repair(target: Window, options: ServiceWorkerControllerGuardRepairOptions | undefined): never {
  const key = options?.queryKey?.trim() || "_flowersec_sw_repair";
  const maxAttempts = options?.maxAttempts ?? 2;
  let url: URL;
  try {
    url = new URL(target.location.href);
  } catch {
    throw new Error("service worker controller repair URL is unavailable");
  }
  const current = Number(url.searchParams.get(key) ?? "0");
  const attempt = Number.isSafeInteger(current) && current >= 0 ? current : 0;
  if (attempt >= maxAttempts) throw new Error("service worker controller mismatch persists");
  if (options?.strategy === "reload") {
    target.location.reload();
  } else {
    url.searchParams.set(key, String(attempt + 1));
    target.location.replace(url.toString());
  }
  throw new Error("service worker controller repair navigation started");
}

export function createServiceWorkerControllerGuard(options: ServiceWorkerControllerGuardOptions): ServiceWorkerControllerGuardHandle {
  const target = options.targetWindow ?? globalThis.window;
  const navigation = options.navigationWindow ?? target;
  const expected = options.expectedScriptPathSuffix.trim();
  if (expected === "") throw new TypeError("expected service worker script suffix is required");
  const container = serviceWorkerContainer(target);
  let disposed = false;
  let lastRepairAt = 0;

  const handleMismatch = async (stage: "ensure" | "monitor") => {
    if (disposed || container === undefined) throw new Error("service worker controller is unavailable");
    const actual = container.controller?.scriptURL ?? "";
    const context = { expectedScriptPathSuffix: expected, actualScriptURL: actual, stage } as const;
    if (options.onControllerMismatch?.(context) === "ignore") return;
    await removeConflicts(container, expected, options.conflicts);
    repair(navigation, options.repair);
  };

  const onControllerChange = () => {
    if (disposed || options.monitor?.enabled === false || scriptMatches(container?.controller?.scriptURL, expected)) return;
    const now = Date.now();
    const throttle = options.monitor?.throttleMs ?? 10_000;
    if (now - lastRepairAt < throttle) return;
    lastRepairAt = now;
    void handleMismatch("monitor").catch(() => undefined);
  };
  container?.addEventListener("controllerchange", onControllerChange);

  return Object.freeze({
    ensure: async () => {
      if (disposed) throw new Error("service worker controller guard is disposed");
      if (container === undefined) throw new Error("service worker controller is unavailable");
      if (scriptMatches(container.controller?.scriptURL, expected)) return;
      const timeoutMs = options.repair?.controllerTimeoutMs ?? 8_000;
      const matched = await new Promise<boolean>((resolve) => {
        const onChange = () => {
          if (!scriptMatches(container.controller?.scriptURL, expected)) return;
          cleanup();
          resolve(true);
        };
        const cleanup = () => {
          clearTimeout(timer);
          container.removeEventListener("controllerchange", onChange);
        };
        container.addEventListener("controllerchange", onChange);
        const timer = setTimeout(() => { cleanup(); resolve(scriptMatches(container.controller?.scriptURL, expected)); }, timeoutMs);
      });
      if (!matched) await handleMismatch("ensure");
    },
    dispose: () => {
      if (disposed) return;
      disposed = true;
      container?.removeEventListener("controllerchange", onControllerChange);
    },
  });
}

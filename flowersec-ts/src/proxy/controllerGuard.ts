import { matchesServiceWorkerRegistration } from "./registerServiceWorker.js";

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
  registration?: Readonly<{ scriptUrl: string; scope: string }>;
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

function nextRepairURL(target: Window, options: ServiceWorkerControllerGuardRepairOptions | undefined): URL {
  const key = options?.queryKey?.trim() || "_flowersec_sw_repair";
  const maxAttempts = options?.maxAttempts ?? 2;
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 0 || maxAttempts > 5) throw new TypeError("invalid service worker repair limit");
  let url: URL;
  try {
    url = new URL(target.location.href);
  } catch {
    throw new Error("service worker controller repair URL is unavailable");
  }
  const current = Number(url.searchParams.get(key) ?? "0");
  const attempt = Number.isSafeInteger(current) && current >= 0 ? current : 0;
  if (attempt >= maxAttempts) throw new Error("service worker controller mismatch persists");
  url.searchParams.set(key, String(attempt + 1));
  return url;
}

export function createServiceWorkerControllerGuard(options: ServiceWorkerControllerGuardOptions): ServiceWorkerControllerGuardHandle {
  const target = options.targetWindow ?? globalThis.window;
  const navigation = options.navigationWindow ?? target;
  const expected = options.expectedScriptPathSuffix.trim();
  if (expected === "") throw new TypeError("expected service worker script suffix is required");
  const container = serviceWorkerContainer(target);
  let disposed = false;
  let lastRepairAt = 0;
  let pendingRepair: Promise<void> | undefined;
  let navigating = false;
  const grant = options.registration && {
    scope: new URL(options.registration.scope, target.location.href).href,
    scriptUrl: new URL(options.registration.scriptUrl, target.location.href).href,
  };
  const matches = async () => {
    if (!grant || !container) return scriptMatches(container?.controller?.scriptURL, expected);
    const current = await container.getRegistration(target.location.href);
    return matchesServiceWorkerRegistration(current, container.controller, grant, target.location.href);
  };
  const clearAttempt = () => {
    if (disposed || navigating) return;
    const url = new URL(navigation.location.href);
    const key = options.repair?.queryKey?.trim() || "_flowersec_sw_repair";
    if (url.searchParams.has(key)) {
      url.searchParams.delete(key);
      navigation.history.replaceState(navigation.history.state, "", url);
    }
  };

  const handleMismatch = async (stage: "ensure" | "monitor") => {
    if (disposed || container === undefined) throw new Error("service worker controller is unavailable");
    const actual = container.controller?.scriptURL ?? "";
    const context = { expectedScriptPathSuffix: expected, actualScriptURL: actual, stage } as const;
    if (options.onControllerMismatch?.(context) === "ignore") return;
    if (navigating) throw new Error("service worker controller repair navigation started");
    const destination = nextRepairURL(navigation, options.repair);
    if (grant && options.conflicts?.uninstallOnMismatch !== false) {
      const current = await container.getRegistration(target.location.href);
      if (disposed) return;
      if (matchesServiceWorkerRegistration(current, container.controller, grant, target.location.href)) { clearAttempt(); return; }
      if (current?.scope === grant.scope && current.active && current.active === container.controller &&
          !current.waiting && !current.installing && !options.conflicts?.keepScriptPathSuffixes?.some(suffix => scriptMatches(current.active?.scriptURL, suffix))) {
        await current.unregister();
      }
    }
    if (disposed) return;
    if (options.repair?.strategy === "reload") {
      navigation.history.replaceState(navigation.history.state, "", destination);
      navigation.location.reload();
    } else navigation.location.replace(destination.href);
    navigating = true;
    throw new Error("service worker controller repair navigation started");
  };
  const repair = (stage: "ensure" | "monitor") => pendingRepair ??= handleMismatch(stage).finally(() => { pendingRepair = undefined; });

  const onControllerChange = () => {
    if (disposed || options.monitor?.enabled === false) return;
    void matches().then(async ok => {
      if (ok) { clearAttempt(); return; }
      const now = Date.now();
      if (now - lastRepairAt < (options.monitor?.throttleMs ?? 10_000)) return;
      lastRepairAt = now;
      await repair("monitor");
    }).catch(() => undefined);
  };
  container?.addEventListener("controllerchange", onControllerChange);

  return Object.freeze({
    ensure: async () => {
      if (disposed) throw new Error("service worker controller guard is disposed");
      if (container === undefined) throw new Error("service worker controller is unavailable");
      if (await matches()) { clearAttempt(); return; }
      const timeoutMs = options.repair?.controllerTimeoutMs ?? 8_000;
      const matched = await new Promise<boolean>((resolve) => {
        const onChange = () => {
          void matches().then(ok => { if (ok) { cleanup(); resolve(true); } }).catch(() => undefined);
        };
        const cleanup = () => {
          clearTimeout(timer);
          container.removeEventListener("controllerchange", onChange);
        };
        container.addEventListener("controllerchange", onChange);
        const timer = setTimeout(() => { cleanup(); resolve(false); }, timeoutMs);
      });
      if (matched || await matches()) clearAttempt();
      else await repair("ensure");
    },
    dispose: () => {
      if (disposed) return;
      disposed = true;
      container?.removeEventListener("controllerchange", onControllerChange);
    },
  });
}

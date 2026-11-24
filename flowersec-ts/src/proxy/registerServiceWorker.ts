export type RegisterServiceWorkerOptions = Readonly<{
  scriptUrl: string;
  scope?: string;
  repairQueryKey?: string;
  maxRepairAttempts?: number;
  controllerTimeoutMs?: number;
}>;

function currentAttempt(key: string): number {
  try {
    const value = Number(new URL(globalThis.location.href).searchParams.get(key) ?? "0");
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
  } catch {
    return 0;
  }
}
function repairNavigation(key: string, attempt: number): never {
  const target = new URL(globalThis.location.href);
  target.searchParams.set(key, String(attempt));
  globalThis.location.replace(target.toString());
  throw new Error("service worker controller navigation started");
}

export function matchesServiceWorkerRegistration(
  registration: ServiceWorkerRegistration | undefined,
  controller: ServiceWorker | null,
  expected: Readonly<{ scriptUrl: string; scope: string }>,
): boolean {
  return controller !== null && registration?.active === controller &&
    controller.scriptURL === new URL(expected.scriptUrl, globalThis.location.href).href &&
    registration.scope === new URL(expected.scope, globalThis.location.href).href;
}

export async function registerServiceWorkerAndEnsureControl(options: RegisterServiceWorkerOptions): Promise<void> {
  const serviceWorker = globalThis.navigator?.serviceWorker;
  if (serviceWorker === undefined) throw new Error("service workers are unavailable");
  const scriptUrl = options.scriptUrl.trim();
  const scope = options.scope?.trim() || "/";
  if (scriptUrl === "" || scope === "") throw new TypeError("service worker script and scope are required");
  const timeoutMs = options.controllerTimeoutMs ?? 8_000;
  const maxAttempts = options.maxRepairAttempts ?? 2;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60_000 || !Number.isSafeInteger(maxAttempts) || maxAttempts < 0 || maxAttempts > 5) {
    throw new TypeError("invalid service worker control policy");
  }
  const registration = await serviceWorker.register(scriptUrl, { scope });
  await serviceWorker.ready;
  const matches = () => matchesServiceWorkerRegistration(registration, serviceWorker.controller, { scriptUrl, scope });
  if (matches()) return;

  const controlled = await new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      serviceWorker.removeEventListener("controllerchange", onChange);
      resolve(value);
    };
    const onChange = () => { if (matches()) finish(true); };
    serviceWorker.addEventListener("controllerchange", onChange);
    const timer = setTimeout(() => finish(matches()), timeoutMs);
  });
  if (controlled) return;

  const key = options.repairQueryKey?.trim() || "_flowersec_sw_repair";
  const attempt = currentAttempt(key);
  if (attempt >= maxAttempts) throw new Error("service worker did not take control");
  repairNavigation(key, attempt + 1);
}

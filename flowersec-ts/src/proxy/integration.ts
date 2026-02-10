import type { Client } from "../client.js";

import { resolveProxyProfile, type ProxyProfile, type ProxyProfileName } from "./profiles.js";
import { registerServiceWorkerAndEnsureControl } from "./registerServiceWorker.js";
import { createProxyRuntime, type ProxyRuntime } from "./runtime.js";
import { createProxyServiceWorkerScript, type ProxyServiceWorkerScriptOptions } from "./serviceWorker.js";

export type ProxyIntegrationMonitorOptions = Readonly<{
  enabled?: boolean;
  throttleMs?: number;
}>;

export type ProxyIntegrationRepairOptions = Readonly<{
  queryKey?: string;
  maxAttempts?: number;
  controllerTimeoutMs?: number;
  strategy?: "replace" | "reload";
}>;

export type ProxyServiceWorkerConflictPolicy = Readonly<{
  keepScriptPathSuffixes?: readonly string[];
  uninstallOnMismatch?: boolean;
}>;

export type ProxyIntegrationServiceWorkerOptions = Readonly<{
  scriptUrl: string;
  scope?: string;
  expectedScriptPathSuffix?: string;
  repair?: ProxyIntegrationRepairOptions;
  monitor?: ProxyIntegrationMonitorOptions;
  conflicts?: ProxyServiceWorkerConflictPolicy;
}>;

export type RegisterProxyIntegrationOptions = Readonly<{
  client: Client;
  profile?: ProxyProfileName | Partial<ProxyProfile>;
  runtime?: Readonly<{
    maxJsonFrameBytes?: number;
    maxChunkBytes?: number;
    maxBodyBytes?: number;
    maxWsFrameBytes?: number;
    timeoutMs?: number;
  }>;
  serviceWorker: ProxyIntegrationServiceWorkerOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

export type ProxyIntegrationContext = Readonly<{
  runtime: ProxyRuntime;
  options: RegisterProxyIntegrationOptions;
  profile: ProxyProfile;
}>;

export type ControllerMismatchContext = Readonly<{
  expectedScriptPathSuffix: string;
  actualScriptURL: string;
  stage: "register" | "monitor";
}>;

export type ProxyIntegrationPlugin = Readonly<{
  name: string;
  mutateOptions?: (opts: RegisterProxyIntegrationOptions) => RegisterProxyIntegrationOptions;
  extendServiceWorkerScriptOptions?: (opts: ProxyServiceWorkerScriptOptions) => ProxyServiceWorkerScriptOptions;
  serviceWorkerConflictPolicy?: ProxyServiceWorkerConflictPolicy;
  forwardFetchMessageTypes?: readonly string[];
  onRegistered?: (ctx: ProxyIntegrationContext) => void | Promise<void>;
  onControllerMismatch?: (ctx: ControllerMismatchContext) => "repair" | "ignore" | void;
  onDisposed?: () => void | Promise<void>;
}>;

export type ProxyIntegrationHandle = Readonly<{
  runtime: ProxyRuntime;
  dispose: () => Promise<void>;
}>;

export type CreateProxyIntegrationServiceWorkerScriptOptions = Readonly<{
  baseOptions?: ProxyServiceWorkerScriptOptions;
  plugins?: readonly ProxyIntegrationPlugin[];
}>;

function dedupeStrings(values: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of values) {
    const n = String(v ?? "").trim();
    if (n === "" || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
  }
  return out;
}

function parseRepairAttemptFromHref(href: string, queryKey: string): number {
  try {
    const u = new URL(href);
    const raw = String(u.searchParams.get(queryKey) ?? "").trim();
    const n = raw === "" ? 0 : Number(raw);
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

function isServiceWorkerScriptPathSuffix(raw: string, suffix: string): boolean {
  const script = String(raw ?? "").trim();
  if (script === "") return false;
  const wanted = String(suffix ?? "").trim();
  if (wanted === "") return false;
  try {
    const u = new URL(script);
    return u.pathname.endsWith(wanted);
  } catch {
    return script.endsWith(wanted);
  }
}

async function waitForControllerSuffix(suffix: string, timeoutMs: number): Promise<boolean> {
  const sw = globalThis.navigator?.serviceWorker;
  if (!sw) return false;

  const isMatch = () => isServiceWorkerScriptPathSuffix(String(sw.controller?.scriptURL ?? ""), suffix);
  if (isMatch()) return true;

  const ms = Math.max(0, Math.floor(timeoutMs));
  return await new Promise<boolean>((resolve) => {
    let done = false;
    let timer: number | null = null;

    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      if (timer != null) window.clearTimeout(timer);
      sw.removeEventListener("controllerchange", onChange);
      resolve(ok);
    };

    const onChange = () => {
      if (isMatch()) finish(true);
    };

    sw.addEventListener("controllerchange", onChange);
    if (isMatch()) {
      finish(true);
      return;
    }

    if (ms > 0) timer = window.setTimeout(() => finish(isMatch()), ms);
  });
}

async function uninstallConflictingServiceWorkers(conflicts: ProxyServiceWorkerConflictPolicy | undefined): Promise<void> {
  if (conflicts?.uninstallOnMismatch === false) return;
  const sw = globalThis.navigator?.serviceWorker;
  if (!sw || typeof sw.getRegistrations !== "function") return;

  const keep = dedupeStrings(conflicts?.keepScriptPathSuffixes ?? []);
  const regs = await sw.getRegistrations();
  for (const reg of regs) {
    const script = String(reg?.active?.scriptURL ?? reg?.waiting?.scriptURL ?? reg?.installing?.scriptURL ?? "").trim();
    if (script === "") continue;

    let shouldKeep = false;
    for (const suffix of keep) {
      if (isServiceWorkerScriptPathSuffix(script, suffix)) {
        shouldKeep = true;
        break;
      }
    }
    if (shouldKeep) continue;

    try {
      await reg.unregister();
    } catch {
      // Best effort cleanup.
    }
  }
}

async function maybeRepairNavigation(opts: {
  queryKey: string;
  maxAttempts: number;
  strategy: "replace" | "reload";
}): Promise<void> {
  const attempt = parseRepairAttemptFromHref(window.location.href, opts.queryKey);
  if (attempt >= opts.maxAttempts) return;

  if (opts.strategy === "reload") {
    window.location.reload();
    await new Promise(() => {
      // keep pending on navigation
    });
    return;
  }

  const next = buildHrefWithRepairAttempt(window.location.href, opts.queryKey, attempt + 1);
  window.location.replace(next);
  await new Promise(() => {
    // keep pending on navigation
  });
}

function applyPluginMutations(opts: RegisterProxyIntegrationOptions, plugins: readonly ProxyIntegrationPlugin[]): RegisterProxyIntegrationOptions {
  let out = opts;
  for (const plugin of plugins) {
    if (!plugin.mutateOptions) continue;
    out = plugin.mutateOptions(out);
  }
  return out;
}

function mergeConflictPolicy(
  base: ProxyServiceWorkerConflictPolicy | undefined,
  plugins: readonly ProxyIntegrationPlugin[]
): ProxyServiceWorkerConflictPolicy | undefined {
  const keep = dedupeStrings([
    ...(base?.keepScriptPathSuffixes ?? []),
    ...plugins.flatMap((p) => p.serviceWorkerConflictPolicy?.keepScriptPathSuffixes ?? []),
  ]);

  let uninstallOnMismatch = base?.uninstallOnMismatch;
  for (const p of plugins) {
    if (p.serviceWorkerConflictPolicy?.uninstallOnMismatch != null) {
      uninstallOnMismatch = p.serviceWorkerConflictPolicy.uninstallOnMismatch;
    }
  }

  if (keep.length === 0 && uninstallOnMismatch == null) return base;
  const out: {
    keepScriptPathSuffixes?: readonly string[];
    uninstallOnMismatch?: boolean;
  } = {};
  if (keep.length > 0) out.keepScriptPathSuffixes = keep;
  if (uninstallOnMismatch != null) out.uninstallOnMismatch = uninstallOnMismatch;
  return out;
}

function shouldIgnoreMismatch(plugins: readonly ProxyIntegrationPlugin[], ctx: ControllerMismatchContext): boolean {
  for (const plugin of plugins) {
    const action = plugin.onControllerMismatch?.(ctx);
    if (action === "ignore") return true;
  }
  return false;
}

function buildRuntimeOptions(profile: ProxyProfile, runtime: RegisterProxyIntegrationOptions["runtime"]): {
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  timeoutMs: number;
} {
  return {
    maxJsonFrameBytes: runtime?.maxJsonFrameBytes ?? profile.maxJsonFrameBytes,
    maxChunkBytes: runtime?.maxChunkBytes ?? profile.maxChunkBytes,
    maxBodyBytes: runtime?.maxBodyBytes ?? profile.maxBodyBytes,
    maxWsFrameBytes: runtime?.maxWsFrameBytes ?? profile.maxWsFrameBytes,
    timeoutMs: runtime?.timeoutMs ?? profile.timeoutMs,
  };
}

export function createProxyIntegrationServiceWorkerScript(
  opts: CreateProxyIntegrationServiceWorkerScriptOptions = {}
): string {
  const plugins = opts.plugins ?? [];
  let scriptOpts: ProxyServiceWorkerScriptOptions = opts.baseOptions ?? {};

  for (const plugin of plugins) {
    if (!plugin.extendServiceWorkerScriptOptions) continue;
    scriptOpts = plugin.extendServiceWorkerScriptOptions(scriptOpts);
  }

  const forwarded = dedupeStrings([
    ...(scriptOpts.forwardFetchMessageTypes ?? []),
    ...plugins.flatMap((p) => p.forwardFetchMessageTypes ?? []),
  ]);
  const keepSuffixes = dedupeStrings([
    ...(scriptOpts.conflictHints?.keepScriptPathSuffixes ?? []),
    ...plugins.flatMap((p) => p.serviceWorkerConflictPolicy?.keepScriptPathSuffixes ?? []),
  ]);

  const finalOpts: ProxyServiceWorkerScriptOptions = {
    ...scriptOpts,
    forwardFetchMessageTypes: forwarded,
  };
  if (keepSuffixes.length > 0) {
    return createProxyServiceWorkerScript({
      ...finalOpts,
      conflictHints: { keepScriptPathSuffixes: keepSuffixes },
    });
  }
  if (scriptOpts.conflictHints != null) {
    return createProxyServiceWorkerScript({
      ...finalOpts,
      conflictHints: scriptOpts.conflictHints,
    });
  }
  return createProxyServiceWorkerScript(finalOpts);
}

export async function registerProxyIntegration(input: RegisterProxyIntegrationOptions): Promise<ProxyIntegrationHandle> {
  const plugins = input.plugins ?? [];
  const opts = applyPluginMutations(input, plugins);
  const profile = resolveProxyProfile(opts.profile);
  const runtimeOpts = buildRuntimeOptions(profile, opts.runtime);
  const runtime = createProxyRuntime({ ...runtimeOpts, client: opts.client });

  const swCfg = opts.serviceWorker;
  const repairQueryKey = String(swCfg.repair?.queryKey ?? "_flowersec_sw_repair").trim() || "_flowersec_sw_repair";
  const maxRepairAttempts = Math.max(0, Math.floor(swCfg.repair?.maxAttempts ?? 2));
  const controllerTimeoutMs = Math.max(0, Math.floor(swCfg.repair?.controllerTimeoutMs ?? 8_000));
  const strategy = swCfg.repair?.strategy ?? "replace";
  const conflicts = mergeConflictPolicy(swCfg.conflicts, plugins);

  const finalScope = String(swCfg.scope ?? "/").trim() || "/";
  const expectedScriptPathSuffix = String(swCfg.expectedScriptPathSuffix ?? "").trim();

  await uninstallConflictingServiceWorkers(conflicts);
  await registerServiceWorkerAndEnsureControl({
    scriptUrl: swCfg.scriptUrl,
    scope: finalScope,
    repairQueryKey,
    maxRepairAttempts,
    controllerTimeoutMs,
  });

  if (expectedScriptPathSuffix !== "") {
    const ok = await waitForControllerSuffix(expectedScriptPathSuffix, controllerTimeoutMs);
    if (!ok) {
      const actual = String(globalThis.navigator?.serviceWorker?.controller?.scriptURL ?? "").trim();
      const ctx: ControllerMismatchContext = {
        expectedScriptPathSuffix,
        actualScriptURL: actual,
        stage: "register",
      };

      if (!shouldIgnoreMismatch(plugins, ctx)) {
        await uninstallConflictingServiceWorkers(conflicts);
        await maybeRepairNavigation({ queryKey: repairQueryKey, maxAttempts: maxRepairAttempts, strategy });
        throw new Error("Proxy Service Worker is installed but not controlling this page");
      }
    }
  }

  const monitorEnabled = swCfg.monitor?.enabled ?? true;
  const monitorThrottleMs = Math.max(0, Math.floor(swCfg.monitor?.throttleMs ?? 10_000));
  const sw = globalThis.navigator?.serviceWorker;
  let monitorHandler: (() => void) | null = null;
  let lastMonitorRepairAt = 0;

  if (monitorEnabled && sw && expectedScriptPathSuffix !== "") {
    monitorHandler = () => {
      const actual = String(sw.controller?.scriptURL ?? "").trim();
      if (isServiceWorkerScriptPathSuffix(actual, expectedScriptPathSuffix)) return;

      const ctx: ControllerMismatchContext = {
        expectedScriptPathSuffix,
        actualScriptURL: actual,
        stage: "monitor",
      };
      if (shouldIgnoreMismatch(plugins, ctx)) return;

      const now = Date.now();
      if (monitorThrottleMs > 0 && now - lastMonitorRepairAt <= monitorThrottleMs) return;
      lastMonitorRepairAt = now;

      void maybeRepairNavigation({ queryKey: repairQueryKey, maxAttempts: maxRepairAttempts, strategy });
    };
    sw.addEventListener("controllerchange", monitorHandler);
  }

  const ctx: ProxyIntegrationContext = {
    runtime,
    options: opts,
    profile,
  };
  for (const plugin of plugins) {
    await plugin.onRegistered?.(ctx);
  }

  return {
    runtime,
    dispose: async () => {
      if (monitorHandler && sw) {
        sw.removeEventListener("controllerchange", monitorHandler);
      }
      runtime.dispose();
      for (const plugin of plugins) {
        await plugin.onDisposed?.();
      }
    },
  };
}

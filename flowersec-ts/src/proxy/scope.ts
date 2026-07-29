import type {
  ProxyRuntimeControllerBridgeScopeV2,
  ProxyRuntimeScopeLimitsV2,
  ProxyRuntimeScopeV2,
  ProxyRuntimeServiceWorkerScopeV2,
} from "./types.js";

export const PROXY_RUNTIME_SCOPE_V2 = Object.freeze({ name: "proxy.runtime", version: 2 as const });

const MAX_PAYLOAD_BYTES = 8 * 1024;
const MAX_FIELDS = 48;
const MAX_DEPTH = 6;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function reject(message: string): never {
  throw new TypeError(`invalid proxy.runtime@2: ${message}`);
}

function exactFields(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const set = new Set(allowed);
  for (const key of Object.keys(value)) if (!set.has(key)) reject(`${label}.${key}`);
}

function containerDepth(value: unknown): number {
  if (Array.isArray(value)) return 1 + value.reduce<number>((best, item) => Math.max(best, containerDepth(item)), 0);
  if (!isRecord(value)) return 0;
  return 1 + Object.values(value).reduce<number>((best, item) => Math.max(best, containerDepth(item)), 0);
}

function fieldCount(value: unknown): number {
  if (Array.isArray(value)) return value.reduce<number>((total, item) => total + fieldCount(item), 0);
  if (!isRecord(value)) return 0;
  return Object.values(value).reduce<number>((total, item) => total + 1 + fieldCount(item), 0);
}

function nonEmpty(name: string, value: unknown): string {
  if (typeof value !== "string" || value.trim() === "" || value !== value.trim()) reject(name);
  return value;
}

function positiveInt(name: string, value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) reject(name);
  return value as number;
}

function optionalLimits(value: unknown): ProxyRuntimeScopeLimitsV2 | undefined {
  if (value === undefined) return undefined;
  if (!isRecord(value)) reject("limits");
  exactFields(value, ["timeoutMs", "maxJsonFrameBytes", "maxChunkBytes", "maxBodyBytes", "maxWsFrameBytes"], "limits");
  const result: Record<string, number> = {};
  for (const key of ["timeoutMs", "maxJsonFrameBytes", "maxChunkBytes", "maxBodyBytes", "maxWsFrameBytes"] as const) {
    if (value[key] !== undefined) result[key] = positiveInt(`limits.${key}`, value[key]);
  }
  return Object.freeze(result) as ProxyRuntimeScopeLimitsV2;
}

function optionalAppBasePath(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const path = nonEmpty("appBasePath", value);
  if (!path.startsWith("/") || path.startsWith("//") || /[\u0000-\u0020]/u.test(path)) reject("appBasePath");
  return path;
}

function allowedOrigins(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) reject("controllerBridge.allowedOrigins");
  const result: string[] = [];
  for (const entry of value) {
    const origin = nonEmpty("controllerBridge.allowedOrigins", entry);
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      reject("controllerBridge.allowedOrigins");
    }
    if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== origin || parsed.username !== "" || parsed.password !== "") {
      reject("controllerBridge.allowedOrigins");
    }
    if (!result.includes(origin)) result.push(origin);
  }
  if (result.length === 0) reject("controllerBridge.allowedOrigins");
  return Object.freeze(result);
}

export function assertProxyRuntimeScopeV2(payload: unknown): ProxyRuntimeScopeV2 {
  if (!isRecord(payload)) reject("payload");
  let encoded: string;
  try {
    encoded = JSON.stringify(payload);
  } catch {
    reject("payload");
  }
  if (new TextEncoder().encode(encoded).length > MAX_PAYLOAD_BYTES || containerDepth(payload) > MAX_DEPTH || fieldCount(payload) > MAX_FIELDS) {
    reject("payload bounds");
  }
  exactFields(payload, ["version", "mode", "appBasePath", "serviceWorker", "controllerBridge", "limits"], "scope");
  if (payload.version !== undefined && payload.version !== 2) reject("version");
  const appBasePath = optionalAppBasePath(payload.appBasePath);
  const limits = optionalLimits(payload.limits);

  if (payload.mode === "service_worker") {
    if (!isRecord(payload.serviceWorker) || payload.controllerBridge !== undefined) reject("serviceWorker");
    exactFields(payload.serviceWorker, ["scriptUrl", "scope"], "serviceWorker");
    const result: ProxyRuntimeServiceWorkerScopeV2 = {
      mode: "service_worker",
      ...(appBasePath === undefined ? {} : { appBasePath }),
      serviceWorker: Object.freeze({
        scriptUrl: nonEmpty("serviceWorker.scriptUrl", payload.serviceWorker.scriptUrl),
        scope: nonEmpty("serviceWorker.scope", payload.serviceWorker.scope),
      }),
      ...(limits === undefined ? {} : { limits }),
    };
    return Object.freeze(result);
  }
  if (payload.mode === "controller_bridge") {
    if (!isRecord(payload.controllerBridge) || payload.serviceWorker !== undefined) reject("controllerBridge");
    exactFields(payload.controllerBridge, ["allowedOrigins"], "controllerBridge");
    const result: ProxyRuntimeControllerBridgeScopeV2 = {
      mode: "controller_bridge",
      ...(appBasePath === undefined ? {} : { appBasePath }),
      controllerBridge: Object.freeze({ allowedOrigins: allowedOrigins(payload.controllerBridge.allowedOrigins) }),
      ...(limits === undefined ? {} : { limits }),
    };
    return Object.freeze(result);
  }
  reject("mode");
}

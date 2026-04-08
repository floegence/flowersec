import type { ConnectArtifact, ScopePayload } from "../connect/artifact.js";

import {
  assertProxyPresetManifest,
  resolveNamedProxyPreset,
  type ProxyPresetInput,
  type ProxyPresetLimits,
} from "./preset.js";

const RUNTIME_SCOPE_NAME = "proxy.runtime";
const PRESET_ID_RE = /^[a-z][a-z0-9._-]{0,63}$/;
const MAX_RUNTIME_PAYLOAD_BYTES = 8 * 1024;
const MAX_RUNTIME_DEPTH = 8;
const MAX_RUNTIME_FIELDS = 64;
const MAX_RUNTIME_SNAPSHOT_BYTES = 4 * 1024;

export type ProxyPresetSnapshotV1 = ReturnType<typeof assertProxyPresetManifest>;

type ProxyRuntimeScopeBaseV1 = Readonly<{
  appBasePath?: string;
  preset: Readonly<{
    presetId: string;
    snapshot?: ProxyPresetSnapshotV1;
  }>;
  limits?: Readonly<{
    timeoutMs?: number;
    maxJsonFrameBytes?: number;
    maxChunkBytes?: number;
    maxBodyBytes?: number;
    maxWsFrameBytes?: number;
  }>;
}>;

export type ProxyRuntimeServiceWorkerScopeV1 = ProxyRuntimeScopeBaseV1 &
  Readonly<{
    mode: "service_worker";
    serviceWorker: Readonly<{
      scriptUrl: string;
      scope: string;
    }>;
  }>;

export type ProxyRuntimeControllerBridgeScopeV1 = ProxyRuntimeScopeBaseV1 &
  Readonly<{
    mode: "controller_bridge";
    controllerBridge: Readonly<{
      allowedOrigins: readonly string[];
    }>;
  }>;

export type ProxyRuntimeScopeV1 = ProxyRuntimeServiceWorkerScopeV1 | ProxyRuntimeControllerBridgeScopeV1;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value != null && !Array.isArray(value);
}

function assertNoUnknownFields(kind: string, value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`bad ${kind}.${key}`);
  }
}

function assertPositiveInt(name: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`bad ${name}`);
  }
  return value;
}

function utf8Len(value: string): number {
  return new TextEncoder().encode(value).length;
}

function maxContainerDepth(value: unknown): number {
  if (Array.isArray(value)) {
    let best = 1;
    for (const entry of value) best = Math.max(best, 1 + maxContainerDepth(entry));
    return best;
  }
  if (isRecord(value)) {
    let best = 1;
    for (const entry of Object.values(value)) best = Math.max(best, 1 + maxContainerDepth(entry));
    return best;
  }
  return 0;
}

function countFields(value: unknown): number {
  if (Array.isArray(value)) return value.reduce((total, entry) => total + countFields(entry), 0);
  if (isRecord(value)) {
    return Object.entries(value).reduce((total, [, entry]) => total + 1 + countFields(entry), 0);
  }
  return 0;
}

function assertRuntimePayloadEnvelope(payload: ScopePayload): Record<string, unknown> {
  if (!isRecord(payload)) throw new Error("bad proxy.runtime.payload");
  if (utf8Len(JSON.stringify(payload)) > MAX_RUNTIME_PAYLOAD_BYTES) throw new Error("bad proxy.runtime.payload");
  if (maxContainerDepth(payload) > MAX_RUNTIME_DEPTH) throw new Error("bad proxy.runtime.payload");
  if (countFields(payload) > MAX_RUNTIME_FIELDS) throw new Error("bad proxy.runtime.payload");
  return payload;
}

function assertServiceWorkerConfig(value: unknown): Readonly<{ scriptUrl: string; scope: string }> {
  if (!isRecord(value)) throw new Error("bad proxy.runtime.serviceWorker");
  assertNoUnknownFields("proxy.runtime.serviceWorker", value, ["scriptUrl", "scope"]);
  const scriptUrl = String(value.scriptUrl ?? "").trim();
  const scope = String(value.scope ?? "").trim();
  if (scriptUrl === "") throw new Error("bad proxy.runtime.serviceWorker.scriptUrl");
  if (scope === "") throw new Error("bad proxy.runtime.serviceWorker.scope");
  return Object.freeze({ scriptUrl, scope });
}

function assertAllowedOrigins(value: unknown): readonly string[] {
  if (!Array.isArray(value)) throw new Error("bad proxy.runtime.controllerBridge.allowedOrigins");
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    const normalized = String(entry ?? "").trim();
    if (normalized === "" || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
  }
  if (out.length === 0) throw new Error("bad proxy.runtime.controllerBridge.allowedOrigins");
  return Object.freeze(out);
}

function assertControllerBridgeConfig(value: unknown): Readonly<{ allowedOrigins: readonly string[] }> {
  if (!isRecord(value)) throw new Error("bad proxy.runtime.controllerBridge");
  assertNoUnknownFields("proxy.runtime.controllerBridge", value, ["allowedOrigins"]);
  return Object.freeze({
    allowedOrigins: assertAllowedOrigins(value.allowedOrigins),
  });
}

function assertLimits(value: unknown): ProxyRuntimeScopeV1["limits"] {
  if (!isRecord(value)) throw new Error("bad proxy.runtime.limits");
  assertNoUnknownFields("proxy.runtime.limits", value, [
    "timeoutMs",
    "maxJsonFrameBytes",
    "maxChunkBytes",
    "maxBodyBytes",
    "maxWsFrameBytes",
  ]);
  const out: Record<string, number> = {};
  if (value.timeoutMs !== undefined) out.timeoutMs = assertPositiveInt("proxy.runtime.limits.timeoutMs", value.timeoutMs);
  if (value.maxJsonFrameBytes !== undefined) {
    out.maxJsonFrameBytes = assertPositiveInt("proxy.runtime.limits.maxJsonFrameBytes", value.maxJsonFrameBytes);
  }
  if (value.maxChunkBytes !== undefined) out.maxChunkBytes = assertPositiveInt("proxy.runtime.limits.maxChunkBytes", value.maxChunkBytes);
  if (value.maxBodyBytes !== undefined) out.maxBodyBytes = assertPositiveInt("proxy.runtime.limits.maxBodyBytes", value.maxBodyBytes);
  if (value.maxWsFrameBytes !== undefined) out.maxWsFrameBytes = assertPositiveInt("proxy.runtime.limits.maxWsFrameBytes", value.maxWsFrameBytes);
  return Object.freeze(out);
}

function assertPreset(value: unknown): ProxyRuntimeScopeV1["preset"] {
  if (!isRecord(value)) throw new Error("bad proxy.runtime.preset");
  assertNoUnknownFields("proxy.runtime.preset", value, ["presetId", "snapshot"]);
  const presetId = String(value.presetId ?? "").trim();
  if (!PRESET_ID_RE.test(presetId)) throw new Error("bad proxy.runtime.preset.presetId");
  if (value.snapshot === undefined) {
    return Object.freeze({ presetId });
  }
  const snapshot = assertProxyPresetManifest(value.snapshot);
  if (utf8Len(JSON.stringify(snapshot)) > MAX_RUNTIME_SNAPSHOT_BYTES) throw new Error("bad proxy.runtime.preset.snapshot");
  return Object.freeze({ presetId, snapshot });
}

export function assertProxyRuntimeScopeV1(payload: ScopePayload): ProxyRuntimeScopeV1 {
  const value = assertRuntimePayloadEnvelope(payload);
  assertNoUnknownFields("proxy.runtime", value, [
    "mode",
    "appBasePath",
    "serviceWorker",
    "controllerBridge",
    "preset",
    "limits",
  ]);
  const mode = value.mode;
  if (mode !== "service_worker" && mode !== "controller_bridge") {
    throw new Error("bad proxy.runtime.mode");
  }
  const appBasePath = value.appBasePath === undefined ? undefined : String(value.appBasePath ?? "").trim();
  if (value.appBasePath !== undefined && appBasePath === "") {
    throw new Error("bad proxy.runtime.appBasePath");
  }
  const preset = assertPreset(value.preset);
  const limits = value.limits === undefined ? undefined : assertLimits(value.limits);

  if (mode === "service_worker") {
    if (value.controllerBridge !== undefined) throw new Error("bad proxy.runtime.controllerBridge");
    const serviceWorker = assertServiceWorkerConfig(value.serviceWorker);
    return Object.freeze({
      mode,
      ...(appBasePath === undefined ? {} : { appBasePath }),
      serviceWorker,
      preset,
      ...(limits === undefined ? {} : { limits }),
    });
  }

  if (value.serviceWorker !== undefined) throw new Error("bad proxy.runtime.serviceWorker");
  const controllerBridge = assertControllerBridgeConfig(value.controllerBridge);
  return Object.freeze({
    mode,
    ...(appBasePath === undefined ? {} : { appBasePath }),
    controllerBridge,
    preset,
    ...(limits === undefined ? {} : { limits }),
  });
}

export function extractProxyRuntimeScopeV1(
  artifact: ConnectArtifact,
  mode: ProxyRuntimeScopeV1["mode"]
): ProxyRuntimeScopeV1 {
  const scoped = artifact.scoped ?? [];
  const entry = scoped.find((item) => item.scope === RUNTIME_SCOPE_NAME);
  if (!entry) {
    throw new Error("missing proxy.runtime@1 scope");
  }
  if (entry.scope_version !== 1) {
    throw new Error(`unsupported proxy.runtime scope_version: ${entry.scope_version}`);
  }
  const scope = assertProxyRuntimeScopeV1(entry.payload);
  if (scope.mode !== mode) {
    throw new Error(`proxy.runtime mode mismatch: expected ${mode}`);
  }
  return scope;
}

export function resolveRuntimeLimitsFromScope(
  scope: ProxyRuntimeScopeV1,
  overrides: Readonly<{
    maxJsonFrameBytes?: number;
    maxChunkBytes?: number;
    maxBodyBytes?: number;
    maxWsFrameBytes?: number;
    timeoutMs?: number;
  }> | undefined
): Readonly<{
  maxJsonFrameBytes?: number;
  maxChunkBytes?: number;
  maxBodyBytes?: number;
  maxWsFrameBytes?: number;
  timeoutMs?: number;
}> | undefined {
  const merged = {
    ...(scope.limits ?? {}),
    ...(overrides ?? {}),
  };
  return Object.keys(merged).length === 0 ? undefined : merged;
}

export function resolvePresetInputFromScope(
  scope: ProxyRuntimeScopeV1,
  presetOverride: ProxyPresetInput | undefined
): ProxyPresetInput | undefined {
  if (presetOverride !== undefined) return presetOverride;
  if (scope.preset.snapshot) return scope.preset.snapshot;
  try {
    return resolveNamedProxyPreset(scope.preset.presetId);
  } catch {
    return undefined;
  }
}

export function resolveRuntimePresetLimits(scope: ProxyRuntimeScopeV1): ProxyPresetLimits | undefined {
  if (scope.limits === undefined) return undefined;
  return Object.freeze({
    ...(scope.limits.maxJsonFrameBytes === undefined ? {} : { max_json_frame_bytes: scope.limits.maxJsonFrameBytes }),
    ...(scope.limits.maxChunkBytes === undefined ? {} : { max_chunk_bytes: scope.limits.maxChunkBytes }),
    ...(scope.limits.maxBodyBytes === undefined ? {} : { max_body_bytes: scope.limits.maxBodyBytes }),
    ...(scope.limits.maxWsFrameBytes === undefined ? {} : { max_ws_frame_bytes: scope.limits.maxWsFrameBytes }),
    ...(scope.limits.timeoutMs === undefined ? {} : { timeout_ms: scope.limits.timeoutMs }),
  });
}

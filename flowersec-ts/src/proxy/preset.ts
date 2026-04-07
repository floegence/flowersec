import { DEFAULT_MAX_JSON_FRAME_BYTES } from "../framing/jsonframe.js";

import { DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_CHUNK_BYTES, DEFAULT_MAX_WS_FRAME_BYTES } from "./constants.js";

const PRESET_ID_RE = /^[a-z][a-z0-9._-]{0,63}$/;

export type ProxyPresetLimits = Readonly<{
  max_json_frame_bytes?: number;
  max_chunk_bytes?: number;
  max_body_bytes?: number;
  max_ws_frame_bytes?: number;
  timeout_ms?: number;
}>;

export type ProxyPresetManifest = Readonly<{
  v: 1;
  preset_id: string;
  deprecated?: boolean;
  limits: ProxyPresetLimits;
}>;

export type ResolvedProxyPreset = Readonly<{
  v: 1;
  preset_id: string;
  deprecated: boolean;
  limits: Readonly<{
    max_json_frame_bytes: number;
    max_chunk_bytes: number;
    max_body_bytes: number;
    max_ws_frame_bytes: number;
    timeout_ms?: number;
  }>;
}>;

const DEFAULT_LIMITS = Object.freeze({
  max_json_frame_bytes: DEFAULT_MAX_JSON_FRAME_BYTES,
  max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
  max_body_bytes: DEFAULT_MAX_BODY_BYTES,
  max_ws_frame_bytes: DEFAULT_MAX_WS_FRAME_BYTES,
});

export const DEFAULT_PROXY_PRESET_MANIFEST: ProxyPresetManifest = Object.freeze({
  v: 1,
  preset_id: "default",
  limits: {
    max_json_frame_bytes: DEFAULT_MAX_JSON_FRAME_BYTES,
    max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
    max_body_bytes: DEFAULT_MAX_BODY_BYTES,
    max_ws_frame_bytes: DEFAULT_MAX_WS_FRAME_BYTES,
  },
});

export const CODESERVER_PROXY_PRESET_MANIFEST: ProxyPresetManifest = Object.freeze({
  v: 1,
  preset_id: "codeserver",
  deprecated: true,
  limits: {
    max_json_frame_bytes: DEFAULT_MAX_JSON_FRAME_BYTES,
    max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
    max_body_bytes: DEFAULT_MAX_BODY_BYTES,
    max_ws_frame_bytes: 32 * 1024 * 1024,
  },
});

export type ProxyPresetInput = ProxyPresetManifest | Partial<ProxyPresetLimits>;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v != null && !Array.isArray(v);
}

function assertNoUnknownFields(kind: string, value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`bad ${kind}.${key}`);
  }
}

function assertPositiveInt(name: string, value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return value;
}

function assertLimits(value: unknown): ProxyPresetLimits {
  if (!isRecord(value)) throw new Error("bad ProxyPresetManifest.limits");
  assertNoUnknownFields("ProxyPresetManifest.limits", value, [
    "max_json_frame_bytes",
    "max_chunk_bytes",
    "max_body_bytes",
    "max_ws_frame_bytes",
    "timeout_ms",
  ]);
  const out: Record<string, number> = {};
  if (value.max_json_frame_bytes !== undefined) out.max_json_frame_bytes = assertPositiveInt("max_json_frame_bytes", value.max_json_frame_bytes);
  if (value.max_chunk_bytes !== undefined) out.max_chunk_bytes = assertPositiveInt("max_chunk_bytes", value.max_chunk_bytes);
  if (value.max_body_bytes !== undefined) out.max_body_bytes = assertPositiveInt("max_body_bytes", value.max_body_bytes);
  if (value.max_ws_frame_bytes !== undefined) out.max_ws_frame_bytes = assertPositiveInt("max_ws_frame_bytes", value.max_ws_frame_bytes);
  if (value.timeout_ms !== undefined) out.timeout_ms = assertPositiveInt("timeout_ms", value.timeout_ms);
  return Object.freeze(out);
}

export function assertProxyPresetManifest(value: unknown): ProxyPresetManifest {
  if (!isRecord(value)) throw new Error("bad ProxyPresetManifest");
  assertNoUnknownFields("ProxyPresetManifest", value, ["v", "preset_id", "deprecated", "limits"]);
  if (value.v !== 1) throw new Error("bad ProxyPresetManifest.v");
  if (typeof value.preset_id !== "string" || !PRESET_ID_RE.test(value.preset_id)) {
    throw new Error("bad ProxyPresetManifest.preset_id");
  }
  if (value.deprecated !== undefined && typeof value.deprecated !== "boolean") {
    throw new Error("bad ProxyPresetManifest.deprecated");
  }
  return Object.freeze({
    v: 1,
    preset_id: value.preset_id,
    ...(value.deprecated === undefined ? {} : { deprecated: value.deprecated }),
    limits: assertLimits(value.limits),
  });
}

export function resolveNamedProxyPreset(name: string): ProxyPresetManifest {
  switch (String(name ?? "").trim()) {
    case "":
    case "default":
      return DEFAULT_PROXY_PRESET_MANIFEST;
    case "codeserver":
      return CODESERVER_PROXY_PRESET_MANIFEST;
    default:
      throw new Error(`unknown proxy preset: ${name}`);
  }
}

function toResolved(manifest: ProxyPresetManifest): ResolvedProxyPreset {
  return Object.freeze({
    v: 1,
    preset_id: manifest.preset_id,
    deprecated: manifest.deprecated === true,
    limits: Object.freeze({
      max_json_frame_bytes: manifest.limits.max_json_frame_bytes ?? DEFAULT_LIMITS.max_json_frame_bytes,
      max_chunk_bytes: manifest.limits.max_chunk_bytes ?? DEFAULT_LIMITS.max_chunk_bytes,
      max_body_bytes: manifest.limits.max_body_bytes ?? DEFAULT_LIMITS.max_body_bytes,
      max_ws_frame_bytes: manifest.limits.max_ws_frame_bytes ?? DEFAULT_LIMITS.max_ws_frame_bytes,
      ...(manifest.limits.timeout_ms === undefined ? {} : { timeout_ms: manifest.limits.timeout_ms }),
    }),
  });
}

export function resolveProxyPreset(input?: ProxyPresetInput): ResolvedProxyPreset {
  if (input == null) return toResolved(DEFAULT_PROXY_PRESET_MANIFEST);
  if (isRecord(input) && ("v" in input || "presetId" in input || "limits" in input)) {
    return toResolved(assertProxyPresetManifest(input));
  }
  const limits = assertLimits(input);
  return Object.freeze({
    v: 1,
    preset_id: "custom",
    deprecated: false,
    limits: Object.freeze({
      max_json_frame_bytes: limits.max_json_frame_bytes ?? DEFAULT_LIMITS.max_json_frame_bytes,
      max_chunk_bytes: limits.max_chunk_bytes ?? DEFAULT_LIMITS.max_chunk_bytes,
      max_body_bytes: limits.max_body_bytes ?? DEFAULT_LIMITS.max_body_bytes,
      max_ws_frame_bytes: limits.max_ws_frame_bytes ?? DEFAULT_LIMITS.max_ws_frame_bytes,
      ...(limits.timeout_ms === undefined ? {} : { timeout_ms: limits.timeout_ms }),
    }),
  });
}

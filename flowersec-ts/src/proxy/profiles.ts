import {
  CODESERVER_PROXY_PRESET_MANIFEST,
  DEFAULT_PROXY_PRESET_MANIFEST,
  resolveProxyPreset,
  type ProxyPresetManifest,
} from "./preset.js";

export type ProxyProfile = Readonly<{
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  timeoutMs: number;
}>;

export type ProxyProfileName = "default" | "codeserver";

function toLegacyProfile(manifest: ProxyPresetManifest): ProxyProfile {
  const resolved = resolveProxyPreset(manifest);
  return Object.freeze({
    maxJsonFrameBytes: resolved.limits.max_json_frame_bytes,
    maxChunkBytes: resolved.limits.max_chunk_bytes,
    maxBodyBytes: resolved.limits.max_body_bytes,
    maxWsFrameBytes: resolved.limits.max_ws_frame_bytes,
    timeoutMs: resolved.limits.timeout_ms ?? 0,
  });
}

const DEFAULT_PROFILE: ProxyProfile = toLegacyProfile(DEFAULT_PROXY_PRESET_MANIFEST);
const CODESERVER_PROFILE: ProxyProfile = toLegacyProfile(CODESERVER_PROXY_PRESET_MANIFEST);

export const PROXY_PROFILE_DEFAULT = DEFAULT_PROFILE;
export const PROXY_PROFILE_CODESERVER = CODESERVER_PROFILE;

function normalizeSafeInt(name: string, value: number): number {
  if (!Number.isFinite(value)) throw new Error(`${name} must be a finite number`);
  const n = Math.floor(value);
  if (!Number.isSafeInteger(n)) throw new Error(`${name} must be a safe integer`);
  if (n < 0) throw new Error(`${name} must be >= 0`);
  return n;
}

function resolveNamedProfile(name: ProxyProfileName): ProxyProfile {
  switch (name) {
    case "default":
      return DEFAULT_PROFILE;
    case "codeserver":
      return CODESERVER_PROFILE;
    default:
      throw new Error(`unknown proxy profile: ${name}`);
  }
}

export function resolveProxyProfile(profile?: ProxyProfileName | Partial<ProxyProfile>): ProxyProfile {
  if (profile == null) return DEFAULT_PROFILE;
  if (typeof profile === "string") {
    return resolveNamedProfile(profile);
  }

  const base = DEFAULT_PROFILE;
  return Object.freeze({
    maxJsonFrameBytes: normalizeSafeInt("maxJsonFrameBytes", profile.maxJsonFrameBytes ?? base.maxJsonFrameBytes),
    maxChunkBytes: normalizeSafeInt("maxChunkBytes", profile.maxChunkBytes ?? base.maxChunkBytes),
    maxBodyBytes: normalizeSafeInt("maxBodyBytes", profile.maxBodyBytes ?? base.maxBodyBytes),
    maxWsFrameBytes: normalizeSafeInt("maxWsFrameBytes", profile.maxWsFrameBytes ?? base.maxWsFrameBytes),
    timeoutMs: normalizeSafeInt("timeoutMs", profile.timeoutMs ?? base.timeoutMs),
  });
}

export function profileToPresetManifest(profile?: ProxyProfileName | Partial<ProxyProfile>): ProxyPresetManifest {
  if (profile == null) return DEFAULT_PROXY_PRESET_MANIFEST;
  if (typeof profile === "string") {
    switch (profile) {
      case "default":
        return DEFAULT_PROXY_PRESET_MANIFEST;
      case "codeserver":
        return CODESERVER_PROXY_PRESET_MANIFEST;
      default:
        throw new Error(`unknown proxy profile: ${profile}`);
    }
  }
  const resolved = resolveProxyProfile(profile);
  return Object.freeze({
    v: 1,
    preset_id: "legacy-profile",
    deprecated: true,
    limits: {
      ...(resolved.maxJsonFrameBytes > 0 ? { max_json_frame_bytes: resolved.maxJsonFrameBytes } : {}),
      ...(resolved.maxChunkBytes > 0 ? { max_chunk_bytes: resolved.maxChunkBytes } : {}),
      ...(resolved.maxBodyBytes > 0 ? { max_body_bytes: resolved.maxBodyBytes } : {}),
      ...(resolved.maxWsFrameBytes > 0 ? { max_ws_frame_bytes: resolved.maxWsFrameBytes } : {}),
      ...(resolved.timeoutMs > 0 ? { timeout_ms: resolved.timeoutMs } : {}),
    },
  });
}

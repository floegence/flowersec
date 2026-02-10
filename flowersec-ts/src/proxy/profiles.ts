import { DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_CHUNK_BYTES, DEFAULT_MAX_WS_FRAME_BYTES } from "./constants.js";

export type ProxyProfile = Readonly<{
  maxJsonFrameBytes: number;
  maxChunkBytes: number;
  maxBodyBytes: number;
  maxWsFrameBytes: number;
  timeoutMs: number;
}>;

export type ProxyProfileName = "default" | "codeserver";

const DEFAULT_PROFILE: ProxyProfile = Object.freeze({
  // Keep aligned with runtime defaults.
  maxJsonFrameBytes: 0,
  maxChunkBytes: DEFAULT_MAX_CHUNK_BYTES,
  maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  maxWsFrameBytes: DEFAULT_MAX_WS_FRAME_BYTES,
  timeoutMs: 0,
});

const CODESERVER_PROFILE: ProxyProfile = Object.freeze({
  maxJsonFrameBytes: 0,
  maxChunkBytes: DEFAULT_MAX_CHUNK_BYTES,
  maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  // Keep aligned with redeven/redeven-agent production profile.
  maxWsFrameBytes: 32 * 1024 * 1024,
  timeoutMs: 0,
});

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

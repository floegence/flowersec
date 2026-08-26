import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { canonicalizeJCSV3, type JCSValue } from "../v3/jcs.js";
import { preflightJSONV3 } from "../v3/jsonPreflight.js";
import { decodeArtifactV3JSON, type ArtifactV3 } from "../v3/artifact.js";
import { createArtifactLeaseV3Internal, type ArtifactLeaseV3 } from "../v3/artifactLease.js";
import type { RetryDispositionV3 } from "../v3/security.js";

export const PRIVATE_LOOPBACK_PROFILE_V1 = "flowersec-private-loopback/1";
const DIRECT_PATH = "/flowersec/v3/direct";
const MIN_PRIVATE_LOOPBACK_PORT = 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });
const encoder = new TextEncoder();

type PrivateLoopbackStateV1 = Readonly<{
  endpoint: string;
  innerArtifact: ArtifactV3;
}>;

export class PrivateLoopbackArtifactV1 {
  declare private readonly privateLoopbackArtifactBrand: void;
  private constructor() {}
}

export class PrivateLoopbackArtifactLeaseV1 {
  declare private readonly privateLoopbackLeaseBrand: void;
  private constructor() {}
}

export class PrivateLoopbackArtifactErrorV1 extends Error {
  readonly code = "invalid_artifact";

  constructor() {
    super("Flowersec private loopback artifact is invalid");
    this.name = "PrivateLoopbackArtifactError";
  }
}

export type PrivateLoopbackArtifactSourceResultV1 =
  | Readonly<{ kind: "lease"; lease: PrivateLoopbackArtifactLeaseV1 }>
  | Readonly<{ kind: "failure"; code: string; disposition: RetryDispositionV3 }>;

export type PrivateLoopbackArtifactSourceV1 = Readonly<{
  acquire(options: Readonly<{ signal: AbortSignal }>): Promise<PrivateLoopbackArtifactSourceResultV1>;
}>;

const artifacts = new WeakMap<PrivateLoopbackArtifactV1, PrivateLoopbackStateV1>();
const leases = new WeakMap<PrivateLoopbackArtifactLeaseV1, PrivateLoopbackStateV1 & { innerLease: ArtifactLeaseV3 }>();

export function parsePrivateLoopbackArtifactV1(input: string | Uint8Array): PrivateLoopbackArtifactV1 {
  try {
    const text = decodeBounded(input);
    preflightJSONV3(text);
    const value = JSON.parse(text) as unknown;
    if (!isRecord(value) || !hasExactKeys(value, ["artifact_b64u", "endpoint", "profile", "v"]) ||
        value.v !== 1 || value.profile !== PRIVATE_LOOPBACK_PROFILE_V1 ||
        typeof value.artifact_b64u !== "string" || typeof value.endpoint !== "string" ||
        canonicalizeJCSV3(value as JCSValue) !== text) {
      throw new Error("invalid private loopback envelope");
    }
    const innerBytes = base64urlDecode(value.artifact_b64u);
    if (innerBytes.length === 0 || innerBytes.length > 65_536 || base64urlEncode(innerBytes) !== value.artifact_b64u) {
      throw new Error("invalid nested artifact encoding");
    }
    const endpoint = validatePrivateLoopbackEndpointV1(value.endpoint);
    const innerArtifact = decodeArtifactV3JSON(innerBytes);
    validateNestedArtifact(innerArtifact, endpoint);
    const handle = new (PrivateLoopbackArtifactV1 as unknown as { new(): PrivateLoopbackArtifactV1 })();
    artifacts.set(handle, Object.freeze({ endpoint, innerArtifact }));
    return Object.freeze(handle) as PrivateLoopbackArtifactV1;
  } catch {
    throw new PrivateLoopbackArtifactErrorV1();
  }
}

export function createPrivateLoopbackArtifactLeaseV1(
  artifact: PrivateLoopbackArtifactV1,
  commitSpend: (signal?: AbortSignal) => Promise<void>,
  retireCleanup?: () => Promise<void>,
): PrivateLoopbackArtifactLeaseV1 {
  const state = artifacts.get(artifact);
  if (state === undefined) throw new PrivateLoopbackArtifactErrorV1();
  const lease = new (PrivateLoopbackArtifactLeaseV1 as unknown as { new(): PrivateLoopbackArtifactLeaseV1 })();
  leases.set(lease, {
    ...state,
    innerLease: createArtifactLeaseV3Internal(state.innerArtifact, commitSpend, retireCleanup),
  });
  return Object.freeze(lease) as PrivateLoopbackArtifactLeaseV1;
}

/** @internal Dedicated private-loopback connector boundary. */
export function unwrapPrivateLoopbackArtifactLeaseV1(lease: PrivateLoopbackArtifactLeaseV1): Readonly<{
  endpoint: string;
  innerLease: ArtifactLeaseV3;
}> {
  const state = leases.get(lease);
  if (state === undefined) throw new PrivateLoopbackArtifactErrorV1();
  return state;
}

export function validatePrivateLoopbackOriginV1(raw: string): string {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new PrivateLoopbackArtifactErrorV1(); }
  if (raw !== parsed.origin || parsed.protocol !== "http:" || parsed.username !== "" || parsed.password !== "" ||
      !privateLoopbackPort(parsed.port) || !numericLoopbackHostname(parsed.hostname)) {
    throw new PrivateLoopbackArtifactErrorV1();
  }
  return parsed.origin;
}

function validatePrivateLoopbackEndpointV1(raw: string): string {
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new PrivateLoopbackArtifactErrorV1(); }
  if (parsed.href !== raw || parsed.protocol !== "ws:" || parsed.username !== "" || parsed.password !== "" ||
      !privateLoopbackPort(parsed.port) || parsed.pathname !== DIRECT_PATH || parsed.search !== "" || parsed.hash !== "" ||
      !numericLoopbackHostname(parsed.hostname)) {
    throw new PrivateLoopbackArtifactErrorV1();
  }
  return raw;
}

function privateLoopbackPort(raw: string): boolean {
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) return false;
  const port = Number(raw);
  return Number.isSafeInteger(port) && port >= MIN_PRIVATE_LOOPBACK_PORT && port <= 65_535;
}

function validateNestedArtifact(artifact: ArtifactV3, endpoint: string): void {
  if (artifact.path.kind !== "direct" || artifact.path.candidates.length !== 1) {
    throw new PrivateLoopbackArtifactErrorV1();
  }
  const candidate = artifact.path.candidates[0]!;
  const privateURL = new URL(endpoint);
  privateURL.protocol = "wss:";
  if (candidate.id !== "private-loopback" || candidate.carrier !== "websocket" || candidate.tls.mode !== "ca" ||
      candidate.wire_profile !== "flowersec-direct/3" || candidate.normalized_url !== privateURL.href ||
      candidate.url !== privateURL.href) {
    throw new PrivateLoopbackArtifactErrorV1();
  }
}

function numericLoopbackHostname(hostname: string): boolean {
  if (hostname === "[::1]") return true;
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
  const octets = hostname.split(".").map(Number);
  return octets.every((value) => value >= 0 && value <= 255) && octets[0] === 127;
}

function decodeBounded(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  if (bytes.length === 0 || bytes.length > 100_000) throw new PrivateLoopbackArtifactErrorV1();
  const text = decoder.decode(bytes);
  if (encoder.encode(text).length !== bytes.length) throw new PrivateLoopbackArtifactErrorV1();
  return text;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

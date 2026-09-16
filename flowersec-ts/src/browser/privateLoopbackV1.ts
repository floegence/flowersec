import type { RetryDispositionV3 } from "../v3/security.js";
import { createDirectWebSocketProfileV1 } from "./directWebSocketProfileV1.js";

export const PRIVATE_LOOPBACK_PROFILE_V1 = "flowersec-private-loopback/1";
const DIRECT_PATH = "/flowersec/v3/direct";
const MIN_PRIVATE_LOOPBACK_PORT = 1024;

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

const profile = createDirectWebSocketProfileV1<PrivateLoopbackArtifactV1, PrivateLoopbackArtifactLeaseV1>({
  profile: PRIVATE_LOOPBACK_PROFILE_V1,
  candidateID: "private-loopback",
  validateEndpoint: validatePrivateLoopbackEndpointV1,
  error: () => new PrivateLoopbackArtifactErrorV1(),
});
export const parsePrivateLoopbackArtifactV1 = profile.parse;
export const createPrivateLoopbackArtifactLeaseV1 = profile.createLease;
/** @internal Dedicated private-loopback connector boundary. */
export const unwrapPrivateLoopbackArtifactLeaseV1 = profile.unwrap;

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

function numericLoopbackHostname(hostname: string): boolean {
  if (hostname === "[::1]") return true;
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
  const octets = hostname.split(".").map(Number);
  return octets.every((value) => value >= 0 && value <= 255) && octets[0] === 127;
}

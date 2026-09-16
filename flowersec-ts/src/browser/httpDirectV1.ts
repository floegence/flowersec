import type { RetryDispositionV3 } from "../v3/security.js";
import { createDirectWebSocketProfileV1 } from "./directWebSocketProfileV1.js";

export const HTTP_DIRECT_PROFILE_V1 = "flowersec-http-direct/1";
const DIRECT_PATH = "/flowersec/v3/direct";
export class HTTPDirectArtifactV1 {
  declare private readonly httpDirectArtifactBrand: void;
  private constructor() {}
}
export class HTTPDirectArtifactLeaseV1 {
  declare private readonly httpDirectLeaseBrand: void;
  private constructor() {}
}
export class HTTPDirectArtifactErrorV1 extends Error {
  readonly code = "invalid_artifact";
  constructor() { super("Flowersec HTTP direct artifact is invalid"); this.name = "HTTPDirectArtifactError"; }
}
export type HTTPDirectArtifactSourceResultV1 =
  | Readonly<{ kind: "lease"; lease: HTTPDirectArtifactLeaseV1 }>
  | Readonly<{ kind: "failure"; code: string; disposition: RetryDispositionV3 }>;
export type HTTPDirectArtifactSourceV1 = Readonly<{
  acquire(options: Readonly<{signal: AbortSignal}>): Promise<HTTPDirectArtifactSourceResultV1>;
}>;
const profile = createDirectWebSocketProfileV1<HTTPDirectArtifactV1, HTTPDirectArtifactLeaseV1>({
  profile: HTTP_DIRECT_PROFILE_V1, candidateID: "http-direct",
  validateEndpoint: validateHTTPDirectEndpointV1, error: () => new HTTPDirectArtifactErrorV1(),
});
export const parseHTTPDirectArtifactV1 = profile.parse;
export const createHTTPDirectArtifactLeaseV1 = profile.createLease;
/** @internal Explicit public HTTP connector boundary. */
export const unwrapHTTPDirectArtifactLeaseV1 = profile.unwrap;

export function validateHTTPDirectOriginV1(raw: string): string {
  const url = new URL(raw);
  if (raw !== url.origin || url.protocol !== "http:" || url.username || url.password) throw new HTTPDirectArtifactErrorV1();
  url.protocol = "ws:";
  url.pathname = DIRECT_PATH;
  validateHTTPDirectEndpointV1(url.href);
  return raw;
}

function validateHTTPDirectEndpointV1(raw: string): string {
  const url = new URL(raw);
  const port = url.port === "" ? 80 : Number(url.port);
  if (url.href !== raw || url.protocol !== "ws:" || url.username || url.password || url.search || url.hash ||
      raw.includes("%") || url.pathname !== DIRECT_PATH || !Number.isSafeInteger(port) || port < 1 || port > 65_535 ||
      !allowedHost(url.hostname)) throw new HTTPDirectArtifactErrorV1();
  return raw;
}
function allowedHost(host: string): boolean {
  if (host === "localhost") return true;
  if (host.startsWith("[")) {
    return host !== "[::]" && !/^\[(?:ff|fe[89ab]|::ffff:)/i.test(host);
  }
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((part) => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)) return false;
  const octets = parts.map(Number);
  return host !== "0.0.0.0" && host !== "255.255.255.255" &&
    !(octets[0]! >= 224 && octets[0]! <= 239) && !(octets[0] === 169 && octets[1] === 254);
}

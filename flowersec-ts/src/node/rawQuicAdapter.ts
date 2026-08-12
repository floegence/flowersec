import { X509Certificate, createPrivateKey } from "node:crypto";

import type { ArtifactV2, CanonicalArtifactCandidateV2 } from "../v2/artifact.js";
import type { NativeCarrierSessionV2 } from "../v2/carrier.js";
import type {
  NativeRawQuicDriver,
  NativeRawQuicConnectOptions,
} from "./nativeTransportAddon.js";

const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;
const CERTIFICATE_PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
const CERTIFICATE_PEM_END = "-----END CERTIFICATE-----";
const MAX_CERTIFICATE_PEM_BYTES = 256 * 1024;
const MAX_CERTIFICATE_CHAIN_LENGTH = 32;

export type RawQuicTLSOptions = Readonly<{
  ca: string | Uint8Array | readonly (string | Uint8Array)[];
}>;

export async function createNodeRawQuicClientV2(
  driver: NativeRawQuicDriver,
  candidate: CanonicalArtifactCandidateV2,
  artifact: ArtifactV2,
  tls: RawQuicTLSOptions,
  signal: AbortSignal,
  handshakeTimeoutMs = DEFAULT_HANDSHAKE_TIMEOUT_MS,
): Promise<NativeCarrierSessionV2> {
  const url = new URL(candidate.normalized_url);
  if (candidate.carrier !== "raw_quic" || url.protocol !== "quic:" || url.port === "") {
    throw new TypeError("invalid raw QUIC candidate");
  }
  const options: NativeRawQuicConnectOptions = {
    host: unbracket(url.hostname),
    port: Number(url.port),
    serverName: unbracket(url.hostname),
    path: artifact.path.kind,
    trustRootsDer: normalizeCertificateChain(tls.ca),
    inboundBidirectionalStreamCapacity: artifact.session.max_inbound_streams + 2,
    handshakeTimeoutMs,
  };
  return await driver.connectRawQuic(options, { signal });
}

export function normalizeCertificateChain(
  input: string | Uint8Array | readonly (string | Uint8Array)[],
): readonly Uint8Array[] {
  const values = Array.isArray(input) ? input : [input];
  const certificates: Uint8Array[] = [];
  let totalInputBytes = 0;
  for (const value of values) {
    if (typeof value !== "string" && !(value instanceof Uint8Array)) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    totalInputBytes += typeof value === "string" ? Buffer.byteLength(value, "utf8") : value.byteLength;
    if (totalInputBytes > MAX_CERTIFICATE_PEM_BYTES) throw new TypeError("invalid raw QUIC certificate");
    if (typeof value === "string") {
      const blocks = splitCertificatePEM(value);
      if (blocks.length === 0) throw new TypeError("invalid raw QUIC certificate");
      if (certificates.length + blocks.length > MAX_CERTIFICATE_CHAIN_LENGTH) {
        throw new TypeError("invalid raw QUIC certificate");
      }
      for (const block of blocks) certificates.push(parseCertificate(block));
    } else if (value instanceof Uint8Array && value.length > 0) {
      if (certificates.length >= MAX_CERTIFICATE_CHAIN_LENGTH) throw new TypeError("invalid raw QUIC certificate");
      certificates.push(parseCertificate(value));
    } else {
      throw new TypeError("invalid raw QUIC certificate");
    }
  }
  if (certificates.length === 0) throw new TypeError("raw QUIC requires explicit trust roots");
  return certificates;
}

function splitCertificatePEM(value: string): readonly string[] {
  if (Buffer.byteLength(value, "utf8") > MAX_CERTIFICATE_PEM_BYTES) {
    throw new TypeError("invalid raw QUIC certificate");
  }
  const blocks: string[] = [];
  let cursor = 0;
  while (cursor < value.length) {
    const begin = value.indexOf(CERTIFICATE_PEM_BEGIN, cursor);
    if (begin < 0) {
      if (value.slice(cursor).trim().length !== 0) throw new TypeError("invalid raw QUIC certificate");
      break;
    }
    if (value.slice(cursor, begin).trim().length !== 0) throw new TypeError("invalid raw QUIC certificate");
    const contentStart = begin + CERTIFICATE_PEM_BEGIN.length;
    const end = value.indexOf(CERTIFICATE_PEM_END, contentStart);
    if (end < 0 || value.indexOf(CERTIFICATE_PEM_BEGIN, contentStart) >= 0 && value.indexOf(CERTIFICATE_PEM_BEGIN, contentStart) < end) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    blocks.push(value.slice(begin, end + CERTIFICATE_PEM_END.length));
    if (blocks.length > MAX_CERTIFICATE_CHAIN_LENGTH) throw new TypeError("invalid raw QUIC certificate");
    cursor = end + CERTIFICATE_PEM_END.length;
  }
  return blocks;
}

export function normalizePrivateKey(input: string | Uint8Array): Uint8Array {
  if ((typeof input === "string" && input.length === 0) ||
    (input instanceof Uint8Array && input.length === 0)) {
    throw new TypeError("invalid raw QUIC private key");
  }
  try {
    const key = createPrivateKey(input);
    return new Uint8Array(key.export({ format: "der", type: "pkcs8" }));
  } catch {
    throw new TypeError("invalid raw QUIC private key");
  }
}

function parseCertificate(input: string | Uint8Array): Uint8Array {
  try {
    return new Uint8Array(new X509Certificate(input).raw);
  } catch {
    throw new TypeError("invalid raw QUIC certificate");
  }
}

function unbracket(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

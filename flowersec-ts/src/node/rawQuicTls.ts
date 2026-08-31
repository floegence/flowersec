import { X509Certificate, createPrivateKey } from "node:crypto";

const CERTIFICATE_PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
const CERTIFICATE_PEM_END = "-----END CERTIFICATE-----";
const MAX_CERTIFICATE_PEM_BYTES = 256 * 1024;
const MAX_CERTIFICATE_CHAIN_LENGTH = 32;

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
    totalInputBytes += typeof value === "string"
      ? Buffer.byteLength(value, "utf8")
      : value.byteLength;
    if (totalInputBytes > MAX_CERTIFICATE_PEM_BYTES) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    if (typeof value === "string") {
      const blocks = splitCertificatePEM(value);
      if (blocks.length === 0 || certificates.length + blocks.length > MAX_CERTIFICATE_CHAIN_LENGTH) {
        throw new TypeError("invalid raw QUIC certificate");
      }
      for (const block of blocks) certificates.push(parseCertificate(block));
    } else if (value.length > 0) {
      if (certificates.length >= MAX_CERTIFICATE_CHAIN_LENGTH) {
        throw new TypeError("invalid raw QUIC certificate");
      }
      certificates.push(parseCertificate(value));
    } else {
      throw new TypeError("invalid raw QUIC certificate");
    }
  }
  if (certificates.length === 0) {
    throw new TypeError("raw QUIC requires explicit trust roots");
  }
  return certificates;
}

export function normalizePrivateKey(input: string | Uint8Array): Uint8Array {
  if (input.length === 0) throw new TypeError("invalid raw QUIC private key");
  try {
    const key = createPrivateKey(input);
    return new Uint8Array(key.export({ format: "der", type: "pkcs8" }));
  } catch {
    throw new TypeError("invalid raw QUIC private key");
  }
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
      if (value.slice(cursor).trim().length !== 0) {
        throw new TypeError("invalid raw QUIC certificate");
      }
      break;
    }
    if (value.slice(cursor, begin).trim().length !== 0) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    const contentStart = begin + CERTIFICATE_PEM_BEGIN.length;
    const end = value.indexOf(CERTIFICATE_PEM_END, contentStart);
    const nested = value.indexOf(CERTIFICATE_PEM_BEGIN, contentStart);
    if (end < 0 || nested >= 0 && nested < end) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    blocks.push(value.slice(begin, end + CERTIFICATE_PEM_END.length));
    if (blocks.length > MAX_CERTIFICATE_CHAIN_LENGTH) {
      throw new TypeError("invalid raw QUIC certificate");
    }
    cursor = end + CERTIFICATE_PEM_END.length;
  }
  return blocks;
}

function parseCertificate(input: string | Uint8Array): Uint8Array {
  try {
    return new Uint8Array(new X509Certificate(input).raw);
  } catch {
    throw new TypeError("invalid raw QUIC certificate");
  }
}

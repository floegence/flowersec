import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, u64be } from "../utils/bin.js";

const te = new TextEncoder();

// SessionKeys holds derived C2S/S2C keys and nonce prefixes.
export type SessionKeys = Readonly<{
  c2sKey: Uint8Array; // 32
  s2cKey: Uint8Array; // 32
  c2sNoncePrefix: Uint8Array; // 4
  s2cNoncePrefix: Uint8Array; // 4
  rekeyBase: Uint8Array; // 32
}>;

// deriveSessionKeys expands the shared secret and transcript into session keys.
export function deriveSessionKeys(psk: Uint8Array, sharedSecret: Uint8Array, transcriptHash: Uint8Array): SessionKeys {
  if (psk.length !== 32) throw new Error("psk must be 32 bytes");
  if (transcriptHash.length !== 32) throw new Error("transcript hash must be 32 bytes");

  const ikm = concatBytes([sharedSecret, transcriptHash]);
  const c2sKey = hkdf(sha256, ikm, psk, te.encode("flowersec-e2ee-v1:c2s:key"), 32);
  const s2cKey = hkdf(sha256, ikm, psk, te.encode("flowersec-e2ee-v1:s2c:key"), 32);
  const rekeyBase = hkdf(sha256, ikm, psk, te.encode("flowersec-e2ee-v1:rekey_base"), 32);
  const c2sNoncePrefix = hkdf(sha256, ikm, psk, te.encode("flowersec-e2ee-v1:c2s:nonce_prefix"), 4);
  const s2cNoncePrefix = hkdf(sha256, ikm, psk, te.encode("flowersec-e2ee-v1:s2c:nonce_prefix"), 4);
  return { c2sKey, s2cKey, c2sNoncePrefix, s2cNoncePrefix, rekeyBase };
}

// computeAuthTag authenticates the transcript hash and timestamp.
export function computeAuthTag(psk: Uint8Array, transcriptHash: Uint8Array, timestampUnixS: bigint): Uint8Array {
  if (psk.length !== 32) throw new Error("psk must be 32 bytes");
  if (transcriptHash.length !== 32) throw new Error("transcript hash must be 32 bytes");
  const msg = concatBytes([transcriptHash, u64be(timestampUnixS)]);
  return hmac(sha256, psk, msg);
}

// deriveRekeyKey derives a new record key bound to sequence and direction.
export function deriveRekeyKey(rekeyBase: Uint8Array, transcriptHash: Uint8Array, seq: bigint, dir: number): Uint8Array {
  if (rekeyBase.length !== 32) throw new Error("rekeyBase must be 32 bytes");
  if (transcriptHash.length !== 32) throw new Error("transcript hash must be 32 bytes");
  const msg = concatBytes([transcriptHash, u64be(seq), new Uint8Array([dir & 0xff])]);
  const salt = hmac(sha256, rekeyBase, msg);
  const prkIkm = te.encode("flowersec-e2ee-v1:rekey");
  return hkdf(sha256, prkIkm, salt, te.encode("flowersec-e2ee-v1:rekey:key"), 32);
}

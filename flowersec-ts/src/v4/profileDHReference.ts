import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { transportV4DH as dh } from "../generated/transportV4Registry.js";

// Internal reference over stable private inputs. No production secret export,
// entropy source, key-handle lifecycle or Noise transcript is implemented here.
export function profileDHPublicReference(profile: string, privateKey: Uint8Array): Uint8Array {
  try {
    if (privateKey.length !== dh.PrivateBytes) throw new Error(dh.Failure);
    if (profile === dh.ProfileX25519) return x25519.getPublicKey(privateKey);
    if (profile === dh.ProfileP256) return p256.getPublicKey(privateKey, false);
  } catch { /* Map library details to the single reference failure. */ }
  throw new Error(dh.Failure);
}

export function profileDHReference(profile: string, privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  try {
    if (privateKey.length !== dh.PrivateBytes) throw new Error(dh.Failure);
    let shared: Uint8Array;
    if (profile === dh.ProfileX25519 && publicKey.length === dh.X25519PublicBytes) {
      // Noble uses a private RFC7748 computation view; original bytes survive.
      shared = x25519.getSharedSecret(privateKey, publicKey);
    } else if (profile === dh.ProfileP256 && publicKey.length === dh.P256PublicBytes && publicKey[0] === 4) {
      // The public API returns SEC1 uncompressed. DH is its 32-byte x field.
      shared = p256.getSharedSecret(privateKey, publicKey, false).slice(1, 33);
    } else throw new Error(dh.Failure);
    let nonzero = 0;
    for (const byte of shared) nonzero |= byte;
    if (shared.length === dh.SecretBytes && nonzero !== 0) return shared;
    shared.fill(0);
  } catch { /* No input normalization, alternative algorithm or retry. */ }
  throw new Error(dh.Failure);
}

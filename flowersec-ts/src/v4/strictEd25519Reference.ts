import { ed25519 } from "@noble/curves/ed25519.js";
import { transportV4StrictEd25519Policy as policy } from "../generated/transportV4Registry.js";

// Reference-only acceptance adapter over SDK-private, stable bytes. This is not
// a public key handle, credential validator, work reservation or runtime gate.
// Both points are checked because Noble verifies the cofactored equation.
export function strictEd25519Reference(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (publicKey.length !== policy.public_key_bytes || signature.length !== policy.signature_bytes) return false;
  try {
    for (const encoded of [publicKey, signature.subarray(0, policy.point_bytes)]) {
      const point = ed25519.Point.fromBytes(encoded, false);
      if (point.is0() || !point.isTorsionFree()) return false;
      const canonical = point.toBytes();
      if (!canonical.every((byte, index) => byte === encoded[index])) return false;
    }
    // Noble's scalar multiplication rejects S >= L without reducing S. After
    // both subgroup checks, multiplication by the cofactor is injective, so
    // its equation has the same acceptance set as the uncofactored equation.
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

export function strictEd25519SignReference(message: Uint8Array, seed: Uint8Array): Uint8Array {
  try {
    const signature = ed25519.sign(message, seed);
    if (strictEd25519Reference(signature, message, ed25519.getPublicKey(seed))) return signature;
  } catch {
    // One stable failure. Never change the message, key or signature mode.
  }
  throw new Error(policy.signing_failure);
}

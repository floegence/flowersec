import { ed25519 } from "@noble/curves/ed25519.js";

// This primitive is called only with SDK-owned bytes in an admitted, bounded
// verification/signing job. It neither resolves trust nor caches inputs.
// Noble's default/cofactored verification alone is not the Flowersec predicate.
// Both points are explicitly canonical, nonidentity members of the order-L
// subgroup; on that subgroup multiplication by eight is invertible, so the
// library's cofactored equality is equivalent to the required equality.
export function verifyEd25519(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  try {
    let scalar = 0n;
    for (let i = 63; i >= 32; i--) scalar = scalar * 256n + BigInt(signature[i]!);
    if (scalar >= ed25519.Point.Fn.ORDER) return false;
    for (const bytes of [publicKey, signature.subarray(0, 32)]) {
      const point = ed25519.Point.fromBytes(bytes, false);
      if (point.is0() || !point.isTorsionFree()) return false;
      const encoded = point.toBytes();
      let different = 0;
      for (let i = 0; i < 32; i++) different |= encoded[i]! ^ bytes[i]!;
      encoded.fill(0);
      if (different !== 0) return false;
    }
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch { return false; }
}

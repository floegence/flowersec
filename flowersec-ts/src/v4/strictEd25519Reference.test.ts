import { readFileSync } from "node:fs";
import { ed25519, ED25519_TORSION_SUBGROUP } from "@noble/curves/ed25519.js";
import type * as Ed25519Library from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { describe, expect, it, vi } from "vitest";
import { strictEd25519Reference, strictEd25519SignReference } from "./strictEd25519Reference.js";
import { transportV4Registry, transportV4StrictEd25519Policy } from "../generated/transportV4Registry.js";

vi.mock("@noble/curves/ed25519.js", async (importOriginal) => {
  const actual = await importOriginal<typeof Ed25519Library>();
  return { ...actual, ed25519: { ...actual.ed25519, sign: vi.fn(actual.ed25519.sign), getPublicKey: vi.fn(actual.ed25519.getPublicKey) } };
});

const point = ed25519.Point, order = point.Fn.ORDER, message = new Uint8Array([1, 2, 3]);
const hex = (value: string): Uint8Array<ArrayBuffer> => Uint8Array.from(Buffer.from(value, "hex"));
const integer = (bytes: Uint8Array): bigint => {
  let result = 0n;
  for (let index = bytes.length - 1; index >= 0; index--) result = (result << 8n) | BigInt(bytes[index]!);
  return result;
};
const little = (value: bigint): Uint8Array => {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index++) { bytes[index] = Number(value & 255n); value >>= 8n; }
  return bytes;
};
const join = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(Buffer.concat(parts));
const challenge = (r: Uint8Array, a: Uint8Array, m = message): bigint => integer(sha512(join(r, a, m))) % order;
const scalar = 7n, nonce = 11n, publicKey = point.BASE.multiply(scalar), commitment = point.BASE.multiply(nonce);

// Construct adversarial signatures whose cofactored equation is valid. A
// malformed-point corpus alone would not detect missing subgroup predicates.
function cofactoredFixture(a: typeof publicKey, r: typeof commitment, secret = scalar, n = nonce) {
  const key = a.toBytes(), encodedR = r.toBytes();
  const signature = join(encodedR, little((n + challenge(encodedR, key) * secret) % order));
  expect(ed25519.verify(signature, message, key, { zip215: true })).toBe(true);
  return { key, signature };
}

describe("strict Pure Ed25519 reference acceptance", () => {
  const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/strict_signatures.json", import.meta.url), "utf8")) as {
    schema_sha256: string;
    policy_revision: number;
    vectors: { id: string; message_hex: string; public_key_hex: string; signature_hex: string; accept: boolean }[];
  };
  it("v4.strict_ed25519.ts_acceptance: binds the shared corpus to the current schema and policy", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    expect(corpus.policy_revision).toBe(transportV4StrictEd25519Policy.revision);
    expect(corpus.vectors.length).toBeGreaterThan(0);
  });

  // Every original vector keeps its own finite test deadline under parallel
  // language builds. A growing corpus is not one five-second crypto job.
  it.each(corpus.vectors)("preserves original inputs for $id", (vector) => {
    const m = hex(vector.message_hex), key = hex(vector.public_key_hex), signature = hex(vector.signature_hex);
    const before = [m.slice(), key.slice(), signature.slice()];
    expect(strictEd25519Reference(signature, m, key), vector.id).toBe(vector.accept);
    expect([m, key, signature], vector.id).toEqual(before);
    if (!vector.accept) {
      const signer = vi.mocked(ed25519.sign), getPublic = vi.mocked(ed25519.getPublicKey);
      signer.mockClear(); getPublic.mockClear();
      signer.mockReturnValueOnce(signature); getPublic.mockReturnValueOnce(key);
      expect(() => strictEd25519SignReference(m, new Uint8Array(32)), vector.id).toThrow("signature_generation_failed");
      expect(signer).toHaveBeenCalledTimes(1);
      expect(getPublic).toHaveBeenCalledTimes(1);
      expect([m, key, signature], vector.id).toEqual(before);
    }
  });

  it("consumes every current shared signature vector under the stronger predicate", () => {
    const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/signatures.json", import.meta.url), "utf8")) as {
      signing_seed_hex: string;
      vectors: { id: string; message_hex: string; public_key_hex: string; signature_hex: string; accept: boolean }[];
    };
    for (const vector of corpus.vectors) {
      const m = hex(vector.message_hex), key = hex(vector.public_key_hex), signature = hex(vector.signature_hex);
      expect(strictEd25519Reference(signature, m, key), vector.id).toBe(vector.accept);
      if (vector.accept) expect(strictEd25519SignReference(m, hex(corpus.signing_seed_hex))).toEqual(signature);
    }
  });

  it("rejects every torsion class and mixed-order A/R even with a valid cofactored equation", () => {
    for (const encoded of ED25519_TORSION_SUBGROUP) {
      const torsion = point.fromHex(encoded);
      for (const f of [
        cofactoredFixture(torsion, commitment, 0n),
        cofactoredFixture(publicKey, torsion, scalar, 0n),
      ]) expect(strictEd25519Reference(f.signature, message, f.key), encoded).toBe(false);
      if (torsion.is0()) continue;
      for (const f of [
        cofactoredFixture(publicKey.add(torsion), commitment),
        cofactoredFixture(publicKey, commitment.add(torsion)),
      ]) {
        expect(ed25519.verify(f.signature, message, f.key, { zip215: false })).toBe(true);
        expect(strictEd25519Reference(f.signature, message, f.key), encoded).toBe(false);
      }
    }
  });

  it("checks the full uncofactored equation without implicit prehash or context", () => {
    const f = cofactoredFixture(publicKey, commitment);
    expect(strictEd25519Reference(f.signature, message, f.key)).toBe(true);
    const s = integer(f.signature.subarray(32));
    expect(point.BASE.multiplyUnsafe(s).equals(commitment.add(publicKey.multiplyUnsafe(challenge(commitment.toBytes(), f.key))))).toBe(true);
    expect(strictEd25519Reference(f.signature, sha512(message), f.key)).toBe(false);
    expect(strictEd25519Reference(f.signature, join(message, new Uint8Array([0])), f.key)).toBe(false);
  });

  it("rejects S=L and S+L without modular normalization", () => {
    const f = cofactoredFixture(publicKey, commitment);
    for (const s of [order, order + integer(f.signature.subarray(32)), (1n << 256n) - 1n]) {
      expect(strictEd25519Reference(join(f.signature.subarray(0, 32), little(s)), message, f.key)).toBe(false);
    }
  });

  it("rejects noncanonical y, negative zero, nonpoints, lengths and tails for both points", () => {
    const f = cofactoredFixture(publicKey, commitment);
    const negativeZero = point.ZERO.toBytes(); negativeZero[31] = negativeZero[31]! | 128;
    const nonpoint = little(2n);
    expect(() => point.fromBytes(nonpoint, false)).toThrow();
    for (const invalid of [little(point.Fp.ORDER), little(point.Fp.ORDER + 1n), negativeZero, nonpoint]) {
      expect(strictEd25519Reference(f.signature, message, invalid)).toBe(false);
      expect(strictEd25519Reference(join(invalid, f.signature.subarray(32)), message, f.key)).toBe(false);
    }
    for (const signature of [f.signature.subarray(0, 63), join(f.signature, new Uint8Array([0]))]) {
      expect(strictEd25519Reference(signature, message, f.key)).toBe(false);
    }
    for (const key of [f.key.subarray(0, 31), join(f.key, new Uint8Array([0]))]) {
      expect(strictEd25519Reference(f.signature, message, key)).toBe(false);
    }
  });

  it("v4.strict_ed25519.signer_failure: fails once and leaves supplied bytes unchanged", () => {
    for (const seed of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33)]) {
      const before = seed.slice(), original = message.slice();
      expect(() => strictEd25519SignReference(message, seed)).toThrow("signature_generation_failed");
      expect(seed).toEqual(before); expect(message).toEqual(original);
    }
    const signer = vi.mocked(ed25519.sign);
    signer.mockClear(); signer.mockReturnValueOnce(new Uint8Array(64));
    expect(() => strictEd25519SignReference(message, new Uint8Array(32))).toThrow("signature_generation_failed");
    expect(signer).toHaveBeenCalledTimes(1);
  });
});

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { strictHex } from "./transport-v4-codec.mjs";

// Fixture construction only, through the SDK's pinned public curve APIs.
// This does not implement a curve or qualify a production verification adapter.
const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { ed25519, ED25519_TORSION_SUBGROUP } = require("@noble/curves/ed25519.js");
const Point = ed25519.Point;
const integer = bytes => BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
const little = value => {
  assert.ok(value >= 0n && value < (1n << 256n));
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex").reverse();
};

export function verifyStrictEd25519Plan(schema) {
  assert.deepEqual(schema.strict_ed25519_policy, {
    revision: 1, source: "3.5.1", algorithm: "PureEd25519",
    public_key_bytes: 32, signature_bytes: 64, point_bytes: 32,
    point_encoding: "rfc8032_canonical_roundtrip",
    public_key_group: "nonidentity_prime_order",
    commitment_group: "nonidentity_prime_order",
    scalar_encoding: "little_endian_less_than_L",
    equation: "uncofactored", implicit_prehash: false,
    signing_failure: "signature_generation_failed",
  });
  const plan = schema.strict_ed25519_vector_plan;
  assert.equal(plan.status, "public_fixture_scalars_only");
  assert.equal(plan.library, "@noble/curves@2.4.0");
  assert.deepEqual(plan.torsion_indices, [0, 1, 2, 3, 4, 5, 6, 7]);
  for (const name of ["scalar", "nonce"]) {
    assert.match(plan[name], /^[1-9][0-9]*$/u);
    assert.ok(BigInt(plan[name]) < Point.Fn.ORDER);
  }
  assert.ok(strictHex(plan.message_hex).length > 0);
}

export function buildStrictEd25519Corpus(schema, signatures) {
  verifyStrictEd25519Plan(schema);
  const plan = schema.strict_ed25519_vector_plan, order = Point.Fn.ORDER;
  const message = strictHex(plan.message_hex), scalar = BigInt(plan.scalar), nonce = BigInt(plan.nonce);
  const a = Point.BASE.multiply(scalar), r = Point.BASE.multiply(nonce);
  const vectors = signatures.vectors.map(v => ({ ...v, id: "strict_" + v.id, source_signature: v.id }));
  function fixture(id, pointA, pointR, secret, random, accept, reason) {
    const key = pointA.toBytes(), encodedR = pointR.toBytes();
    const challenge = integer(createHash("sha512").update(encodedR).update(key).update(message).digest()) % order;
    const signature = Buffer.concat([encodedR, little((random + challenge * secret) % order)]);
    assert.ok(ed25519.verify(signature, message, key, { zip215: true }), id + ": not a cofactored witness");
    const vector = { id, domain: null, message_hex: message.toString("hex"), public_key_hex: Buffer.from(key).toString("hex"), signature_hex: signature.toString("hex"), accept, reason, cofactored_valid: true };
    vectors.push(vector);
    return vector;
  }
  const valid = fixture("strict_public_scalar_valid", a, r, scalar, nonce, true, "prime_order_equation");
  for (const index of plan.torsion_indices) {
    const torsion = Point.fromHex(ED25519_TORSION_SUBGROUP[index]);
    assert.ok(torsion.multiplyUnsafe(8n).is0());
    fixture("strict_A_torsion_" + index, torsion, r, 0n, nonce, false, torsion.is0() ? "A_identity" : "A_small_order");
    fixture("strict_R_torsion_" + index, a, torsion, scalar, 0n, false, torsion.is0() ? "R_identity" : "R_small_order");
    if (!torsion.is0()) {
      fixture("strict_A_mixed_" + index, a.add(torsion), r, scalar, nonce, false, "A_mixed_order");
      fixture("strict_R_mixed_" + index, a, r.add(torsion), scalar, nonce, false, "R_mixed_order");
    }
  }
  function mutate(id, changes, reason) {
    vectors.push({ ...valid, id, ...changes, accept: false, reason, cofactored_valid: undefined });
  }
  const negativeZero = Buffer.from(Point.ZERO.toBytes()); negativeZero[31] |= 128;
  const nonpoint = little(2n);
  assert.throws(() => Point.fromBytes(nonpoint, false));
  for (const [name, bytes] of [["y_eq_p", little(Point.Fp.ORDER)], ["y_above_p", little(Point.Fp.ORDER + 1n)], ["negative_zero", negativeZero], ["nonpoint", nonpoint]]) {
    mutate("strict_A_" + name, { public_key_hex: bytes.toString("hex") }, "A_" + name);
    mutate("strict_R_" + name, { signature_hex: bytes.toString("hex") + valid.signature_hex.slice(64) }, "R_" + name);
  }
  for (const [name, s] of [["L", order], ["S_plus_L", integer(strictHex(valid.signature_hex).subarray(32)) + order], ["maximum", (1n << 256n) - 1n]]) {
    mutate("strict_scalar_" + name.toLowerCase(), { signature_hex: valid.signature_hex.slice(0, 64) + little(s).toString("hex") }, "scalar_range");
  }
  mutate("strict_no_implicit_prehash", { message_hex: createHash("sha512").update(message).digest("hex") }, "message");
  const positiveDomains = signatures.vectors.filter(v => v.accept && v.domain !== null);
  for (const vector of positiveDomains) {
    const other = positiveDomains.find(v => v.domain !== vector.domain);
    assert.ok(other, "at least two independent signature domains required");
    vectors.push({ ...vector, id: "strict_wrong_domain_" + vector.id, message_hex: other.message_hex, accept: false, reason: "domain_substitution" });
  }
  assert.equal(new Set(vectors.map(v => v.id)).size, vectors.length);
  return {
    schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    policy_revision: schema.strict_ed25519_policy.revision,
    qualification: "strict_acceptance_reference_vectors_only",
    unverified: ["Independent four-library strict acceptance and signer output gates", "Independent cryptographic adapter equivalence review", "Trusted issuer chains, all runtime signing entries, cache and work ownership", "Noise/post-handshake composition and provider interoperability"],
    vectors,
  };
}

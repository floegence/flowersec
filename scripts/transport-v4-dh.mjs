import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { strictHex } from "./transport-v4-codec.mjs";

// Public, deterministic fixtures only. These primitive operations do not
// implement Noise, certify key handles or confer handshake completion rights.
const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { x25519 } = require("@noble/curves/ed25519.js");
const { p256 } = require("@noble/curves/nist.js");
const hex = bytes => Buffer.from(bytes).toString("hex");
const be = value => Buffer.from(value.toString(16).padStart(64, "0"), "hex");
const le = value => be(value).reverse();

export function verifyDHPolicy(schema) {
  assert.deepEqual(schema.profile_dh_policy, {
    revision: 1, source: "3.5.1", private_bytes: 32, secret_bytes: 32,
    failure: "dh_failed", reject_zero_result: true, mutate_inputs: false,
    x25519: { algorithm: 0, public_bytes: 32, remote: "exact_bytes_rfc7748",
      local: "canonical_rfc7748", scalar: "rfc7748_clamp", transcript: "original_bytes" },
    p256: { algorithm: 1, public_bytes: 65, remote: "canonical_sec1_uncompressed_on_curve",
      local: "canonical_sec1_uncompressed_on_curve", scalar: "big_endian_1_to_n_minus_1",
      secret: "big_endian_x_coordinate" },
  });
  for (const kind of ["x25519", "p256"]) {
    const policy = schema.profile_dh_policy[kind];
    const profiles = Object.entries(schema.crypto_profiles).filter(([, p]) => p.dh_algorithm === policy.algorithm);
    assert.equal(profiles.length, 1);
    assert.equal(profiles[0][1].dh_public_bytes, policy.public_bytes);
    assert.equal(profiles[0][1].dh_secret_bytes, schema.profile_dh_policy.secret_bytes);
  }
  const plan = schema.profile_dh_vector_plan;
  assert.equal(plan.library, "@noble/curves@2.4.0");
  assert.equal(plan.status, "public_fixture_material_only");
  assert.equal(plan.rfc7748.length, 2);
  for (const fixture of plan.rfc7748) {
    for (const field of ["private_hex", "public_hex", "shared_hex"]) assert.equal(strictHex(fixture[field]).length, 32);
  }
  assert.equal(strictHex(plan.x25519_private_hex).length, 32);
}

export function buildDHCorpus(schema) {
  verifyDHPolicy(schema);
  const policy = schema.profile_dh_policy, plan = schema.profile_dh_vector_plan;
  const profile = kind => Object.entries(schema.crypto_profiles).find(([, p]) => p.dh_algorithm === policy[kind].algorithm)[0];
  const vectors = [], keys = [];
  function derive(kind, privateKey, publicKey) {
    assert.equal(privateKey.length, policy.private_bytes);
    assert.equal(publicKey.length, policy[kind].public_bytes);
    if (kind === "p256") assert.equal(publicKey[0], 4);
    const shared = kind === "x25519" ? x25519.getSharedSecret(privateKey, publicKey)
      : p256.getSharedSecret(privateKey, publicKey, false).slice(1, 33);
    assert.equal(shared.length, policy.secret_bytes);
    assert.ok(shared.some(byte => byte !== 0));
    return shared;
  }
  function add(id, kind, privateKey, publicKey, accept, extras = {}) {
    let shared;
    if (accept) shared = derive(kind, privateKey, publicKey);
    else assert.throws(() => derive(kind, privateKey, publicKey), id);
    const vector = { id, profile: profile(kind), private_hex: hex(privateKey), public_hex: hex(publicKey),
      accept, shared_hex: shared ? hex(shared) : null, ...extras };
    vectors.push(vector);
    return vector;
  }
  function key(id, kind, material, accept) {
    let publicKey;
    if (accept) {
      assert.equal(material.length, policy.private_bytes);
      publicKey = kind === "x25519" ? x25519.getPublicKey(material) : p256.getPublicKey(material, false);
    } else assert.throws(() => {
      assert.equal(material.length, policy.private_bytes);
      return kind === "x25519" ? x25519.getPublicKey(material) : p256.getPublicKey(material, false);
    });
    keys.push({ id, profile: profile(kind), private_hex: hex(material), accept,
      public_hex: publicKey ? hex(publicKey) : null });
  }
  for (const [index, fixture] of plan.rfc7748.entries()) {
    const v = add(`dh_x_rfc7748_${index + 1}`, "x25519", strictHex(fixture.private_hex), strictHex(fixture.public_hex), true, { source: "RFC7748-5.2" });
    assert.equal(v.shared_hex, fixture.shared_hex);
  }
  const scalar = strictHex(plan.x25519_private_hex), prime = (1n << 255n) - 19n;
  // Four encodings for each residue cover the entire noncanonical interval
  // and the independent high-bit rule. They are distinct original inputs.
  for (let residue = 0n; residue < 19n; residue++) {
    for (const [name, value] of [["canonical", residue], ["high", residue + (1n << 255n)],
      ["noncanonical", prime + residue], ["noncanonical_high", prime + residue + (1n << 255n)]]) {
      add(`dh_x_u_${residue}_${name}`, "x25519", scalar, le(value), residue > 1n,
        { equivalence_group: `u_${residue}`, reason: residue > 1n ? "rfc7748_equivalent" : "zero_shared_secret" });
    }
  }
  // Remaining low-order representatives, on the curve and its twist.
  for (const [index, value] of [prime - 1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n].entries()) {
    for (const high of [0n, 1n]) add(`dh_x_low_${index}_${high}`, "x25519", scalar, le(value + (high << 255n)), false,
      { reason: "zero_shared_secret" });
  }
  for (const [name, material] of [["zero", Buffer.alloc(32)], ["maximum", Buffer.alloc(32, 255)], ["fixture", scalar]]) {
    key(`dh_key_x_${name}`, "x25519", material, true);
    add(`dh_x_scalar_${name}`, "x25519", material, le(9n), true);
  }
  const alias = Buffer.from(scalar); alias[0] ^= 7; alias[31] ^= 192;
  key("dh_key_x_clamp_alias", "x25519", alias, true);
  assert.equal(keys.at(-1).public_hex, keys.at(-2).public_hex);

  const one = be(1n), two = be(2n), order = p256.Point.Fn.ORDER;
  const publicOne = p256.getPublicKey(one, false), publicTwo = p256.getPublicKey(two, false);
  add("dh_p_one_two", "p256", one, publicTwo, true);
  add("dh_p_two_one", "p256", two, publicOne, true);
  assert.equal(vectors.at(-1).shared_hex, vectors.at(-2).shared_hex);
  for (const [name, material] of [["one", one], ["two", two], ["order_minus_one", be(order - 1n)]]) key(`dh_key_p_${name}`, "p256", material, true);
  // A valid P-256 point with x=0 makes a real, on-curve ECDH result zero for
  // scalar 1. This distinguishes the result gate from public-point validation.
  const zeroX = p256.Point.fromBytes(Buffer.concat([Buffer.from([2]), Buffer.alloc(32)])).toBytes(false);
  assert.equal(hex(p256.getSharedSecret(one, zeroX, false).slice(1, 33)), "00".repeat(32));
  add("dh_p_zero_result", "p256", one, zeroX, false, { reason: "zero_shared_secret", valid_public_point: true });
  add("dh_p_zero_x_nonzero_result", "p256", two, zeroX, true, { valid_public_point: true });
  for (const [name, material] of [["zero", be(0n)], ["order", be(order)], ["maximum", Buffer.alloc(32, 255)]]) {
    key(`dh_key_p_${name}`, "p256", material, false);
    add(`dh_p_scalar_${name}`, "p256", material, publicOne, false, { reason: "private_scalar" });
  }
  const nonpoint = Buffer.alloc(65); nonpoint[0] = 4;
  const coordinateP = Buffer.from(publicOne); be(p256.Point.Fp.ORDER).copy(coordinateP, 1);
  const coordinateY = Buffer.from(publicOne); be(p256.Point.Fp.ORDER).copy(coordinateY, 33);
  const hybrid = Buffer.from(publicOne); hybrid[0] = 6 | (hybrid[64] & 1);
  for (const [name, encoded] of [["compressed", p256.getPublicKey(one)], ["hybrid", hybrid],
    ["infinity", Buffer.from([0])], ["nonpoint", nonpoint], ["x_eq_p", coordinateP], ["y_eq_p", coordinateY]]) {
    add(`dh_p_${name}`, "p256", one, encoded, false, { reason: "public_encoding" });
  }
  for (const kind of ["x25519", "p256"]) {
    const secret = kind === "x25519" ? scalar : one;
    const publicKey = kind === "x25519" ? le(9n) : publicOne;
    for (const length of [0, 31, 33]) {
      key(`dh_key_${kind}_length_${length}`, kind, Buffer.alloc(length, 1), false);
      add(`dh_${kind}_private_length_${length}`, kind, Buffer.alloc(length, 1), publicKey, false, { reason: "private_length" });
    }
    for (const length of [0, publicKey.length - 1, publicKey.length + 1]) {
      const encoded = Buffer.alloc(length); publicKey.copy ? publicKey.copy(encoded) : encoded.set(publicKey.slice(0, length));
      add(`dh_${kind}_public_length_${length}`, kind, secret, encoded, false, { reason: "public_length" });
    }
  }
  for (const cases of [vectors, keys]) assert.equal(new Set(cases.map(v => v.id)).size, cases.length);
  return { schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    policy_revision: policy.revision, qualification: "profile_dh_reference_only",
    unverified: ["Noise tokens and original transcript binding", "Key handles, entropy, cancellation and runtime ownership", "Independent cryptographic review and provider interoperability"],
    vectors, keys };
}

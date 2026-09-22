import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifyDHPolicy } from "./transport-v4-dh.mjs";

const { schema, files, manifest } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/profile_dh.json"));
const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { p256 } = require("@noble/curves/nist.js");
const { pow } = require("@noble/curves/abstract/modular.js");

test("v4.profile_dh.policy: policy drift and profile length conflation fail", () => {
  for (const field of Object.keys(schema.profile_dh_policy)) {
    const changed = structuredClone(schema); changed.profile_dh_policy[field] = null;
    assert.throws(() => verifyDHPolicy(changed), field);
  }
  for (const kind of ["x25519", "p256"]) {
    for (const field of Object.keys(schema.profile_dh_policy[kind])) {
      const changed = structuredClone(schema); changed.profile_dh_policy[kind][field] = null;
      assert.throws(() => verifyDHPolicy(changed), `${kind}.${field}`);
    }
  }
  const changed = structuredClone(schema);
  Object.values(changed.crypto_profiles).find(p => p.dh_algorithm === 1).dh_secret_bytes = 65;
  assert.throws(() => verifyDHPolicy(changed));
});

test("v4.profile_dh.x25519: all aliases retain their distinct original encodings", () => {
  for (let residue = 0; residue < 19; residue++) {
    const group = corpus.vectors.filter(v => v.equivalence_group === `u_${residue}`);
    assert.equal(group.length, 4);
    assert.equal(new Set(group.map(v => v.public_hex)).size, 4);
    assert.equal(new Set(group.map(v => v.shared_hex)).size, 1);
    assert.ok(group.every(v => v.accept === (residue > 1)));
  }
  // The Montgomery RHS at u=2 is a quadratic non-residue: a real twist input.
  const p = (1n << 255n) - 19n, u = 2n;
  assert.equal(pow((u ** 3n + 486662n * u ** 2n + u) % p, (p - 1n) / 2n, p), p - 1n);
  assert.ok(corpus.vectors.find(v => v.id === "dh_x_u_2_canonical").accept);
  for (const v of corpus.keys.filter(v => v.id.startsWith("dh_key_x_") && v.accept)) {
    const publicKey = Buffer.from(v.public_hex, "hex");
    assert.equal(publicKey.length, 32);
    assert.equal(publicKey[31] & 128, 0);
    assert.ok(BigInt("0x" + Buffer.from(publicKey).reverse().toString("hex")) < p);
  }
});

test("v4.profile_dh.p256: a valid public point can produce a forbidden zero result", () => {
  const zero = corpus.vectors.find(v => v.id === "dh_p_zero_result");
  const accepted = corpus.vectors.find(v => v.id === "dh_p_zero_x_nonzero_result");
  const point = p256.Point.fromHex(zero.public_hex);
  assert.equal(point.is0(), false);
  assert.equal(zero.accept, false);
  assert.equal(zero.valid_public_point, true);
  assert.equal(accepted.public_hex, zero.public_hex);
  assert.equal(accepted.accept, true);
  assert.notEqual(accepted.shared_hex, "00".repeat(32));
  for (const v of corpus.keys.filter(v => v.profile.includes("p256") && v.accept)) {
    const key = Buffer.from(v.public_hex, "hex");
    assert.equal(key.length, 65); assert.equal(key[0], 4);
    assert.equal(Buffer.from(p256.Point.fromBytes(key).toBytes(false)).toString("hex"), v.public_hex);
  }
});

test("v4.profile_dh.coverage: corpus and generated adapters bind the shared schema", () => {
  assert.equal(corpus.schema_sha256, manifest.schema_sha256);
  assert.equal(corpus.policy_revision, schema.profile_dh_policy.revision);
  assert.deepEqual(manifest.dh_vectors.map(v => v.id), [...corpus.vectors, ...corpus.keys].map(v => v.id));
  const policy = JSON.stringify(schema.profile_dh_policy);
  for (const file of ["flowersec-go/internal/protocolv4/registry_generated.go",
    "flowersec-rust/src/protocol_v4_registry_generated.rs", "flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",
    "flowersec-ts/src/generated/transportV4Registry.ts"]) assert.ok(files.get(file).includes(JSON.stringify(policy)), file);
  assert.equal(corpus.vectors.filter(v => v.source === "RFC7748-5.2").length, 2);
  assert.ok(corpus.vectors.some(v => v.reason === "zero_shared_secret" && v.profile.includes("x25519")));
  for (const kind of ["x25519", "p256"]) {
    const cases = corpus.vectors.filter(v => v.profile.includes(kind));
    for (const reason of ["private_length", "public_length"]) assert.equal(cases.filter(v => v.reason === reason).length, 3);
  }
});

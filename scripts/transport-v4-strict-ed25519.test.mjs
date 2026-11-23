import assert from "node:assert/strict";
import test from "node:test";
import { createRequire } from "node:module";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifyStrictEd25519Plan } from "./transport-v4-strict-ed25519.mjs";

const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { ed25519 } = require("@noble/curves/ed25519.js");
const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/strict_signatures.json"));

test("v4.strict_ed25519.policy: all predicate changes fail the exact schema audit", () => {
  for (const field of Object.keys(schema.strict_ed25519_policy)) {
    const changed = structuredClone(schema);
    changed.strict_ed25519_policy[field] = null;
    assert.throws(() => verifyStrictEd25519Plan(changed), field);
  }
  for (const field of ["scalar", "nonce"]) {
    for (const bad of ["0", "-1", "1.5", "01", ed25519.Point.Fn.ORDER.toString()]) {
      const changed = structuredClone(schema);
      changed.strict_ed25519_vector_plan[field] = bad;
      assert.throws(() => verifyStrictEd25519Plan(changed));
    }
  }
});

test("v4.strict_ed25519.torsion: all eight classes have valid cofactored witnesses", () => {
  const witnesses = corpus.vectors.filter(v => v.cofactored_valid);
  assert.equal(witnesses.length, 31);
  for (const vector of witnesses) {
    const signature = Buffer.from(vector.signature_hex, "hex"), key = Buffer.from(vector.public_key_hex, "hex");
    assert.ok(ed25519.verify(signature, Buffer.from(vector.message_hex, "hex"), key, { zip215: true }), vector.id);
    const a = ed25519.Point.fromBytes(key, false), r = ed25519.Point.fromBytes(signature.subarray(0, 32), false);
    const strictPoints = !a.is0() && a.isTorsionFree() && !r.is0() && r.isTorsionFree();
    assert.equal(strictPoints, vector.accept, vector.id);
    if (vector.reason.endsWith("mixed_order")) {
      assert.ok(ed25519.verify(signature, Buffer.from(vector.message_hex, "hex"), key, { zip215: false }), vector.id);
    }
  }
  for (const side of ["A", "R"]) {
    for (let i = 0; i < 8; i++) assert.ok(witnesses.some(v => v.id === `strict_${side}_torsion_${i}`));
    assert.equal(witnesses.filter(v => v.id.startsWith(`strict_${side}_mixed_`)).length, 7);
  }
});

test("v4.strict_ed25519.coverage: domain inputs, malformed points and outputs bind to one manifest", () => {
  const signatures = JSON.parse(files.get("testdata/transport_v4/signatures.json"));
  assert.equal(corpus.schema_sha256, signatures.schema_sha256);
  assert.equal(corpus.policy_revision, schema.strict_ed25519_policy.revision);
  assert.deepEqual(corpus.vectors.filter(v => v.source_signature).map(v => v.source_signature), signatures.vectors.map(v => v.id));
  for (const side of ["A", "R"]) for (const kind of ["y_eq_p", "y_above_p", "negative_zero", "nonpoint"]) {
    assert.ok(corpus.vectors.some(v => v.id === `strict_${side}_${kind}` && !v.accept));
  }
  for (const domain of schema.domains.filter(d => d.operation === "ed25519")) {
    assert.ok(corpus.vectors.some(v => v.domain === domain.name && v.accept));
    assert.ok(corpus.vectors.some(v => v.domain === domain.name && v.reason === "domain_substitution" && !v.accept));
  }
  const manifest = JSON.parse(files.get("testdata/transport_v4/manifest.json"));
  assert.deepEqual(manifest.strict_signature_vectors.map(v => v.id), corpus.vectors.map(v => v.id));
  const policy = JSON.stringify(schema.strict_ed25519_policy);
  for (const path of ["flowersec-go/internal/protocolv4/registry_generated.go", "flowersec-rust/src/protocol_v4_registry_generated.rs", "flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift"]) {
    assert.ok(files.get(path).includes(JSON.stringify(policy)), path);
  }
  assert.ok(files.get("flowersec-ts/src/generated/transportV4Registry.ts").includes(policy));
});

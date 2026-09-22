import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { recordUsageReference, verifyCryptoUsageRegistry } from "./transport-v4-crypto-usage.mjs";
import { VectorError } from "./transport-v4-codec.mjs";

const { schema, files, manifest } = buildArtifacts();
const profiles = Object.keys(schema.crypto_usage_registry.profiles);
const fail = (fn, code) => assert.throws(fn, error => error instanceof VectorError && error.code === code);

test("v4.crypto_usage.registry: fixed profile-specific caps and common charge declarations", () => {
  verifyCryptoUsageRegistry(schema);
  for (const profile of profiles) {
    for (const scope of ["key", "epoch", "session"]) for (const field of Object.keys(schema.crypto_usage_registry.profiles[profile][scope])) {
      const altered = structuredClone(schema); altered.crypto_usage_registry.profiles[profile][scope][field] = "0";
      assert.throws(() => verifyCryptoUsageRegistry(altered));
    }
    for (const field of ["root_max_age_ms", "max_epochs", "max_record_key_derivations"]) {
      const altered = structuredClone(schema); delete altered.crypto_usage_registry.profiles[profile][field];
      assert.throws(() => verifyCryptoUsageRegistry(altered));
    }
  }
  const corpus = JSON.parse(files.get("testdata/transport_v4/crypto_usage.json"));
  assert.equal(corpus.vectors.length, 28); assert.equal(manifest.crypto_usage_vectors.length, 28);
  for (const vector of corpus.vectors) {
    if (vector.expected_error) fail(() => recordUsageReference(schema, vector.profile, vector.input), vector.expected_error);
    else assert.deepEqual(recordUsageReference(schema, vector.profile, vector.input), vector.expected);
  }
  for (const path of ["flowersec-go/internal/protocolv4/registry_generated.go", "flowersec-rust/src/protocol_v4_registry_generated.rs",
    "flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", "flowersec-ts/src/generated/transportV4Registry.ts"]) {
    assert.match(files.get(path), /design_fixed_limits_reference_charges_only/u);
    assert.match(files.get(path), /max_record_key_derivations/u);
  }
});

test("v4.crypto_usage.blocks: exact complete authentication inputs at both sides of every block boundary", () => {
  for (const profile of profiles) for (let aad = 0; aad <= 65; aad++) for (let payload = 0; payload <= 65; payload++) {
    const seal = recordUsageReference(schema, profile, { operation: "seal", aad_bytes: String(aad), input_bytes: String(payload) });
    const open = recordUsageReference(schema, profile, { operation: "open", aad_bytes: String(aad), input_bytes: String(payload + 16) });
    assert.deepEqual(seal, open);
    assert.equal(seal.authentication_blocks, String(Math.ceil(aad / 16) + Math.ceil(payload / 16) + 1));
    assert.equal(seal.ciphertext_bytes, String(payload + 16));
    assert.equal(seal.calls, "1");
  }
});

test("v4.crypto_usage.inputs: quantities are bounded primitive strings and inputs cannot invoke hooks", () => {
  let calls = 0;
  const trap = () => { calls++; throw new Error("caller hook"); };
  const input = { operation: "seal", aad_bytes: "0", input_bytes: "0" };
  fail(() => recordUsageReference(schema, { toString: trap }, input), "crypto_usage_profile");
  fail(() => recordUsageReference(schema, profiles[0], new Proxy(input, { getPrototypeOf: trap })), "crypto_usage_input");
  fail(() => recordUsageReference(schema, profiles[0], Object.defineProperty({ ...input }, "aad_bytes", { get: trap })), "crypto_usage_data");
  fail(() => recordUsageReference(schema, profiles[0], { ...input, scope: "key" }), "crypto_usage_fields");
  fail(() => recordUsageReference(schema, profiles[0], { ...input, operation: { toString: trap } }), "crypto_usage_operation");
  for (const value of [0, 0n, true, null, "", "00", "-1", "+1", "1.0", "1\n", "١", "9".repeat(21), { toString: trap }]) {
    for (const field of ["aad_bytes", "input_bytes"]) fail(() => recordUsageReference(schema, profiles[0], { ...input, [field]: value }), "crypto_usage_integer");
  }
  const result = recordUsageReference(schema, profiles[0], input); input.input_bytes = "100";
  assert.ok(Object.isFrozen(result)); assert.equal(result.ciphertext_bytes, "16"); assert.equal(calls, 0);
});

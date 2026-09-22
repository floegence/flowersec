import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeMap, encodeCBOR, VectorError } from "./transport-v4-codec.mjs";
import { deriveRekeyCapacityReference } from "./transport-v4-rekey-capacity.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, field]) => field.name === name)[0]);
const get = (type, map, name) => map.get(key(type, name));
const put = (type, map, name, value) => map.set(key(type, name), value);
const time = { rate_numerator: "1", rate_denominator: "10000", quantization_ms: "2" };
const failure = (fn, code) => assert.throws(fn, error => error instanceof VectorError && error.code === code);
function fixture() {
  const original = Buffer.from(corpus.vectors.find(v => v.id === "artifact_transport_fields").hex, "hex");
  const artifact = decodeMap(schema, "Artifact", original);
  const contract = get("Artifact", artifact, "session_contract"), envelope = get("SessionContract", contract, "rekey_envelope");
  put("Artifact", artifact, "issued_at_ms", 1n);
  put("Artifact", artifact, "initiation_not_after_ms", 100n);
  put("Artifact", artifact, "session_not_after_ms", 86400001n);
  put("RekeyEnvelope", envelope, "burst_rounds", 2n);
  put("RekeyEnvelope", envelope, "refill_period_ms", 30000n);
  put("RekeyEnvelope", envelope, "request_start_budget_ms", 5000n);
  return { artifact, envelope, bytes: () => encodeCBOR(artifact) };
}

test("v4.rekey_capacity.original: derives all capacity parameters from the complete original Artifact", () => {
  for (const profile of Object.keys(schema.crypto_usage_registry.profiles)) {
    const f = fixture(); put("Artifact", f.artifact, "crypto_profile_id", profile);
    // These are structural fixtures, not real signatures or admission evidence.
    const bytes = f.bytes(), before = Buffer.from(bytes), result = deriveRekeyCapacityReference(schema, bytes, time);
    assert.deepEqual(result.service, { service_ms: "86400000", error_allowance_ms: "6", denominator_ms: "29988",
      capacity_credit: "60000", max_rounds: "5765", required_epochs: "5766" });
    assert.equal(result.request_start_budget_ms, "5000");
    const domain = schema.domains.find(item => item.name === "artifact_digest"), length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
    assert.deepEqual(result.artifact_digest, createHash("sha256").update(Buffer.concat([Buffer.from(domain.label_bytes, "hex"), length, bytes])).digest());
    assert.deepEqual(bytes, before); assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.service));
  }
});

test("v4.rekey_capacity.deadlines: short admission and earlier local/root deadlines never reduce responsibility", () => {
  const f = fixture(), expected = deriveRekeyCapacityReference(schema, f.bytes(), time);
  put("Artifact", f.artifact, "initiation_not_after_ms", 2n);
  assert.deepEqual(deriveRekeyCapacityReference(schema, f.bytes(), time).service, expected.service);
  for (const [name, value] of [["root_age_ms", "1"], ["session_not_after_ms", "2"], ["activation_not_after_ms", "2"],
    ["max_epochs", "99999999"], ["crypto_profile_id", "other"], ["burst_rounds", "1"], ["additional_tolerance_ms", "1000"]]) {
    failure(() => deriveRekeyCapacityReference(schema, f.bytes(), { ...time, [name]: value }), "rekey_capacity_time_fields");
  }
});

test("v4.rekey_capacity.epochs: rejects full-service excess even when initiation would fit", () => {
  const f = fixture(); put("RekeyEnvelope", f.envelope, "burst_rounds", 1n); put("RekeyEnvelope", f.envelope, "refill_period_ms", 2n);
  const exact = { rate_numerator: "0", rate_denominator: "1", quantization_ms: "0" };
  failure(() => deriveRekeyCapacityReference(schema, f.bytes(), exact), "configuration_capacity");
  put("Artifact", f.artifact, "session_not_after_ms", 65534n);
  assert.equal(deriveRekeyCapacityReference(schema, f.bytes(), exact).service.required_epochs, "65536");
  put("Artifact", f.artifact, "session_not_after_ms", 65535n);
  failure(() => deriveRekeyCapacityReference(schema, f.bytes(), exact), "configuration_capacity");
});

test("v4.rekey_capacity.binding: complete signed bytes remain digest-bound and detached", () => {
  const f = fixture(), before = deriveRekeyCapacityReference(schema, f.bytes(), time);
  put("Artifact", f.artifact, "signature", Buffer.alloc(64, 71));
  const after = deriveRekeyCapacityReference(schema, f.bytes(), time);
  assert.deepEqual(after.service, before.service); assert.notDeepEqual(after.artifact_digest, before.artifact_digest);
  const bytes = f.bytes(), result = deriveRekeyCapacityReference(schema, bytes, time), digest = Buffer.from(result.artifact_digest);
  const sibling = deriveRekeyCapacityReference(schema, bytes, time);
  assert.equal(result.artifact_digest.byteOffset, 0);
  assert.equal(result.artifact_digest.buffer.byteLength, 32);
  assert.equal(sibling.artifact_digest.buffer.byteLength, 32);
  assert.notEqual(result.artifact_digest.buffer, sibling.artifact_digest.buffer);
  assert.notEqual(result.artifact_digest.buffer, bytes.buffer);
  bytes.fill(0); assert.deepEqual(result.artifact_digest, digest);
  new Uint8Array(result.artifact_digest.buffer).fill(0);
  assert.deepEqual(sibling.artifact_digest, digest);
  assert.deepEqual(deriveRekeyCapacityReference(schema, f.bytes(), time).artifact_digest, digest);
});

test("v4.rekey_capacity.inputs: closed profile and canonical bounded bytes reject hooks and malformed encodings", () => {
  const f = fixture(); let calls = 0; const trap = () => { calls++; throw new Error("caller hook"); };
  failure(() => deriveRekeyCapacityReference(schema, f.bytes(), new Proxy(time, { getPrototypeOf: trap })), "rekey_capacity_time_profile");
  failure(() => deriveRekeyCapacityReference(schema, f.bytes(), Object.defineProperty({ ...time }, "rate_numerator", { get: trap })), "rekey_capacity_time_data");
  failure(() => deriveRekeyCapacityReference(schema, f.bytes(), { ...time, quantization_ms: { toString: trap } }), "rekey_credit_integer");
  const shadowed = f.bytes(); Object.defineProperty(shadowed, "byteLength", { get: trap });
  assert.throws(() => deriveRekeyCapacityReference(schema, shadowed, time), /shadowed byte metadata/u);
  failure(() => deriveRekeyCapacityReference(schema, Buffer.alloc(schema.frame_maps.Artifact.max_encoded_bytes + 1), time), "rekey_capacity_artifact_size");
  assert.throws(() => deriveRekeyCapacityReference(schema, f.bytes().subarray(1), time));
  assert.throws(() => deriveRekeyCapacityReference(schema, Buffer.concat([f.bytes(), Buffer.from([0])]), time));
  assert.equal(calls, 0);
});

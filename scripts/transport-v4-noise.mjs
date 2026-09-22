import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { x25519 } = require("@noble/curves/ed25519.js");
const { p256 } = require("@noble/curves/nist.js");
const hex = bytes => Buffer.from(bytes).toString("hex");

// The generator validates captured library output and expands mutation recipes.
// It does not implement Noise or attest that opaque prologue bytes are authorized.
export function verifyNoisePlan(schema) {
  const plan = schema.noise_vector_plan;
  assert.equal(plan.status, "public_fixed_material_library_reference_only");
  assert.equal(plan.source.library, "snow@0.10.0");
  for (const field of ["crate_sha256", "capture_sha256"]) assert.match(plan.source[field], /^[0-9a-f]{64}$/u);
  assert.match(plan.source.vcs_sha, /^[0-9a-f]{40}$/u);
  assert.deepEqual(Object.keys(plan.inputs).sort(), ["client_static_private_hex", "server_static_private_hex",
    "client_ephemeral_private_hex", "server_ephemeral_private_hex", "psk_hex", "context_digest_hex", "prologue_hex", "payload_hex"].sort());
  for (const [name, value] of Object.entries(plan.inputs)) {
    const bytes = strictHex(value);
    if (name !== "prologue_hex" && name !== "payload_hex") assert.equal(bytes.length, 32);
  }
  assert.equal(plan.inputs.payload_hex, "");
  assert.ok(strictHex(plan.inputs.prologue_hex).length > 0);
  assert.deepEqual(plan.negative_mutations, ["every_byte_high_bit", "every_truncation", "one_byte_suffix", "two_byte_suffix"]);
  assert.deepEqual(plan.transcripts.map(t => t.profile).sort(), Object.keys(schema.crypto_profiles).sort());
  assert.equal(new Set(plan.transcripts.map(t => t.id)).size, plan.transcripts.length);
  for (const transcript of plan.transcripts) {
    assert.match(transcript.id, /^noise_[a-z0-9_]+$/u);
    const profile = schema.crypto_profiles[transcript.profile];
    assert.equal(profile.handshake_message_bytes, profile.dh_public_bytes + profile.tag_bytes);
    for (const field of ["handshake_hash_hex", "split_i2r_hex", "split_r2i_hex", "initial_root_hex"]) {
      assert.equal(strictHex(transcript[field]).length, profile.key_bytes);
    }
    assert.notEqual(transcript.split_i2r_hex, transcript.split_r2i_hex);
    for (const [flight, side] of [[1, "client"], [2, "server"]]) {
      const message = strictHex(transcript[`message${flight}_hex`]);
      assert.equal(message.length, profile.handshake_message_bytes);
      const privateKey = strictHex(plan.inputs[`${side}_ephemeral_private_hex`]);
      const publicKey = profile.dh_algorithm === 0 ? x25519.getPublicKey(privateKey) : p256.getPublicKey(privateKey, false);
      assert.equal(hex(message.subarray(0, profile.dh_public_bytes)), hex(publicKey));
    }
    const derived = rootDomain(schema, transcript, plan.inputs);
    assert.equal(derived.output_hex, transcript.initial_root_hex);
  }
}

function rootDomain(schema, transcript, inputs) {
  return evaluateDomain(schema, "initial_root", {
    profile: transcript.profile,
    handshake_hash: strictHex(transcript.handshake_hash_hex),
    context_digest: strictHex(inputs.context_digest_hex),
    split_i2r: strictHex(transcript.split_i2r_hex),
  });
}

export function buildNoiseCorpus(schema) {
  verifyNoisePlan(schema);
  const plan = schema.noise_vector_plan;
  const transcripts = plan.transcripts.map(t => ({ ...t, initial_root_info_hex: rootDomain(schema, t, plan.inputs).input_hex }));
  const negatives = [];
  for (const transcript of transcripts) {
    for (const flight of [1, 2]) {
      const original = strictHex(transcript[`message${flight}_hex`]);
      const add = (suffix, reason, bytes) => negatives.push({
        id: `${transcript.id}_m${flight}_${suffix}`, transcript: transcript.id, flight,
        reason, message_hex: hex(bytes), expected_error: "noise_reference_failed",
      });
      for (let i = 0; i < original.length; i++) {
        const mutated = Buffer.from(original); mutated[i] ^= 0x80;
        add(`bit_${i}`, "modified_message_with_original_tag", mutated);
        add(`short_${i}`, "truncated_message", original.subarray(0, i));
      }
      add("suffix_1", "extended_message", Buffer.concat([original, Buffer.from([0])]));
      add("suffix_2", "extended_message", Buffer.concat([original, Buffer.from([0, 1])]));
    }
  }
  return {
    schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: plan.status, source: plan.source, inputs: plan.inputs, transcripts, negatives,
    unverified: ["Authenticated Flowersec prologue/admission and certificate bindings", "Signed dual READY, records and rekey",
      "Four-library transcript agreement for both required profiles", "Runtime entropy, key handles, ownership and cleanup",
      "Independent cryptographic composition proof and provider qualification"],
  };
}

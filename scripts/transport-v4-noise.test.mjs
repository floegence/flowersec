import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifyNoisePlan } from "./transport-v4-noise.mjs";

const { schema, files, manifest } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/noise.json"));

test("v4.noise.corpus: both required profiles and complete mutation coverage", () => {
  assert.equal(corpus.schema_sha256, manifest.schema_sha256);
  assert.deepEqual(corpus.transcripts.map(t => t.profile).sort(), Object.keys(schema.crypto_profiles).sort());
  const all = [...corpus.transcripts, ...corpus.negatives];
  assert.equal(new Set(all.map(v => v.id)).size, all.length);
  assert.equal(manifest.noise_vectors.length, all.length);
  for (const transcript of corpus.transcripts) {
    for (const flight of [1, 2]) {
      const original = Buffer.from(transcript[`message${flight}_hex`], "hex");
      const cases = corpus.negatives.filter(v => v.transcript === transcript.id && v.flight === flight);
      assert.equal(cases.length, original.length * 2 + 2);
      for (const vector of cases) {
        const message = Buffer.from(vector.message_hex, "hex");
        assert.equal(vector.expected_error, "noise_reference_failed");
        if (vector.reason === "modified_message_with_original_tag") {
          assert.equal(message.length, original.length);
          const differences = [...message].map((b, i) => b ^ original[i]).filter(b => b !== 0);
          assert.deepEqual(differences, [128]);
        } else if (vector.reason === "truncated_message") {
          assert.ok(message.length < original.length);
          assert.deepEqual(message, original.subarray(0, message.length));
        } else {
          assert.equal(vector.reason, "extended_message");
          assert.ok(message.length === original.length + 1 || message.length === original.length + 2);
          assert.deepEqual(message.subarray(0, original.length), original);
        }
      }
    }
  }
});

test("v4.noise.plan: profile, direction, public bytes and derivation drift fail", () => {
  const changes = [
    s => s.noise_vector_plan.transcripts.pop(),
    s => { s.noise_vector_plan.inputs.payload_hex = "00"; },
    s => { s.noise_vector_plan.inputs.client_static_private_hex = "00"; },
    s => { s.noise_vector_plan.transcripts[0].message1_hex += "00"; },
    s => { s.noise_vector_plan.transcripts[0].message2_hex = s.noise_vector_plan.transcripts[0].message1_hex; },
    s => { s.noise_vector_plan.transcripts[0].split_i2r_hex = s.noise_vector_plan.transcripts[0].split_r2i_hex; },
    s => { s.noise_vector_plan.inputs.context_digest_hex = "00".repeat(32); },
    s => { s.noise_vector_plan.transcripts[0].handshake_hash_hex = "00".repeat(32); },
    s => { s.noise_vector_plan.transcripts[0].initial_root_hex = "00".repeat(32); },
    s => { s.crypto_profiles[s.noise_vector_plan.transcripts[1].profile].dh_public_bytes = 32; },
  ];
  for (const change of changes) {
    const altered = structuredClone(schema); change(altered);
    assert.throws(() => verifyNoisePlan(altered));
  }
});

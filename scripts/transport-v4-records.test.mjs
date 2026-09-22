import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildRecordCorpus, encodeRecordLayout, openRecordReference, verifyRecordPlan } from "./transport-v4-records.mjs";
import { strictHex } from "./transport-v4-codec.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = buildRecordCorpus(schema);
const byID = new Map(corpus.vectors.map(v => [v.id, v]));

test("v4.record.bytes: exact nonce, length chain and isolated key domains", () => {
  assert.equal(corpus.vectors.length, 2 * schema.record_vector_plan.cases.length);
  for (const profile of Object.keys(schema.crypto_profiles)) {
    const vectors = corpus.vectors.filter(v => v.profile === profile);
    const at = name => vectors.find(v => v.case === name);
    assert.equal(at("datagram_integer_boundary").nonce_hex, "01020304ffffffffffffffff");
    const first = at("stream_client"), next = at("stream_next_sequence");
    assert.equal(first.key_hex, next.key_hex);
    assert.notEqual(first.nonce_hex, next.nonce_hex);
    for (const alternate of ["stream_server", "stream_other_scope", "stream_other_epoch", "maintenance_client"]) {
      assert.notEqual(first.key_hex, at(alternate).key_hex);
    }
    for (const vector of vectors) {
      const envelope = strictHex(vector.envelope_header_hex), wire = strictHex(vector.wire_hex);
      assert.equal(envelope.length, 8);
      assert.equal(envelope.readUInt32BE(), wire.length - envelope.length);
      assert.equal(vector.record_header_hex.length / 2, 20);
      assert.equal(vector.ciphertext_hex.length / 2, vector.plaintext_hex.length / 2 + 16);
      assert.equal(wire.toString("hex"), vector.envelope_header_hex + vector.record_header_hex + vector.ciphertext_hex);
      assert.equal(openRecordReference(vector.algorithm, strictHex(vector.key_hex), strictHex(vector.nonce_hex),
        strictHex(vector.aad_hex), strictHex(vector.ciphertext_hex)).toString("hex"), vector.plaintext_hex);
    }
  }
});

test("v4.record.auth: every AAD/nonce/ciphertext/tag byte and wrong key rejects", () => {
  for (const negative of corpus.negatives) {
    const source = byID.get(negative.source), vector = { ...source, [`${negative.field}_hex`]: negative.value_hex };
    assert.throws(() => openRecordReference(vector.algorithm, strictHex(vector.key_hex), strictHex(vector.nonce_hex),
      strictHex(vector.aad_hex), strictHex(vector.ciphertext_hex)), undefined, negative.id);
  }
  for (const vector of corpus.vectors) {
    const required = (vector.aad_hex.length + vector.nonce_hex.length + vector.ciphertext_hex.length) / 2 + 3;
    assert.equal(corpus.negatives.filter(n => n.source === vector.id).length, required);
  }
});

test("v4.record.registry: profile/layout drift, duplicate bindings and integer overflow fail", () => {
  for (const mutate of [
    s => { s.record_nonce.reverse(); }, s => { s.record_header.reverse(); },
    s => { Object.values(s.crypto_profiles)[1].record_aead = "aes-128-gcm"; },
    s => { s.record_vector_plan.cases[2].values.sequence = 0; },
    s => { s.record_vector_plan.cases[0].sequence_scope = "1"; },
    s => { s.record_vector_plan.cases[0].epoch = 4294967296; },
    s => { s.record_vector_plan.cases[0].sequence = "18446744073709551616"; },
  ]) {
    const changed = structuredClone(schema); mutate(changed);
    assert.throws(() => verifyRecordPlan(changed));
  }
  for (const sequence of [-1n, 1n << 64n, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => encodeRecordLayout(schema.record_nonce, { epoch: 0, sequence }));
  }
  assert.equal(encodeRecordLayout(schema.record_nonce, { epoch: 4294967295, sequence: 0n }).toString("hex"), "ffffffff0000000000000000");
});

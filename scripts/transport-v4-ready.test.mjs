import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildReadyCorpus, readyMaterial, verifyReadyPlan, verifyReadyReference } from "./transport-v4-ready.mjs";
import { decodeMap, strictHex } from "./transport-v4-codec.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = buildReadyCorpus(schema);
const byID = new Map(corpus.vectors.map(v => [v.id, v]));

test("v4.ready.composition: both roles, profiles and feature selections bind independent proof and MAC", () => {
  assert.equal(corpus.vectors.length, 8);
  for (const v of corpus.vectors) {
    const ready = strictHex(v.ready_hex), wire = strictHex(v.wire_hex);
    assert.equal(ready.length, 103);
    assert.equal(wire.length, 111);
    assert.equal(wire.readUInt32BE(), ready.length);
    assert.ok(verifyReadyReference(schema, v.context, ready), v.id);
    const proof = decodeMap(schema, "ReadyProofInput", strictHex(v.proof_input_hex));
    const mac = decodeMap(schema, "ReadyMACInput", strictHex(v.mac_input_hex));
    for (const [field, value] of proof) assert.deepEqual(mac.get(field), value);
    const alternate = corpus.vectors.find(other => other.context.crypto_profile_id === v.context.crypto_profile_id && other.context.role === v.context.role && other.context.selected_features !== v.context.selected_features);
    assert.equal(v.identity_proof_hex, alternate.identity_proof_hex);
    assert.notEqual(v.confirmation_mac_hex, alternate.confirmation_mac_hex);
    assert.equal(v.key_hex, alternate.key_hex);
    const peer = corpus.vectors.find(other => other.context.crypto_profile_id === v.context.crypto_profile_id && other.context.role !== v.context.role);
    assert.notEqual(v.key_hex, peer.key_hex);
  }
});

test("v4.ready.rejection: malformed bytes, every context binding, reflection and valid-MAC invalid-proof reject", () => {
  for (const n of corpus.negatives) {
    const v = byID.get(n.source);
    assert.equal(verifyReadyReference(schema, { ...v.context, ...n.context_patch }, strictHex(n.ready_hex)), false, n.id);
    if (n.reason === "invalid_proof_valid_mac") {
      const map = decodeMap(schema, "READY", strictHex(n.ready_hex));
      const actual = readyMaterial(schema, { ...v.context, ...n.context_patch }, map.get(0n));
      assert.equal(map.get(1n).toString("hex"), actual.confirmation_mac_hex, n.id);
    }
  }
  for (const v of corpus.vectors) {
    const cases = corpus.negatives.filter(n => n.source === v.id);
    assert.equal(cases.filter(n => n.reason === "wire_mutation").length, 103);
    assert.equal(cases.filter(n => n.reason === "truncation").length, 103);
    assert.equal(cases.filter(n => n.reason === "invalid_proof_valid_mac").length, 10);
    assert.equal(cases.filter(n => n.reason === "reflection").length, 1);
  }
});

test("v4.ready.registry: key/schema drift and unsupported feature bits cannot be silently accepted", () => {
  for (const mutate of [
    s => s.ready_vector_plan.roles.reverse(),
    s => { s.ready_vector_plan.roles[1].public_key_hex = s.ready_vector_plan.roles[0].public_key_hex; },
    s => { s.frame_maps.ReadyMACInput.fields[7].name = "other_certificate"; },
    s => { s.ready_vector_plan.selected_features = [0, 4]; },
  ]) {
    const changed = structuredClone(schema); mutate(changed);
    assert.throws(() => verifyReadyPlan(changed));
  }
  const first = corpus.vectors[0];
  assert.equal(verifyReadyReference(schema, { ...first.context, selected_features: 4 }, strictHex(first.ready_hex)), false);
});

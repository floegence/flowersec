import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { buildRekeyCorpus, rekeyDHReference, verifyRekeyPhaseReference, verifyRekeyPlan } from "./transport-v4-rekey.mjs";
import { decodeMap, encodeCBOR, strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { openRecordReference } from "./transport-v4-records.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = buildRekeyCorpus(schema);
const phases = new Map(corpus.rounds.flatMap(r => r.phases.map(p => [p.id, { round: r, phase: p }])));
const bytes = strictHex;

test("v4.rekey.composition: two successive roots, both DH directions and salt/IKM order", () => {
  assert.equal(corpus.rounds.length, 4);
  for (const r of corpus.rounds) {
    const c = r.context;
    assert.equal(rekeyDHReference(schema, c.profile, bytes(r.input.client_private_hex), bytes(r.server_public_hex)).toString("hex"), r.dh_hex);
    assert.equal(rekeyDHReference(schema, c.profile, bytes(r.input.server_private_hex), bytes(r.client_public_hex)).toString("hex"), r.dh_hex);
    assert.equal(r.extract_salt_hex, r.secret_hex);
    assert.equal(r.extract_ikm_hex, r.dh_hex);
    const prk = createHmac("sha256", bytes(r.secret_hex)).update(bytes(r.dh_hex)).digest();
    assert.equal(prk.toString("hex"), r.prk_hex);
    const expand = key => createHmac("sha256", key).update(bytes(r.root_info_hex)).update(Buffer.from([1])).digest("hex");
    assert.equal(expand(prk), r.new_root_hex);
    assert.notEqual(expand(bytes(r.dh_hex)), r.new_root_hex);
    assert.notEqual(expand(createHmac("sha256", bytes(r.dh_hex)).update(bytes(r.secret_hex)).digest()), r.new_root_hex);
    if (c.epoch === 1) {
      const previous = corpus.rounds.find(p => p.context.profile === c.profile && p.context.epoch === 0);
      assert.equal(r.old_root_hex, previous.new_root_hex);
      assert.notEqual(r.secret_hex, previous.secret_hex);
    }
  }
});

test("v4.rekey.messages: exact complete I/J digests and MAC omission retain field IDs", () => {
  for (const r of corpus.rounds) {
    const c = r.context;
    const args = { profile: c.profile, handshake_hash: bytes(c.handshake_hash_hex), epoch: c.epoch };
    const init = bytes(r.phases[0].message_hex), reply = bytes(r.phases[1].message_hex);
    assert.equal(evaluateDomain(schema, "rekey_init_digest", { ...args, init }).output_hex, r.init_digest_hex);
    assert.equal(evaluateDomain(schema, "rekey_transcript", { ...args, init, reply }).output_hex, r.transcript_hex);
    for (const p of r.phases) {
      const map = decodeMap(schema, p.schema, bytes(p.message_hex), { crypto_profile_id: c.profile });
      map.delete(BigInt(schema.frame_maps[p.schema].mac_field));
      assert.equal(encodeCBOR(map).toString("hex"), p.unsigned_hex);
      assert.equal(p.role, schema.frame_maps[p.schema].sender_role);
      assert.equal(p.base_hex, p.phase < 3 ? r.secret_hex : r.new_root_hex);
      assert.ok(verifyRekeyPhaseReference(schema, c, p.phase, bytes(p.base_hex), bytes(p.message_hex), p.expected));
    }
    for (const [phase, field] of [[0, "init"], [1, "reply"]]) {
      const p = r.phases[phase], map = decodeMap(schema, p.schema, bytes(p.message_hex), { crypto_profile_id: c.profile });
      map.get(BigInt(schema.frame_maps[p.schema].mac_field))[0] ^= 1;
      const altered = encodeCBOR(map);
      assert.notEqual(evaluateDomain(schema, "rekey_transcript", { ...args, init, reply, [field]: altered }).output_hex, r.transcript_hex);
      if (field === "init") assert.notEqual(evaluateDomain(schema, "rekey_init_digest", { ...args, init: altered }).output_hex, r.init_digest_hex);
    }
  }
});

test("v4.rekey.records: old INIT/REPLY and new direction-specific scope-zero markers", () => {
  for (const r of corpus.rounds) for (const p of r.phases) {
    const rec = p.record, profile = schema.crypto_profiles[r.context.profile];
    assert.equal(rec.epoch, p.phase < 3 ? r.context.epoch : r.context.next_epoch);
    assert.equal(rec.root_hex, p.phase < 3 ? r.old_root_hex : r.new_root_hex);
    assert.equal(bytes(rec.record_header_hex).readBigUInt64BE(4), 0n);
    const opened = openRecordReference(profile.record_aead, bytes(rec.key_hex), bytes(rec.nonce_hex), bytes(rec.aad_hex), bytes(rec.ciphertext_hex));
    assert.equal(opened.toString("hex"), p.message_hex);
    if (p.phase >= 3) {
      assert.equal(rec.sequence, "0");
      const side = p.role === 0 ? "client" : "server";
      assert.equal(p.expected.old_maintenance_next_sequence, (BigInt(r.input[side + "_old_sequence"]) + 1n).toString());
      const wrong = evaluateDomain(schema, "record_key", { profile: r.context.profile, handshake_hash: bytes(r.context.handshake_hash_hex),
        epoch_root: bytes(r.old_root_hex), epoch: rec.epoch, direction: rec.direction, sequence_scope: 0n });
      assert.throws(() => openRecordReference(profile.record_aead, bytes(wrong.output_hex), bytes(rec.nonce_hex), bytes(rec.aad_hex), bytes(rec.ciphertext_hex)));
    }
  }
});

test("v4.rekey.rejection: malformed, reflected, substituted and stale-key phases reject", () => {
  for (const n of corpus.negatives) {
    const { round: r, phase: p } = phases.get(n.source);
    assert.equal(verifyRekeyPhaseReference(schema, { ...r.context, ...n.context_patch }, p.phase, bytes(n.base_hex), bytes(n.message_hex), n.expected), false, n.id);
  }
  assert.equal(corpus.negatives.filter(n => n.id.endsWith("_stale_base")).length, 8);
  for (const r of corpus.rounds) {
    const profile = schema.crypto_profiles[r.context.profile];
    assert.throws(() => rekeyDHReference(schema, r.context.profile, bytes(r.input.client_private_hex), Buffer.alloc(profile.dh_public_bytes)));
  }
  for (const mutate of [s => s.rekey_vector_plan.rounds.reverse(), s => { s.rekey_vector_plan.rounds[0].client_barrier[0].scope_id = "0"; }]) {
    const changed = structuredClone(schema); mutate(changed); assert.throws(() => verifyRekeyPlan(changed));
  }
});

test("v4.rekey.frontier: markers bind old maintenance frontiers without changing T/root", () => {
  const changed = structuredClone(schema);
  changed.rekey_vector_plan.rounds[0].client_old_sequence = "5";
  const frontier = buildRekeyCorpus(changed);
  for (const r of corpus.rounds.filter(r => r.context.epoch === 0)) {
    const other = frontier.rounds.find(v => v.id === r.id);
    assert.equal(other.transcript_hex, r.transcript_hex);
    assert.equal(other.new_root_hex, r.new_root_hex);
    assert.notEqual(other.phases[2].confirmation_mac_hex, r.phases[2].confirmation_mac_hex);
    assert.equal(other.phases[3].confirmation_mac_hex, r.phases[3].confirmation_mac_hex);
  }
  const barrier = structuredClone(schema);
  barrier.rekey_vector_plan.rounds[0].client_barrier[0].next_sequence = "4";
  const bound = buildRekeyCorpus(barrier);
  for (const r of corpus.rounds) {
    const other = bound.rounds.find(v => v.id === r.id);
    assert.notEqual(other.transcript_hex, r.transcript_hex);
    assert.notEqual(other.new_root_hex, r.new_root_hex);
  }
});

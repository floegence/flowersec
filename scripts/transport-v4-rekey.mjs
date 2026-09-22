import assert from "node:assert/strict";
import { createCipheriv, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import { decodeMap, encodeCBOR, mapFromNames, strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { buildNoiseCorpus } from "./transport-v4-noise.mjs";
import { encodeRecordLayout } from "./transport-v4-records.mjs";

// Public fixture bytes only, not a rekey owner, valid barrier history, clock/
// credit admission, real key installation or permission to publish an epoch.
const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { x25519 } = require("@noble/curves/ed25519.js");
const { p256 } = require("@noble/curves/nist.js");
const hex = bytes => Buffer.from(bytes).toString("hex");
const flip = value => { const b = strictHex(value); b[0] ^= 128; return hex(b); };
const phaseNames = schema => schema.domains.find(d => d.name === "rekey_confirm_mac").input_schema.parts.find(p => p.encoding === "lp-map").schema_cases;
const keyBytes = (value) => ({ $bytes: value });

export function rekeyDHReference(schema, profile, privateKey, publicKey) {
  const spec = schema.crypto_profiles[profile];
  assert.equal(privateKey.length, 32); assert.equal(publicKey.length, spec.dh_public_bytes);
  if (spec.dh_algorithm === 1) assert.equal(publicKey[0], 4);
  const shared = spec.dh_algorithm === 0 ? x25519.getSharedSecret(privateKey, publicKey)
    : p256.getSharedSecret(privateKey, publicKey, false).slice(1, 33);
  assert.equal(shared.length, 32); assert.ok(shared.some(b => b !== 0), "zero DH before KDF");
  return Buffer.from(shared);
}

export function verifyRekeyPlan(schema) {
  const plan = schema.rekey_vector_plan;
  assert.equal(plan.status, "public_fixture_rekey_composition_only");
  assert.deepEqual(plan.rounds.map(r => r.epoch), [0, 1]);
  assert.deepEqual(plan.negative_mutations, ["each_phase_byte", "each_phase_truncation", "noncanonical_map", "context_substitution", "phase_reflection", "stale_phase_base", "wrong_init_digest", "wrong_transcript", "wrong_old_frontier"]);
  assert.deepEqual(Object.keys(phaseNames(schema)), ["1", "2", "3", "4"]);
  assert.equal(new Set(plan.rounds.map(r => r.rekey_id_hex)).size, plan.rounds.length);
  for (const round of plan.rounds) {
    assert.equal(strictHex(round.rekey_id_hex).length, 16);
    for (const side of ["client", "server"]) {
      assert.equal(strictHex(round[side + "_private_hex"]).length, 32);
      assert.match(round[side + "_old_sequence"], /^[1-9][0-9]*$/u);
      assert.ok(BigInt(round[side + "_old_sequence"]) < (1n << 64n) - 1n);
      let last = 0n;
      for (const entry of round[side + "_barrier"]) {
        assert.match(entry.scope_id, /^[1-9][0-9]*$/u);
        assert.match(entry.next_sequence, /^(?:0|[1-9][0-9]*)$/u);
        assert.ok(BigInt(entry.scope_id) > last && BigInt(entry.scope_id) < 1n << 64n); last = BigInt(entry.scope_id);
        assert.ok(BigInt(entry.next_sequence) < 1n << 64n);
      }
    }
  }
}

const domainArgs = context => ({
  profile: context.profile, handshake_hash: strictHex(context.handshake_hash_hex),
  context_digest: strictHex(context.context_digest_hex), epoch: context.epoch,
  next_epoch: context.next_epoch, rekey_id: strictHex(context.rekey_id_hex),
});
function phaseMaterial(schema, context, phase, base, message) {
  const name = phaseNames(schema)[phase];
  assert.ok(name, "phase");
  const role = schema.frame_maps[name].sender_role;
  const args = { ...domainArgs(context), phase, role };
  const key = evaluateDomain(schema, "rekey_confirm_key", { ...args, phase_base_key: base });
  const { rekey_id: _id, ...macArgs } = args;
  const mac = evaluateDomain(schema, "rekey_confirm_mac", { ...macArgs, phase_key: strictHex(key.output_hex), message }, { crypto_profile_id: context.profile });
  const unsigned = decodeMap(schema, name, message, { crypto_profile_id: context.profile });
  unsigned.delete(BigInt(schema.frame_maps[name].mac_field));
  return { role, key_info_hex: key.input_hex, key_hex: key.output_hex, mac_message_hex: mac.input_hex,
    unsigned_hex: hex(encodeCBOR(unsigned)), confirmation_mac_hex: mac.output_hex };
}

export function verifyRekeyPhaseReference(schema, context, phase, base, message, expected) {
  try {
    const name = phaseNames(schema)[phase], spec = schema.frame_maps[name];
    const map = decodeMap(schema, name, message, { crypto_profile_id: context.profile });
    const named = Object.fromEntries(Object.entries(spec.fields).map(([id, field]) => [field.name, map.get(BigInt(id))]));
    if (named.phase !== BigInt(phase) || named.next_epoch !== BigInt(context.next_epoch) || !named.rekey_id.equals(strictHex(context.rekey_id_hex))) return false;
    for (const [field, value] of Object.entries(expected)) {
      if (field === "old_maintenance_next_sequence") { if (named[field] !== BigInt(value)) return false; }
      else if (!named[field].equals(strictHex(value))) return false;
    }
    const m = phaseMaterial(schema, context, phase, base, message);
    return timingSafeEqual(named.confirmation_mac, strictHex(m.confirmation_mac_hex));
  } catch { return false; }
}

function phaseRecord(schema, context, role, epoch, sequence, root, plain) {
  const profile = schema.crypto_profiles[context.profile];
  const numbers = { epoch, sequence_scope: 0n, sequence, direction: role };
  const header = encodeRecordLayout(schema.record_header, numbers), nonce = encodeRecordLayout(schema.record_nonce, numbers);
  const envelope = encodeRecordLayout(schema.envelope.layout, { payload_length: header.length + plain.length + profile.tag_bytes, frame_type: schema.frame_types.REKEY });
  const key = evaluateDomain(schema, "record_key", { profile: context.profile, handshake_hash: strictHex(context.handshake_hash_hex), epoch_root: root, epoch, direction: role, sequence_scope: 0n });
  const aad = evaluateDomain(schema, "record_aad", { profile: context.profile, direction: role, envelope_header: envelope, record_header: header });
  const cipher = createCipheriv(profile.record_aead, strictHex(key.output_hex), nonce, { authTagLength: profile.tag_bytes });
  cipher.setAAD(strictHex(aad.input_hex));
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  return { epoch, sequence: sequence.toString(), direction: role, root_hex: hex(root),
    key_info_hex: key.input_hex, key_hex: key.output_hex, nonce_hex: hex(nonce), envelope_header_hex: hex(envelope),
    record_header_hex: hex(header), aad_hex: aad.input_hex, ciphertext_hex: hex(ciphertext), wire_hex: hex(Buffer.concat([envelope, header, ciphertext])) };
}

export function buildRekeyCorpus(schema) {
  verifyRekeyPlan(schema);
  const noise = buildNoiseCorpus(schema), rounds = [], negatives = [];
  for (const transcript of noise.transcripts) {
    let root = strictHex(transcript.initial_root_hex), previous;
    for (const input of schema.rekey_vector_plan.rounds) {
      const context = { profile: transcript.profile, handshake_hash_hex: transcript.handshake_hash_hex,
        context_digest_hex: noise.inputs.context_digest_hex, epoch: input.epoch, next_epoch: input.epoch + 1, rekey_id_hex: input.rekey_id_hex };
      const id = `${transcript.id}_rekey_epoch${input.epoch}`;
      const args = domainArgs(context), profile = schema.crypto_profiles[context.profile];
      const pub = secret => Buffer.from(profile.dh_algorithm === 0 ? x25519.getPublicKey(secret) : p256.getPublicKey(secret, false));
      const clientPrivate = strictHex(input.client_private_hex), serverPrivate = strictHex(input.server_private_hex);
      const clientPublic = pub(clientPrivate), serverPublic = pub(serverPrivate);
      const shared = rekeyDHReference(schema, context.profile, clientPrivate, serverPublic);
      assert.deepEqual(shared, rekeyDHReference(schema, context.profile, serverPrivate, clientPublic));
      const digestArgs = { profile: context.profile, handshake_hash: args.handshake_hash, epoch: context.epoch };
      const secret = evaluateDomain(schema, "rekey_secret", { ...digestArgs, context_digest: args.context_digest, epoch_root: root });
      const phases = [];
      const construct = (phase, base, values, expected, recordRoot) => {
        const name = phaseNames(schema)[phase], spec = schema.frame_maps[name];
        const map = mapFromNames(schema, name, { phase, rekey_id: keyBytes(context.rekey_id_hex), next_epoch: context.next_epoch,
          ...values, confirmation_mac: keyBytes("00".repeat(32)) }, { crypto_profile_id: context.profile });
        const m = phaseMaterial(schema, context, phase, base, encodeCBOR(map));
        map.set(BigInt(spec.mac_field), strictHex(m.confirmation_mac_hex));
        const message = encodeCBOR(map), side = m.role === 0 ? "client" : "server";
        assert.ok(verifyRekeyPhaseReference(schema, context, phase, base, message, expected));
        const record = phaseRecord(schema, context, m.role, phase < 3 ? context.epoch : context.next_epoch,
          phase < 3 ? BigInt(input[side + "_old_sequence"]) : 0n, recordRoot, message);
        const entry = { id: `${id}_phase${phase}`, schema: name, phase, ...m, base_hex: hex(base), message_hex: hex(message), expected, record };
        phases.push(entry); return message;
      };
      const barrier = side => input[side + "_barrier"].map(e => ({ scope_id: { $uint: e.scope_id }, next_sequence: { $uint: e.next_sequence } }));
      const init = construct(1, strictHex(secret.output_hex), { client_ephemeral: keyBytes(hex(clientPublic)), client_barrier: barrier("client") }, {}, root);
      const initDigest = evaluateDomain(schema, "rekey_init_digest", { ...digestArgs, init }, { crypto_profile_id: context.profile });
      const reply = construct(2, strictHex(secret.output_hex), { init_digest: keyBytes(initDigest.output_hex), server_ephemeral: keyBytes(hex(serverPublic)), server_barrier: barrier("server") }, { init_digest: initDigest.output_hex }, root);
      const t = evaluateDomain(schema, "rekey_transcript", { ...digestArgs, init, reply }, { crypto_profile_id: context.profile });
      const extract = evaluateDomain(schema, "rekey_extract", { rekey_secret: strictHex(secret.output_hex), dh: shared });
      const next = evaluateDomain(schema, "rekey_root", { ...args, transcript_digest: strictHex(t.output_hex), rekey_prk: strictHex(extract.output_hex) });
      for (const phase of [3, 4]) {
        const side = schema.frame_maps[phaseNames(schema)[phase]].sender_role === 0 ? "client" : "server";
        const frontier = (BigInt(input[side + "_old_sequence"]) + 1n).toString();
        construct(phase, strictHex(next.output_hex), { transcript_digest: keyBytes(t.output_hex), old_maintenance_next_sequence: { $uint: frontier } },
          { transcript_digest: t.output_hex, old_maintenance_next_sequence: frontier }, strictHex(next.output_hex));
      }
      rounds.push({ id, noise_transcript: transcript.id, context, input, old_root_hex: hex(root),
        client_public_hex: hex(clientPublic), server_public_hex: hex(serverPublic), dh_hex: hex(shared),
        secret_info_hex: secret.input_hex, secret_hex: secret.output_hex, init_digest_input_hex: initDigest.input_hex, init_digest_hex: initDigest.output_hex,
        transcript_input_hex: t.input_hex, transcript_hex: t.output_hex, extract_salt_hex: extract.salt_hex, extract_ikm_hex: extract.ikm_hex,
        prk_hex: extract.output_hex, root_info_hex: next.input_hex, new_root_hex: next.output_hex, phases });
      for (const entry of phases) {
        const base = strictHex(entry.base_hex), original = strictHex(entry.message_hex);
        const add = (suffix, message, patch = {}, changedBase = base, expected = entry.expected) => {
          assert.equal(verifyRekeyPhaseReference(schema, { ...context, ...patch }, entry.phase, changedBase, message, expected), false, entry.id + suffix);
          negatives.push({ id: entry.id + "_" + suffix, source: entry.id, message_hex: hex(message), context_patch: patch,
            base_hex: hex(changedBase), expected, expected_error: "rekey_reference_failed" });
        };
        for (let i = 0; i < original.length; i++) {
          const changed = Buffer.from(original); changed[i] ^= 128;
          add(`byte_${i}`, changed); add(`truncate_${i}`, original.subarray(0, i));
        }
        const pairs = [...decodeMap(schema, entry.schema, original, { crypto_profile_id: context.profile })]
          .map(([k, v]) => Buffer.concat([encodeCBOR(k), encodeCBOR(v)]));
        for (const [suffix, message] of [
          ["suffix", Buffer.concat([original, Buffer.from([0])])],
          ["reordered", Buffer.concat([original.subarray(0, 1), ...pairs.toReversed()])],
          ["duplicate", Buffer.concat([Buffer.from([0xa0 + pairs.length + 1]), pairs[0], ...pairs])],
          ["unknown", Buffer.concat([Buffer.from([0xa0 + pairs.length + 1]), ...pairs, Buffer.from([23, 0])])],
          ["overlong_key", Buffer.concat([original.subarray(0, 1), Buffer.from([24, 0]), original.subarray(2)])],
          ["indefinite", Buffer.concat([Buffer.from([0xbf]), original.subarray(1), Buffer.from([0xff])])],
        ]) add(suffix, message);
        for (const field of ["handshake_hash_hex", "context_digest_hex", "rekey_id_hex"]) add(field, original, { [field]: flip(context[field]) });
        add("epoch", original, { epoch: context.epoch + 1 });
        add("next_epoch", original, { next_epoch: context.next_epoch + 1 });
        add("profile", original, { profile: Object.keys(schema.crypto_profiles).find(p => p !== context.profile) });
        add("wrong_base", original, {}, strictHex(flip(entry.base_hex)));
        add("wrong_phase_base", original, {}, entry.phase < 3 ? root : strictHex(secret.output_hex));
        if (previous) add("stale_base", original, {}, strictHex(previous.phases[entry.phase - 1].base_hex));
        const other = phases.find(p => p.phase === (entry.phase % 2 === 0 ? entry.phase - 1 : entry.phase + 1));
        add("reflection", strictHex(other.message_hex));
        for (const [field, value] of Object.entries(entry.expected)) {
          const changed = field === "old_maintenance_next_sequence" ? (BigInt(value) + 1n).toString() : flip(value);
          add(`expected_${field}`, original, {}, base, { ...entry.expected, [field]: changed });
          if (field === "old_maintenance_next_sequence") add(`expected_lower_${field}`, original, {}, base, { ...entry.expected, [field]: (BigInt(value) - 1n).toString() });
        }
      }
      root = strictHex(next.output_hex); previous = rounds.at(-1);
    }
  }
  return { schema_revision: schema.schema_revision, design_sha256: schema.design_sha256, coverage: schema.rekey_vector_plan.status, rounds, negatives,
    unverified: ["Authenticated full Noise/READY context", "Actual barrier/maintenance history and single-publisher gates", "Clock/credit/resources, one-shot owner and irreversible phase state", "Runtime keys/cleanup and independent cryptographic proof", "Provider and pairwise qualification"] };
}

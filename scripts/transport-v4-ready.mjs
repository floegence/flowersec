import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, sign, timingSafeEqual } from "node:crypto";
import { createRequire } from "node:module";
import { decodeMap, encodeCBOR, mapFromNames, strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { buildNoiseCorpus } from "./transport-v4-noise.mjs";
import { encodeRecordLayout } from "./transport-v4-records.mjs";

// Public fixture composition only. Supplied digests are not authenticated
// credentials. This helper cannot publish a Session or grant READY authority.
const require = createRequire(new URL("../flowersec-ts/package.json", import.meta.url));
const { ed25519 } = require("@noble/curves/ed25519.js");
const hex = bytes => Buffer.from(bytes).toString("hex");
const flip = value => { const changed = strictHex(value); changed[0] ^= 0x80; return hex(changed); };
const privatePrefix = Buffer.from("302e020100300506032b657004220420", "hex");

function strictProof(proof, message, key) {
  if (key.length !== 32 || proof.length !== 64) return false;
  try {
    for (const encoded of [key, proof.subarray(0, 32)]) {
      const point = ed25519.Point.fromBytes(encoded, false);
      if (point.is0() || !point.isTorsionFree() || !Buffer.from(point.toBytes()).equals(encoded)) return false;
    }
    return ed25519.verify(proof, message, key, { zip215: false });
  } catch { return false; }
}

export function verifyReadyPlan(schema) {
  const plan = schema.ready_vector_plan;
  assert.equal(plan.status, "public_fixture_ready_composition_only");
  assert.match(plan.source, /synthetic context digests/u);
  assert.deepEqual(plan.roles.map(r => r.role), [0, 1]);
  assert.deepEqual(plan.selected_features, [0, 3]);
  assert.deepEqual(plan.negative_mutations, ["each_ready_byte", "each_truncation", "noncanonical_map", "context_substitution", "invalid_proof_valid_mac", "reflection"]);
  assert.equal(new Set(plan.roles.map(r => r.public_key_hex)).size, 2);
  for (const role of plan.roles) for (const key of ["seed_hex", "public_key_hex", "certificate_digest_hex"]) assert.equal(strictHex(role[key]).length, 32);
  assert.deepEqual(Object.keys(plan.context).sort(), ["admission_binding_hex", "fsa_digest_hex", "fsb_digest_hex"]);
  for (const value of Object.values(plan.context)) assert.equal(strictHex(value).length, 32);
  const proof = schema.frame_maps.ReadyProofInput, mac = schema.frame_maps.ReadyMACInput;
  for (const [id, field] of Object.entries(proof.fields)) assert.deepEqual(mac.fields[id], field);
  assert.deepEqual(proof.required, [0,1,2,3,4,5,6,7]);
  assert.deepEqual(mac.required, [0,1,2,3,4,5,6,7,8,9]);
  assert.equal(schema.frame_maps.READY.fields[0].length, 64);
  assert.equal(schema.frame_maps.READY.fields[1].length, 32);
}

export function readyMap(schema, name, context) {
  const values = Object.fromEntries(Object.values(schema.frame_maps[name].fields).map(field => [field.name,
    field.type === "bytes" ? { $bytes: context[field.name + "_hex"] } : context[field.name],
  ]));
  const bytes = encodeCBOR(mapFromNames(schema, name, values));
  decodeMap(schema, name, bytes);
  return bytes;
}

export function readyMaterial(schema, context, proof) {
  const proofInput = readyMap(schema, "ReadyProofInput", context);
  const message = evaluateDomain(schema, "ready_identity", { proof: proofInput });
  const key = evaluateDomain(schema, "ready_key", {
    profile: context.crypto_profile_id, role: context.role,
    handshake_hash: strictHex(context.handshake_hash_hex), context_digest: strictHex(context.transport_context_digest_hex),
    epoch_root: strictHex(context.epoch_root_hex),
  });
  const out = { proof_input_hex: hex(proofInput), signature_message_hex: message.input_hex, key_info_hex: key.input_hex, key_hex: key.output_hex };
  if (proof !== undefined) {
    const macInput = readyMap(schema, "ReadyMACInput", { ...context, identity_proof_hex: hex(proof) });
    const mac = evaluateDomain(schema, "ready_mac", { mac_input: macInput, ready_key: strictHex(key.output_hex) });
    Object.assign(out, { mac_input_hex: hex(macInput), mac_message_hex: mac.input_hex, confirmation_mac_hex: mac.output_hex });
  }
  return out;
}

export function verifyReadyReference(schema, context, bytes) {
  try {
    const received = decodeMap(schema, "READY", bytes), fields = schema.frame_maps.READY.fields;
    const named = Object.fromEntries(Object.entries(fields).map(([id, field]) => [field.name, received.get(BigInt(id))]));
    const material = readyMaterial(schema, context, named.identity_proof);
    return timingSafeEqual(named.confirmation_mac, strictHex(material.confirmation_mac_hex))
      && strictProof(named.identity_proof, strictHex(material.signature_message_hex), strictHex(context.public_key_hex));
  } catch { return false; }
}

export function buildReadyCorpus(schema) {
  verifyReadyPlan(schema);
  const plan = schema.ready_vector_plan, noise = buildNoiseCorpus(schema), vectors = [], negatives = [];
  const encode = (proof, mac) => readyMap(schema, "READY", { identity_proof_hex: hex(proof), confirmation_mac_hex: hex(mac) });
  for (const transcript of noise.transcripts) for (const role of plan.roles) for (const features of plan.selected_features) {
    const context = { ...plan.context, role: role.role, crypto_profile_id: transcript.profile,
      handshake_hash_hex: transcript.handshake_hash_hex, transport_context_digest_hex: noise.inputs.context_digest_hex,
      certificate_digest_hex: role.certificate_digest_hex, selected_features: features,
      epoch_root_hex: transcript.initial_root_hex, public_key_hex: role.public_key_hex };
    const privateKey = createPrivateKey({ key: Buffer.concat([privatePrefix, strictHex(role.seed_hex)]), format: "der", type: "pkcs8" });
    assert.equal(hex(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32)), role.public_key_hex);
    const proof = sign(null, strictHex(readyMaterial(schema, context).signature_message_hex), privateKey);
    const material = readyMaterial(schema, context, proof), ready = encode(proof, strictHex(material.confirmation_mac_hex));
    assert.equal(ready.length, 103);
    assert.ok(verifyReadyReference(schema, context, ready));
    const envelope = encodeRecordLayout(schema.envelope.layout, { payload_length: ready.length, frame_type: schema.frame_types.READY });
    const id = `${transcript.id}_ready_role${role.role}_features${features}`;
    vectors.push({ id, noise_transcript: transcript.id, context, signing_seed_hex: role.seed_hex, ...material,
      identity_proof_hex: hex(proof), ready_hex: hex(ready), envelope_header_hex: hex(envelope), wire_hex: hex(Buffer.concat([envelope, ready])) });
    const add = (suffix, bytes, patch = {}, reason = suffix) => {
      assert.equal(verifyReadyReference(schema, { ...context, ...patch }, bytes), false, id + suffix);
      negatives.push({ id: `${id}_${suffix}`, source: id, ready_hex: hex(bytes), context_patch: patch, reason, expected_error: "ready_rejected" });
    };
    for (let i = 0; i < ready.length; i++) {
      const changed = Buffer.from(ready); changed[i] ^= 0x80;
      add(`byte_${i}`, changed, {}, "wire_mutation");
      add(`truncate_${i}`, ready.subarray(0, i), {}, "truncation");
    }
    const pairs = [...decodeMap(schema, "READY", ready)].map(([k,v]) => Buffer.concat([encodeCBOR(k), encodeCBOR(v)]));
    for (const [name, bytes] of [
      ["suffix", Buffer.concat([ready, Buffer.from([0])])],
      ["reordered", Buffer.concat([Buffer.from([0xa2]), ...pairs.toReversed()])],
      ["duplicate", Buffer.concat([Buffer.from([0xa3]), pairs[0], ...pairs])],
      ["unknown", Buffer.concat([Buffer.from([0xa3]), ...pairs, Buffer.from([2, 0])])],
      ["overlong_key", Buffer.concat([Buffer.from([0xa2, 0x18, 0]), ready.subarray(2)])],
      ["indefinite", Buffer.concat([Buffer.from([0xbf]), ready.subarray(1), Buffer.from([0xff])])],
    ]) add(name, bytes, {}, "noncanonical_map");
    for (const [name, original] of Object.entries(context)) {
      const value = name.endsWith("_hex") ? flip(original) : name === "crypto_profile_id"
        ? Object.keys(schema.crypto_profiles).find(p => p !== original) : name === "role" ? 1 - original : original ^ 1;
      const patch = { [name]: value };
      add(`context_${name}`, ready, patch, "context_substitution");
      // A root holder can construct a correct MAC, but cannot reuse the old
      // identity proof on a different signed context or certificate key.
      if (Object.values(schema.frame_maps.ReadyProofInput.fields).some(f => (f.type === "bytes" ? f.name + "_hex" : f.name) === name) || name === "public_key_hex") {
        const changed = readyMaterial(schema, { ...context, ...patch }, proof);
        add(`context_${name}_valid_mac`, encode(proof, strictHex(changed.confirmation_mac_hex)), patch, "invalid_proof_valid_mac");
      }
    }
    const badProof = Buffer.alloc(64); badProof[0] = 1;
    add("identity_R_valid_mac", encode(badProof, strictHex(readyMaterial(schema, context, badProof).confirmation_mac_hex)), {}, "invalid_proof_valid_mac");
    add("unknown_feature", ready, { selected_features: 4 }, "invalid_context");
    add("invalid_role", ready, { role: 2 }, "invalid_context");
    add("unknown_profile", ready, { crypto_profile_id: "unknown" }, "invalid_context");
  }
  for (const vector of vectors) {
    const other = vectors.find(v => v.context.crypto_profile_id === vector.context.crypto_profile_id && v.context.selected_features === vector.context.selected_features && v.context.role !== vector.context.role);
    assert.equal(verifyReadyReference(schema, vector.context, strictHex(other.ready_hex)), false);
    negatives.push({ id: vector.id + "_reflection", source: vector.id, ready_hex: other.ready_hex, context_patch: {}, reason: "reflection", expected_error: "ready_rejected" });
  }
  assert.equal(new Set([...vectors, ...negatives].map(v => v.id)).size, vectors.length + negatives.length);
  return { schema_revision: schema.schema_revision, design_sha256: schema.design_sha256, coverage: plan.status, vectors, negatives,
    unverified: ["Authenticated FSB/FSA/certificate/admission and complete Flowersec Noise prologue", "One-shot dual READY owner, publication and authorization/resource/deadline gates", "Four-SDK full Noise-to-rekey composition and independent cryptographic qualification", "Runtime secret handling, provider and pairwise qualification"] };
}

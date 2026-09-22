import assert from "node:assert/strict";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { decodeMap, encodeCBOR, mapFromNames, strictHex } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { buildNoiseCorpus } from "./transport-v4-noise.mjs";

// Fixed public material only. These byte/AEAD references do not own a Session,
// prove READY, allocate live scopes or grant replay/sequence/key-use permission.
const hex = bytes => Buffer.from(bytes).toString("hex");
const widths = { uint8: 1, uint16_be: 2, uint32_be: 4, uint64_be: 8 };

export function encodeRecordLayout(layout, values) {
  return Buffer.concat(layout.map(field => {
    const width = widths[field.type];
    assert.ok(width, "unknown record integer type");
    const value = field.const ?? values[field.name];
    assert.ok(typeof value === "bigint" || Number.isSafeInteger(value), "record integer required");
    const integer = BigInt(value);
    assert.ok(integer >= 0n && integer < 1n << BigInt(width * 8), "record integer range");
    if (field.max !== undefined) assert.ok(integer <= BigInt(field.max), "record integer cap");
    const bytes = Buffer.alloc(width);
    if (width === 8) bytes.writeBigUInt64BE(integer); else bytes.writeUIntBE(Number(integer), 0, width);
    return bytes;
  }));
}

export function verifyRecordPlan(schema) {
  assert.equal(schema.record_vector_plan.status, "fixed_material_record_encoding_and_aead_reference_only");
  assert.deepEqual(schema.record_header, [
    { name: "epoch", type: "uint32_be" }, { name: "sequence_scope", type: "uint64_be" }, { name: "sequence", type: "uint64_be" },
  ]);
  assert.deepEqual(schema.record_nonce, [{ name: "epoch", type: "uint32_be" }, { name: "sequence", type: "uint64_be" }]);
  for (const spec of Object.values(schema.crypto_profiles)) {
    assert.equal(spec.record_aead, spec.dh_algorithm === 0 ? "chacha20-poly1305" : "aes-256-gcm");
    assert.equal(spec.key_bytes, 32); assert.equal(spec.nonce_bytes, 12); assert.equal(spec.tag_bytes, 16);
  }
  const cases = schema.record_vector_plan.cases;
  assert.equal(new Set(cases.map(entry => entry.id)).size, cases.length);
  assert.ok(cases.length > 0);
  assert.deepEqual(schema.record_vector_plan.negative_mutations, ["each_aad_byte", "each_nonce_byte", "each_ciphertext_and_tag_byte", "short_tag", "extended_ciphertext", "wrong_key"]);
  for (const entry of cases) {
    assert.match(entry.id, /^[a-z][a-z0-9_]+$/u);
    assert.ok([0, 1].includes(entry.direction));
    assert.ok(["PING", "STREAM_DATA", "DATAGRAM"].includes(entry.frame));
    for (const field of ["sequence_scope", "sequence"]) assert.match(entry[field], /^(?:0|[1-9][0-9]*)$/u);
    encodeRecordLayout(schema.record_header, { ...entry, sequence_scope: BigInt(entry.sequence_scope), sequence: BigInt(entry.sequence) });
    const expectedBindings = entry.frame === "PING" ? {} : entry.frame === "DATAGRAM"
      ? { scope: "sequence_scope", epoch: "epoch", sequence: "sequence" }
      : { stream_id: "sequence_scope", epoch: "epoch", sequence: "sequence", direction: "direction" };
    assert.deepEqual(entry.bindings ?? {}, expectedBindings);
    assert.ok(Object.keys(expectedBindings).every(field => !Object.hasOwn(entry.values, field)), "record binding duplicated in payload");
    if (entry.frame === "PING") assert.equal(entry.sequence_scope, "0");
  }
}

export function openRecordReference(algorithm, key, nonce, aad, ciphertext) {
  // Node may expose tentative plaintext from update. Keep it private until
  // final authenticates; no callback or return occurs on authentication failure.
  const decipher = createDecipheriv(algorithm, key, nonce, { authTagLength: 16 });
  assert.ok(ciphertext.length >= 16, "record tag truncated");
  decipher.setAAD(aad);
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
  let tentative;
  try {
    tentative = decipher.update(ciphertext.subarray(0, ciphertext.length - 16));
    const final = decipher.final();
    return Buffer.concat([tentative, final]);
  } finally {
    tentative?.fill(0);
  }
}

export function buildRecordCorpus(schema) {
  verifyRecordPlan(schema);
  const noise = buildNoiseCorpus(schema), vectors = [], negatives = [];
  for (const transcript of noise.transcripts) {
    const profile = transcript.profile, spec = schema.crypto_profiles[profile];
    for (const entry of schema.record_vector_plan.cases) {
      const input = { ...entry, sequence_scope: BigInt(entry.sequence_scope), sequence: BigInt(entry.sequence) };
      const values = { ...entry.values };
      for (const [field, source] of Object.entries(entry.bindings ?? {})) values[field] = input[source];
      const plaintext = encodeCBOR(mapFromNames(schema, entry.frame, values, { max_data_payload_bytes: 16 }));
      decodeMap(schema, entry.frame, plaintext, { max_data_payload_bytes: 16 });
      const recordHeader = encodeRecordLayout(schema.record_header, input);
      const nonce = encodeRecordLayout(schema.record_nonce, input);
      const envelopeHeader = encodeRecordLayout(schema.envelope.layout, {
        payload_length: recordHeader.length + plaintext.length + spec.tag_bytes, frame_type: schema.frame_types[entry.frame],
      });
      const key = evaluateDomain(schema, "record_key", {
        profile, handshake_hash: strictHex(transcript.handshake_hash_hex), epoch_root: strictHex(transcript.initial_root_hex),
        epoch: entry.epoch, direction: entry.direction, sequence_scope: input.sequence_scope,
      });
      const aad = evaluateDomain(schema, "record_aad", { profile, direction: entry.direction, envelope_header: envelopeHeader, record_header: recordHeader });
      const cipher = createCipheriv(spec.record_aead, strictHex(key.output_hex), nonce, { authTagLength: spec.tag_bytes });
      cipher.setAAD(strictHex(aad.input_hex));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
      assert.deepEqual(openRecordReference(spec.record_aead, strictHex(key.output_hex), nonce, strictHex(aad.input_hex), ciphertext), plaintext);
      const id = `${transcript.id}_record_${entry.id}`;
      vectors.push({ id, profile, noise_transcript: transcript.id, case: entry.id,
        epoch: entry.epoch, direction: entry.direction, sequence_scope: entry.sequence_scope, sequence: entry.sequence,
        frame: entry.frame, frame_type: schema.frame_types[entry.frame], algorithm: spec.record_aead,
        epoch_root_hex: transcript.initial_root_hex, handshake_hash_hex: transcript.handshake_hash_hex,
        key_info_hex: key.input_hex, key_hex: key.output_hex, nonce_hex: hex(nonce),
        envelope_header_hex: hex(envelopeHeader), record_header_hex: hex(recordHeader), aad_hex: aad.input_hex,
        plaintext_hex: hex(plaintext), ciphertext_hex: hex(ciphertext), wire_hex: hex(Buffer.concat([envelopeHeader, recordHeader, ciphertext])),
      });
      for (const [field, original] of [["aad", strictHex(aad.input_hex)], ["nonce", nonce], ["ciphertext", ciphertext]]) {
        for (let index = 0; index < original.length; index++) {
          const changed = Buffer.from(original); changed[index] ^= 0x80;
          negatives.push({ id: `${id}_${field}_${index}`, source: id, field, value_hex: hex(changed), expected_error: "record_authentication_failed" });
        }
      }
      const changedKey = strictHex(key.output_hex); changedKey[0] ^= 0x80;
      for (const [suffix, field, bytes] of [["short_tag", "ciphertext", ciphertext.subarray(0, ciphertext.length - 1)],
        ["suffix", "ciphertext", Buffer.concat([ciphertext, Buffer.from([0])])], ["wrong_key", "key", changedKey]]) {
        negatives.push({ id: `${id}_${suffix}`, source: id, field, value_hex: hex(bytes), expected_error: "record_authentication_failed" });
      }
    }
  }
  return { schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: schema.record_vector_plan.status, vectors, negatives,
    unverified: ["READY and authenticated context/authorization", "Runtime record parser/error scope, sequence/replay and key-use budgets",
      "Epoch transitions and rekey", "Runtime owners, opaque keys, cancellation and cleanup", "Provider and independent cryptographic qualification"],
  };
}

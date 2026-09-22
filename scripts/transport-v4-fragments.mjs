import assert from "node:assert/strict";

export class FragmentError extends Error {
  constructor(code) { super(code); this.name = "FragmentError"; this.code = code; }
}

const exactKeys = (value, keys, label) => {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label}: object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label}: keys`);
};

export function verifyFragmentRegistry(registry) {
  exactKeys(registry, ["transport", "length_prefix_bytes", "length_counts", "max_fragment_bytes", "max_body_length", "kinds"], "fragment_registry");
  assert.equal(registry.transport, "rpc_reliable_ordered");
  assert.equal(registry.length_prefix_bytes, 4);
  assert.equal(registry.length_counts, "kind_and_body");
  assert.equal(registry.max_fragment_bytes, 16384);
  assert.equal(registry.max_body_length, 16380);
  exactKeys(registry.kinds, ["BEGIN", "DATA", "ABORT", "STOP_OUTPUT"], "fragment_registry.kinds");
  const expected = {
    BEGIN: {value: 0, body_fixed_bytes: 18, body_min_bytes: 19, body_max_bytes: 530, payload: "canonical_header", payload_min_bytes: 1, payload_max_bytes: 512, total_min_bytes: 24, total_max_bytes: 535},
    DATA: {value: 1, body_fixed_bytes: 12, body_min_bytes: 13, body_max_bytes: 16379, payload: "payload_bytes", payload_min_bytes: 1, payload_max_bytes: 16367, total_min_bytes: 18, total_max_bytes: 16384},
    ABORT: {value: 2, body_fixed_bytes: 12, body_min_bytes: 12, body_max_bytes: 12, payload: null, payload_min_bytes: 0, payload_max_bytes: 0, total_min_bytes: 17, total_max_bytes: 17},
    STOP_OUTPUT: {value: 3, body_fixed_bytes: 8, body_min_bytes: 8, body_max_bytes: 8, payload: null, payload_min_bytes: 0, payload_max_bytes: 0, total_min_bytes: 13, total_max_bytes: 13},
  };
  for (const [name, definition] of Object.entries(registry.kinds)) {
    exactKeys(definition, ["value", "body_fixed_bytes", "body_min_bytes", "body_max_bytes", "payload", "payload_min_bytes", "payload_max_bytes", "total_min_bytes", "total_max_bytes"], `fragment_registry.kinds.${name}`);
    assert.deepEqual(definition, expected[name], `fragment registry allocation differs for ${name}`);
    assert.ok(Number.isInteger(definition.value) && definition.value >= 0 && definition.value <= 255);
    assert.ok(definition.body_min_bytes <= definition.body_max_bytes && definition.total_min_bytes <= definition.total_max_bytes);
    assert.equal(definition.total_min_bytes, registry.length_prefix_bytes + 1 + definition.body_min_bytes);
    assert.equal(definition.total_max_bytes, registry.length_prefix_bytes + 1 + definition.body_max_bytes);
  }
  assert.equal(new Set(Object.values(registry.kinds).map(item => item.value)).size, 4);
  return registry;
}

const u64 = (value, label, minimum = 1n) => {
  if (typeof value !== "bigint" || value < minimum || value > 0xffffffffffffffffn) throw new FragmentError(`${label}_range`);
  const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(value); return bytes;
};
const u32 = (value, label) => {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new FragmentError(`${label}_range`);
  const bytes = Buffer.alloc(4); bytes.writeUInt32BE(value); return bytes;
};

export function encodeFragment(registry, fragment) {
  verifyFragmentRegistry(registry);
  if (!fragment || typeof fragment !== "object" || !Number.isInteger(fragment.kind)) throw new FragmentError("kind");
  const kind = Object.values(registry.kinds).find(item => item.value === fragment.kind);
  if (!kind) throw new FragmentError("unknown_kind");
  let body;
  if (fragment.kind === 0) {
    if (!Buffer.isBuffer(fragment.canonical_header)) throw new FragmentError("header_type");
    const header = Buffer.from(fragment.canonical_header);
    if (header.length < 1 || header.length > 512) throw new FragmentError("header_length");
    body = Buffer.concat([u64(fragment.message_serial, "message_serial"), u64(fragment.reply_to_serial, "reply_to_serial", 0n), Buffer.from([header.length >>> 8, header.length & 0xff]), header]);
  } else if (fragment.kind === 1) {
    if (!Buffer.isBuffer(fragment.payload_bytes)) throw new FragmentError("payload_type");
    const payload = Buffer.from(fragment.payload_bytes);
    if (payload.length < 1 || payload.length > 16367) throw new FragmentError("payload_length");
    body = Buffer.concat([u64(fragment.message_serial, "message_serial"), u32(fragment.payload_offset, "payload_offset"), payload]);
  } else if (fragment.kind === 2) {
    body = Buffer.concat([u64(fragment.message_serial, "message_serial"), u32(fragment.next_offset, "next_offset")]);
  } else {
    body = u64(fragment.request_serial, "request_serial");
  }
  if (body.length + 1 > registry.max_body_length) throw new FragmentError("fragment_length");
  return Buffer.concat([u32(body.length + 1, "body_length"), Buffer.from([fragment.kind]), body]);
}

export function decodeFragment(registry, bytes) {
  verifyFragmentRegistry(registry);
  if (!Buffer.isBuffer(bytes)) throw new FragmentError("bytes_type");
  if (bytes.length < 5) throw new FragmentError("truncated_length");
  const bodyLength = bytes.readUInt32BE(0);
  if (bodyLength < 1 || bodyLength > registry.max_body_length) throw new FragmentError("body_length");
  if (bytes.length !== registry.length_prefix_bytes + bodyLength) throw new FragmentError("length_mismatch");
  const kind = bytes[4], body = bytes.subarray(5);
  if (![0, 1, 2, 3].includes(kind)) throw new FragmentError("unknown_kind");
  const readSerial = (offset, label, minimum = 1n) => { const value = bytes.readBigUInt64BE(offset); if (value < minimum) throw new FragmentError(`${label}_range`); return value; };
  if (kind === 0) {
    if (body.length < 19 || body.length > 530) throw new FragmentError("begin_length");
    const message_serial = readSerial(5, "message_serial"), reply_to_serial = readSerial(13, "reply_to_serial", 0n);
    const headerLength = bytes.readUInt16BE(21);
    if (headerLength < 1 || headerLength > 512 || body.length !== 18 + headerLength) throw new FragmentError("header_length");
    return {kind, message_serial, reply_to_serial, canonical_header: Buffer.from(bytes.subarray(23))};
  }
  if (kind === 1) {
    if (body.length < 13 || body.length > 16379) throw new FragmentError("data_length");
    return {kind, message_serial: readSerial(5, "message_serial"), payload_offset: bytes.readUInt32BE(13), payload_bytes: Buffer.from(bytes.subarray(17))};
  }
  if (kind === 2) {
    if (body.length !== 12) throw new FragmentError("abort_length");
    return {kind, message_serial: readSerial(5, "message_serial"), next_offset: bytes.readUInt32BE(13)};
  }
  if (body.length !== 8) throw new FragmentError("stop_output_length");
  return {kind, request_serial: readSerial(5, "request_serial")};
}

function hex(bytes) { return bytes.toString("hex"); }

export function buildFragmentCorpus(registry) {
  verifyFragmentRegistry(registry);
  const positive = [
    {id: "fragment_begin_minimum", value: encodeFragment(registry, {kind: 0, message_serial: 1n, reply_to_serial: 0n, canonical_header: Buffer.from([0])})},
    {id: "fragment_begin_maximum", value: encodeFragment(registry, {kind: 0, message_serial: 0xffffffffffffffffn, reply_to_serial: 0xffffffffffffffffn, canonical_header: Buffer.alloc(512, 0xa5)})},
    {id: "fragment_data_minimum", value: encodeFragment(registry, {kind: 1, message_serial: 1n, payload_offset: 0, payload_bytes: Buffer.from([0])})},
    {id: "fragment_data_maximum", value: encodeFragment(registry, {kind: 1, message_serial: 0xffffffffffffffffn, payload_offset: 0xffffffff, payload_bytes: Buffer.alloc(16367, 0x5a)})},
    {id: "fragment_abort", value: encodeFragment(registry, {kind: 2, message_serial: 9n, next_offset: 17})},
    {id: "fragment_stop_output", value: encodeFragment(registry, {kind: 3, request_serial: 9n})},
  ];
  const malformed = [
    {id: "fragment_unknown_kind", error: "unknown_kind", value: Buffer.from("00000001ff", "hex")},
    {id: "fragment_truncated_length", error: "truncated_length", value: Buffer.from("00000001", "hex")},
    {id: "fragment_length_mismatch", error: "length_mismatch", value: Buffer.from("000000030000", "hex")},
    {id: "fragment_begin_empty_header", error: "header_length", value: (() => { const b = Buffer.alloc(24); b.writeUInt32BE(20, 0); b[4] = 0; b.writeBigUInt64BE(1n, 5); b.writeBigUInt64BE(0n, 13); b.writeUInt16BE(0, 21); return b; })()},
    {id: "fragment_data_empty_payload", error: "data_length", value: Buffer.concat([Buffer.from("0000000d01", "hex"), Buffer.alloc(12)])},
    {id: "fragment_abort_extra_byte", error: "abort_length", value: Buffer.concat([Buffer.from("0000000e02", "hex"), Buffer.alloc(13)])},
    {id: "fragment_zero_serial", error: "message_serial_range", value: Buffer.concat([Buffer.from("0000000e01", "hex"), Buffer.alloc(12), Buffer.from([0])])},
  ];
  return {registry_version: 1, coverage: "draft_binary_fragment_framing", vectors: [...positive.map(item => ({id:item.id, kind:"fragment", hex:hex(item.value)})), ...malformed.map(item => ({id:item.id, kind:"fragment", hex:hex(item.value), expected_error:item.error}))]};
}

export function verifyFragmentCorpus(registry, corpus) {
  verifyFragmentRegistry(registry);
  assert.equal(corpus.registry_version, 1);
  assert.equal(corpus.coverage, "draft_binary_fragment_framing");
  if (corpus.schema_revision !== undefined || corpus.design_sha256 !== undefined || corpus.schema_sha256 !== undefined) {
    exactKeys(corpus, ["registry_version", "coverage", "vectors", "schema_revision", "design_sha256", "schema_sha256"], "fragment corpus");
    assert.match(corpus.schema_revision, /^flowersec-v4\./u);
    assert.match(corpus.design_sha256, /^[0-9a-f]{64}$/u);
    assert.match(corpus.schema_sha256, /^[0-9a-f]{64}$/u);
  }
  assert.ok(Array.isArray(corpus.vectors));
  const ids = new Set();
  for (const vector of corpus.vectors) {
    assert.ok(!ids.has(vector.id), `duplicate fragment vector ${vector.id}`); ids.add(vector.id);
    let error;
    try { decodeFragment(registry, Buffer.from(vector.hex, "hex")); } catch (err) { error = err; }
    if (vector.expected_error) assert.ok(error instanceof FragmentError && error.code === vector.expected_error, `${vector.id}: expected ${vector.expected_error}, got ${error?.code ?? "accepted"}`);
    else { if (error) throw error; }
  }
  assert.equal(ids.size, 13);
  return corpus;
}

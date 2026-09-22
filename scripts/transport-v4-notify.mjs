import assert from "node:assert/strict";
import { encodeCBOR, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { decodeApplicationHeader } from "./transport-v4-application-headers.mjs";

// NOTIFY is a sequence of complete length-prefixed application messages. It
// has neither RPC fragments/serials nor a response/acknowledgment variant.
export function verifyNotifyRegistry(schema) {
  assert.deepEqual(schema.notify_registry, {
    kind: "flowersec.notify.v4", transport: "notify_reliable_ordered",
    header_length_prefix_bytes: 2, byte_order: "big_endian",
    length_counts: "canonical_header_only", min_header_bytes: 1,
    max_header_bytes: 512, max_payload_bytes: 1048576,
    message_kinds: ["execution_notify", "observation_notify"], metadata_bytes: 0,
    channels_per_opener: 1, subscribers_per_type: 32, subscribers_per_session: 128,
    pending_per_subscriber: 16, running_per_subscriber: 1,
  });
}

export function decodeNotify(schema, wire) {
  verifyNotifyRegistry(schema);
  if (wire.length < 2) throw new VectorError("notify_truncated");
  const length = wire.readUInt16BE();
  if (length < 1 || length > schema.notify_registry.max_header_bytes) throw new VectorError("notify_header_length");
  if (wire.length < length + 2) throw new VectorError("notify_truncated");
  const header = decodeApplicationHeader(schema, wire.subarray(2, 2 + length));
  if (!schema.notify_registry.message_kinds.includes(header.kind)) throw new VectorError("notify_kind");
  const total = 2 + length + Number(header.map.get(3n));
  if (wire.length < total) throw new VectorError("notify_truncated");
  if (wire.length > total) throw new VectorError("notify_trailing");
  return header;
}

export function buildNotifyCorpus(schema) {
  verifyNotifyRegistry(schema);
  const vectors = [];
  const add = (id, bytes, expected_error) => {
    if (expected_error) assert.throws(() => decodeNotify(schema, bytes), error => error.code === expected_error);
    else decodeNotify(schema, bytes);
    vectors.push({ id, hex: bytes.toString("hex"), ...(expected_error ? { expected_error } : {}) });
  };
  const frame = (kind, payload) => {
    const fields = Object.fromEntries(schema.application_message_kinds[kind].fields.map(id => [
      schema.frame_maps.ApplicationHeader.fields[id].name,
      id === 0 ? schema.application_message_kinds[kind].code : id === 3 ? payload.length :
        Object.hasOwn(schema.application_message_kinds[kind].constants ?? {}, id) ? schema.application_message_kinds[kind].constants[id] : schema.application_headers.maximum_values[id],
    ]));
    const header = encodeCBOR(mapFromNames(schema, "ApplicationHeader", fields));
    const prefix = Buffer.alloc(2); prefix.writeUInt16BE(header.length);
    return Buffer.concat([prefix, header, payload]);
  };
  for (const kind of schema.notify_registry.message_kinds) {
    add(`${kind}_empty`, frame(kind, Buffer.alloc(0)));
    add(`${kind}_payload`, frame(kind, Buffer.from("notification")));
  }
  const valid = frame("observation_notify", Buffer.from("event"));
  add("notify_empty_prefix", Buffer.alloc(0), "notify_truncated");
  add("notify_split_prefix", valid.subarray(0, 1), "notify_truncated");
  add("notify_zero_header", Buffer.from([0, 0]), "notify_header_length");
  add("notify_large_header", Buffer.from([2, 1]), "notify_header_length");
  add("notify_short_header", valid.subarray(0, 6), "notify_truncated");
  add("notify_short_payload", valid.subarray(0, -1), "notify_truncated");
  add("notify_extra_payload", Buffer.concat([valid, Buffer.from([0])]), "notify_trailing");
  add("notify_rpc_kind", frame("transient_unary_request", Buffer.alloc(0)), "notify_kind");
  return { schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: "notify_framing_only", vectors };
}

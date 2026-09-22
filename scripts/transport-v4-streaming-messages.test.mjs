import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { decodeMap, encodeCBOR, mapFromNames } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { executionRequestDigest } from "./transport-v4-application-headers.mjs";
import { StreamingMessageReference } from "./transport-v4-streaming-messages.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = JSON.parse(fs.readFileSync(new URL("../testdata/transport_v4/corpus.json", import.meta.url)));
const bytes = value => ({ $bytes: value.toString("hex") });
const encode = fields => encodeCBOR(mapFromNames(schema, "ApplicationHeader", fields));
const id = key => BigInt(Object.entries(schema.frame_maps.ServiceContract.fields).find(([, field]) => field.name === key)[0]);
const code = (fn, expected) => assert.throws(fn, error => error.code === expected);

function request(semantics = "execution", payload = Buffer.alloc(0), { limit = 16, changes = {} } = {}) {
  const map = decodeMap(schema, "ServiceContract", Buffer.from(corpus.vectors.find(entry => entry.id === `service_stream_${semantics}`).hex, "hex"));
  for (const [key, value] of Object.entries(changes)) map.set(id(key), value);
  const contract = encodeCBOR(map), kind = `${semantics}_stream_request`;
  const fields = { message_kind: schema.application_message_kinds[kind].code, type_id: Number(map.get(id("type_id"))),
    payload_length: payload.length, deadline_at_ms: 50000,
    service_contract_digest: { $bytes: evaluateDomain(schema, "service_contract_digest", { contract }).output_hex },
    admission_mode: 0, response_limit_bytes: limit };
  if (semantics === "execution") {
    fields.operation_id = bytes(Buffer.alloc(32, 1)); fields.request_digest = bytes(Buffer.alloc(32));
    fields.request_digest = bytes(executionRequestDigest(schema, encode(fields), contract, payload));
  }
  return { semantics, fields, header: encode(fields), contract, payload };
}
function response(original, length = 0, suffix = "item", extra = {}) {
  const variant = schema.application_message_kinds[`${original.semantics}_stream_${suffix}`], fields = {};
  for (const key of variant.fields) {
    const name = schema.frame_maps.ApplicationHeader.fields[key].name;
    fields[name] = name === "message_kind" ? variant.code : name === "payload_length" ? length : original.fields[name];
  }
  return encode({ ...fields, ...extra });
}
function model(original, inputChunkBytes = 65536, source = schema) {
  return new StreamingMessageReference(source, { contract: original.contract, inputChunkBytes });
}
function feed(state, direction, payload, chunk = 65536) {
  for (let offset = 0; offset < payload.length; offset += chunk) state.payload(direction, payload.subarray(offset, offset + chunk));
}
function ready(original) {
  const state = model(original); state.beginRequest(original.header); feed(state, "request", original.payload); return state;
}

// v4.streaming_messages.request_boundary
test("exact streaming variants bind one complete initial request and release input backing", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics, Buffer.from("abcd")), state = model(original, 2);
    state.beginRequest(original.header); state.payload("request", Buffer.from("ab"));
    assert.equal(state.snapshot().request_validated, false);
    assert.equal(state.snapshot().payload_bytes, 4);
    assert.equal(state.wait({ canceled: true }).wait_status, "wait_canceled");
    state.payload("request", Buffer.from("cd"));
    assert.equal(state.snapshot().request_validated, true); assert.equal(state.snapshot().payload_bytes, 0);
    state.eof("request"); state.beginResponse(response(original));
    assert.equal(state.snapshot().received_items, 1n); assert.equal(state.snapshot().delivered_items, 0n);
    assert.deepEqual(state.observeDelivery(), { type: "item", payload_bytes: 0 });
    state.eof("response"); assert.equal(state.wait().wait_status, "ready");
    assert.equal(state.snapshot().terminal, "normal");
    const duplicate = ready(original); code(() => duplicate.beginRequest(original.header), "streaming_second_request");
    const incomplete = model(original); incomplete.beginRequest(original.header);
    code(() => incomplete.beginResponse(response(original)), "streaming_request_incomplete");
    const extra = ready(original); code(() => extra.payload("request", Buffer.from("x")), "streaming_payload_owner");
  }
});

test("execution input including empty payload is verified before any response", () => {
  for (const payload of [Buffer.alloc(0), Buffer.from("original")]) {
    const original = request("execution", payload), state = model(original);
    if (payload.length) {
      state.beginRequest(original.header);
      code(() => state.payload("request", Buffer.from("modified")), "application_request_digest");
    } else {
      code(() => state.beginRequest(encode({ ...original.fields, request_digest: bytes(Buffer.alloc(32)) })), "application_request_digest");
    }
    assert.equal(state.snapshot().closed, true); assert.equal(state.snapshot().request_validated, false);
    assert.equal(state.snapshot().payload_bytes, 0);
  }
  const original = request(), mismatched = request("execution", Buffer.alloc(0), { changes: { type_id: 7n } });
  code(() => model(mismatched).beginRequest(original.header), "application_contract_binding");
  const shape = model(original);
  code(() => shape.beginRequest(encode({ ...original.fields, message_kind: schema.application_message_kinds.execution_unary_request.code })), "streaming_request_kind");
});

// v4.streaming_messages.original_response
test("each item retains original variant, contract, type, execution identity and item limit", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics, Buffer.alloc(0), { limit: 3 });
    for (const [key, value] of [["type_id", 2], ["service_contract_digest", bytes(Buffer.alloc(32))],
      ...(semantics === "execution" ? [["operation_id", bytes(Buffer.alloc(32, 2))], ["request_digest", bytes(Buffer.alloc(32, 3))]] : [])]) {
      const state = ready(original);
      code(() => state.beginResponse(response(original, 0, "item", { [key]: value })), "application_response_binding");
    }
    code(() => ready(original).beginResponse(response(original, 4)), "application_response_limit");
    code(() => ready(original).beginResponse(response(original, 0, "item", { deadline_at_ms: 60000 })), "application_fields");
    code(() => ready(original).beginResponse(response(original, 0, "item", { message_kind: schema.application_message_kinds[`${semantics}_unary_response`].code })), "application_response_kind");
    const state = ready(original); state.beginResponse(response(original, 3));
    code(() => state.payload("response", Buffer.from("four")), "streaming_payload_length");
    assert.equal(state.snapshot().delivered_bytes, 0n);
  }
});

// v4.streaming_messages.cumulative_bounds
test("zero-length items still consume count; cumulative bytes use the complete original contract", () => {
  const original = request("transient", Buffer.alloc(0), { limit: 4, changes: { max_item_count: 2n, max_stream_payload_bytes: 5n } });
  const counts = ready(original);
  for (let i = 0; i < 2; i++) { counts.beginResponse(response(original)); counts.observeDelivery(); }
  code(() => counts.beginResponse(response(original)), "streaming_item_count");
  const totals = ready(original); totals.beginResponse(response(original, 3)); feed(totals, "response", Buffer.from("abc")); totals.observeDelivery();
  code(() => totals.beginResponse(response(original, 3)), "streaming_payload_total");
  const exact = ready(original);
  for (const payload of [Buffer.from("abc"), Buffer.from("de")]) {
    exact.beginResponse(response(original, payload.length)); feed(exact, "response", payload); exact.observeDelivery();
  }
  exact.eof("response"); assert.equal(exact.snapshot().received_bytes, 5n); assert.equal(exact.snapshot().delivered_bytes, 5n);
  const wide = request("execution", Buffer.alloc(0), { changes: { max_stream_payload_bytes: 0xffffffffffffffffn } });
  const state = ready(wide); state.beginResponse(response(wide)); state.observeDelivery(); state.eof("response");
  assert.equal(state.snapshot().terminal, "normal");
});

// v4.streaming_messages.terminal_boundary
test("EOF preserves one complete item but rejects every partial prefix", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics, Buffer.from("abc"));
    for (let offset = 0; offset < original.payload.length; offset++) {
      const state = model(original); state.beginRequest(original.header);
      if (offset) state.payload("request", original.payload.subarray(0, offset));
      code(() => state.eof("request"), "streaming_request_eof"); assert.equal(state.snapshot().payload_bytes, 0);
    }
    for (let offset = 0; offset < 4; offset++) {
      const state = ready(original); state.beginResponse(response(original, 4));
      if (offset) state.payload("response", Buffer.alloc(offset));
      code(() => state.eof("response"), "streaming_partial_eof"); assert.equal(state.snapshot().received_items, 0n);
    }
    const state = ready(original); state.beginResponse(response(original, 4)); state.payload("response", Buffer.from("item"));
    state.eof("response"); const before = state.snapshot();
    assert.equal(before.terminal, "normal"); assert.equal(before.payload_bytes, 4); assert.equal(before.delivered_items, 0n);
    for (let i = 0; i < 4; i++) { assert.equal(state.wait({ canceled: true }).wait_status, "ready"); assert.deepEqual(state.snapshot(), before); }
    assert.deepEqual(state.observeDelivery(), { type: "item", payload_bytes: 4 });
    assert.equal(state.snapshot().delivered_bytes, 4n); assert.equal(state.snapshot().payload_bytes, 0);
    code(() => state.beginResponse(response(original)), "streaming_terminal");
  }
});

test("business errors terminate only after a complete bound payload and never claim local item delivery", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics), state = ready(original);
    state.beginResponse(response(original, 2)); state.payload("response", Buffer.from("ok")); state.observeDelivery();
    state.beginResponse(response(original, 3, "application_error", { application_error_code: 777 }));
    state.payload("response", Buffer.from("e")); assert.equal(state.snapshot().terminal, "open");
    state.payload("response", Buffer.from("rr")); assert.equal(state.snapshot().terminal, "application_error");
    assert.equal(state.snapshot().received_items, 1n); assert.equal(state.snapshot().delivered_bytes, 2n);
    state.eof("response"); assert.equal(state.snapshot().terminal, "application_error");
    assert.deepEqual(state.observeDelivery(), { type: "application_error", payload_bytes: 3, classification: "unknown_application_error", code: 777n });
    assert.equal(state.snapshot().delivered_bytes, 2n);
    code(() => state.beginResponse(response(original)), "streaming_terminal");
  }
  const zero = request("transient", Buffer.alloc(0), { limit: 0 });
  code(() => ready(zero).beginResponse(response(zero, 1, "application_error", { application_error_code: 777 })), "application_response_limit");
  const original = request("execution", Buffer.alloc(0), { limit: 3, changes: { max_stream_payload_bytes: 2n } });
  code(() => ready(original).beginResponse(response(original, 3, "application_error", { application_error_code: 777 })), "streaming_payload_total");
});

// v4.streaming_messages.ownership
test("canceled status waits do not consume partial or complete items; close retains prior delivery facts", () => {
  const original = request(), state = ready(original);
  state.beginResponse(response(original, 4)); state.payload("response", Buffer.from("ab"));
  const partial = state.snapshot();
  for (let i = 0; i < 3; i++) { assert.equal(state.wait({ canceled: true }).wait_status, "wait_canceled"); assert.deepEqual(state.snapshot(), partial); }
  state.payload("response", Buffer.from("cd"));
  assert.equal(state.wait().wait_status, "blocked"); assert.equal(state.snapshot().delivered_items, 0n);
  state.observeDelivery(); state.beginResponse(response(original, 4)); state.payload("response", Buffer.from("next"));
  state.close(); assert.equal(state.snapshot().payload_bytes, 0); assert.equal(state.snapshot().delivered_items, 1n);
  assert.equal(state.snapshot().delivered_bytes, 4n); assert.equal(state.snapshot().terminal, "open");
  code(() => state.observeDelivery(), "streaming_reference_closed");
  const pending = ready(original); pending.beginResponse(response(original));
  code(() => pending.beginResponse(response(original)), "streaming_candidate_pending");
});

test("capture original header, contract and schema; expose metadata rather than mutable payloads", () => {
  const original = request("execution", Buffer.from("abcd")), source = structuredClone(schema), state = model(original, 2, source);
  const goodHeader = Buffer.from(original.header);
  state.beginRequest(goodHeader); goodHeader.fill(0); original.contract.fill(0); source.application_message_kinds.execution_stream_item.request = "execution_unary_request";
  const prefix = Buffer.from("ab"); state.payload("request", prefix); prefix.fill(0); state.payload("request", Buffer.from("cd"));
  state.beginResponse(response(original, 2)); state.payload("response", Buffer.from("ok"));
  const result = state.observeDelivery(); assert.ok(Object.isFrozen(result));
  assert.deepEqual(Object.keys(result).sort(), ["payload_bytes", "type"]);
  const invalid = request(); code(() => model(invalid, 0), "streaming_chunk_capacity");
  const tooLarge = model(invalid, 1); tooLarge.beginRequest(invalid.header); tooLarge.beginResponse(response(invalid, 2));
  code(() => tooLarge.payload("response", Buffer.from("ab")), "application_input_size");
});

// v4.streaming_messages.churn
test("inherited byte proxies cannot reenter Close or EOF during response capture", () => {
  for (const terminate of [state => state.close(), state => state.eof("response")]) {
    const original = request(), state = ready(original), header = response(original, 1);
    let calls = 0;
    Object.setPrototypeOf(header, new Proxy({}, { getPrototypeOf() {
      calls++; terminate(state); Object.setPrototypeOf(header, Buffer.prototype); return Buffer.prototype;
    } }));
    code(() => state.beginResponse(header), "application_input_bytes");
    assert.equal(calls, 0); assert.equal(state.snapshot().closed, true);
    assert.equal(state.snapshot().payload_bytes, 0); assert.equal(state.snapshot().received_items, 0n);
    assert.equal(state.snapshot().response_eof, false);
  }
});

test("maximum item payloads and repeated items retain only one bounded payload", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics, Buffer.alloc(1048576, 9), { limit: 1048576 });
    const state = ready(original); assert.equal(state.snapshot().payload_bytes, 0);
    state.beginResponse(response(original, 1048576)); assert.equal(state.snapshot().payload_bytes, 1048576);
    feed(state, "response", Buffer.alloc(1048576, 10)); state.eof("response"); state.observeDelivery();
    assert.equal(state.snapshot().delivered_bytes, 1048576n); assert.equal(state.snapshot().payload_bytes, 0);
  }
  const original = request("transient"), state = ready(original);
  for (let i = 0; i < 1024; i++) {
    state.beginResponse(response(original, 1)); state.payload("response", Buffer.from([i & 255]));
    assert.equal(state.snapshot().payload_bytes, 1); state.observeDelivery(); assert.equal(state.snapshot().payload_bytes, 0);
  }
  state.eof("response"); assert.equal(state.snapshot().received_items, 1024n); assert.equal(state.snapshot().delivered_items, 1024n);
});

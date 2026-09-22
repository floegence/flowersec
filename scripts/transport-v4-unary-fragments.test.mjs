import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { decodeMap, encodeCBOR, mapFromNames } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { executionRequestDigest } from "./transport-v4-application-headers.mjs";
import { encodeFragment } from "./transport-v4-fragments.mjs";
import { UnaryFragmentReference } from "./transport-v4-unary-fragments.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = JSON.parse(fs.readFileSync(new URL("../testdata/transport_v4/corpus.json", import.meta.url)));
const bytes = value => ({ $bytes: value.toString("hex") });
const id = (name, key) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([, field]) => field.name === key)[0]);
const value = (name, map, key) => map.get(id(name, key));
const encode = fields => encodeCBOR(mapFromNames(schema, "ApplicationHeader", fields));
const digest = contract => Buffer.from(evaluateDomain(schema, "service_contract_digest", { contract }).output_hex, "hex");
const wire = fragment => encodeFragment(schema.fragment_registry, fragment);
const kind = name => schema.fragment_registry.kinds[name].value;
const begin = (serial, header, reply = 0n) => wire({ kind: kind("BEGIN"), message_serial: serial, reply_to_serial: reply, canonical_header: header });
const data = (serial, offset, payload) => wire({ kind: kind("DATA"), message_serial: serial, payload_offset: offset, payload_bytes: payload });
const abort = (serial, offset) => wire({ kind: kind("ABORT"), message_serial: serial, next_offset: offset });
const stop = serial => wire({ kind: kind("STOP_OUTPUT"), request_serial: serial });
const model = (requestCapacity = 2) => new UnaryFragmentReference(schema, { requestCapacity });
const code = (fn, expected) => assert.throws(fn, error => error.code === expected);

function request(semantics = "execution", payload = Buffer.alloc(0), limit = 16, editContract) {
  const contractMap = decodeMap(schema, "ServiceContract", Buffer.from(corpus.vectors.find(entry => entry.id === `service_unary_${semantics}`).hex, "hex"));
  editContract?.(contractMap);
  const contract = encodeCBOR(contractMap), requestKind = `${semantics}_unary_request`;
  const fields = {
    message_kind: schema.application_message_kinds[requestKind].code,
    type_id: Number(value("ServiceContract", contractMap, "type_id")), payload_length: payload.length,
    deadline_at_ms: 50000, service_contract_digest: bytes(digest(contract)), admission_mode: 0, response_limit_bytes: limit,
  };
  if (semantics === "execution") {
    fields.operation_id = bytes(Buffer.alloc(32, 1));
    fields.request_digest = bytes(Buffer.alloc(32));
    fields.request_digest = bytes(executionRequestDigest(schema, encode(fields), contract, payload));
  }
  return { contract, fields, header: encode(fields), payload, semantics };
}

function response(original, length = 0, suffix = "response", extra = {}) {
  const variant = schema.application_message_kinds[`${original.semantics}_unary_${suffix}`];
  const fields = {};
  for (const field of variant.fields) {
    const name = schema.frame_maps.ApplicationHeader.fields[field].name;
    fields[name] = name === "message_kind" ? variant.code : name === "payload_length" ? length : original.fields[name];
  }
  return encode({ ...fields, ...extra });
}

function sdkPayload(code) {
  return encodeCBOR(mapFromNames(schema, schema.application_sdk_errors.payload_schema, { code: schema.application_sdk_error_codes[code] }));
}

function completePayload(state, direction, serial, payload) {
  const chunk = schema.fragment_registry.kinds.DATA.payload_max_bytes;
  let result;
  for (let offset = 0; offset < payload.length; offset += chunk) {
    result = state.accept(direction, data(serial, offset, payload.subarray(offset, offset + chunk)));
    assert.ok(state.snapshot().payload_bytes <= state.snapshot().payload_bound);
  }
  return result;
}

function completeRequest(state, direction, serial, original) {
  const event = state.accept(direction, begin(serial, original.header), original.contract);
  return original.payload.length ? completePayload(state, direction, serial, original.payload) : event;
}

function sdkResponse(state, original, code, serial = 1n, reply = 1n) {
  const body = sdkPayload(code);
  state.accept(1, begin(serial, response(original, body.length, "sdk_error"), reply));
  return state.accept(1, data(serial, 0, body));
}

// v4.unary_fragments.empty_input
test("empty BEGIN validates execution digest before response or STOP eligibility", () => {
  for (const semantics of ["execution", "transient"]) {
    const state = model(), original = request(semantics);
    assert.deepEqual(completeRequest(state, 0, 1n, original), { type: "request", status: "complete", offset: 0 });
    assert.equal(state.snapshot().payload_bytes, 0);
    assert.equal(state.accept(0, stop(1n)).status, "stop_requested");
    // A normal response may already have won its publication race.
    assert.deepEqual(state.accept(1, begin(1n, response(original), 1n)), { type: "response", status: "complete", offset: 0 });
    assert.deepEqual(state.snapshot().requests, [0, 0]);
    assert.equal(state.accept(0, stop(1n)).status, "ignored");
  }
  const invalid = request(), state = model();
  invalid.fields.request_digest = bytes(Buffer.alloc(32));
  code(() => state.accept(0, begin(1n, encode(invalid.fields)), invalid.contract), "application_request_digest");
  assert.equal(state.snapshot().closed, true);
  assert.equal(state.snapshot().payload_bytes, 0);
  code(() => completeRequest(state, 0, 1n, request()), "channel_closed");
});

// v4.unary_fragments.interleaving
test("bidirectional interleaving derives type, length and private owners from actual headers", () => {
  const state = model(), left = request("execution", Buffer.from("abcd")), right = request("transient", Buffer.from("xyz"));
  state.accept(0, begin(1n, left.header), left.contract);
  state.accept(1, begin(1n, right.header), right.contract);
  state.accept(0, data(1n, 0, left.payload.subarray(0, 2)));
  state.accept(1, data(1n, 0, right.payload));
  assert.equal(state.snapshot().payload_bytes, 4);
  state.accept(0, begin(2n, response(right, 2), 1n));
  state.accept(0, data(1n, 2, left.payload.subarray(2)));
  state.accept(1, begin(2n, response(left, 1), 1n));
  assert.deepEqual(state.snapshot().payload_bytes, 3);
  assert.equal(state.accept(0, data(2n, 0, Buffer.from("ok"))).status, "complete");
  // Receive-side ABORT does not guess or require the remote local reason.
  assert.deepEqual(state.accept(1, abort(2n, 0)), { type: "response", status: "aborted", offset: 0 });
  assert.deepEqual(state.snapshot().indexed_messages, [0, 0]);
  assert.deepEqual(state.snapshot().highwater, [2n, 2n]);

  const early = model();
  early.accept(0, begin(1n, left.header), left.contract);
  code(() => early.accept(1, begin(1n, response(left), 1n)), "response_boundary");
  const stopped = model();
  stopped.accept(0, begin(1n, left.header), left.contract);
  code(() => stopped.accept(0, stop(1n)), "stop_ineligible");
});

// v4.unary_fragments.input_integrity
test("full execution bytes, lengths and offsets are checked before complete input", () => {
  const original = request("execution", Buffer.from("abcd"));
  for (const [fragment, expected] of [
    [data(1n, 1, Buffer.from("a")), "offset_mismatch"],
    [data(1n, 0, Buffer.from("abcde")), "payload_overrun"],
    [data(1n, 0, Buffer.from("abce")), "application_request_digest"],
    [abort(1n, 1), "abort_offset"],
  ]) {
    const state = model(); state.accept(0, begin(1n, original.header), original.contract);
    code(() => state.accept(0, fragment), expected);
    assert.equal(state.snapshot().closed, true);
    assert.equal(state.snapshot().payload_bytes, 0);
  }
  const state = model(); completeRequest(state, 0, 1n, original);
  code(() => state.accept(0, abort(1n, 4)), "message_not_open");
});

// v4.unary_fragments.request_abort
test("partial request ABORT retains only its original association until the bounded SDK terminal", () => {
  for (const semantics of ["execution", "transient"]) {
    const state = model(1), original = request(semantics, Buffer.from("abcd"), 0);
    if (semantics === "execution") {
      original.fields.request_digest = bytes(Buffer.alloc(32, 9));
      original.header = encode(original.fields); // Deliberately unverified input.
    }
    state.accept(0, begin(1n, original.header), original.contract);
    state.accept(0, data(1n, 0, original.payload.subarray(0, 2)));
    assert.deepEqual(state.accept(0, abort(1n, 2)), { type: "request", status: "aborted", offset: 2 });
    assert.deepEqual(state.snapshot().requests, [1, 0]);
    assert.equal(state.snapshot().payload_bytes, 0);
    const body = sdkPayload("request_message_aborted");
    state.accept(1, begin(1n, response(original, body.length, "sdk_error"), 1n));
    state.accept(1, data(1n, 0, body.subarray(0, 1)));
    assert.deepEqual(state.snapshot().requests, [1, 0]);
    const done = state.accept(1, data(1n, 1, body.subarray(1)));
    assert.deepEqual(done.result, { code: "request_message_aborted" });
    assert.ok(Object.isFrozen(done) && Object.isFrozen(done.result));
    assert.deepEqual(state.snapshot().requests, [0, 0]);
    assert.equal(state.accept(0, stop(1n)).status, "ignored");
  }
});

// v4.unary_fragments.stop_binding
test("SDK stop code must match the actual original request boundary", () => {
  const original = request("execution", Buffer.from("abc"), 0);
  const aborted = model(); aborted.accept(0, begin(1n, original.header), original.contract); aborted.accept(0, abort(1n, 0));
  code(() => sdkResponse(aborted, original, "response_output_stopped"), "response_stop_code");
  const stopped = model(); completeRequest(stopped, 0, 1n, original);
  assert.equal(stopped.accept(0, stop(1n)).status, "stop_requested");
  assert.equal(stopped.accept(0, stop(1n)).status, "coalesced");
  assert.deepEqual(sdkResponse(stopped, original, "response_output_stopped").result, { code: "response_output_stopped" });
  const wrong = model(); completeRequest(wrong, 0, 1n, original); wrong.accept(0, stop(1n));
  code(() => sdkResponse(wrong, original, "request_message_aborted"), "response_stop_code");
  const unsolicited = model(); completeRequest(unsolicited, 0, 1n, original);
  code(() => sdkResponse(unsolicited, original, "response_output_stopped"), "response_stop_boundary");
  const lateStop = model(); lateStop.accept(0, begin(1n, original.header), original.contract); lateStop.accept(0, abort(1n, 0));
  code(() => lateStop.accept(0, stop(1n)), "stop_ineligible");
});

// v4.unary_fragments.responses
test("original variant, type, digest, direction and limit govern response BEGIN", () => {
  for (const semantics of ["execution", "transient"]) {
    const original = request(semantics, Buffer.alloc(0), 0);
    const errors = [[response(original, 1), "application_response_limit"],
      [response(original, 0, "response", { type_id: 42 }), "application_response_binding"],
      [response(original, 0, "response", { service_contract_digest: bytes(Buffer.alloc(32, 7)) }), "application_response_binding"],
      [response(original, 0, "response", { deadline_at_ms: 0 }), "application_fields"]];
    if (semantics === "execution") for (const key of ["operation_id", "request_digest"]) errors.push([response(original, 0, "response", { [key]: bytes(Buffer.alloc(32, 7)) }), "application_response_binding"]);
    for (const [header, expected] of errors) {
      const state = model(); completeRequest(state, 0, 1n, original);
      code(() => state.accept(1, begin(1n, header, 1n)), expected);
      assert.equal(state.snapshot().payload_bytes, 0);
    }
    const otherDirection = model(); completeRequest(otherDirection, 0, 1n, original);
    code(() => otherDirection.accept(0, begin(2n, response(original), 1n)), "response_binding");
    const duplicate = model(), bounded = request(semantics, Buffer.alloc(0), 2); completeRequest(duplicate, 0, 1n, bounded);
    duplicate.accept(1, begin(1n, response(bounded, 1), 1n));
    code(() => duplicate.accept(1, begin(2n, response(bounded, 1), 1n)), "response_duplicate");
  }
});

// v4.unary_fragments.business_errors
test("business size failures and unknown codes are complete results within original response bounds", () => {
  for (const semantics of ["execution", "transient"]) for (const [length, applicationCode, classification] of [[2, 7, "known_application_error"], [3, 7, "application_result_decode_failed"], [3, 99, "unknown_application_error"]]) {
    const original = request(semantics, Buffer.alloc(0), 3, contract => contract.set(id("ServiceContract", "application_error_catalog"), [mapFromNames(schema, "ErrorDefinition", { code: 7, schema_revision: "1", max_payload_bytes: 2, schema_digest: bytes(Buffer.alloc(32, 1)) })]));
    const state = model(); completeRequest(state, 0, 1n, original);
    state.accept(1, begin(1n, response(original, length, "application_error", { application_error_code: applicationCode }), 1n));
    const result = state.accept(1, data(1n, 0, Buffer.alloc(length)));
    assert.deepEqual(result.result, { classification, code: BigInt(applicationCode) });
    assert.equal(state.snapshot().closed, false);
    assert.deepEqual(state.snapshot().requests, [0, 0]);
  }
  const original = request("transient", Buffer.alloc(0), 0), state = model(); completeRequest(state, 0, 1n, original);
  code(() => state.accept(1, begin(1n, response(original, 1, "application_error", { application_error_code: 99 }), 1n)), "application_response_limit");
});

// v4.unary_fragments.response_abort
test("response ABORT retires partial success, business or SDK bytes without decoding them", () => {
  for (const suffix of ["response", "application_error", "sdk_error"]) {
    const original = request(), state = model(); completeRequest(state, 0, 1n, original);
    if (suffix === "sdk_error") state.accept(0, stop(1n));
    state.accept(1, begin(1n, response(original, 3, suffix, suffix === "application_error" ? { application_error_code: 1 } : {}), 1n));
    state.accept(1, data(1n, 0, Buffer.from([255])));
    assert.deepEqual(state.accept(1, abort(1n, 1)), { type: "response", status: "aborted", offset: 1 });
    assert.deepEqual(state.snapshot().indexed_messages, [0, 0]);
    assert.equal(state.snapshot().payload_bytes, 0);
    assert.equal(state.accept(0, stop(1n)).status, "ignored");
  }
});

// v4.unary_fragments.max_payload
test("1 MiB requests and responses use one bounded payload backing per live association", () => {
  const max = schema.resource_caps.max_payload_length;
  const original = request("execution", Buffer.alloc(max, 65), max), state = model(1);
  state.accept(0, begin(1n, original.header), original.contract);
  assert.equal(state.snapshot().payload_bytes, max);
  completePayload(state, 0, 1n, original.payload);
  assert.equal(state.snapshot().payload_bytes, 0);
  state.accept(1, begin(1n, response(original, max), 1n));
  assert.equal(state.snapshot().payload_bytes, max);
  assert.equal(completePayload(state, 1, 1n, Buffer.alloc(max, 66)).status, "complete");
  assert.equal(state.snapshot().payload_bytes, 0);
  assert.deepEqual(state.snapshot().requests, [0, 0]);
});

// v4.unary_fragments.ownership
test("input bytes and trusted contracts are captured; closed references cannot be reopened", () => {
  const original = request("execution", Buffer.from("abc")), state = model();
  const contract = Buffer.from(original.contract), frame = begin(1n, original.header);
  state.accept(0, frame, contract); frame.fill(0); contract.fill(0);
  completePayload(state, 0, 1n, original.payload);
  state.accept(1, begin(1n, response(original), 1n));
  const snapshot = state.snapshot(); assert.ok(Object.isFrozen(snapshot.highwater));
  code(() => state.accept(0, data(1n, 0, Buffer.from([0]))), "message_not_open");
  state.close(); state.close();
  assert.deepEqual(state.snapshot().highwater, [1n, 1n]);
  code(() => completeRequest(state, 0, 2n, original), "channel_closed");
  let getters = 0;
  const forged = begin(1n, original.header); Object.defineProperty(forged, "length", { get() { getters++; throw Error("unexpected getter"); } });
  code(() => model().accept(0, forged, original.contract), "application_input_bytes");
  assert.equal(getters, 0);
  code(() => model().accept(0, Buffer.alloc(16385), original.contract), "application_input_size");
});

// v4.unary_fragments.churn
test("old aborted requests coexist with churn without serial tombstones or stale STOP aliasing", () => {
  const state = model(2), old = request("transient", Buffer.from([1])), next = request("transient");
  state.accept(0, begin(1n, old.header), old.contract); state.accept(0, abort(1n, 0));
  for (let serial = 2n; serial <= 1025n; serial++) {
    completeRequest(state, 0, serial, next);
    if (serial > 2n) assert.equal(state.accept(0, stop(serial - 1n)).status, "ignored");
    state.accept(1, begin(serial - 1n, response(next), serial));
    assert.deepEqual(state.snapshot().indexed_messages, [1, 0]);
    assert.deepEqual(state.snapshot().requests, [1, 0]);
    assert.equal(state.snapshot().payload_bytes, 0);
  }
  sdkResponse(state, old, "request_message_aborted", 1025n);
  assert.deepEqual(state.snapshot().indexed_messages, [0, 0]);
  assert.deepEqual(state.snapshot().highwater, [1025n, 1025n]);
});

// v4.unary_fragments.malformed
test("complete malformed SDK payloads and wrong framing kinds cannot become application results", () => {
  const original = request("transient");
  for (const hex of ["a10000", "a10019ffff", "a0", "a200010100", "a200010001", "a1180001", "a1000200", "a100"]) {
    const state = model(), payload = Buffer.from(hex, "hex"); completeRequest(state, 0, 1n, original); state.accept(0, stop(1n));
    state.accept(1, begin(1n, response(original, payload.length, "sdk_error"), 1n));
    assert.throws(() => state.accept(1, data(1n, 0, payload)), error => typeof error.code === "string");
    assert.equal(state.snapshot().closed, true); assert.deepEqual(state.snapshot().indexed_messages, [0, 0]);
  }
  const empty = model(); completeRequest(empty, 0, 1n, original); empty.accept(0, stop(1n));
  assert.throws(() => empty.accept(1, begin(1n, response(original, 0, "sdk_error"), 1n)));
  const future = model(); completeRequest(future, 0, 1n, original);
  code(() => future.accept(0, stop(2n)), "stop_future");
  const headers = JSON.parse(fs.readFileSync(new URL("../testdata/transport_v4/application_headers.json", import.meta.url)));
  for (const vector of headers.vectors.filter(entry => entry.accept && ["execution_stream_request", "transient_stream_request", "observation_notify", "query_contracts_request", "query_operation_request"].includes(entry.kind))) {
    code(() => model().accept(0, begin(1n, Buffer.from(vector.hex, "hex")), original.contract), "unary_fragment_kind");
  }
  code(() => model().accept(0, begin(1n, original.header)), "reference_contract_required");
  const bounded = model(1); completeRequest(bounded, 0, 1n, original);
  code(() => completeRequest(bounded, 0, 2n, original), "state_capacity");
});

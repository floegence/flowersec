import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {encodeCBOR, mapFromNames, VectorError} from "./transport-v4-codec.mjs";
import {buildArtifacts} from "./generate-transport-v4-vectors.mjs";
import {buildApplicationHeaderCorpus, decodeApplicationHeader, verifyApplicationHeaderSchema, verifyApplicationResponse} from "./transport-v4-application-headers.mjs";
import {verifyApplicationSDKErrorReference} from "./transport-v4-application-sdk-errors.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const bytes = byte => ({$bytes:byte.repeat(32)});
const header = values => encodeCBOR(mapFromNames(schema, "ApplicationHeader", values));
const error = code => encodeCBOR(mapFromNames(schema, "ApplicationSDKError", {code}));
const fail = (operation, code) => assert.throws(operation, caught => caught instanceof VectorError && caught.code === code);
function pair(requestKind, code = 1, limit = 0) {
  const requestVariant = schema.application_message_kinds[requestKind];
  const [kind, variant] = Object.entries(schema.application_message_kinds).find(([,value]) => value.request === requestKind && value.sdk_error);
  const body = error(code);
  const request = {message_kind:requestVariant.code,type_id:9,payload_length:17,deadline_at_ms:999,service_contract_digest:bytes("ab")};
  if (requestVariant.fields.includes(1)) Object.assign(request, {operation_id:bytes("01"),request_digest:bytes("02")});
  if (requestVariant.fields.includes(8)) Object.assign(request, {admission_mode:1,response_limit_bytes:limit});
  const response = {...request,message_kind:variant.code,payload_length:body.length};
  for (const field of ["deadline_at_ms","admission_mode","response_limit_bytes"]) delete response[field];
  return {kind,request,response,body};
}
const verify = p => verifyApplicationSDKErrorReference(schema, header(p.request), header(p.response), p.body);

test("v4.sdk_stop_errors.bindings: registered codes retain each original ordinary request shape", () => {
  for (const requestKind of schema.application_sdk_errors.requests) for (const [name, code] of Object.entries(schema.application_sdk_error_codes)) {
    const p = pair(requestKind,code), before = structuredClone(p);
    const stream = ["execution_stream_request", "transient_stream_request"].includes(requestKind);
    if (stream && ["request_message_aborted", "response_output_stopped"].includes(name)) {
      fail(() => verify(p), "streaming_sdk_error_code"); continue;
    }
    if (!stream && name === "source_overflow") {
      fail(() => verify(p), "application_sdk_error_code"); continue;
    }
    assert.deepEqual(verify(p), {code:name});
    assert.equal(p.body.toString("hex"), `a100${code.toString(16).padStart(2,"0")}`);
    assert.deepEqual({...p,body:new Uint8Array(p.body)}, before);
    for (const field of ["type_id","service_contract_digest", ...(p.request.operation_id ? ["operation_id","request_digest"] : [])]) {
      const value = field === "type_id" ? 8 : bytes("cd");
      fail(() => verify({...p,response:{...p.response,[field]:value}}), "application_response_binding");
    }
    for (const field of ["deadline_at_ms","admission_mode","response_limit_bytes","application_error_code"]) {
      fail(() => verify({...p,response:{...p.response,[field]:1}}), "application_fields");
    }
    if (!p.request.operation_id) for (const field of ["operation_id","request_digest"]) fail(() => verify({...p,response:{...p.response,[field]:bytes("01")}}), "application_fields");
  }
});

test("v4.sdk_stop_errors.reservation: exact SDK errors use the fixed small reservation when success limit is zero", () => {
  for (const kind of ["execution_unary_request","transient_unary_request"]) {
    const p = pair(kind);
    assert.equal(p.request.response_limit_bytes,0);
    verify(p);
    for (const size of [0,1,255,256]) verifyApplicationResponse(schema, header(p.request), header({...p.response,payload_length:size}));
    fail(() => verifyApplicationResponse(schema, header(p.request), header({...p.response,payload_length:257})), "application_sdk_error_limit");
    fail(() => verify({...p,body:Buffer.alloc(257)}), "application_input_size");
    const successKind = Object.entries(schema.application_message_kinds).find(([,v]) => v.request === kind && !v.sdk_error && !v.application_error)[1].code;
    fail(() => verifyApplicationResponse(schema, header(p.request), header({...p.response,message_kind:successKind})), "application_response_limit");
    const businessKind = Object.entries(schema.application_message_kinds).find(([,v]) => v.request === kind && v.application_error)[1].code;
    fail(() => verifyApplicationResponse(schema, header(p.request), header({...p.response,message_kind:businessKind,application_error_code:777})), "application_response_limit");
  }
});

test("v4.sdk_stop_errors.payload: complete canonical payloads cannot add execution claims or raw causes", () => {
  const p = pair("execution_unary_request");
  for (const [hex,code] of [["a10000","field_range"],["a10019ffff","enum_value"],["a0","missing_field"],["a200010100","unknown_field"],["a200010001","duplicate_key"],["a1180001","non_shortest_integer"],["a1000100","trailing_bytes"],["a100","truncated"]]) {
    const body = Buffer.from(hex,"hex");
    fail(() => verify({...p,body,response:{...p.response,payload_length:body.length}}),code);
  }
  fail(() => verify({...p,response:{...p.response,payload_length:2}}), "application_payload_length");
  // The echo is an association, not evidence that a partial payload's digest was verified.
  p.request.request_digest = p.response.request_digest = bytes("ff");
  assert.deepEqual(verify(p), {code:"request_message_aborted"});
  const result = verify(pair("execution_unary_request",2));
  assert.deepEqual(Object.keys(result),["code"]);
  assert.ok(Object.isFrozen(result));
  for (const field of ["not_submitted","executed","not_executed","retryable","delivered"]) assert.equal(Object.hasOwn(result,field),false);
});

test("v4.sdk_stop_errors.scope: request pairing cannot create streaming, notify or management responses", () => {
  const p = pair("execution_unary_request");
  for (const message_kind of [25,26]) fail(() => verify({...p,request:{...p.request,message_kind}}), "application_response_kind");
  for (const requestKind of schema.application_sdk_errors.requests) for (const other of schema.application_sdk_errors.requests) {
    if (other === requestKind) continue;
    const current = pair(requestKind), wrong = pair(other);
    fail(() => verify({...current,response:wrong.response}),"application_response_kind");
  }
  const success = pair("transient_unary_request",1,256); success.response.message_kind = 31;
  fail(() => verify(success), "application_sdk_error_kind");
  for (const mutation of [s => s.application_message_kinds.execution_unary_sdk_error.request = "execution_notify",s => s.application_message_kinds.execution_unary_sdk_error.application_error = true,s => s.application_sdk_errors.requests.push("query_operation_request"),s => s.frame_maps.ApplicationSDKError.max_encoded_bytes = 257]) {
    const changed = structuredClone(schema); mutation(changed); assert.throws(() => verifyApplicationHeaderSchema(changed));
  }
});

test("v4.sdk_stop_errors.generated: exact header sizes and four registry declarations share the schema", () => {
  const corpus = buildApplicationHeaderCorpus(schema);
  for (const vector of corpus.vectors.filter(v => v.accept && schema.application_message_kinds[v.kind].sdk_error)) {
    const raw = Buffer.from(vector.hex,"hex"), decoded = decodeApplicationHeader(schema,raw);
    assert.equal(decoded.map.get(3n),256n);
    assert.equal(raw.length, vector.kind.startsWith("execution_") ? 119 : 49);
  }
  const artifacts = buildArtifacts();
  for (const name of ["flowersec-go/internal/protocolv4/registry_generated.go","flowersec-rust/src/protocol_v4_registry_generated.rs","flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift","flowersec-ts/src/generated/transportV4Registry.ts"]) {
    const content = artifacts.files.get(name);
    for (const key of ["sdk_error_payload","application_sdk_error_codes","request_message_aborted","response_output_stopped"]) assert.ok(content.includes(key),`${name}: ${key}`);
  }
});

import assert from "node:assert/strict";
import { cborHead, decodeMap, encodeCBOR, mapFromNames, strictHex, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { referenceByteView } from "./transport-v4-bytes.mjs";

// Reference validation of complete authenticated header candidates. Authentication,
// original channel/serial ownership, admission and dispatch are external gates.
const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const name = "ApplicationHeader";
const same = (left, right) => Buffer.isBuffer(left) ? Buffer.isBuffer(right) && left.equals(right) : left === right;
export function captureApplicationBytes(value, cap) {
  let view;
  try { view=referenceByteView(value); } catch { throw new VectorError("application_input_bytes"); }
  requireThat(Buffer.isBuffer(value), "application_input_bytes");
  requireThat(view.length <= cap, "application_input_size");
  return Buffer.from(view);
}

export function verifyApplicationHeaderSchema(schema) {
  const registry = schema.application_headers;
  assert.equal(registry.status, "draft_business_and_rpc_stop_error_variants");
  const sdk = schema.application_sdk_errors;
  assert.equal(sdk.status, "draft_rpc_and_stream_errors");
  assert.equal(sdk.payload_schema, "ApplicationSDKError");
  assert.deepEqual(sdk.refusal_codes, Object.keys(schema.application_sdk_error_codes).filter(code => !["request_message_aborted","response_output_stopped", ...sdk.stream_only_codes].includes(code)));
  assert.deepEqual(sdk.stream_only_codes, ["source_overflow"]);
  assert.equal(schema.frame_maps[sdk.payload_schema].max_encoded_bytes, 256);
  assert.equal(new Set(sdk.requests).size, sdk.requests.length);
  assert.ok(sdk.requests.every(kind => [0,1].includes(registry.contract_variants[kind]?.[2]) || ["query_contracts_request","read_result_request"].includes(kind)), "SDK responses belong to ordinary RPC or dedicated streaming");
  const sdkRequests = [];
  const fields = schema.frame_maps[name].fields;
  assert.equal(schema.frame_maps[name].max_encoded_bytes, 512);
  const codes = new Set();
  for (const [kind, variant] of Object.entries(schema.application_message_kinds)) {
    assert.match(kind, /^[a-z][a-z0-9_]*$/u);
    assert.deepEqual(Object.keys(variant).sort(), ["code", "fields", "max_encoded_bytes", ...(variant.request ? ["request"] : []), ...(variant.constants ? ["constants"] : []), ...(variant.application_error !== undefined ? ["application_error"] : []), ...(variant.sdk_error !== undefined ? ["sdk_error"] : [])].sort());
    assert.ok(Number.isInteger(variant.code) && variant.code >= 0 && variant.code <= 255 && !codes.has(variant.code));
    codes.add(variant.code);
    assert.ok(Array.isArray(variant.fields) && variant.fields.length > 0);
    assert.deepEqual(variant.fields, [...new Set(variant.fields)].sort((a,b) => a-b));
    assert.ok(variant.fields.every(id => Object.hasOwn(fields,id)));
    assert.ok([0,2,3,6].every(id => variant.fields.includes(id)));
    assert.ok(Number.isInteger(variant.max_encoded_bytes) && variant.max_encoded_bytes > 0 && variant.max_encoded_bytes <= 512);
    for (const [id, value] of Object.entries(variant.constants ?? {})) {
      assert.ok(variant.fields.includes(Number(id)) && fields[id].type.startsWith("uint"));
      assert.ok(Number.isSafeInteger(value) && value >= 0);
    }
    if (variant.request) {
      const request = schema.application_message_kinds[variant.request];
      assert.ok(request && !request.request && request.fields.includes(5), "response requires original request variant");
      assert.ok(![5,7,8].some(id => variant.fields.includes(id)), "response cannot override request options");
      for (const id of [1,4,9]) assert.equal(variant.fields.includes(id), request.fields.includes(id));
    }
    assert.equal(variant.fields.includes(10),variant.application_error === true,"business code belongs only to business-error variants");
    if (variant.sdk_error !== undefined) {
      assert.equal(variant.sdk_error, true);
      assert.ok(sdk.requests.includes(variant.request), "SDK error requires a registered request");
      assert.ok(!variant.application_error && !variant.fields.includes(9), "SDK and business/management errors are separate");
      sdkRequests.push(variant.request);
    }
    if (variant.application_error !== undefined) {
      assert.equal(variant.application_error,true);
      assert.ok(variant.request && Object.hasOwn(registry.contract_variants,variant.request));
      assert.ok([0,1].includes(registry.contract_variants[variant.request][2]),"NOTIFY has no business error response");
      assert.ok(!variant.fields.includes(9),"management responses cannot carry business errors");
    }
  }
  assert.deepEqual(sdkRequests.slice().sort(), sdk.requests.slice().sort(), "each registered request needs exactly one SDK error variant");
  assert.deepEqual(registry.execution_requests, Object.keys(registry.contract_variants).filter(kind=>schema.application_message_kinds[kind].fields.includes(1)));
  assert.equal(new Set(registry.execution_requests).size, registry.execution_requests.length);
  for (const kind of registry.execution_requests) {
    const variant = schema.application_message_kinds[kind];
    assert.ok(variant && !variant.request && variant.fields.includes(1) && variant.fields.includes(4));
  }
  for (const [kind,shape] of Object.entries(registry.contract_variants)) {
    assert.ok(schema.application_message_kinds[kind] && !schema.application_message_kinds[kind].request);
    assert.ok([0,1,2].includes(shape[2]));
    assert.deepEqual(Object.keys(shape),["2",String(shape[2]+3)],"request shape has one applicable semantic variant");
    assert.equal(shape[shape[2]+3],schema.application_message_kinds[kind].fields.includes(1)?1:0);
    for (const [id,value] of Object.entries(shape)) {
      const field=schema.frame_maps.ServiceContract.fields[id];
      assert.ok(field?.enum && Object.values(field.enum).includes(value));
    }
  }
  const domain=schema.domains.find(entry=>entry.name==="execution_request_digest");
  assert.deepEqual(domain.input_schema.parts.find(part=>part.name==="message_kind").enum, registry.execution_requests.map(kind=>schema.application_message_kinds[kind].code));
}

export function decodeApplicationHeader(schema, input) {
  const bytes = captureApplicationBytes(input,schema.frame_maps[name].max_encoded_bytes);
  const map = decodeMap(schema, name, bytes);
  const entry = Object.entries(schema.application_message_kinds).find(([,variant]) => BigInt(variant.code) === map.get(0n));
  requireThat(entry !== undefined, "application_kind");
  const [kind, variant] = entry;
  requireThat(map.size === variant.fields.length && variant.fields.every(id => map.has(BigInt(id))), "application_fields");
  for (const [id,value] of Object.entries(variant.constants ?? {})) requireThat(map.get(BigInt(id)) === BigInt(value), "application_constant");
  if (variant.sdk_error) requireThat(map.get(3n) <= BigInt(schema.frame_maps[schema.application_sdk_errors.payload_schema].max_encoded_bytes), "application_sdk_error_limit");
  return {kind, map, bytes};
}

export function verifyApplicationResponse(schema, originalRequest, response) {
  const request = decodeApplicationHeader(schema,originalRequest), result = decodeApplicationHeader(schema,response);
  requireThat(schema.application_message_kinds[result.kind].request === request.kind, "application_response_kind");
  // No response-derived deadline/limit is returned. Serial, channel generation,
  // peer and target attribution must already come from the real request owner.
  for (const id of [1n,2n,4n,6n,9n]) requireThat(same(request.map.get(id),result.map.get(id)), "application_response_binding");
  if (request.map.has(8n) && !schema.application_message_kinds[result.kind].sdk_error) requireThat(result.map.get(3n) <= request.map.get(8n), "application_response_limit");
  return result;
}

export function executionRequestDigest(schema, header, contract, payload) {
  const request = decodeApplicationHeader(schema,header);
  requireThat(schema.application_headers.execution_requests.includes(request.kind), "application_execution_request");
  const { bytes: ownedContract } = matchApplicationRequestContractReference(schema, request.bytes, contract);
  const ownedPayload = captureApplicationBytes(payload,schema.resource_caps.max_payload_length);
  requireThat(BigInt(ownedPayload.length) === request.map.get(3n), "application_payload_length");
  return strictHex(evaluateDomain(schema,"execution_request_digest",{
    contract:ownedContract, message_kind:request.map.get(0n), operation_id:request.map.get(1n),
    type_id:request.map.get(2n), deadline_at_ms:request.map.get(5n), admission_mode:request.map.get(7n),
    response_limit_bytes:request.map.get(8n), payload:ownedPayload,
  }).output_hex);
}

// Only an already routed exact local contract may enter this relation. Matching
// bytes does not install a handler or authorize admission, dispatch or history.
export function matchApplicationRequestContractReference(schema, header, contract) {
  const request = decodeApplicationHeader(schema, header);
  const expected = schema.application_headers.contract_variants[request.kind];
  requireThat(expected !== undefined, "application_contract_request");
  const bytes = captureApplicationBytes(contract, schema.frame_maps.ServiceContract.max_encoded_bytes);
  const definition = decodeMap(schema, "ServiceContract", bytes);
  const hash = strictHex(evaluateDomain(schema, "service_contract_digest", { contract: bytes }).output_hex);
  requireThat(same(hash, request.map.get(6n)) && definition.get(1n) === request.map.get(2n), "application_contract_binding");
  for (const [id, value] of Object.entries(expected)) requireThat(definition.get(BigInt(id)) === BigInt(value), "application_contract_variant");
  requireThat(request.map.get(3n) <= definition.get(23n), "application_request_limit");
  if (request.map.has(8n)) requireThat(request.map.get(8n) >= definition.get(9n) && request.map.get(8n) <= definition.get(10n), "application_response_limit");
  return { bytes, map: definition };
}

export function verifyExecutionRequest(schema, header, contract, payload) {
  // Capture the complete candidate once; the helper never grants dispatch.
  const ownedHeader = captureApplicationBytes(header,schema.frame_maps[name].max_encoded_bytes);
  const expected = executionRequestDigest(schema,ownedHeader,contract,payload);
  requireThat(same(decodeApplicationHeader(schema,ownedHeader).map.get(4n),expected), "application_request_digest");
}

export function buildApplicationHeaderCorpus(schema) {
  verifyApplicationHeaderSchema(schema);
  const registry = schema.application_headers, vectors = [];
  for (const [kind,variant] of Object.entries(schema.application_message_kinds)) {
    const values = Object.fromEntries(variant.fields.map(id => [schema.frame_maps[name].fields[id].name,
      id === 0 ? variant.code : variant.constants?.[id] ?? (id === 3 && variant.sdk_error ? schema.frame_maps[schema.application_sdk_errors.payload_schema].max_encoded_bytes : registry.maximum_values[id])]));
    const map = mapFromNames(schema,name,values), bytes = encodeCBOR(map);
    assert.equal(bytes.length,variant.max_encoded_bytes, `${kind}: maximal encoding differs`);
    vectors.push({id:`application_${kind}_maximum`,kind,hex:bytes.toString("hex"),accept:true});
    for (const mutation of registry.vector_mutations) {
      const cases = [];
      if (mutation === "missing_field") for (const id of variant.fields) {
        const changed = new Map(map); changed.delete(BigInt(id)); cases.push([String(id),encodeCBOR(changed),schema.frame_maps[name].required.includes(id)?"missing_field":"application_fields"]);
      } else if (mutation === "forbidden_field") for (const [id,field] of Object.entries(schema.frame_maps[name].fields)) {
        if (variant.fields.includes(Number(id))) continue;
        const changed = mapFromNames(schema,name,{...values,[field.name]:registry.maximum_values[id]});
        cases.push([id,encodeCBOR(changed),"application_fields"]);
      } else if (mutation === "unknown_kind") {
        const changed = new Map(map); changed.set(0n,255n); cases.push(["",encodeCBOR(changed),"enum_value"]);
      } else if (mutation === "unknown_field") {
        const changed = new Map(map); changed.set(65535n,0n); cases.push(["",encodeCBOR(changed),"unknown_field"]);
      } else if (["duplicate_field","noncanonical_key","reversed_fields"].includes(mutation)) {
        const pairs=[...map].map(([key,value])=>Buffer.concat([encodeCBOR(key),encodeCBOR(value)]));
        if(mutation==="duplicate_field") cases.push(["",Buffer.concat([cborHead(5,map.size+1),pairs[0],...pairs]),"duplicate_key"]);
        else if(mutation==="noncanonical_key") cases.push(["",Buffer.concat([cborHead(5,map.size),Buffer.from([0x18,0]),pairs[0].subarray(1),...pairs.slice(1)]),"non_shortest_integer"]);
        else cases.push(["",Buffer.concat([cborHead(5,map.size),...pairs.reverse()]),"map_order"]);
      } else if (mutation === "truncated") cases.push(["",bytes.subarray(0,-1),"truncated"]);
      else if (mutation === "trailing") cases.push(["",Buffer.concat([bytes,Buffer.from([0])]),"trailing_bytes"]);
      else throw new Error(`unknown application vector mutation: ${mutation}`);
      for (const [suffix,raw,error] of cases) vectors.push({id:`application_${kind}_${mutation}${suffix?"_"+suffix:""}`,kind,hex:raw.toString("hex"),expected_error:error});
    }
  }
  for (const vector of vectors) {
    let error;
    try { const result=decodeApplicationHeader(schema,strictHex(vector.hex)); assert.equal(result.kind,vector.kind); }
    catch (caught) { error=caught; }
    if (vector.accept) { if(error) throw error; }
    else assert.ok(error instanceof VectorError && error.code === vector.expected_error, `${vector.id}: expected ${vector.expected_error}, got ${error?.code ?? "accepted"}`);
  }
  return {schema_revision:schema.schema_revision,design_sha256:schema.design_sha256,coverage:"draft_business_and_rpc_stop_error_header_variants",vectors};
}

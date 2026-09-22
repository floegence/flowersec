import assert from "node:assert/strict";
import test from "node:test";
import { createHash, createHmac } from "node:crypto";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeMap, encodeCBOR, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { executionRequestDigest } from "./transport-v4-application-headers.mjs";
import { verifyResumeRequestReference, verifyResumeTokenUseReference, verifyResumeResponseReference } from "./transport-v4-resume.mjs";

const { schema, files } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes = id => Buffer.from(corpus.vectors.find(v => v.id === id).hex, "hex");
const key = (type, name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([, value]) => value.name === name)[0]);
const get = (type, value, name) => value.get(key(type, name));
const put = (type, value, name, data) => value.set(key(type, name), data);
const failure = (fn, code) => assert.throws(fn, error => error instanceof VectorError && error.code === code);
function fixture(protection = "signed") {
  const payload = decodeMap(schema, "ResumeRequest", bytes(`resume_${protection}_request_fields`));
  const contract = bytes("service_unary_execution");
  const header = mapFromNames(schema, "ApplicationHeader", { message_kind: 50, operation_id: Buffer.alloc(32, 0x88), type_id: 1,
    payload_length: encodeCBOR(payload).length, request_digest: Buffer.alloc(32), deadline_at_ms: 40000,
    service_contract_digest: Buffer.from(evaluateDomain(schema, "service_contract_digest", { contract }).output_hex, "hex"),
    admission_mode: 0, response_limit_bytes: 8192 });
  function seal() {
    put("ApplicationHeader", header, "payload_length", BigInt(encodeCBOR(payload).length));
    put("ApplicationHeader", header, "request_digest", executionRequestDigest(schema, encodeCBOR(header), contract, encodeCBOR(payload)));
    return encodeCBOR(header);
  }
  seal();
  return { payload, header, contract, seal, verify: () => verifyResumeRequestReference(schema, encodeCBOR(header), contract, encodeCBOR(payload), Buffer.alloc(32, 0x66), 3n) };
}

test("v4.resume.target: signed and MAC requests bind both the exact Session context and Stream", () => {
  for (const protection of ["signed", "mac"]) {
    const f = fixture(protection), result = f.verify();
    assert.equal(result.generation, 7n); assert.ok(Object.isFrozen(result));
    failure(() => verifyResumeRequestReference(schema, f.seal(), f.contract, encodeCBOR(f.payload), Buffer.alloc(32, 0x65), 3n), "resume_target_binding");
    failure(() => verifyResumeRequestReference(schema, f.seal(), f.contract, encodeCBOR(f.payload), Buffer.alloc(32, 0x66), 5n), "resume_target_binding");
    failure(() => verifyResumeRequestReference(schema, f.seal(), f.contract, encodeCBOR(f.payload), Buffer.alloc(32, 0x66), 3), "resume_target_type");
    put("ApplicationHeader", f.header, "operation_id", get("ResumeRequest", f.payload, "original_operation_id")); f.seal();
    failure(f.verify, "resume_operation_reuse");
  }
});

test("v4.resume.digest: all immutable resume bytes and execution options affect the original request digest", () => {
  for (const name of ["stream_id", "transport_context_digest", "token"]) {
    const f = fixture(), before = get("ApplicationHeader", f.header, "request_digest");
    if (name === "token") {
      const token = decodeMap(schema, "ResumeSignedToken", get("ResumeRequest", f.payload, name));
      put("ResumeSignedToken", token, "signature", Buffer.alloc(64, 1)); put("ResumeRequest", f.payload, name, encodeCBOR(token));
    } else put("ResumeRequest", f.payload, name, name === "stream_id" ? 5n : Buffer.alloc(32, 0x67));
    failure(f.verify, "application_request_digest"); f.seal();
    assert.notDeepEqual(get("ApplicationHeader", f.header, "request_digest"), before);
  }
  for (const name of ["deadline_at_ms", "response_limit_bytes", "admission_mode"]) {
    const f = fixture(); put("ApplicationHeader", f.header, name, BigInt(get("ApplicationHeader", f.header, name)) + 1n);
    failure(f.verify, "application_request_digest");
  }
  for (const name of ["original_operation_id", "original_request_digest", "generation", "expected_checkpoint"]) {
    const f = fixture(), original = get("ResumeRequest", f.payload, name);
    put("ResumeRequest", f.payload, name, typeof original === "bigint" ? original + 1n : Buffer.isBuffer(original) ? Buffer.alloc(32, 9) : new Map([[0n,"other"],[1n,Buffer.alloc(0)]]));
    failure(() => decodeMap(schema, "ResumeRequest", encodeCBOR(f.payload)), "field_equality");
  }
});

test("v4.resume.domains: complete claims and key selector are protected by distinct signature and MAC domains", () => {
  for (const [type, id, domain, excluded] of [["ResumeSignedToken", "resume_signed_token_fields", "resume_token_signature", "signature"], ["ResumeMACToken", "resume_mac_token_fields", "resume_token_mac", "mac"]]) {
    const token = bytes(id), map = decodeMap(schema, type, token), recovery_key = Buffer.alloc(32, 0x77);
    const args = { token, ...(excluded === "mac" ? { recovery_key } : {}) }, result = evaluateDomain(schema, domain, args);
    map.delete(key(type, excluded)); const body = encodeCBOR(map), length = Buffer.alloc(4); length.writeUInt32BE(body.length);
    assert.equal(result.input_hex, Buffer.concat([Buffer.from(schema.domains.find(d => d.name === domain).label_bytes, "hex"), length, body]).toString("hex"));
    if (excluded === "mac") assert.equal(result.output_hex, createHmac("sha256", recovery_key).update(Buffer.from(result.input_hex, "hex")).digest("hex"));
    const original = decodeMap(schema, type, token); put(type, original, "key_id", Buffer.alloc(16, 0x99));
    assert.notEqual(evaluateDomain(schema, domain, { ...args, token: encodeCBOR(original) }).input_hex, result.input_hex);
    const changed = decodeMap(schema, type, token); put(type, changed, excluded, Buffer.alloc(excluded === "mac" ? 32 : 64, 1));
    assert.equal(evaluateDomain(schema, domain, { ...args, token: encodeCBOR(changed) }).input_hex, result.input_hex);
  }
});

test("v4.resume.policy: current input cap applies without replacing the original token expiry", () => {
  const f = fixture(), policy = mapFromNames(schema, "ResumePolicy", { enabled:true,purpose:0,scope:0,max_issued_token_duration_ms:49000,max_token_bytes:4992 });
  const verify = (lower = 1000n, upper = 49999n) => verifyResumeTokenUseReference(schema, encodeCBOR(f.payload), encodeCBOR(policy), lower, upper);
  assert.equal(verify().expires_at_ms, 50000n);
  failure(() => verify(999n, 1000n), "resume_token_time"); failure(() => verify(1000n, 50000n), "resume_token_time");
  failure(() => verify(1000, 1001n), "resume_time_interval");
  put("ResumePolicy", policy, "max_issued_token_duration_ms", 1n); assert.equal(verify().expires_at_ms, 50000n);
  put("ResumePolicy", policy, "max_token_bytes", 1n);
  failure(() => verify(), "resume_token_policy_size");
  failure(() => verifyResumeTokenUseReference(schema, encodeCBOR(f.payload), encodeCBOR(new Map([[0n,false]])), 1000n, 1001n), "resume_disabled");
});

test("v4.resume.results: accepted requires confirmed progress and advanced generation; unknown stays unknown", () => {
  const f = fixture(), response = mapFromNames(schema, "ApplicationHeader", { message_kind:51,operation_id:get("ApplicationHeader",f.header,"operation_id"),type_id:1,payload_length:0,
    request_digest:get("ApplicationHeader",f.header,"request_digest"),service_contract_digest:get("ApplicationHeader",f.header,"service_contract_digest") });
  const result = decodeMap(schema, "ResumeResult", bytes("resume_result_accepted"));
  const verify = () => { const body = encodeCBOR(result); put("ApplicationHeader",response,"payload_length",BigInt(body.length)); return verifyResumeResponseReference(schema,encodeCBOR(f.header),f.contract,encodeCBOR(f.payload),encodeCBOR(response),body); };
  assert.deepEqual(verify(), {status:"accepted",new_generation:8n});
  put("ResumeProgress", get("ResumeResult",result,"progress"), "new_generation", 7n); failure(verify,"resume_generation_not_advanced");
  put("ResumeResult",result,"status",2n); result.delete(key("ResumeResult","progress")); assert.deepEqual(verify(),{status:"unknown",new_generation:null});
  put("ApplicationHeader",response,"request_digest",Buffer.alloc(32)); failure(verify,"application_response_binding");
});

test("v4.resume.inputs: bounded snapshots reject malformed bytes and caller hooks without retaining aliases", () => {
  const f = fixture(), payload = encodeCBOR(f.payload), header = f.seal();
  const result = verifyResumeRequestReference(schema,header,f.contract,payload,Buffer.alloc(32,0x66),3n);
  const hash = createHash("sha256").update(JSON.stringify(result,(_key,value)=>typeof value === "bigint" ? String(value) : value)).digest("hex");
  payload.fill(0); header.fill(0);
  assert.equal(createHash("sha256").update(JSON.stringify(result,(_key,value)=>typeof value === "bigint" ? String(value) : value)).digest("hex"),hash);
  let calls = 0; const shadowed = encodeCBOR(f.payload); Object.defineProperty(shadowed,"byteLength",{get(){calls++;throw Error("hook");}});
  assert.throws(()=>verifyResumeRequestReference(schema,f.seal(),f.contract,shadowed,Buffer.alloc(32),3n),/shadowed byte metadata/u);
  failure(()=>verifyResumeRequestReference(schema,f.seal(),f.contract,Buffer.alloc(schema.frame_maps.ResumeRequest.max_encoded_bytes+1),Buffer.alloc(32),3n),"resume_input_size");
  assert.equal(calls,0);
});

test("v4.resume.maxima: complete canonical witnesses reach every finite map bound", () => {
  // Independent CBOR size arithmetic: all field IDs fit one byte, text <=128,
  // checkpoint bytes <=4096, uint64 values use nine bytes, digests use 34.
  const checkpoint = 1 + 1 + 2 + 128 + 1 + 3 + 4096;
  const claims = 1 + 4 * (1 + 2 + 128) + 2 * 35 + 1 + checkpoint + 3 * 10 + 35;
  const signed = 1 + 1 + claims + 1 + 17 + 1 + 66;
  const mac = signed - 32;
  const request = 1 + 2 * 35 + 2 + 1 + 3 + signed + 10 + 1 + checkpoint + 35 + 10;
  const progress = 1 + 1 + checkpoint + 10, result = 1 + 2 + 1 + progress;
  for (const [type, size] of Object.entries({ResumeCheckpoint:checkpoint,ResumeTokenClaims:claims,ResumeSignedToken:signed,
    ResumeMACToken:mac,ResumeRequest:request,ResumeProgress:progress,ResumeResult:result})) {
    const encoded = bytes("resume_maximum_" + type);
    assert.equal(encoded.length,size); assert.equal(schema.frame_maps[type].max_encoded_bytes,size);
    decodeMap(schema,type,encoded);
    failure(()=>decodeMap(schema,type,Buffer.concat([encoded,Buffer.from([0])])),"map_size");
  }
});

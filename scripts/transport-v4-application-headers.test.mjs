import assert from "node:assert/strict";
import fs from "node:fs";
import {createHash} from "node:crypto";
import test from "node:test";
import {buildArtifacts} from "./generate-transport-v4-vectors.mjs";
import {decodeMap,encodeCBOR,mapFromNames,VectorError} from "./transport-v4-codec.mjs";
import {evaluateDomain} from "./transport-v4-domains.mjs";
import {buildApplicationHeaderCorpus,decodeApplicationHeader,executionRequestDigest,matchApplicationRequestContractReference,verifyApplicationHeaderSchema,verifyApplicationResponse,verifyExecutionRequest} from "./transport-v4-application-headers.mjs";

const schema=JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json",import.meta.url)));
const bytes=value=>({$bytes:value.toString("hex")});
const encode=values=>encodeCBOR(mapFromNames(schema,"ApplicationHeader",values));
const hash=contract=>Buffer.from(evaluateDomain(schema,"service_contract_digest",{contract}).output_hex,"hex");
let artifactCorpus;
function execution(kind="execution_unary_request",payload=Buffer.from("abc")) {
  artifactCorpus ??= JSON.parse(buildArtifacts().files.get("testdata/transport_v4/corpus.json"));
  const suffix={execution_unary_request:"unary_execution",execution_stream_request:"stream_execution",execution_notify:"notify_execution",resume_request:"unary_execution"}[kind];
  const contract=Buffer.from(artifactCorpus.vectors.find(vector=>vector.id==="service_"+suffix).hex,"hex");
  const fields=decodeMap(schema,"ServiceContract",contract);
  const values={message_kind:schema.application_message_kinds[kind].code,operation_id:bytes(Buffer.alloc(32,1)),type_id:Number(fields.get(1n)),payload_length:payload.length,request_digest:bytes(Buffer.alloc(32)),deadline_at_ms:50000,service_contract_digest:bytes(hash(contract)),admission_mode:0,response_limit_bytes:Number(fields.get(10n))};
  values.request_digest=bytes(executionRequestDigest(schema,encode(values),contract,payload));
  return {contract,payload,values,header:encode(values)};
}

test("observation notifications match their exact contract without response or execution fields",()=>{
  artifactCorpus ??= JSON.parse(buildArtifacts().files.get("testdata/transport_v4/corpus.json"));
  const contract=Buffer.from(artifactCorpus.vectors.find(vector=>vector.id==="service_notify_observation").hex,"hex");
  const fields=decodeMap(schema,"ServiceContract",contract);
  const values={message_kind:schema.application_message_kinds.observation_notify.code,type_id:Number(fields.get(1n)),payload_length:0,deadline_at_ms:50000,service_contract_digest:bytes(hash(contract))};
  const header=encode(values);
  assert.deepEqual(matchApplicationRequestContractReference(schema,header,contract).bytes,contract);
  assert.equal(decodeApplicationHeader(schema,header).map.has(8n),false);
  assert.throws(()=>decodeApplicationHeader(schema,encode({...values,response_limit_bytes:0})),/application_fields/u);
  assert.throws(()=>executionRequestDigest(schema,header,contract,Buffer.alloc(0)),/application_execution_request/u);
  const wrong=Buffer.from(artifactCorpus.vectors.find(vector=>vector.id==="service_notify_execution").hex,"hex");
  const wrongFields=decodeMap(schema,"ServiceContract",wrong);
  assert.throws(()=>matchApplicationRequestContractReference(schema,encode({...values,type_id:Number(wrongFields.get(1n)),service_contract_digest:bytes(hash(wrong))}),wrong),/application_contract_variant/u);
});

test("v4.application_headers.exact_variants: every registered field is required or forbidden",()=>{
  const corpus=buildApplicationHeaderCorpus(schema);
  assert.equal(corpus.vectors.length,589);
  for(const vector of corpus.vectors.filter(item=>item.accept)) {
    const result=decodeApplicationHeader(schema,Buffer.from(vector.hex,"hex"));
    assert.equal(result.kind,vector.kind);
  }
  const original=execution();
  const response={message_kind:27,operation_id:original.values.operation_id,type_id:original.values.type_id,payload_length:0,request_digest:original.values.request_digest,service_contract_digest:original.values.service_contract_digest};
  for(const field of ["deadline_at_ms","admission_mode","response_limit_bytes"]) for(const value of [0,1]) assert.throws(()=>decodeApplicationHeader(schema,encode({...response,[field]:value})),/application_fields/u);
  assert.throws(()=>decodeApplicationHeader(schema,encode({...original.values,message_kind:26,response_limit_bytes:1})),/application_constant/u);
});

test("v4.application_headers.response_binding: original kind, identifiers and request limits own responses",()=>{
  const request=execution();
  const response={message_kind:27,operation_id:request.values.operation_id,type_id:request.values.type_id,payload_length:request.values.response_limit_bytes,request_digest:request.values.request_digest,service_contract_digest:request.values.service_contract_digest};
  verifyApplicationResponse(schema,request.header,encode(response));
  for(const field of ["operation_id","request_digest","service_contract_digest"]) assert.throws(()=>verifyApplicationResponse(schema,request.header,encode({...response,[field]:bytes(Buffer.alloc(32,9))})),/application_response_binding/u);
  assert.throws(()=>verifyApplicationResponse(schema,request.header,encode({...response,type_id:42})),/application_response_binding/u);
  assert.throws(()=>verifyApplicationResponse(schema,request.header,encode({...response,message_kind:28})),/application_response_kind/u);
  const smaller=encode({...request.values,response_limit_bytes:2});
  assert.throws(()=>verifyApplicationResponse(schema,smaller,encode({...response,payload_length:3})),/application_response_limit/u);
  const management={message_kind:38,type_id:1,payload_length:0,deadline_at_ms:5,service_contract_digest:bytes(Buffer.alloc(32)),control_serial:2};
  const result={message_kind:39,type_id:1,payload_length:0,service_contract_digest:management.service_contract_digest,control_serial:2};
  verifyApplicationResponse(schema,encode(management),encode(result));
  assert.throws(()=>verifyApplicationResponse(schema,encode(management),encode({...result,control_serial:3})),/application_response_binding/u);
  assert.throws(()=>decodeApplicationHeader(schema,encode({...result,control_serial:0})),/field_range/u);
});

test("v4.application_headers.execution_digest: an independent byte assembly binds every immutable input",()=>{
  const pack=(n,size)=>{const result=Buffer.alloc(size);if(size===8)result.writeBigUInt64BE(BigInt(n));else result.writeUIntBE(Number(n),0,size);return result;};
  const lp=value=>Buffer.concat([pack(value.length,4),value]);
  for(const kind of schema.application_headers.execution_requests) {
    const {contract,payload,values,header}=execution(kind);
    const input=Buffer.concat([Buffer.from("flowersec/v4/execution-request\0"),lp(contract),pack(values.message_kind,1),lp(Buffer.from(values.operation_id.$bytes,"hex")),pack(values.type_id,4),pack(values.deadline_at_ms,8),pack(values.admission_mode,1),pack(values.response_limit_bytes,4),lp(payload)]);
    assert.equal(createHash("sha256").update(input).digest("hex"),values.request_digest.$bytes);
    verifyExecutionRequest(schema,header,contract,payload);
    for(const [field,value] of [["operation_id",bytes(Buffer.alloc(32,2))],["deadline_at_ms",50001],["admission_mode",1]]) assert.throws(()=>verifyExecutionRequest(schema,encode({...values,[field]:value}),contract,payload),/application_request_digest/u);
    assert.throws(()=>verifyExecutionRequest(schema,header,contract,Buffer.from("abd")),/application_request_digest/u);
    assert.throws(()=>verifyExecutionRequest(schema,header,contract,Buffer.from("ab")),/application_payload_length/u);
  }
});

test("execution digest has no nonexecution or response use and requires a matching complete contract",()=>{
  const {contract,payload,header,values}=execution();
  const transient={message_kind:29,type_id:values.type_id,payload_length:3,deadline_at_ms:50000,service_contract_digest:values.service_contract_digest,admission_mode:0,response_limit_bytes:values.response_limit_bytes};
  assert.throws(()=>executionRequestDigest(schema,encode(transient),contract,payload),/application_execution_request/u);
  const response={message_kind:27,operation_id:values.operation_id,type_id:values.type_id,payload_length:3,request_digest:values.request_digest,service_contract_digest:values.service_contract_digest};
  assert.throws(()=>executionRequestDigest(schema,encode(response),contract,payload),/application_execution_request/u);
  assert.throws(()=>executionRequestDigest(schema,encode({...values,type_id:42}),contract,payload),/application_contract_binding/u);
  const changed=decodeMap(schema,"ServiceContract",contract);changed.set(6n,"next-revision");
  const newContract=encodeCBOR(changed);
  assert.throws(()=>verifyExecutionRequest(schema,header,newContract,payload),/application_contract_binding/u);
  assert.throws(()=>verifyExecutionRequest(schema,encode({...values,service_contract_digest:bytes(hash(newContract))}),newContract,payload),/application_request_digest/u);
  assert.throws(()=>executionRequestDigest(schema,encode({...values,message_kind:25}),contract,payload),/application_contract_variant/u);
});

test("v4.application_headers.maxima: canonical witnesses match independent base-size arithmetic",()=>{
  const corpus=buildApplicationHeaderCorpus(schema);
  const sizes={execution_unary_request:139,execution_notify:135,execution_unary_response:121,observation_notify:61,transient_unary_request:69,transient_unary_response:51,query_operation_request:71,query_operation_response:61};
  for(const [kind,size] of Object.entries(sizes)) assert.equal(Buffer.from(corpus.vectors.find(vector=>vector.kind===kind&&vector.accept).hex,"hex").length,size);
  const broken=structuredClone(schema);broken.application_message_kinds.execution_unary_response.fields.push(5);
  assert.throws(()=>verifyApplicationHeaderSchema(broken));
  const drift=structuredClone(schema);drift.application_message_kinds.execution_unary_request.code=42;
  assert.throws(()=>verifyApplicationHeaderSchema(drift));
});

test("application inputs use branded snapshots and bound copying before digest construction",()=>{
  const {header,contract,payload}=execution();
  let traps=0;
  const wrapped=value=>new Proxy(value,{getPrototypeOf(){traps++;throw Error("proxy trap must not run");}});
  const revoked=Proxy.revocable(Buffer.alloc(0),{});revoked.revoke();
  for(const wrap of [wrapped,()=>revoked.proxy]) {
    assert.throws(()=>decodeApplicationHeader(schema,wrap(header)),caught=>caught instanceof VectorError&&caught.code==="application_input_bytes");
    assert.throws(()=>executionRequestDigest(schema,header,wrap(contract),payload),caught=>caught instanceof VectorError&&caught.code==="application_input_bytes");
    assert.throws(()=>executionRequestDigest(schema,header,contract,wrap(payload)),caught=>caught instanceof VectorError&&caught.code==="application_input_bytes");
  }
  assert.equal(traps,0);
  const backingSafe=input=>{
    const backing=new ArrayBuffer(input.length+4),view=new Uint8Array(backing,2,input.length);
    view.set(input);
    Object.defineProperty(backing,"byteLength",{get(){traps++;throw Error("must not read backing metadata");}});
    return Object.setPrototypeOf(view,Buffer.prototype);
  };
  verifyExecutionRequest(schema,backingSafe(header),backingSafe(contract),backingSafe(payload));
  assert.equal(traps,0);
  for(const field of ["length","buffer","byteOffset","byteLength"]) {
    const forged=Buffer.from(header);Object.defineProperty(forged,field,{get(){throw Error("must not invoke input metadata");}});
    assert.throws(()=>decodeApplicationHeader(schema,forged),/application_input_bytes/u);
  }
  assert.throws(()=>decodeApplicationHeader(schema,Buffer.alloc(513)),/application_input_size/u);
  assert.throws(()=>executionRequestDigest(schema,header,Buffer.alloc(8193),payload),/application_input_size/u);
  assert.throws(()=>executionRequestDigest(schema,header,contract,Buffer.alloc(1048577)),/application_input_size/u);
  const full=execution("execution_unary_request",Buffer.alloc(1048576,65));
  verifyExecutionRequest(schema,full.header,full.contract,full.payload);
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeMap, encodeMap, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { buildApplicationHeaderCorpus, decodeApplicationHeader, verifyApplicationHeaderSchema } from "./transport-v4-application-headers.mjs";
import { classifyApplicationErrorReference, matchApplicationErrorCatalogReference, matchApplicationErrorSchemaReference } from "./transport-v4-application-errors.mjs";

const {schema,files}=buildArtifacts();
const corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const fixture=id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex");
const bytes=value=>({$bytes:value.toString("hex")});
const digest=(name,args)=>Buffer.from(evaluateDomain(schema,name,args).output_hex,"hex");
const encode=(name,values)=>encodeMap(schema,name,mapFromNames(schema,name,values));
const header=values=>encode("ApplicationHeader",values);
const failure=(run,code)=>assert.throws(run,error=>error instanceof VectorError&&error.code===code);
const definitionBytes=Buffer.from("a2000101820102","hex");
const errorValues={code:12345,schema_revision:"error-1",max_payload_bytes:2,schema_digest:bytes(digest("business_error_schema_digest",{error_schema:definitionBytes}))};
const error=encode("ErrorDefinition",errorValues);

function candidate(shape="unary",semantics="execution",length=2,code=12345,limit=10) {
  const contractMap=decodeMap(schema,"ServiceContract",fixture(`service_${shape}_${semantics}`));
  contractMap.set(27n,[decodeMap(schema,"ErrorDefinition",error)]);
  const contract=encodeMap(schema,"ServiceContract",contractMap);
  const requestKind=`${semantics}_${shape}_request`,resultKind=`${semantics}_${shape}_application_error`;
  const requestValues={message_kind:schema.application_message_kinds[requestKind].code,type_id:Number(contractMap.get(1n)),payload_length:0,deadline_at_ms:5000,service_contract_digest:bytes(digest("service_contract_digest",{contract})),admission_mode:0,response_limit_bytes:limit};
  if(semantics==="execution") Object.assign(requestValues,{operation_id:bytes(Buffer.alloc(32,1)),request_digest:bytes(Buffer.alloc(32,2))});
  const responseValues={...requestValues,message_kind:schema.application_message_kinds[resultKind].code,payload_length:length,application_error_code:code};
  for(const key of ["deadline_at_ms","admission_mode","response_limit_bytes"]) delete responseValues[key];
  return {contract,request:header(requestValues),response:header(responseValues),requestValues,responseValues};
}

test("v4.application_errors.schema_digest: exact registered bytes use the independent SHA256 domain",()=>{
  const length=Buffer.alloc(4); length.writeUInt32BE(definitionBytes.length);
  const expected=createHash("sha256").update(Buffer.concat([Buffer.from("flowersec/v4/application-error-schema\0"),length,definitionBytes])).digest();
  assert.deepEqual(digest("business_error_schema_digest",{error_schema:definitionBytes}),expected);
  matchApplicationErrorSchemaReference(schema,error,definitionBytes);
  failure(()=>matchApplicationErrorSchemaReference(schema,error,Buffer.from("a0","hex")),"application_error_schema_mismatch");
  failure(()=>matchApplicationErrorSchemaReference(schema,error,Buffer.alloc(8193)),"application_input_size");
  failure(()=>matchApplicationErrorSchemaReference(schema,error,new Proxy(definitionBytes,{})),"application_input_bytes");
  const maximum=Buffer.alloc(8192,1);
  const maximumError=encode("ErrorDefinition",{...errorValues,schema_digest:bytes(digest("business_error_schema_digest",{error_schema:maximum}))});
  matchApplicationErrorSchemaReference(schema,maximumError,maximum);
  // Hashing opaque pre-registered bytes does not validate their application
  // schema language or authorize loading a decoder from a remote definition.
});

test("v4.application_errors.catalog: Bind metadata matches every immutable definition field",()=>{
  const {contract}=candidate();
  matchApplicationErrorCatalogReference(schema,contract,[error]);
  failure(()=>matchApplicationErrorCatalogReference(schema,contract,[]),"application_error_catalog_mismatch");
  failure(()=>matchApplicationErrorCatalogReference(schema,contract,Array(65).fill(error)),"application_error_catalog_size");
  for(const change of [{code:12346},{schema_revision:"error-2"},{max_payload_bytes:3},{schema_digest:bytes(Buffer.alloc(32,7))}]) {
    failure(()=>matchApplicationErrorCatalogReference(schema,contract,[encode("ErrorDefinition",{...errorValues,...change})]),"application_error_catalog_mismatch");
  }
  const empty=decodeMap(schema,"ServiceContract",contract);empty.set(27n,[]);
  matchApplicationErrorCatalogReference(schema,encodeMap(schema,"ServiceContract",empty),[]);
});

test("v4.application_errors.responses: all four shapes preserve association and business limits",()=>{
  for(const shape of ["unary","stream"]) for(const semantics of ["execution","transient"]) {
    const c=candidate(shape,semantics);
    assert.deepEqual(classifyApplicationErrorReference(schema,c.request,c.response,c.contract,Buffer.alloc(2)),{classification:"known_application_error",code:12345n});
    for(const change of [{type_id:99},{service_contract_digest:bytes(Buffer.alloc(32,9))},...(semantics==="execution"?[{operation_id:bytes(Buffer.alloc(32,9))},{request_digest:bytes(Buffer.alloc(32,9))}]:[])]) {
      failure(()=>classifyApplicationErrorReference(schema,c.request,header({...c.responseValues,...change}),c.contract,Buffer.alloc(2)),"application_response_binding");
    }
    for(const key of ["deadline_at_ms","admission_mode","response_limit_bytes"]) {
      failure(()=>decodeApplicationHeader(schema,header({...c.responseValues,[key]:0})),"application_fields");
    }
    failure(()=>decodeApplicationHeader(schema,header({...c.responseValues,application_error_code:0})),"field_range");
    failure(()=>classifyApplicationErrorReference(schema,c.request,c.response,c.contract,Buffer.alloc(1)),"application_payload_length");
    failure(()=>classifyApplicationErrorReference(schema,c.request,c.response,c.contract,Buffer.alloc(3)),"application_input_size");
  }
});

test("v4.application_errors.classification: unknown codes and decode failure preserve result scope",()=>{
  const known=candidate("unary","execution",3);
  assert.deepEqual(classifyApplicationErrorReference(schema,known.request,known.response,known.contract,Buffer.alloc(3)),{classification:"application_result_decode_failed",code:12345n});
  const unknown=candidate("unary","execution",3,0xffffffff);
  assert.deepEqual(classifyApplicationErrorReference(schema,unknown.request,unknown.response,unknown.contract,Buffer.alloc(3)),{classification:"unknown_application_error",code:0xffffffffn});
  for(const code of [12345,0xffffffff]) {
    const zero=candidate("unary","transient",0,code,0);
    assert.ok(Object.isFrozen(classifyApplicationErrorReference(schema,zero.request,zero.response,zero.contract,Buffer.alloc(0))));
    const extra=candidate("unary","transient",1,code,0);
    failure(()=>classifyApplicationErrorReference(schema,extra.request,extra.response,extra.contract,Buffer.alloc(1)),"application_response_limit");
  }
  const success=candidate();
  const fields={...success.responseValues,message_kind:schema.application_message_kinds.execution_unary_response.code}; delete fields.application_error_code;
  failure(()=>classifyApplicationErrorReference(schema,success.request,header(fields),success.contract,Buffer.alloc(2)),"application_error_kind");
  const invalid=structuredClone(schema);
  invalid.application_message_kinds.execution_unary_application_error.request="execution_notify";
  assert.throws(()=>verifyApplicationHeaderSchema(invalid),/NOTIFY/u);
});

test("v4.application_errors.maxima: error code overhead and generated trust registry are explicit",()=>{
  const app=buildApplicationHeaderCorpus(schema);
  for(const kind of ["execution_unary_application_error","execution_stream_application_error","transient_unary_application_error","transient_stream_application_error"]) {
    const vector=app.vectors.find(v=>v.kind===kind&&v.accept);
    assert.equal(vector.hex.length/2,kind.startsWith("execution")?121+6:51+6);
  }
  for(const path of ["flowersec-go/internal/protocolv4/registry_generated.go","flowersec-rust/src/protocol_v4_registry_generated.rs","flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift","flowersec-ts/src/generated/transportV4Registry.ts"]) {
    assert.ok(files.get(path).includes("RevokedIssuerEntry"));
    assert.ok(files.get(path).includes("max_revoked_issuer_authorizations"));
    assert.ok(files.get(path).includes("application_error_code"));
  }
});

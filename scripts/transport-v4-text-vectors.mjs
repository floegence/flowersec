import assert from "node:assert/strict";
import { IDNAValidationError, issuerDNS151, validateWireDNS151 } from "./transport-v4-idna.mjs";
import { HostValidationError, issuerHost151, validateWireHost151 } from "./transport-v4-host.mjs";
import { OriginValidationError, validateWireOrigin } from "./transport-v4-origin.mjs";

const operations = {issuer_dns:issuerDNS151, wire_dns:validateWireDNS151, issuer_host:issuerHost151, wire_host:validateWireHost151, wire_origin:validateWireOrigin};

export function verifyTextCorpus(corpus, schema) {
  const ids=new Set();
  for(const vector of corpus.vectors) {
    assert.match(vector.id,/^[a-z][a-z0-9_]+$/u);assert.ok(!ids.has(vector.id),"duplicate text vector");ids.add(vector.id);
    assert.ok(Object.hasOwn(operations, vector.operation),"unknown text operation");
    assert.equal(typeof vector.input,"string");
    let output,error;
    try{output=operations[vector.operation](vector.input,schema);}catch(err){error=err;}
    if(vector.expected_error!==undefined) {
      assert.equal(typeof vector.expected_error,"string");assert.equal(vector.output,undefined);assert.equal(vector.utf8_hex,undefined);
      assert.ok(error instanceof IDNAValidationError || error instanceof HostValidationError || error instanceof OriginValidationError,`${vector.id}: expected rejection`);assert.equal(error.message,vector.expected_error,vector.id);
    } else {
      assert.equal(error,undefined,vector.id);assert.equal(output,vector.output,vector.id);
      assert.equal(Buffer.from(output,"utf8").toString("hex"),vector.utf8_hex,vector.id);
    }
  }
}

export function buildTextCorpus(schema,schemaSHA) {
  const corpus={schema_revision:schema.schema_revision,design_sha256:schema.design_sha256,schema_sha256:schemaSHA,coverage:"reference_dns_host_and_origin_syntax",unverified:["custom Origin schemes and actual request admission","complete route validation","four-SDK algorithms and resource bounds"],vectors:schema.text_vector_plan.map(vector=>({ ...vector, ...(vector.output===undefined ? {} : {utf8_hex:Buffer.from(vector.output,"utf8").toString("hex")}) }))};
  verifyTextCorpus(corpus,schema);return corpus;
}

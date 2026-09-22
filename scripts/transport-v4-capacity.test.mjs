import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";
import { cborHead, decodeCBOR, decodeMap, encodeCBOR, encodeMap, mapFromNames, validateMap, VectorError } from "./transport-v4-codec.mjs";
import { issuerImpactFrontiersReference, namespaceParserLimitsReference } from "./transport-v4-revocation.mjs";

const {schema,files} = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex,"hex");
const id = (name,key) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([,field]) => field.name === key)[0]);
const name = "RevokedIssuerEntry", impact = "IssuerAuthorizationImpact";
const fixtureLimits = {max_state_encoded_bytes:4096,max_revoked_issuer_authorizations:93};
const failure = (run,code) => assert.throws(run,error => error instanceof VectorError && error.code === code);
function capacity(size) {
  const map=decodeMap(schema,"NamespaceCapacity",bytes("namespace_capacity_fields"));
  map.set(id("NamespaceCapacity","max_state_encoded_bytes"),size);
  return encodeMap(schema,"NamespaceCapacity",map);
}
function entry(count,limits) {
  const template = decodeMap(schema,name,bytes("revoked_issuer_mixed"),fixtureLimits);
  const originals = template.get(id(name,"authorizations"));
  template.set(id(name,"authorizations"),Array.from({length:count},(_,index) => {
    const digest=Buffer.alloc(32); digest.writeUInt32BE(index,28);
    const authorization=new Map(originals[index % originals.length]);
    authorization.set(id(impact,"authorization_digest"),digest);
    return authorization;
  }));
  return {map:template,bytes:encodeMap(schema,name,template,limits)};
}

test("v4.capacity.parameters: bounds come from the original descriptor with checked representation", () => {
  const limits=namespaceParserLimitsReference(schema,capacity(100000n));
  assert.deepEqual(limits,{max_state_encoded_bytes:100000,max_revoked_issuer_authorizations:2272,max_revoked_issuers:64,max_revoked_certificates:1024,max_revoked_leases:1024,max_cohort_policy_segments:16});
  assert.ok(Object.isFrozen(limits));
  const minimum=decodeMap(schema,name,bytes("revoked_issuer_minimum"),fixtureLimits).get(id(name,"authorizations"))[0];
  assert.equal(encodeMap(schema,impact,minimum).length,44);
  assert.equal(schema.validation_parameters.max_revoked_issuer_authorizations.divisor,44);
  assert.equal(namespaceParserLimitsReference(schema,capacity(43n)).max_revoked_issuer_authorizations,0);
  failure(() => namespaceParserLimitsReference(schema,capacity(0xffffffffffffffffn)),"revocation_parser_capacity");
  for(const parameters of [{},{max_state_encoded_bytes:100000},{max_state_encoded_bytes:0,max_revoked_issuer_authorizations:1}]) {
    failure(() => decodeMap(schema,name,bytes("revoked_issuer_mixed"),parameters),"limit_unresolved");
  }
  failure(() => decodeMap(schema,name,bytes("revoked_issuer_mixed"),{...fixtureLimits,max_revoked_issuer_authorizations:0}),"array_limit");
  for(const max of [-1,1.5,NaN,Infinity,0x100000000,1n,"10"]) {
    failure(() => decodeMap(schema,name,bytes("revoked_issuer_mixed"),{...fixtureLimits,max_revoked_issuer_authorizations:max}),"limit_unresolved");
  }
});

test("v4.capacity.counts: only declared capacity arrays exceed the ordinary parser cap", () => {
  const limits=namespaceParserLimitsReference(schema,capacity(100000n));
  const large=entry(1036,limits);
  assert.deepEqual(decodeMap(schema,name,large.bytes,limits),large.map);
  assert.deepEqual(issuerImpactFrontiersReference(schema,capacity(100000n),large.bytes),[50n,90n]);
  failure(() => decodeCBOR(large.bytes),"array_limit");
  failure(() => encodeCBOR(large.map),"array_limit");
  failure(() => decodeMap(schema,name,large.bytes,{...limits,max_revoked_issuer_authorizations:1035}),"array_limit");
  failure(() => validateMap(schema,name,large.map,{...limits,max_revoked_issuer_authorizations:1035}),"array_length");
  failure(() => decodeMap(schema,name,large.bytes,{...limits,max_state_encoded_bytes:large.bytes.length-1}),"map_size");
  assert.deepEqual(decodeMap(schema,name,large.bytes,{...limits,max_state_encoded_bytes:large.bytes.length}),large.map);
  // Unknown fields do not inherit another field's capacity grant.
  const unknown=Buffer.concat([Buffer.from([0xa1,0x02]),cborHead(4,1036),Buffer.alloc(1036)]);
  failure(() => decodeMap(schema,name,unknown,limits),"array_limit");
  failure(() => decodeCBOR(Buffer.from([0x81,0xf6]),{schema,name,limits}),"unsupported_type");
});

test("v4.capacity.preallocation: untrusted sizes fail before copying or array allocation", () => {
  const original=Array.from;
  let allocations=0;
  Array.from=function(...args) { allocations++; return Reflect.apply(original,this,args); };
  try {
    const limits={max_state_encoded_bytes:1000,max_revoked_issuer_authorizations:10000000};
    const forged=Buffer.concat([Buffer.from([0xa1,0x01]),cborHead(4,10000000)]);
    failure(() => decodeMap(schema,name,forged,limits),"truncated");
    failure(() => decodeMap(schema,name,forged,{...limits,max_revoked_issuer_authorizations:10}),"array_limit");
    assert.equal(allocations,0);
  } finally { Array.from=original; }
  const input=Buffer.from(bytes("revoked_issuer_mixed"));
  Object.defineProperty(input,"length",{get() { throw new Error("untrusted metadata invoked"); }});
  assert.throws(() => decodeMap(schema,name,input,fixtureLimits),/shadowed byte metadata/u);
  assert.throws(() => decodeCBOR(input,{schema,name,limits:fixtureLimits}),/shadowed byte metadata/u);
  const tooSmall={...fixtureLimits,max_state_encoded_bytes:1};
  failure(() => decodeCBOR(bytes("revoked_issuer_mixed"),{schema,name,limits:tooSmall}),"map_size");
});

test("v4.capacity.issuer_history: every supplied original contributes once without shortening", () => {
  const input=bytes("revoked_issuer_mixed");
  const result=issuerImpactFrontiersReference(schema,capacity(4096n),input);
  assert.deepEqual(result,[50n,90n]); assert.ok(Object.isFrozen(result));
  assert.deepEqual(issuerImpactFrontiersReference(schema,capacity(4096n),bytes("revoked_issuer_minimum")),[null,null]);
  const map=decodeMap(schema,name,input,fixtureLimits), key=id(name,"authorizations"), originals=map.get(key);
  for(const entries of [[originals[0],originals[0]],[...originals].reverse()]) {
    map.set(key,entries);
    failure(() => decodeMap(schema,name,encodeMap(schema,name,map,fixtureLimits),fixtureLimits),"item_order");
  }
  map.set(key,[originals[0],new Map(originals[1])]);
  map.get(key)[1].delete(id(impact,"max_affected_cohorts"));
  failure(() => decodeMap(schema,name,encodeMap(schema,name,map,fixtureLimits),fixtureLimits),"missing_field");
  // Complete-history authentication and issuer/namespace membership are not
  // inferable from these bytes; no helper grants deletion or renewal authority.
});

test("v4.capacity.schema: dynamic counts and byte bounds resolve one registered authority", () => {
  for(const mutate of [
    s => { s.frame_maps[name].fields[1].max_items=2000; },
    s => { s.frame_maps[name].fields[1].max_items_ref="unknown"; },
    s => { s.frame_maps[name].max_encoded_bytes=4096; },
    s => { s.frame_maps[name].max_encoded_bytes_ref="unknown"; },
    s => { s.validation_parameters.max_revoked_issuer_authorizations.divisor=0; },
    s => { s.validation_parameters.max_revoked_issuer_authorizations.capacity_field="cohort_time_origin_ms"; }
  ]) {
    const changed=structuredClone(schema); mutate(changed); assert.throws(() => verifySchema(changed));
  }
  verifySchema(schema);
  assert.throws(() => mapFromNames(schema,name,{issuer_key_id:{$bytes:"00".repeat(16)},authorizations:[],max_state_encoded_bytes:10000}),/unknown_field/u);
});

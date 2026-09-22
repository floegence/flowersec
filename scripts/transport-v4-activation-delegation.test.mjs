import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";
import { decodeMap, encodeCBOR, encodeMap, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { verifyActivationDelegationReference, verifyActivationDelegationContinuityReference } from "./transport-v4-activation-delegation.mjs";

const {schema,files} = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes = id => Buffer.from(corpus.vectors.find(v => v.id === id).hex,"hex");
const key = (type,name) => BigInt(Object.entries(schema.frame_maps[type].fields).find(([,f]) => f.name === name)[0]);
const get = (type,map,name) => map.get(key(type,name));
const set = (type,map,name,value) => map.set(key(type,name),value);
const failure = (run,code) => assert.throws(run,e => e instanceof VectorError && e.code === code);
const type = "ConnectionActivationDelegation";
const hash = (name,args) => Buffer.from(evaluateDomain(schema,name,args).output_hex,"hex");
function fixture(profile = "live_authority") {
  const d=decodeMap(schema,type,bytes("activation_delegation_fields"));
  const c=decodeMap(schema,"NamespaceCapacity",bytes("namespace_capacity_fields"));
  set("NamespaceCapacity",c,"cohort_time_origin_ms",0n);
  set("NamespaceCapacity",c,"max_connection_impact_ms",1000000n);
  const a=decodeMap(schema,"Artifact",bytes("artifact_transport_fields"));
  const digest=hash("namespace_capacity_digest",{capacity:encodeCBOR(c)});
  set("Artifact",a,"namespace_capacity_digest",digest); set(type,d,"namespace_capacity_digest",digest);
  const p=decodeMap(schema,"ActivationAuthorization",bytes(profile === "live_authority" ? "activation_live_fields" : "activation_pool_fields"),{activation_source_profile:profile});
  for (const field of ["client_identity_digest","server_identity_digest"]) set("ActivationAuthorization",p,field,get("Artifact",a,field));
  set("ActivationAuthorization",p,"issued_at_ms",1001n);
  const authority=mapFromNames(schema,"OnceAuthorityRef",{tenant_id:"tenant-1",artifact_issuer_key_id:Buffer.alloc(16,0x12),spend_authority_id:"spend-1",winner_authority_id:"winner-1"});
  function seal() {
    const digest=hash("artifact_digest",{artifact:encodeCBOR(a)}); set("ActivationAuthorization",p,"artifact_digest",digest);
    if(profile === "preauthorized_pool") set("PoolSelectionRef",get("ActivationAuthorization",p,"candidate_selection"),"artifact_digest",digest);
  }
  seal();
  return {d,c,a,p,authority,seal,verify:()=>verifyActivationDelegationReference(schema,encodeMap(schema,type,d),encodeCBOR(authority),encodeCBOR(c),encodeCBOR(a),encodeCBOR(p),profile)};
}

test("v4.activation_delegation.binding: both sources retain parent, signer and fixed logical authority", () => {
  for(const profile of ["live_authority","preauthorized_pool"]) {
    const f=fixture(profile), result=f.verify();
    assert.equal(result.authority_id,"spend-1"); assert.deepEqual(result.max_affected_cohorts,[null,100n]);
    assert.equal(result.issuer_key_id,"22".repeat(16));assert.notEqual(result.issuer_key_id,get("Artifact",f.a,"issuer_key_id").toString("hex"));
    assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.max_affected_cohorts));
    for(const [map,name,value,code] of [
      [f.d,"authority_id","other","activation_delegation_authority"],
      [f.d,"artifact_issuer_key_id",Buffer.alloc(16),"activation_delegation_authority"],
      [f.d,"signing_key_id","other","activation_delegation_authority"],
      [f.d,"tenant_id","other","activation_delegation_tenant"],
      [f.d,"authority_generation",2n,"activation_delegation_namespace"],
      [f.d,"namespace_capacity_digest",Buffer.alloc(32),"activation_delegation_namespace"]]) {
      const old=get(type,map,name);set(type,map,name,value);failure(f.verify,code);set(type,map,name,old);
    }
    set("OnceAuthorityRef",f.authority,"spend_authority_id","fresh-empty-store");failure(f.verify,"activation_delegation_authority");
  }
  const pool=fixture("preauthorized_pool");
  set("OnceAuthorityRef",get("PoolSelectionRef",get("ActivationAuthorization",pool.p,"candidate_selection"),"once_authority_ref"),"winner_authority_id","fresh-winner");
  failure(pool.verify,"activation_delegation_authority");
});

test("v4.activation_delegation.parent: complete original digest and identity projection cannot be replaced", () => {
  for(const name of ["lease_id","client_identity_digest","server_identity_digest","artifact_digest"]) {
    const f=fixture();set("ActivationAuthorization",f.p,name,Buffer.alloc(name === "lease_id" ? 16 : 32));failure(f.verify,"activation_delegation_parent");
  }
  const f=fixture();set("Artifact",f.a,"signature",Buffer.alloc(64));failure(f.verify,"activation_delegation_parent");
  f.seal();f.verify(); // Authentication of these original bytes remains external.
});

test("v4.activation_delegation.time: late signing preserves parent cohort and original finite impact", () => {
  const f=fixture();assert.equal(get("ActivationAuthorization",f.p,"issued_at_ms"),1001n);f.verify();
  set("ActivationAuthorization",f.p,"issued_at_ms",0n);failure(f.verify,"activation_delegation_signing_time");set("ActivationAuthorization",f.p,"issued_at_ms",1001n);
  set("Artifact",f.a,"revocation_epoch",1n);f.seal();failure(f.verify,"activation_delegation_parent_cohort");set("Artifact",f.a,"revocation_epoch",0n);f.seal();
  set(type,f.d,"first_parent_cohort",1n);failure(f.verify,"activation_delegation_cohort");set(type,f.d,"first_parent_cohort",0n);
  set(type,f.d,"signing_not_before_ms",1002n);failure(f.verify,"activation_delegation_signing_time");set(type,f.d,"signing_not_before_ms",1n);
  set(type,f.d,"signing_not_after_ms",1001n);failure(f.verify,"activation_delegation_signing_time");set(type,f.d,"signing_not_after_ms",1000000n);
  set(type,f.d,"max_session_not_after_ms",999999n);failure(f.verify,"activation_delegation_impact");set(type,f.d,"max_session_not_after_ms",1000000n);
  set(type,f.d,"max_activation_not_after_ms",499999n);failure(f.verify,"activation_delegation_impact");set(type,f.d,"max_activation_not_after_ms",500000n);
  set("Artifact",f.a,"session_not_after_ms",999999n);f.seal();failure(f.verify,"activation_delegation_impact");
  const narrow=fixture();set("NamespaceCapacity",narrow.c,"max_connection_impact_ms",10000n);
  const digest=hash("namespace_capacity_digest",{capacity:encodeCBOR(narrow.c)});set(type,narrow.d,"namespace_capacity_digest",digest);set("Artifact",narrow.a,"namespace_capacity_digest",digest);narrow.seal();failure(narrow.verify,"activation_delegation_impact");
});

test("v4.activation_delegation.class_bounds: unrelated certificate overflow cannot deny connection authority", () => {
  for (const profile of ["live_authority","preauthorized_pool"]) {
  const f=fixture(profile), max=0xffffffffffffffffn;
  set("NamespaceCapacity",f.c,"max_certificate_impact_ms",max-100000n);
  set("Artifact",f.a,"revocation_epoch",1000n);set("Artifact",f.a,"issued_at_ms",100001n);
  set("ActivationAuthorization",f.p,"issued_at_ms",100001n);
  set(type,f.d,"last_parent_cohort",1000n);set(type,f.d,"max_affected_cohorts",[null,1000n]);
  function rebind() {
    const digest=hash("namespace_capacity_digest",{capacity:encodeCBOR(f.c)});
    set(type,f.d,"namespace_capacity_digest",digest);set("Artifact",f.a,"namespace_capacity_digest",digest);f.seal();
  }
  rebind();assert.deepEqual(f.verify().max_affected_cohorts,[null,1000n]);
  set("NamespaceCapacity",f.c,"max_connection_impact_ms",max-100100n);rebind();f.verify();
  set("NamespaceCapacity",f.c,"max_connection_impact_ms",max-100099n);rebind();failure(f.verify,"activation_delegation_impact_overflow");
  set("NamespaceCapacity",f.c,"cohort_duration_ms",max);rebind();failure(f.verify,"activation_delegation_impact_overflow");
  }
});

test("v4.activation_delegation.immutable: ordinary refresh cannot replace key, bounds or original history", () => {
  const original=bytes("activation_delegation_fields");
  const digest=verifyActivationDelegationContinuityReference(schema,original,Buffer.from(original));
  for(const [name,value] of [["signer_public_key",Buffer.alloc(32,1)],["issuer_key_id",Buffer.alloc(16,1)],["max_session_not_after_ms",999999n],["authority_id","another-authority"]]) {
    const changed=decodeMap(schema,type,original);set(type,changed,name,value);
    assert.notEqual(hash("connection_activation_delegation_digest",{delegation:encodeMap(schema,type,changed)}).toString("hex"),digest);
    failure(()=>verifyActivationDelegationContinuityReference(schema,original,encodeMap(schema,type,changed)),"activation_delegation_changed");
  }
  const changed=decodeMap(schema,type,original);set(type,changed,"signing_key_id","new-id");
  failure(()=>verifyActivationDelegationContinuityReference(schema,original,encodeMap(schema,type,changed)),"activation_delegation_identity");
  const shortened=decodeMap(schema,type,original);set(type,shortened,"last_parent_cohort",99n);set(type,shortened,"max_affected_cohorts",[null,99n]);
  failure(()=>verifyActivationDelegationContinuityReference(schema,original,encodeMap(schema,type,shortened)),"activation_delegation_changed");
});

test("v4.activation_delegation.history: explicit impact vector excludes certificate authority and cannot shrink", () => {
  for(const [vector,code] of [[[0n,100n],"field_null"],[[null,null],"field_equality"],[[null,99n],"field_equality"],[[null],"array_length"]]) {
    const map=decodeMap(schema,type,bytes("activation_delegation_fields"));set(type,map,"max_affected_cohorts",vector);
    failure(()=>decodeMap(schema,type,encodeMap(schema,type,map)),code);
  }
  for(const field of ["signer_public_key","last_parent_cohort","purpose"]) {
    const changed=structuredClone(schema);changed.map_rules[type][0].field=field;assert.throws(()=>verifySchema(changed),/null predicate requires/u);
  }
});

test("v4.activation_delegation.bounds: maximum witness, hostile inputs and immutable scalar results", () => {
  // 18 one-byte field IDs: five <=128-byte strings, two bytes32, two
  // bytes16, seven uint64, one fixed purpose and the explicit [null,uint64]
  // original impact vector, plus a one-byte map header.
  assert.equal(1 + 5*131 + 2*35 + 2*18 + 7*10 + 2 + 12,846);
  assert.equal(bytes("activation_delegation_maximum").length,846);assert.equal(schema.frame_maps[type].max_encoded_bytes,846);
  const once=mapFromNames(schema,"OnceAuthorityRef",{tenant_id:"a".repeat(128),artifact_issuer_key_id:Buffer.alloc(16),spend_authority_id:"b".repeat(128),winner_authority_id:"c".repeat(128)});
  assert.equal(encodeCBOR(once).length,1+3*131+18);assert.equal(encodeCBOR(once).length,schema.frame_maps.OnceAuthorityRef.max_encoded_bytes);
  const f=fixture(), input=encodeMap(schema,type,f.d), output=verifyActivationDelegationReference(schema,input,encodeCBOR(f.authority),encodeCBOR(f.c),encodeCBOR(f.a),encodeCBOR(f.p),"live_authority");
  const digest=output.delegation_digest;input.fill(0);assert.equal(output.delegation_digest,digest);
  failure(()=>verifyActivationDelegationContinuityReference(schema,Buffer.alloc(847),bytes("activation_delegation_fields")),"activation_delegation_input_size");
  let calls=0;const hostile=bytes("activation_delegation_fields");Object.defineProperty(hostile,"byteLength",{get(){calls++;throw Error("hook");}});
  assert.throws(()=>verifyActivationDelegationContinuityReference(schema,hostile,hostile),/shadowed byte metadata/u);assert.equal(calls,0);
  failure(()=>decodeMap(schema,type,bytes("head_delegation_fields")),"field_type");
});

import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";
import { cborHead, decodeMap, encodeMap, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { namespaceParserLimitsReference, checkStateReferenceBindings, cohortPolicyReference, checkCohortIssuanceReference, checkActivationCohortReference, checkGrantCohortReference, checkRetainedCohortsReference } from "./transport-v4-revocation.mjs";

const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes=id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex");
const id=(name,field)=>BigInt(Object.entries(schema.frame_maps[name].fields).find(([,f])=>f.name===field)[0]);
const capacity=bytes("namespace_capacity_fields"), limits=namespaceParserLimitsReference(schema,capacity);
const stateName="RevocationState", segmentName="CohortPolicySegment", MAX=0xffffffffffffffffn;
const failure=(run,code)=>assert.throws(run,error=>error instanceof VectorError && error.code===code);
const hash=(name,input,value,context)=>Buffer.from(evaluateDomain(schema,name,{[input]:value},context).output_hex,"hex");
function rewrite(name,input,changes,context=limits) {
  const map=decodeMap(schema,name,input,context);
  for(const [field,value] of Object.entries(changes)) map.set(id(name,field),value);
  return encodeMap(schema,name,map,context);
}
function pair(c=capacity,s=bytes("revocation_state_fields")) {
  const l=namespaceParserLimitsReference(schema,c);
  s=rewrite(stateName,s,{namespace_capacity_digest:hash("namespace_capacity_digest","capacity",c)});
  const h=rewrite("FreshnessHead",bytes("freshness_head_fields"),{
    namespace_capacity_digest:hash("namespace_capacity_digest","capacity",c),
    state_digest:hash("revocation_state_digest","state",s,l),state_encoded_bytes:BigInt(s.length)
  });
  return {c,s,h,l,check:()=>checkStateReferenceBindings(schema,c,h,s)};
}
function stateWithSegments(segments,extra={}) {
  const maps=segments.map(values=>mapFromNames(schema,segmentName,values));
  maps.sort((a,b)=>Buffer.compare(encodeMap(schema,segmentName,a),encodeMap(schema,segmentName,b)));
  return rewrite(stateName,bytes("revocation_state_empty"),{cohort_policy_segments:maps,...extra});
}
const policy=(first,last,certificate=500n,connection=5000n)=>({first_cohort:first,last_cohort:last,...(certificate===undefined?{}:{certificate_impact_ms:certificate}),...(connection===undefined?{}:{connection_impact_ms:connection})});

test("v4.revocation_state.encoding: complete required arrays, exact witnesses and presence rules",()=>{
  for(const [vector,size] of [["cohort_segment_minimum",7],["cohort_segment_maximum",41],["revocation_state_minimum",64],["revocation_state_empty_maximum",608]]) assert.equal(bytes(vector).length,size);
  const empty=decodeMap(schema,stateName,bytes("revocation_state_empty"),limits);
  const zero={...limits,max_revoked_issuers:0,max_revoked_certificates:0,max_revoked_leases:0,max_cohort_policy_segments:0};
  assert.deepEqual(decodeMap(schema,stateName,encodeMap(schema,stateName,empty,zero),zero),empty);
  failure(()=>decodeMap(schema,stateName,bytes("revocation_state_fields"),zero),"array_limit");
  for(const field of [8n,9n,10n,11n]) {
    const changed=new Map(empty);changed.delete(field);
    const encoded=encodeMap(schema,stateName,changed,zero);
    failure(()=>decodeMap(schema,stateName,encoded,zero),"missing_field");
  }
  const noClass=mapFromNames(schema,segmentName,{first_cohort:0,last_cohort:0});
  failure(()=>decodeMap(schema,segmentName,encodeMap(schema,segmentName,noClass)),"field_presence");
  for(const mutate of [
    s=>{s.map_rules.CohortPolicySegment[0].fields=[];},
    s=>{s.map_rules.CohortPolicySegment[0].fields=["certificate_impact_ms","certificate_impact_ms"];},
    s=>{s.map_rules.CohortPolicySegment[0].fields=["first_cohort"];},
    s=>{s.validation_parameters.max_revoked_leases.minimum_item_bytes=0;},
    s=>{s.validation_parameters.max_revoked_leases.byte_capacity_field="max_head_encoded_bytes";}
  ]) {const copy=structuredClone(schema);mutate(copy);assert.throws(()=>verifySchema(copy));}
});

test("v4.revocation_state.capacity: all count caps intersect the original byte envelope",()=>{
  const counts={max_revoked_issuers:MAX,max_revoked_certificates:MAX,max_revoked_leases:MAX,max_cohort_policy_segments:MAX};
  const c=rewrite("NamespaceCapacity",capacity,{max_state_encoded_bytes:1000n,...counts});
  assert.deepEqual(namespaceParserLimitsReference(schema,c),{max_state_encoded_bytes:1000,max_revoked_issuer_authorizations:22,max_revoked_issuers:15,max_revoked_certificates:25,max_revoked_leases:13,max_cohort_policy_segments:142});
  const tiny=namespaceParserLimitsReference(schema,rewrite("NamespaceCapacity",c,{max_state_encoded_bytes:1n}));
  assert.equal(tiny.max_revoked_issuer_authorizations,0);
  for(const name of Object.keys(counts)) assert.equal(tiny[name],0);
  assert.equal(namespaceParserLimitsReference(schema,rewrite("NamespaceCapacity",c,{max_state_encoded_bytes:0xffffffffn})).max_state_encoded_bytes,0xffffffff);
  failure(()=>namespaceParserLimitsReference(schema,rewrite("NamespaceCapacity",c,{max_state_encoded_bytes:0x100000000n})),"revocation_parser_capacity");
  const p=pair(), exact=rewrite("NamespaceCapacity",capacity,{max_state_encoded_bytes:BigInt(p.s.length)});
  pair(exact).check();
  const tooSmall=rewrite("NamespaceCapacity",capacity,{max_state_encoded_bytes:BigInt(p.s.length-1)});
  failure(()=>checkStateReferenceBindings(schema,tooSmall,p.h,p.s),"revocation_input_size");
  const identityFields={revoked_issuers:["issuer_key_id",16],revoked_certificates:["certificate_digest",32],revoked_leases:["lease_id",16]};
  for(const [field,[identity,width]] of Object.entries(identityFields)) {
    const map=decodeMap(schema,stateName,p.s,limits),key=id(stateName,field),items=map.get(key);
    const itemName=schema.frame_maps[stateName].fields[Number(key)].items.schema_ref;
    const other=new Map(items[0]);other.set(id(itemName,identity),Buffer.alloc(width,255));map.set(key,[items[0],other]);
    const encoded=encodeMap(schema,stateName,map,limits);
    const cap=rewrite("NamespaceCapacity",capacity,{["max_"+field]:1n});
    failure(()=>checkStateReferenceBindings(schema,cap,p.h,encoded),"array_limit");
    map.set(key,[other,items[0]]);
    failure(()=>decodeMap(schema,stateName,encodeMap(schema,stateName,map,limits),limits),"item_order");
  }
  const segments=stateWithSegments([policy(0,0),policy(1,1)]);
  failure(()=>checkStateReferenceBindings(schema,rewrite("NamespaceCapacity",capacity,{max_cohort_policy_segments:1n}),p.h,segments),"array_limit");
  const largeCap=rewrite("NamespaceCapacity",capacity,{max_revoked_certificates:2000n}), largeLimits=namespaceParserLimitsReference(schema,largeCap);
  const large=decodeMap(schema,stateName,bytes("revocation_state_empty"),limits);
  large.set(9n,Array.from({length:1036},(_,index)=>{
    const digest=Buffer.alloc(32);digest.writeUInt32BE(index,28);
    return mapFromNames(schema,"RevokedCertificateEntry",{certificate_digest:{$bytes:digest.toString("hex")},cohort:0,expires_at_ms:1});
  }));
  const largeBytes=encodeMap(schema,stateName,large,largeLimits);
  assert.equal(decodeMap(schema,stateName,largeBytes,largeLimits).get(9n).length,1036);
  failure(()=>decodeMap(schema,stateName,largeBytes,limits),"array_limit");
});

test("v4.revocation_state.preallocation: forged array sizes reject before allocating",()=>{
  const original=Array.from;let allocations=0;
  Array.from=function(...args){allocations++;return Reflect.apply(original,this,args);};
  try {
    for(const key of [8,9,10,11]) {
      const encoded=Buffer.concat([Buffer.from([0xa1,key]),cborHead(4,1000000)]);
      failure(()=>decodeMap(schema,stateName,encoded,limits),"array_limit");
    }
    assert.equal(allocations,0);
  } finally {Array.from=original;}
});

test("v4.revocation_state.binding: every repeated field, floor and original byte digest must match",()=>{
  const p=pair();p.check();
  assert.deepEqual(p.h,bytes("freshness_head_state_bound"));
  for(const [field,value] of Object.entries({schema_revision:"5",tenant_id:"tenant-2",revocation_authority_id:"revocation-2",authority_generation:2n,publication_policy_id:"other",publication_policy_revision:2n})) {
    const h=rewrite("FreshnessHead",p.h,{[field]:value});
    failure(()=>checkStateReferenceBindings(schema,p.c,h,p.s),["tenant_id","revocation_authority_id"].includes(field)?"revocation_namespace":"revocation_state_binding");
  }
  for(const floors of [[1n,0n],[0n,1n]]) failure(()=>checkStateReferenceBindings(schema,p.c,rewrite("FreshnessHead",p.h,{credential_revocation_floors:floors}),p.s),"revocation_state_floors");
  failure(()=>checkStateReferenceBindings(schema,p.c,rewrite("FreshnessHead",p.h,{state_encoded_bytes:BigInt(p.s.length+1)}),p.s),"revocation_state_length");
  failure(()=>checkStateReferenceBindings(schema,p.c,rewrite("FreshnessHead",p.h,{state_digest:Buffer.alloc(32)}),p.s),"revocation_state_digest");
  const prefix=Buffer.alloc(4);prefix.writeUInt32BE(p.s.length);
  const input=Buffer.concat([Buffer.from("flowersec/v4/revocation-state\0"),prefix,p.s]);
  assert.deepEqual(hash("revocation_state_digest","state",p.s,p.l),createHash("sha256").update(input).digest());
  for(const field of ["revoked_issuers","revoked_certificates","revoked_leases","cohort_policy_segments"]) {
    const changed=rewrite(stateName,p.s,{[field]:[]});
    assert.notDeepEqual(hash("revocation_state_digest","state",changed,p.l),hash("revocation_state_digest","state",p.s,p.l));
  }
  failure(()=>evaluateDomain(schema,"revocation_state_digest",{state:p.s}),"limit_unresolved");
});

test("v4.revocation_state.segments: per-class inclusive intervals and immutable bounds",()=>{
  const select=(s,kind="connection",cohort=0n)=>cohortPolicyReference(schema,capacity,s,kind,cohort);
  const s=stateWithSegments([policy(0n,9n)]), result=select(s);
  assert.deepEqual(result,{issuance_not_before_ms:1000n,issuance_not_after_ms:2000n,cohort_not_before_ms:1000n,cohort_not_after_ms:1100n,impact_not_after_ms:6100n,immutable_gc_not_before_ms:11100n});
  assert.ok(Object.isFrozen(result));
  failure(()=>select(s,"connection",10n),"revocation_segment_missing");
  failure(()=>select(s,"other"),"revocation_class_context");
  const historical=stateWithSegments([],{credential_revocation_floors:[0n,1n]});
  failure(()=>select(historical),"revocation_floor_rejected");
  for(const segments of [[policy(0,4),policy(4,5)],[policy(2,5),policy(0,3)]]) failure(()=>select(stateWithSegments(segments)),"revocation_segment_overlap");
  const certificate={first_cohort:0,last_cohort:4,certificate_impact_ms:500},connection={first_cohort:0,last_cohort:4,connection_impact_ms:5000};
  select(stateWithSegments([certificate,connection]));
  failure(()=>select(stateWithSegments([certificate])),"revocation_segment_missing");
  select(stateWithSegments([policy(0,4),policy(5,9)]));
  for(const segment of [policy(0,0,1001,5000),policy(0,0,500,10001)]) failure(()=>select(stateWithSegments([segment])),"revocation_segment_impact");
  failure(()=>select(stateWithSegments([policy(MAX,MAX)])),"revocation_overflow");
  const c=rewrite("NamespaceCapacity",capacity,{cohort_time_origin_ms:MAX-100n});
  const p=pair(c,stateWithSegments([policy(0,0)]));
  failure(p.check,"revocation_overflow");
});

test("v4.revocation_state.issuance: original signing window and actual cohort intersect",()=>{
  const s=stateWithSegments([policy(0,9)]);
  const check=(at=1050n,before=1000n,after=1060n,impact=6000n)=>checkCohortIssuanceReference(schema,capacity,s,"connection",0n,at,before,after,impact);
  check();
  failure(()=>check(1060n),"revocation_issuer_window");
  failure(()=>check(1050n,1051n),"revocation_issuer_window");
  failure(()=>check(1150n,1000n,2000n),"revocation_cohort_issuance");
  failure(()=>check(1050n,1000n,1060n,6101n),"revocation_credential_impact");
  const activation=(impact=5900n,parent=6000n,at=3000n)=>checkActivationCohortReference(schema,capacity,s,0n,parent,at,2000n,4000n,impact);
  activation(); // Later signing does not re-enter the parent's issuance cohort.
  failure(()=>activation(6001n),"revocation_activation_impact");
  failure(()=>activation(5900n,6101n),"revocation_activation_impact");
  failure(()=>activation(5900n,6000n,4000n),"revocation_issuer_window");
  const grant=(end=5900n)=>checkGrantCohortReference(schema,capacity,s,5n,1550n,1500n,1600n,end,capacity,s,0n,6000n);
  grant();
  failure(()=>grant(6001n),"revocation_grant_parent_impact");
  failure(()=>grant(6601n),"revocation_credential_impact");
});

test("v4.revocation_state.retention: complete original segments persist until floors and real exit",()=>{
  const before=stateWithSegments([policy(0,9)]), original=decodeMap(schema,stateName,before,limits).get(11n)[0];
  const exited=new Set([encodeMap(schema,segmentName,original).toString("hex")]);
  const check=(after,refs=new Set())=>checkRetainedCohortsReference(schema,capacity,before,after,refs);
  check(before);
  failure(()=>check(stateWithSegments([policy(0,9,499,5000)])),"revocation_segment_retained");
  failure(()=>check(stateWithSegments([policy(0,4),policy(5,9)])),"revocation_segment_retained");
  failure(()=>check(stateWithSegments([],{credential_revocation_floors:[10n,9n]}),exited),"revocation_segment_retained");
  const removed=stateWithSegments([],{credential_revocation_floors:[10n,10n]});
  failure(()=>check(removed),"revocation_segment_references");check(removed,exited);
  const single=stateWithSegments([{first_cohort:0,last_cohort:9,certificate_impact_ms:500}]);
  failure(()=>checkRetainedCohortsReference(schema,capacity,single,before,new Set()),"revocation_segment_retained");
  checkRetainedCohortsReference(schema,capacity,single,stateWithSegments([{first_cohort:0,last_cohort:9,certificate_impact_ms:500},{first_cohort:0,last_cohort:9,connection_impact_ms:5000}]),new Set());
});

test("v4.revocation_state.generated: all four registries include complete State and parameters",()=>{
  for(const path of ["flowersec-go/internal/protocolv4/registry_generated.go","flowersec-rust/src/protocol_v4_registry_generated.rs","flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift","flowersec-ts/src/generated/transportV4Registry.ts"])
    for(const name of ["RevocationState","CohortPolicySegment","at_least_one","minimum_item_bytes","max_cohort_policy_segments","revocation_state_digest"]) assert.ok(files.get(path).includes(name),`${path}: ${name}`);
});

test("minimum entry witnesses justify byte-derived count bounds",()=>{
  const named=(name,values)=>mapFromNames(schema,name,values);
  const fixed=n=>({$bytes:"00".repeat(n)});
  const impact={authorization_digest:fixed(32),max_affected_cohorts:[null,null],signing_not_before_ms:0n,signing_not_after_ms:1n};
  for(const [name,values,minimum] of [
    ["IssuerAuthorizationImpact",impact,44],
    ["RevokedIssuerEntry",{issuer_key_id:fixed(16),authorizations:[impact]},65],
    ["RevokedCertificateEntry",{certificate_digest:fixed(32),cohort:0n,expires_at_ms:0n},40],
    ["RevokedLeaseEntry",{issuer_key_id:fixed(16),lease_id:fixed(16),artifact_digest:fixed(32),cohort:0n,latest_impact_not_after_ms:0n},76]
  ]) {
    const original=named(name,values),encoded=encodeMap(schema,name,original,limits);
    assert.equal(encoded.length,minimum);assert.deepEqual(decodeMap(schema,name,encoded,limits),original);
  }
});

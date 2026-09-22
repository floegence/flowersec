import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeMap, encodeCBOR, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { checkHeadReferenceBindings, checkHeadReferenceTransition, cohortImpactBounds, credentialPolicyRequirements, intersectCredentialRequirements, namespacePolicyDeadlineReference } from "./transport-v4-revocation.mjs";

const {schema, files} = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
const bytes = id => Buffer.from(corpus.vectors.find(vector => vector.id === id).hex, "hex");
const capacity = bytes("namespace_capacity_fields"), delegation = bytes("head_delegation_fields"), head = bytes("freshness_head_fields");
const MAX = 0xffffffffffffffffn;
const id = (name, field) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([,entry]) => entry.name === field)[0]);
const rewrite = (name, input, changes) => {
  const map = decodeMap(schema, name, input);
  for (const [field, value] of Object.entries(changes)) map.set(id(name, field), value);
  return encodeCBOR(map);
};
const hash = (name, field, input) => Buffer.from(evaluateDomain(schema, name, {[field]:input}).output_hex, "hex");
const failure = (run, code) => assert.throws(run, error => error instanceof VectorError && error.code === code);
const check = (h=head, d=delegation, c=capacity, lifetime=59000n, lower=1100n, upper=1200n) => checkHeadReferenceBindings(schema, c, d, h, lifetime, lower, upper);
function rebind(c=capacity, d=delegation, h=head) {
  const digest = hash("namespace_capacity_digest", "capacity", c);
  d = rewrite("HeadSignerDelegation", d, {namespace_capacity_digest:digest});
  h = rewrite("FreshnessHead", h, {namespace_capacity_digest:digest, signer_delegation_digest:hash("head_signer_delegation_digest", "delegation", d)});
  return {c,d,h};
}

test("v4.revocation_reference.encoding: exact maximal witnesses include every canonical byte", () => {
  // Keys are all single-byte integers; the map heads are single bytes.
  const sizes = {
    namespace_capacity_maximum:1+15+3*130+12*9,
    head_delegation_maximum:1+14+4*130+34+9+2*17+34+1+9+3*9,
    freshness_head_maximum:1+16+4*130+34+9+19+9+9+2*9+34+9+17+34+66
  };
  assert.deepEqual(Object.values(sizes), [514,683,795]);
  for (const [vector, size] of Object.entries(sizes)) assert.equal(bytes(vector).length, size);
  const map = decodeMap(schema, "FreshnessHead", bytes("freshness_head_maximum"));
  assert.equal(encodeCBOR(map.get(id("FreshnessHead","credential_revocation_floors"))).length, 19);
  for (const field of ["credential_revocation_floors","namespace_capacity_digest","state_digest","signer_delegation_digest","signature"]) {
    const changed = new Map(map); changed.delete(id("FreshnessHead",field));
    failure(() => decodeMap(schema,"FreshnessHead",encodeCBOR(changed)), "missing_field");
  }
  // Signature has one fixed field ID and is never included in its own input.
  assert.equal(schema.frame_maps.FreshnessHead.signature_field, 15);
});

test("v4.revocation_reference.domains: complete raw objects and signature projection have independent domains", () => {
  const lp = input => { const size=Buffer.alloc(4);size.writeUInt32BE(input.length);return Buffer.concat([size,input]); };
  for (const [domain,label,field,input] of [
    ["namespace_capacity_digest","namespace-capacity","capacity",capacity],
    ["head_signer_delegation_digest","head-signer-delegation","delegation",delegation],
    ["freshness_head_digest","freshness-head-digest","head",head]
  ]) {
    const expected=Buffer.concat([Buffer.from("flowersec/v4/"+label+"\0"),lp(input)]);
    const actual=evaluateDomain(schema,domain,{[field]:input});
    assert.equal(actual.input_hex,expected.toString("hex"));
    assert.equal(actual.output_hex,createHash("sha256").update(expected).digest("hex"));
  }
  const unsigned=decodeMap(schema,"FreshnessHead",head);unsigned.delete(15n);
  const signature=evaluateDomain(schema,"freshness_head_signature",{head});
  assert.equal(signature.input_hex,Buffer.concat([Buffer.from("flowersec/v4/freshness-head-signature\0"),lp(encodeCBOR(unsigned))]).toString("hex"));
  assert.equal(signature.output_hex,undefined,"reference input is not an actual signature");
  const replaced=rewrite("FreshnessHead",head,{signature:Buffer.alloc(64,9)});
  assert.equal(evaluateDomain(schema,"freshness_head_signature",{head:replaced}).input_hex,signature.input_hex);
  assert.notDeepEqual(hash("freshness_head_digest","head",replaced),hash("freshness_head_digest","head",head));
  for (const changes of [{state_digest:Buffer.alloc(32,9)},{state_encoded_bytes:1001n},{credential_revocation_floors:[1n,0n]},{head_sequence:2n},{signing_key_id:Buffer.alloc(16,9)},{next_update_ms:49999n},{publication_policy_revision:2n}]) {
    assert.notEqual(evaluateDomain(schema,"freshness_head_signature",{head:rewrite("FreshnessHead",head,changes)}).input_hex,signature.input_hex);
  }
});

test("v4.revocation_reference.bindings: namespace, signer, capacity and exact delegation remain distinct", () => {
  check();
  for (const [changes,code] of [
    [{tenant_id:"other"},"revocation_namespace"],
    [{namespace_capacity_digest:Buffer.alloc(32)},"revocation_capacity_digest"],
    [{authority_generation:2n},"revocation_delegation_binding"],
    [{schema_revision:"next"},"revocation_delegation_binding"],
    [{publication_policy_id:"other"},"revocation_delegation_binding"],
    [{publication_policy_revision:2n},"revocation_delegation_binding"],
    [{signing_key_id:Buffer.alloc(16)},"revocation_signer_key"],
    [{signer_delegation_digest:Buffer.alloc(32)},"revocation_delegation_digest"],
    [{state_encoded_bytes:1048577n},"revocation_state_capacity"]
  ]) failure(() => check(rewrite("FreshnessHead",head,changes)),code);
  const changedKey=rewrite("HeadSignerDelegation",delegation,{signer_public_key:Buffer.alloc(32,9)});
  failure(() => check(head,changedKey),"revocation_delegation_digest");
  const cap=rewrite("NamespaceCapacity",capacity,{max_head_encoded_bytes:1n});
  const bound=rebind(cap);
  failure(() => check(bound.h,bound.d,bound.c),"revocation_head_capacity");
  // The exact current encoding fits; future maximum capacity is a separate
  // pre-subscription reservation gate, not proven by this relation helper.
  const exact=rebind(rewrite("NamespaceCapacity",capacity,{max_head_encoded_bytes:BigInt(head.length)}));
  check(exact.h,exact.d,exact.c);
});

test("v4.revocation_reference.time: original signer lifetime and trusted interval cannot be extended", () => {
  failure(() => check(head,delegation,capacity,58999n),"revocation_delegation_lifetime");
  failure(() => check(head,delegation,capacity,MAX),"revocation_overflow");
  failure(() => check(head,delegation,capacity,59000n,1099n,1200n),"revocation_time_pending");
  failure(() => check(head,delegation,capacity,59000n,1100n,50000n),"revocation_expired");
  failure(() => check(head,delegation,capacity,59000n,1200n,1100n),"revocation_time_context");
  failure(() => check(rewrite("FreshnessHead",head,{this_update_ms:999n})),"revocation_head_issuance");
  const late=rewrite("FreshnessHead",head,{next_update_ms:70000n});
  check(late,delegation,capacity,59000n,59000n,59999n);
  failure(() => check(late,delegation,capacity,59000n,59000n,60000n),"revocation_expired");
  const renewed=rewrite("HeadSignerDelegation",delegation,{delegation_id:Buffer.alloc(16,7),issued_at_ms:2000n,not_after_ms:61000n});
  failure(() => check(head,renewed),"revocation_delegation_digest");
  for (const lower of [0, -1n, MAX+1n]) failure(() => check(head,delegation,capacity,59000n,lower,1200n),"revocation_uint64");
});

test("v4.revocation_reference.cohorts: all arithmetic is checked uint64 without saturation", () => {
  assert.deepEqual(cohortImpactBounds(schema,capacity,0n),{certificate:2100n,connection:11100n});
  assert.deepEqual(cohortImpactBounds(schema,capacity,1n),{certificate:2200n,connection:11200n});
  for (const cohort of [MAX,MAX/100n]) failure(() => cohortImpactBounds(schema,capacity,cohort),"revocation_overflow");
  for (const changes of [{cohort_time_origin_ms:MAX},{max_certificate_impact_ms:MAX},{max_connection_impact_ms:MAX}]) {
    failure(() => cohortImpactBounds(schema,rewrite("NamespaceCapacity",capacity,changes),0n),"revocation_overflow");
  }
  const last=rewrite("NamespaceCapacity",capacity,{cohort_time_origin_ms:MAX-2n,cohort_duration_ms:1n,max_certificate_impact_ms:1n,max_connection_impact_ms:1n});
  assert.deepEqual(cohortImpactBounds(schema,last,0n),{certificate:MAX,connection:MAX});
});

test("v4.revocation_reference.frontiers: sequence and both maturity components advance independently", () => {
  const transition=(next,lower=11100n,previous=head)=>checkHeadReferenceTransition(schema,capacity,previous,next,lower);
  assert.equal(transition(head),"duplicate");
  const cert=rewrite("FreshnessHead",head,{head_sequence:2n,credential_revocation_floors:[1n,0n]});
  assert.equal(transition(cert,2100n),"advance");
  failure(() => transition(cert,2099n),"revocation_floor_immature");
  const connection=rewrite("FreshnessHead",head,{head_sequence:2n,credential_revocation_floors:[0n,1n]});
  failure(() => transition(connection,11099n),"revocation_floor_immature");
  assert.equal(transition(connection,11100n),"advance");
  const both=rewrite("FreshnessHead",head,{head_sequence:2n,credential_revocation_floors:[1n,1n]});
  assert.equal(transition(both),"advance");
  const before=rewrite("FreshnessHead",head,{credential_revocation_floors:[5n,0n]});
  failure(() => transition(rewrite("FreshnessHead",both,{credential_revocation_floors:[4n,1n]}),50000n,before),"revocation_floor_rollback");
  failure(() => transition(rewrite("FreshnessHead",head,{state_digest:Buffer.alloc(32,7)})),"revocation_head_equivocation");
  failure(() => transition(head,11100n,cert),"revocation_head_rollback");
  failure(() => transition(rewrite("FreshnessHead",cert,{authority_generation:2n})),"revocation_transition_binding");
  failure(() => transition(rewrite("FreshnessHead",cert,{credential_revocation_floors:[MAX,0n]}),MAX),"revocation_overflow");
  const maximum=rewrite("FreshnessHead",head,{head_sequence:MAX});
  assert.equal(transition(maximum,11100n,maximum),"duplicate");
  failure(() => transition(head,11100n,maximum),"revocation_head_rollback");
});

test("trust reference inputs reject wrappers before traps and cap copies before decoding", () => {
  let calls=0;
  const proxy=input=>new Proxy(input,{getPrototypeOf(){calls++;throw Error("must not run");}});
  const revoked=Proxy.revocable({},{});revoked.revoke();
  for (const wrap of [proxy,()=>revoked.proxy]) {
    failure(() => check(head,delegation,wrap(capacity)),"revocation_input_bytes");
    failure(() => check(head,wrap(delegation)),"revocation_input_bytes");
    failure(() => check(wrap(head)),"revocation_input_bytes");
  }
  assert.equal(calls,0);
  failure(() => check(Buffer.alloc(796)),"revocation_input_size");
  failure(() => check(head,Buffer.alloc(684)),"revocation_input_size");
  failure(() => check(head,delegation,Buffer.alloc(515)),"revocation_input_size");
});

test("v4.revocation_reference.policies: exact references and independently intersected requirements", () => {
  const online=credentialPolicyRequirements(schema,bytes("credential_policy_online"));
  const intermittent=credentialPolicyRequirements(schema,bytes("credential_policy_intermittent"));
  assert.deepEqual(online,{max_staleness_ms:300000n,max_head_signer_lifetime_ms:86400000n});
  assert.deepEqual(intermittent,{max_staleness_ms:86400000n,max_head_signer_lifetime_ms:604800000n});
  assert.deepEqual(intersectCredentialRequirements(online.max_staleness_ms,online.max_head_signer_lifetime_ms,intermittent.max_staleness_ms,intermittent.max_head_signer_lifetime_ms),online);
  assert.deepEqual(intersectCredentialRequirements(10n,50n,20n,30n),{max_staleness_ms:10n,max_head_signer_lifetime_ms:30n});
  assert.deepEqual(intersectCredentialRequirements(MAX,MAX,MAX,MAX),{max_staleness_ms:MAX,max_head_signer_lifetime_ms:MAX});
  for (const value of [0n,-1n,MAX+1n,1]) assert.throws(()=>intersectCredentialRequirements(value,1n,1n,1n),VectorError);
  for(const name of ["publication_policy_maximum","credential_policy_online_maximum"]) assert.equal(bytes(name).length,1+4+130+3*9);
  const renamed=rewrite("CredentialRevocationPolicy",bytes("credential_policy_online"),{revocation_policy_id:"zzz",revocation_policy_revision:MAX});
  assert.deepEqual(credentialPolicyRequirements(schema,renamed),online);
  assert.ok(Object.isFrozen(online));
});

test("v4.revocation_reference.policy_deadlines: fixed publication envelope precedes remaining lifetime", () => {
  const policy=bytes("publication_policy");
  const resolve=(p=policy,h=head,d=delegation,w=300000n,t=86400000n,trust=100000n,credential=100000n,lower=1100n,upper=1200n)=>namespacePolicyDeadlineReference(schema,capacity,p,d,h,w,t,trust,credential,lower,upper);
  assert.deepEqual(resolve(),{namespace_deadline_ms:50000n,authorization_deadline_ms:50000n});
  for (const changes of [{publication_policy_id:"other"},{publication_policy_revision:2n}]) {
    failure(()=>resolve(rewrite("PublicationPolicy",policy,changes)),"revocation_publication_policy");
  }
  // A short current delegation cannot repair an incompatible fixed envelope.
  const sevenDays=rewrite("PublicationPolicy",policy,{max_signer_lifetime_ms:604800000n});
  failure(()=>resolve(sevenDays),"revocation_policy_incompatible");
  // Nor can one hour remaining repair a seven-day original delegation.
  const d=rewrite("HeadSignerDelegation",delegation,{not_after_ms:604801000n});
  const h=rewrite("FreshnessHead",head,{signer_delegation_digest:hash("head_signer_delegation_digest","delegation",d),this_update_ms:601201000n,next_update_ms:601251000n});
  const oneDay=rewrite("PublicationPolicy",policy,{max_signer_lifetime_ms:86400000n});
  failure(()=>resolve(oneDay,h,d,300000n,86400000n,MAX,MAX,601201000n,601202000n),"revocation_delegation_lifetime");
  failure(()=>resolve(rewrite("PublicationPolicy",policy,{max_head_validity_ms:48899n})),"revocation_head_validity");
  assert.deepEqual(resolve(rewrite("PublicationPolicy",policy,{max_head_validity_ms:48900n})),{namespace_deadline_ms:50000n,authorization_deadline_ms:50000n});
  assert.deepEqual(resolve(policy,head,delegation,200n),{namespace_deadline_ms:1300n,authorization_deadline_ms:1300n});
  assert.deepEqual(resolve(policy,head,delegation,300000n,86400000n,30000n,20000n),{namespace_deadline_ms:30000n,authorization_deadline_ms:20000n});
  const late=rewrite("FreshnessHead",head,{next_update_ms:61000n});
  assert.deepEqual(resolve(policy,late),{namespace_deadline_ms:60000n,authorization_deadline_ms:60000n});
  failure(()=>resolve(policy,head,delegation,MAX),"revocation_overflow");
  for (const [trust,credential] of [[1200n,MAX],[MAX,1200n]]) failure(()=>resolve(policy,head,delegation,300000n,86400000n,trust,credential),"revocation_expired");
  assert.deepEqual(resolve(policy,head,delegation,300000n,86400000n,100000n,100000n,49000n,49999n),resolve());
});

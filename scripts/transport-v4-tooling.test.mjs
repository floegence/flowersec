import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createHash } from "node:crypto";
import { encodeCBOR, encodeMap, decodeCBOR, decodeMap, validateMap, mapFromNames, projectMap, strictHex } from "./transport-v4-codec.mjs";
import { buildArtifacts, checkArtifacts, digest, repositoryRoot, verifyCorpus, malformed, domainArguments, verifyDomainCorpus, verifyErrorCorpus } from "./generate-transport-v4-vectors.mjs";
import { evaluateDomain, verifyDomains } from "./transport-v4-domains.mjs";
import { verifyBinding, verifyTraceability } from "./check-transport-v4-binding.mjs";
import { architectureReviewLanes, verifyArchitectureReviews } from "./transport-v4-review-evidence.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";
import { verifyTextCorpus } from "./transport-v4-text-vectors.mjs";
import { validateWireOrigin } from "./transport-v4-origin.mjs";
import { derivePoolSelection, verifyPoolSelection, verifyPoolSet, verifyPoolAuthorization } from "./transport-v4-pool.mjs";

function poolFixture(indices = [0,1]) {
  const {schema,files} = buildArtifacts(), corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const bytes = id => Buffer.from(corpus.vectors.find(v => v.id === id).hex,"hex");
  const artifact = decodeCBOR(bytes("artifact_transport_fields"));
  const selected = derivePoolSelection(schema,encodeCBOR(artifact),indices);
  const proof = decodeCBOR(bytes("activation_pool_fields")), reference = proof.get(7n), fsb = decodeCBOR(bytes("fsb_fields"));
  reference.set(0n,selected.values.artifact_digest); reference.set(1n,indices.map(BigInt)); reference.set(2n,selected.candidate_set_digest);
  proof.set(6n,selected.values.artifact_digest); proof.set(8n,selected.route_set_digest);
  proof.set(10n,artifact.get(9n)); proof.set(11n,artifact.get(10n));
  fsb.set(0n,selected.values.artifact_digest); fsb.set(4n,artifact.get(7n));
  fsb.set(5n,selected.values.entries[0].candidate_id); fsb.set(6n,selected.values.entries[0].route_digest);
  const context = {activation_source_profile:"preauthorized_pool"};
  const fsbBytes = () => { fsb.set(13n,encodeCBOR(proof)); return encodeCBOR(fsb); };
  const check = () => verifyPoolAuthorization(schema,encodeCBOR(artifact),fsbBytes(),context);
  return {schema,corpus,bytes,artifact,selected,proof,reference,fsb,context,fsbBytes,check};
}

test("pool set corpus derives complete Artifact and Route bytes under distinct exact domains", () => {
  const f = poolFixture(), {schema,corpus,bytes} = f;
  for (const buffer of [f.selected.bytes,f.selected.values.artifact_digest,f.selected.candidate_set_digest,f.selected.route_set_digest,...f.selected.values.entries.flatMap(entry=>[entry.candidate_id,entry.route_digest])]) {
    assert.equal(buffer.buffer.byteLength,buffer.length); // No Artifact views or shared allocator slabs.
  }
  for (const [id,count] of [["one",1],["two",2],["sixteen",16]]) {
    const setBytes = bytes("pool_set_"+id), set = decodeMap(schema,"PoolSelectionSet",setBytes);
    assert.equal(setBytes.length,38+56*count);
    assert.equal(set.get(1n).length,count);
    for (const entry of set.get(1n)) assert.equal(encodeCBOR(entry).length,56);
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(setBytes.length);
    const outputs = ["candidate","route"].map(kind => {
      const input = Buffer.concat([Buffer.from("flowersec/v4/"+kind+"-set\0"),prefix,setBytes]);
      const result = evaluateDomain(schema,kind+"_set_digest",{selection:setBytes});
      assert.equal(result.input_hex,input.toString("hex"));
      assert.equal(result.output_hex,createHash("sha256").update(input).digest("hex"));
      return result.output_hex;
    });
    assert.notEqual(...outputs);
  }
  // All sixteen signed candidates use the same endpoint, but each complete
  // Route includes its candidate identity and remains an independent member.
  const sixteen = decodeCBOR(bytes("pool_set_sixteen")).get(1n);
  assert.equal(new Set(sixteen.map(x => x.get(1n).toString("hex"))).size,16);
  assert.equal(new Set(sixteen.map(x => x.get(2n).toString("hex"))).size,16);
  const forged = structuredClone(corpus);
  forged.vectors.find(v => v.id === "pool_set_two").pool_derivation.indices = [0];
  assert.throws(() => verifyCorpus(schema,forged),/pool_set_membership/u);
});

test("TopUp domains preserve raw digest projections and owner-fence scope", () => {
  const {schema, files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const bytes = id => Buffer.from(corpus.vectors.find(v => v.id === id).hex, "hex");
  const request = bytes("topup_request_fields");
  const response = bytes("topup_response_fields");
  const proof = bytes("topup_owner_proof_fields");
  const requestDigest = evaluateDomain(schema, "topup_request_digest", {request});
  const responseDigest = evaluateDomain(schema, "topup_response_digest", {response});
  const material = Buffer.alloc(64, 0x28);
  const materialDigest = evaluateDomain(schema, "topup_material_digest", {material});
  assert.equal(requestDigest.input_hex, encodeCBOR((() => { const m = decodeCBOR(request); m.delete(6n); m.delete(7n); return m; })()).toString("hex"));
  assert.equal(responseDigest.input_hex, encodeCBOR((() => { const m = decodeCBOR(response); m.delete(9n); return m; })()).toString("hex"));
  assert.equal(materialDigest.input_hex, material.toString("hex"));
  assert.equal(materialDigest.output_hex, createHash("sha256").update(material).digest("hex"));
  assert.equal(evaluateDomain(schema, "topup_owner_fence_signature", {proof}).label_hex, Buffer.from("flowersec/v6/topup-owner-fence\0").toString("hex"));
  assert.throws(() => evaluateDomain(schema, "topup_material_digest", {material:Buffer.alloc(65537)}), /domain_bytes_length/u);
  assert.throws(() => evaluateDomain(schema, "topup_request_digest", {request:request.subarray(0, -1)}), /truncated/u);
  const responseMap = decodeCBOR(response); responseMap.set(9n, Buffer.alloc(32, 0xaa));
  assert.equal(evaluateDomain(schema, "topup_response_digest", {response:encodeCBOR(responseMap)}).output_hex, responseDigest.output_hex);
  responseMap.set(9n, decodeCBOR(response).get(9n));
  responseMap.set(8n, false);
  assert.throws(() => evaluateDomain(schema, "topup_response_digest", {response:encodeCBOR(responseMap)}), /field_equality/u);
});

test("pool construction rejects invalid indices without sorting, truncating or mutating input", () => {
  const f = poolFixture(), original = encodeCBOR(f.artifact);
  for (const [indices,error] of [
    [[],/array_length/u], [Array(17).fill(0),/array_length/u],
    [[0,0],/item_order/u], [[1,0],/item_order/u], [[2],/pool_index_membership/u],
    [[16],/field_range/u], [[-1],/field_range/u], [[1n<<64n],/field_range/u],
    [["0"],/integer_type/u], [[false],/integer_type/u], [[0.5],/integer_type/u], [[NaN],/integer_type/u],
  ]) {
    const before = indices.slice();
    assert.throws(() => derivePoolSelection(f.schema,original,indices),error);
    assert.deepEqual(indices,before); assert.deepEqual(original,encodeCBOR(f.artifact));
  }
  assert.throws(() => derivePoolSelection(f.schema,f.bytes("artifact_over_encoding_cap"),[0]),/map_size/u);
  assert.throws(() => derivePoolSelection(f.schema,original.subarray(0,-1),[0]),/truncated/u);
});

test("pool set verification rejects self-reported index, candidate and route substitutions", () => {
  const f = poolFixture();
  for (const mutate of [
    map => map.set(0n,Buffer.alloc(32)),
    map => map.get(1n)[0].set(0n,1n),
    map => map.get(1n)[0].set(1n,Buffer.alloc(16,99)),
    map => map.get(1n)[0].set(2n,Buffer.alloc(32,99)),
    map => { const entries=map.get(1n), first=entries[0].get(2n); entries[0].set(2n,entries[1].get(2n)); entries[1].set(2n,first); },
    map => map.get(1n).reverse(),
    map => map.get(1n)[1].set(1n,map.get(1n)[0].get(1n)),
    map => map.get(1n).push(...Array(15).fill(map.get(1n)[0])),
  ]) {
    const map = decodeCBOR(f.selected.bytes); mutate(map);
    const bytes = encodeCBOR(map), before = Buffer.from(bytes);
    assert.throws(() => verifyPoolSet(f.schema,encodeCBOR(f.artifact),[0,1],bytes),/pool_set_membership|item_order|item_identity|array_length/u);
    assert.deepEqual(bytes,before);
  }
});

test("received pool references bind the complete signature-bearing Artifact and subset", () => {
  const f = poolFixture(), original = encodeCBOR(f.artifact), ref = encodeCBOR(f.reference);
  assert.deepEqual(verifyPoolSelection(f.schema,original,ref).bytes,f.selected.bytes);
  f.artifact.set(27n,Buffer.alloc(64,99)); // Same candidates, different signed Artifact.
  const changed = derivePoolSelection(f.schema,encodeCBOR(f.artifact),[0,1]);
  assert.notDeepEqual(changed.values.artifact_digest,f.selected.values.artifact_digest);
  assert.notDeepEqual(changed.candidate_set_digest,f.selected.candidate_set_digest);
  assert.notDeepEqual(changed.route_set_digest,f.selected.route_set_digest);
  assert.throws(() => verifyPoolSelection(f.schema,encodeCBOR(f.artifact),ref),/pool_artifact_digest/u);
  f.reference.set(1n,[0n]);
  assert.throws(() => verifyPoolSelection(f.schema,original,encodeCBOR(f.reference)),/pool_candidate_set_digest/u);
  f.reference.set(2n,derivePoolSelection(f.schema,original,[0]).route_set_digest);
  assert.throws(() => verifyPoolSelection(f.schema,original,encodeCBOR(f.reference)),/pool_candidate_set_digest/u);
});

test("pool authorization verifies one signed source, Artifact, proof and winner projection", () => {
  const f = poolFixture();
  assert.deepEqual(f.check().bytes,f.selected.bytes);
  for (const context of [{},{activation_source_profile:"live_authority"}]) assert.throws(() => verifyPoolAuthorization(f.schema,encodeCBOR(f.artifact),f.fsbBytes(),context),/pool_source_profile/u);
  assert.throws(() => verifyPoolAuthorization(f.schema,encodeCBOR(f.artifact),f.fsbBytes(),{...f.context,crypto_profile_id:"wrong"}),/pool_crypto_profile/u);
  for (const [mutate,error] of [
    [f => f.proof.set(8n,Buffer.alloc(32)),/pool_route_set_digest/u],
    [f => { f.reference.set(2n,Buffer.alloc(32)); f.proof.set(8n,Buffer.alloc(32)); },/pool_candidate_set_digest/u],
    [f => f.fsb.set(5n,Buffer.alloc(16,77)),/pool_winner_membership/u],
    [f => f.fsb.set(6n,f.selected.values.entries[1].route_digest),/pool_winner_membership/u],
    [f => f.fsb.set(4n,Buffer.alloc(32,77)),/pool_artifact_binding/u],
    [f => f.proof.set(10n,Buffer.alloc(32,77)),/pool_artifact_binding/u],
    [f => f.proof.set(11n,Buffer.alloc(32,77)),/pool_artifact_binding/u],
    [f => f.proof.set(14n,500001n),/pool_parent_deadline/u],
    [f => f.proof.set(15n,1000001n),/pool_parent_deadline/u],
    [f => f.reference.set(0n,Buffer.alloc(32)),/field_equality/u],
    [f => f.proof.set(6n,Buffer.alloc(32)),/field_equality/u],
    [f => f.reference.get(4n).set(2n,"wrong-authority"),/field_equality/u],
  ]) { const fresh=poolFixture(); mutate(fresh); assert.throws(fresh.check,error); }
  const single = poolFixture([0]);
  single.fsb.set(5n,f.selected.values.entries[1].candidate_id); single.fsb.set(6n,f.selected.values.entries[1].route_digest);
  assert.throws(single.check,/pool_winner_membership/u);
  f.fsb.set(5n,f.selected.values.entries[1].candidate_id); f.fsb.set(6n,f.selected.values.entries[1].route_digest);
  assert.doesNotThrow(f.check); // Either authorized member, always the same ID/route pair.
});

test("maximal pool references fit the unchanged 17-field authorization cap", () => {
  const {schema} = buildArtifacts();
  const context = {activation_source_profile:"preauthorized_pool"};
  const maximum = name => Object.fromEntries(Object.values(schema.frame_maps[name].fields).filter(f => !f.optional).map(f => {
    const value = field => {
      if (field.type.startsWith("uint")) return BigInt(field.const ?? field.max ?? (field.enum ? Math.max(...Object.values(field.enum)) : (1n<<BigInt(field.type.slice(4)))-1n));
      if (field.type === "text") return "a".repeat(128);
      if (field.type === "bytes") return Buffer.alloc(field.length,1);
      if (field.type === "map") return maximum(field.schema_ref);
      if (field.type === "context_variant") return value(field.cases.preauthorized_pool);
      if (field.type === "array" && field.name === "candidate_indices") return Array.from({length:field.max_items},(_,i) => i);
      throw new Error("unhandled maximum field "+name+"."+field.name);
    };
    return [f.name,value(f)];
  }));
  const values = maximum("ActivationAuthorization");
  values.issued_at_ms -= 2n; values.activation_not_after_ms -= 1n;
  const bytes = encodeCBOR(mapFromNames(schema,"ActivationAuthorization",values,context));
  const proof = decodeMap(schema,"ActivationAuthorization",bytes,context);
  assert.equal(proof.size,17); assert.equal(proof.get(7n).size,5);
  assert.equal(bytes.length,1352); assert.equal(encodeCBOR(proof.get(7n)).length,533);
  assert.equal(schema.frame_maps.ActivationAuthorization.max_encoded_bytes,4096);
  assert.ok(bytes.length < schema.frame_maps.ActivationAuthorization.max_encoded_bytes);
});

test("Artifact signs all fields except its own signature and digests the complete signed object", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const artifact=decodeCBOR(Buffer.from(corpus.vectors.find(v=>v.id==="artifact_execution_fields").hex,"hex"));
  const unsigned=new Map(artifact); unsigned.delete(27n);
  const lp=bytes=>{const prefix=Buffer.alloc(4); prefix.writeUInt32BE(bytes.length); return Buffer.concat([prefix,bytes]);};
  const signing=evaluateDomain(schema,"artifact_signature",{artifact:encodeCBOR(artifact)});
  const digest=evaluateDomain(schema,"artifact_digest",{artifact:encodeCBOR(artifact)});
  assert.equal(signing.input_hex,Buffer.concat([Buffer.from("flowersec/v4/artifact/signature\0"),lp(encodeCBOR(unsigned))]).toString("hex"));
  assert.equal(digest.input_hex,Buffer.concat([Buffer.from("flowersec/v4/artifact-digest\0"),lp(encodeCBOR(artifact))]).toString("hex"));
  assert.equal(digest.output_hex,createHash("sha256").update(Buffer.from(digest.input_hex,"hex")).digest("hex"));
  artifact.set(27n,Buffer.alloc(64,0xaa));
  assert.deepEqual(evaluateDomain(schema,"artifact_signature",{artifact:encodeCBOR(artifact)}),signing);
  assert.notEqual(evaluateDomain(schema,"artifact_digest",{artifact:encodeCBOR(artifact)}).output_hex,digest.output_hex);
  // Secret and policy fields remain in the signed input; no other field is
  // omitted along with the signature. Fixtures do not qualify actual signing.
  artifact.set(8n,Buffer.alloc(32,0xbb));
  assert.notEqual(evaluateDomain(schema,"artifact_signature",{artifact:encodeCBOR(artifact)}).input_hex,signing.input_hex);
  const contract=encodeCBOR(artifact.get(13n));
  const contractDigest=evaluateDomain(schema,"session_contract_digest",{session_contract:contract});
  assert.equal(contractDigest.input_hex,Buffer.concat([Buffer.from("flowersec/v4/session-contract\0"),lp(contract)]).toString("hex"));
  assert.notEqual(contractDigest.label_hex,Buffer.from("flowersec/v4/service-contract\0").toString("hex"));
  artifact.delete(27n);
  for (const name of ["artifact_signature","artifact_digest"]) assert.throws(()=>evaluateDomain(schema,name,{artifact:encodeCBOR(artifact)}),/missing_field/u);
});

test("Artifact candidate order uses priority before ID and allows the full bounded count", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const artifact=decodeCBOR(Buffer.from(corpus.vectors.find(v=>v.id==="artifact_transport_fields").hex,"hex"));
  const base=artifact.get(12n)[0];
  const candidates=Array.from({length:3},(_,i)=>{const item=new Map(base); item.set(0n,Buffer.alloc(16,i+1)); item.set(1n,i===2 ? 0n : 1n); return item;});
  for (const order of [[0,1,2],[0,2,1],[1,0,2],[1,2,0],[2,0,1],[2,1,0]]) {
    artifact.set(12n,order.map(i=>candidates[i]));
    if (order.join() === "2,0,1") assert.doesNotThrow(()=>validateMap(schema,"Artifact",artifact));
    else assert.throws(()=>validateMap(schema,"Artifact",artifact),/item_order/u);
  }
  artifact.set(12n,Array.from({length:16},(_,i)=>{const item=new Map(base); item.set(0n,Buffer.alloc(16,i)); return item;}));
  assert.doesNotThrow(()=>decodeMap(schema,"Artifact",encodeCBOR(artifact)));
  artifact.get(12n).push(new Map(base));
  assert.throws(()=>validateMap(schema,"Artifact",artifact),/array_length/u);
});

test("whole Artifact size remains independent of legal field widths and candidate count", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const seed=id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex");
  const valid=seed("artifact_encoding_boundary"), oversized=seed("artifact_over_encoding_cap");
  assert.equal(valid.length,65536);
  assert.equal(oversized.length,65537);
  assert.equal(createHash("sha256").update(valid).digest("hex"),"e36c0e9b505ebd1e736e4dea438db1efebea7e564ecaa5aaee45ebe616c5278b");
  assert.equal(createHash("sha256").update(oversized).digest("hex"),"2cef36b5ff2670fc11714a7a579cd386974c5f0e5815377073e7864c8237b8d1");
  assert.equal(decodeMap(schema,"Artifact",valid).get(12n).length,7);
  assert.throws(()=>decodeMap(schema,"Artifact",oversized),/map_size/u);
  // The one-byte change remains valid under every other rule. A per-field
  // decoder or the candidate-count limit alone would incorrectly accept it.
  const fieldsOnly=structuredClone(schema); delete fieldsOnly.frame_maps.Artifact.max_encoded_bytes;
  assert.doesNotThrow(()=>decodeMap(fieldsOnly,"Artifact",oversized));
});

test("signed policy integers retain full width without imposing another optional feature mask", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const seed=id=>decodeCBOR(Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex"));
  const session=seed("session_contract_encoding_maximum");
  assert.equal(session.get(2n),(1n<<63n)-1n);
  assert.equal(session.get(3n),(1n<<64n)-1n);
  for (const duration of [0n,1n,9007199254740991n,9007199254740992n,9007199254740993n,(1n<<64n)-1n]) {
    session.set(3n,duration);
    assert.equal(decodeMap(schema,"SessionContract",encodeCBOR(session)).get(3n),duration);
  }
  const optional=seed("artifact_unknown_optional");
  assert.equal(optional.get(14n),9223372036854775811n);
  assert.equal(optional.get(15n),0n);
  assert.equal(optional.get(16n).get(0n),false);
  assert.doesNotThrow(()=>validateMap(schema,"Artifact",optional));
  assert.equal(seed("session_contract_services").get(2n),16384n);
  assert.equal(seed("session_contract_transport_zero").get(0n),0n);
});

test("schema audit rejects ill-typed policy predicates and ambiguous tuple columns", () => {
  const {schema}=buildArtifacts();
  for (const badValue of [0,1,"false"]) {
    const changed=structuredClone(schema); changed.map_rules.ResumePolicy[0].value=badValue;
    assert.throws(()=>verifySchema(changed),/boolean condition/u);
  }
  for (const alter of [
    rule=>{rule.feature="unregistered";},
    rule=>{rule.field="resume_policy.enabled";},
    rule=>{rule.present=1;},
    rule=>{rule.when.value=0;},
  ]) {
    const changed=structuredClone(schema); alter(changed.map_rules.Artifact.find(r=>r.op==="feature_bit"));
    assert.throws(()=>verifySchema(changed));
  }
  for (const columns of [["priority","priority"],["direct_leg.endpoint_role"],["path_kind","direct_leg"],["missing"]]) {
    const changed=structuredClone(schema); changed.map_rules.Artifact.find(r=>r.op==="increasing_tuple").item_fields=columns;
    assert.throws(()=>verifySchema(changed));
  }
  const unknownVariant=structuredClone(schema); unknownVariant.map_rules.Artifact.find(r=>r.op==="exclusive_item").value=2;
  assert.throws(()=>verifySchema(unknownVariant),/condition value/u);
});

test("field-removal recipes cannot silently delete an unknown field or mix mutations", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const plan=schema.vector_plan.maps.find(v=>v.id==="artifact_transport_fields");
  const bytes=Buffer.from(corpus.vectors.find(v=>v.id===plan.id).hex,"hex"), seeds=new Map([[plan.id,{bytes,plan}]]);
  for (const recipe of [{remove:[]},{remove:["missing"]},{remove:["signature","signature"]},{remove:["signature"],mutation:"append_zero"}]) {
    assert.throws(()=>malformed(schema,{source:plan.id,...recipe},seeds),/remov/u);
  }
});

test("Grant retains independent parent authority and forwarding validity while binding its ordered route", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const seed=id=>decodeCBOR(Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex"));
  const id=(map,name)=>BigInt(Object.entries(schema.frame_maps[map].fields).find(([,field])=>field.name===name)[0]);
  const grant=seed("grant_fields"), parent=grant.get(id("Grant","parent_ref"));
  assert.equal(grant.size,20);
  // A later Grant can forward beyond parent initiation, within the original
  // parent Session deadline. Parent and Grant authorities need not coincide.
  assert.ok(grant.get(id("Grant","issued_at_ms")) > parent.get(id("GrantParentRef","initiation_not_after_ms")));
  assert.notEqual(grant.get(id("Grant","namespace")).get(id("GrantNamespace","revocation_authority_id")),parent.get(id("GrantParentRef","revocation_authority_id")));
  assert.doesNotThrow(()=>validateMap(schema,"Grant",grant));
  assert.doesNotThrow(()=>validateMap(schema,"Grant",seed("grant_server_namespace")));
  for (const [name,length] of [["grant_id",16],["replay_nonce",32],["attempt_id",16],["pairing_id",16]]) {
    const changed=new Map(grant); changed.set(id("Grant",name),Buffer.alloc(length));
    assert.doesNotThrow(()=>validateMap(schema,"Grant",changed));
  }
  // Digest order is role order, not byte sorting. Certificate role matching
  // requires the actual authenticated certificates outside the opaque array.
  const reversed=new Map(grant); reversed.set(id("Grant","identity_digests"),[...grant.get(id("Grant","identity_digests"))].reverse());
  assert.doesNotThrow(()=>validateMap(schema,"Grant",reversed));
  const hello=seed("hop_endpoint_hello_fields");
  const damaged=new Map(grant); damaged.set(id("Grant","route_digest"),Buffer.alloc(32));
  hello.set(id("HOP_AUTH_HELLO","grant"),encodeCBOR(damaged));
  assert.throws(()=>validateMap(schema,"HOP_AUTH_HELLO",hello,{hop_sender_role:"endpoint"}),/map_digest_mismatch/u);
});

test("Grant digest and signature inputs omit only field 19 under separate domains", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const grant=decodeCBOR(Buffer.from(corpus.vectors.find(v=>v.id==="grant_fields").hex,"hex"));
  const unsigned=new Map(grant); unsigned.delete(19n);
  const bytes=encodeCBOR(unsigned), prefix=Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
  const digest=evaluateDomain(schema,"grant_digest",{grant:encodeCBOR(grant)});
  const signing=evaluateDomain(schema,"grant_signature",{grant:encodeCBOR(grant)});
  assert.equal(digest.input_hex,Buffer.concat([Buffer.from("flowersec/v4/grant\0"),prefix,bytes]).toString("hex"));
  assert.equal(signing.input_hex,Buffer.concat([Buffer.from("flowersec/v4/grant/signature\0"),prefix,bytes]).toString("hex"));
  assert.equal(digest.output_hex,createHash("sha256").update(Buffer.from(digest.input_hex,"hex")).digest("hex"));
  assert.notEqual(signing.label_hex,digest.label_hex);
  grant.set(19n,Buffer.alloc(64,0xaa));
  assert.deepEqual(evaluateDomain(schema,"grant_digest",{grant:encodeCBOR(grant)}),digest);
  assert.deepEqual(evaluateDomain(schema,"grant_signature",{grant:encodeCBOR(grant)}),signing);
  // Parent issuance bytes are retained, including their original field IDs.
  grant.get(3n).set(2n,4n);
  assert.notEqual(evaluateDomain(schema,"grant_digest",{grant:encodeCBOR(grant)}).output_hex,digest.output_hex);
});

test("HOP_AUTH binds the endpoint certificate tenant, logical role and complete signed digest", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  for (const name of ["hop_endpoint_hello_fields","hop_server_endpoint_hello_fields"]) {
    const bytes=Buffer.from(corpus.vectors.find(v=>v.id===name).hex,"hex");
    const hello=decodeMap(schema,"HOP_AUTH_HELLO",bytes,{hop_sender_role:"endpoint"}), certificate=decodeMap(schema,"IdentityCertificate",hello.get(4n));
    const grant=decodeMap(schema,"Grant",hello.get(3n)), role=certificate.get(5n);
    assert.equal(grant.get(13n).get(4n),role===0n ? 5n : 6n);
    const digest=evaluateDomain(schema,"certificate_digest",{certificate:hello.get(4n)});
    assert.equal(grant.get(8n)[Number(role)].toString("hex"),digest.output_hex);
    // Certificate audience is checked against its original authenticated
    // audience context; Grant audience describes the relay authorization.
    certificate.set(6n,"other-application-audience");
    hello.set(4n,encodeCBOR(certificate));
    grant.get(8n)[Number(role)]=Buffer.from(evaluateDomain(schema,"certificate_digest",{certificate:hello.get(4n)}).output_hex,"hex");
    hello.set(3n,encodeCBOR(grant));
    assert.doesNotThrow(()=>validateMap(schema,"HOP_AUTH_HELLO",hello,{hop_sender_role:"endpoint"}));
  }
});

test("complete maximum Grant and HELLO witnesses retain nested encoding overhead", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const bytes=id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex");
  const grant=bytes("grant_maximum_fields"), certificate=bytes("grant_certificate_maximum_fields"), hello=bytes("hop_endpoint_maximum_fields");
  assert.equal(grant.length,9302);
  assert.equal(grant.length,schema.frame_maps.Grant.max_encoded_bytes);
  assert.equal(certificate.length,980);
  // Map head, five keys, phase, complete incarnation/challenge bstrs,
  // and both three-byte length heads of the embedded signed objects.
  assert.equal(hello.length,1+5+1+17+34+3+grant.length+3+certificate.length);
  assert.equal(hello.length,schema.frame_maps.HOP_AUTH_HELLO.max_encoded_bytes);
  assert.equal(bytes("hop_relay_maximum_fields").length,hello.length-(1+3+grant.length));
  assert.throws(()=>decodeMap(schema,"Grant",Buffer.concat([grant,Buffer.from([0])])),/map_size/u);
  assert.throws(()=>decodeMap(schema,"HOP_AUTH_HELLO",Buffer.concat([hello,Buffer.from([0])]),{hop_sender_role:"endpoint"}),/map_size/u);
});

test("schema auditing bounds array paths and prevents incompatible digest projections", () => {
  const {schema}=buildArtifacts();
  for (const field of ["legs.2.logical_role","legs.01.logical_role","legs.-1.logical_role","legs.0.missing","legs.0.leg_id.0","identity_digests.length"]) {
    const changed=structuredClone(schema); changed.map_rules.Grant.push({op:"range",field,min:0,max:1});
    assert.throws(()=>verifySchema(changed),/unresolved rule field/u);
  }
  for (const mutate of [
    rule=>{rule.source="parent_ref";},
    rule=>{rule.field="signature";},
    rule=>{rule.domain="grant_signature";},
    rule=>{rule.domain="grant_digest";},
  ]) {
    const changed=structuredClone(schema); mutate(changed.map_rules.Grant.find(rule=>rule.op==="map_digest"));
    assert.throws(()=>verifySchema(changed),/digest/u);
  }
  const wrapper=structuredClone(schema);
  wrapper.frame_maps.GrantWrapper={fields:{0:{name:"grant",type:"bytes",encoded_schema_ref:"Grant"}},required:[0]};
  wrapper.map_rules.GrantWrapper=[{op:"range",field:"grant.legs.1.logical_role",min:1,max:1}];
  verifySchema(wrapper);
  const {files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const grant=Buffer.from(corpus.vectors.find(v=>v.id==="grant_fields").hex,"hex");
  assert.doesNotThrow(()=>validateMap(wrapper,"GrantWrapper",new Map([[0n,grant]])));
  wrapper.map_rules.GrantWrapper[0].max=0;
  assert.throws(()=>validateMap(wrapper,"GrantWrapper",new Map([[0n,grant]])),/field_range/u);
});

test("signed route context owns leg roles, carrier tuples and union presence", () => {
  const {schema,files} = buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const id=(map,name)=>BigInt(Object.entries(schema.frame_maps[map].fields).find(([,field])=>field.name===name)[0]);
  const vector=name=>corpus.vectors.find(item=>item.id===name);
  const seed=name=>decodeCBOR(Buffer.from(vector(name).hex,"hex"));
  for (const pathKind of ["direct","tunnel"]) for (let endpoint=0;endpoint<3;endpoint++) for (let dialer=0;dialer<3;dialer++) for (let listener=0;listener<3;listener++) {
    const leg=seed(pathKind==="direct" ? "leg_direct_ws" : "leg_tunnel_client_ws");
    for (const [field,value] of Object.entries({endpoint_role:endpoint,dialer_role:dialer,listener_role:listener})) leg.set(id("Leg",field),BigInt(value));
    const allowed=pathKind==="direct" ? endpoint===1 && dialer===0 && listener===1 : endpoint<2 && ((dialer===endpoint && listener===2) || (dialer===2 && listener===endpoint));
    const check=()=>validateMap(schema,"Leg",leg,{path_kind:pathKind});
    if (allowed) assert.doesNotThrow(check); else assert.throws(check);
  }
  assert.throws(()=>validateMap(schema,"Leg",seed("leg_direct_quic")),/context_unresolved/u);
  // Enclosing signed fields override unrelated caller context.
  assert.doesNotThrow(()=>validateMap(schema,"Candidate",seed("candidate_tunnel_fields"),{path_kind:"direct"}));
  for (const [name,field] of [["candidate_direct_fields","direct_leg"],["candidate_tunnel_fields","client_leg"],["candidate_tunnel_fields","server_leg"]]) {
    const candidate=seed(name); candidate.delete(id("Candidate",field));
    assert.throws(()=>validateMap(schema,"Candidate",candidate),/variant_required/u);
  }
  const wt=seed("leg_direct_wt"); wt.delete(id("Leg","origin_policy"));
  assert.throws(()=>validateMap(schema,"Leg",wt,{path_kind:"direct"}),/variant_required/u);
  const ws=seed("leg_direct_ws"); ws.delete(id("Leg","origin_policy"));
  assert.doesNotThrow(()=>validateMap(schema,"Leg",ws,{path_kind:"direct"}));
  const local=seed("leg_local_ipv6");
  assert.throws(()=>validateMap(schema,"Leg",local,{path_kind:"tunnel"}),/variant_constant/u);
});

test("route digest projects complete selected legs without Candidate scheduling fields", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const seed=name=>decodeCBOR(Buffer.from(corpus.vectors.find(item=>item.id===name).hex,"hex"));
  const id=(map,name)=>BigInt(Object.entries(schema.frame_maps[map].fields).find(([,field])=>field.name===name)[0]);
  const candidate=seed("candidate_tunnel_fields"), route=projectMap(schema,"candidate_route",candidate), bytes=encodeCBOR(route);
  assert.deepEqual(bytes,encodeCBOR(seed("route_tunnel_mixed_fields")));
  const prefix=Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
  const input=Buffer.concat([Buffer.from("flowersec/v4/route\0","ascii"),prefix,bytes]);
  const evaluated=evaluateDomain(schema,"route_digest",{route:bytes});
  assert.equal(evaluated.input_hex,input.toString("hex"));
  assert.equal(evaluated.output_hex,createHash("sha256").update(input).digest("hex"));
  candidate.set(id("Candidate","priority"),0n);
  candidate.get(id("Candidate","revocation_namespace_refs"))[0].set(id("RevocationNamespaceRef","generation"),2n);
  assert.deepEqual(encodeCBOR(projectMap(schema,"candidate_route",candidate)),bytes);
  const leg=candidate.get(id("Candidate","client_leg"));
  leg.get(id("Leg","origin_policy")).set(id("OriginPolicy","origins"),["https://different.example"]);
  const changed=encodeCBOR(projectMap(schema,"candidate_route",candidate));
  assert.notDeepEqual(changed,bytes);
  assert.notEqual(evaluateDomain(schema,"route_digest",{route:changed}).output_hex,evaluated.output_hex);
  assert.throws(()=>projectMap(schema,"constructor",candidate),/projection_unresolved/u);
});

test("namespace dependency identity is distinct from its canonical encoded value", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const id=(map,name)=>BigInt(Object.entries(schema.frame_maps[map].fields).find(([,field])=>field.name===name)[0]);
  const candidate=decodeCBOR(Buffer.from(corpus.vectors.find(item=>item.id==="candidate_direct_fields").hex,"hex"));
  const refs=id("Candidate","revocation_namespace_refs"), first=candidate.get(refs)[0];
  const second=new Map(first); second.set(id("RevocationNamespaceRef","generation"),2n);
  candidate.set(refs,[first,second]);
  assert.throws(()=>validateMap(schema,"Candidate",candidate),/item_identity/u);
  second.set(id("RevocationNamespaceRef","revocation_authority_id"),"revocation-2");
  assert.doesNotThrow(()=>validateMap(schema,"Candidate",candidate));
  candidate.set(refs,[second,first]);
  assert.throws(()=>validateMap(schema,"Candidate",candidate),/item_order/u);
});

test("route schema rejects malformed conditions, tuple selectors and incomplete projections", () => {
  const {schema}=buildArtifacts();
  for (const value of [2,false,"local_loopback"]) {
    const changed=structuredClone(schema);
    changed.map_rules.Leg.find(rule=>rule.op==="range").when.value=value;
    assert.throws(()=>verifySchema(changed),/condition value must be registered/u);
  }
  const selector=structuredClone(schema);
  selector.map_rules.Leg.find(rule=>rule.op==="registry_tuple").selectors[0]={field:"missing"};
  assert.throws(()=>verifySchema(selector),/unresolved rule field/u);
  const tuple=structuredClone(schema);
  tuple.map_rules.Leg.find(rule=>rule.op==="allowed_tuples").rows[0][0]=2;
  assert.throws(()=>verifySchema(tuple),/tuple value is not registered/u);
  const context=structuredClone(schema);
  context.frame_maps.Route.context_fields.path_kind="candidate_id";
  assert.throws(()=>verifySchema(context),/context requires a required enum field/u);
  const projection=structuredClone(schema);
  projection.map_projections.candidate_route.fields.pop();
  assert.throws(()=>verifySchema(projection),/projection must cover the complete target/u);
  for (const mutate of [
    rule=>{rule.context="path_kid";},
    rule=>{rule.cases.driect=rule.cases.direct; delete rule.cases.direct;},
  ]) {
    const changed=structuredClone(schema); mutate(changed.map_rules.Leg[0]);
    assert.throws(()=>verifySchema(changed),/unregistered context or variant labels/u);
  }
  for (const [rule,expected] of [
    [{op:"unique_by",field:"candidate.revocation_namespace_refs",item_fields:["tenant_id"]},/identity array requires a root field/u],
    [{op:"registry_tuple",registry:"carrier_tuples",selectors:[{field:"candidate.direct_leg.carrier"},{context:"path_kind"}],fields:["candidate.direct_leg.path"]},/tuple selector requires a root field/u],
  ]) {
    const changed=structuredClone(schema);
    changed.frame_maps.Wrapper={fields:{0:{name:"candidate",type:"map",schema_ref:"Candidate"}},required:[0]};
    changed.map_rules.Wrapper=[rule];
    assert.throws(()=>verifySchema(changed),expected);
  }
});

test("Origin syntax preserves host, scheme and port without URL correction", () => {
  const {schema} = buildArtifacts();
  const hosts = ["example.com", "xn--bcher-kva.example", "192.0.2.1", "[::1]", "[::ffff:c000:201]"];
  for (const [scheme, {default_port:defaultPort}] of Object.entries(schema.origin_schemes)) {
    for (const host of hosts) for (const port of [undefined, 0, 1, 80, 443, 65535]) {
      const origin = scheme + "://" + host + (port === undefined ? "" : ":" + port);
      if (port === defaultPort) assert.throws(() => validateWireOrigin(origin,schema), /origin_default_port/u,origin);
      else {
        assert.equal(validateWireOrigin(origin,schema),origin);
        assert.equal(new URL(origin).origin,origin);
      }
    }
  }
  for (const suffix of ["/", "/path", "?query", "#fragment", "\\path", ":", ":01", ":65536", ":-1", ":+1", ":1.0", "\n", " https://b"]) {
    assert.throws(() => validateWireOrigin("https://a" + suffix,schema), undefined,suffix);
  }
  assert.throws(() => validateWireOrigin("chrome-extension://example",schema), /origin_scheme_unregistered/u);
  assert.throws(() => validateWireOrigin("constructor://example",schema), /origin_scheme_unregistered/u);
  for (let code=0;code<=32;code++) for (const base of ["https://a","https://a:8443"]) {
    const character=String.fromCharCode(code);
    for (const origin of [base+character,character+base,base+character+"evil"]) assert.throws(() => validateWireOrigin(origin,schema), /origin_ascii/u);
  }
});

test("OriginPolicy orders complete canonical CBOR values and enforces the full encoding bound", () => {
  const {schema} = buildArtifacts();
  const policy = (origins,allowAbsent=false) => decodeMap(schema,"OriginPolicy",encodeCBOR(mapFromNames(schema,"OriginPolicy",{origins,allow_absent:allowAbsent})));
  // CBOR includes the text-length head; UTF-8 order reverses this pair.
  assert.doesNotThrow(() => policy(["https://z", "https://aa"]));
  assert.throws(() => policy(["https://aa", "https://z"]), /item_order/u);
  assert.throws(() => policy(["https://z", "https://z"]), /item_order/u);
  assert.throws(() => policy(["https://a:443"],true), /origin_default_port/u);
  const host = ["a".repeat(63),"b".repeat(63),"c".repeat(63),"d".repeat(61)].join(".");
  assert.equal(host.length,253);
  const origins = Array.from({length:8},(_,i) => "https://" + host + ":" + (65528+i));
  assert.equal(origins[0].length,267);
  const maximum = encodeCBOR(policy(origins));
  assert.equal(maximum.length, 1 + 2 + 8 * (3 + 267) + 2);
  assert.equal(maximum.length,schema.frame_maps.OriginPolicy.max_encoded_bytes);
  assert.throws(() => policy([...origins,origins[0]]), /map_size/u);
  assert.throws(() => policy(Array.from({length:9},(_,i) => "https://a"+i)), /array_length/u);
  const invalidFormat = structuredClone(schema);
  invalidFormat.frame_maps.OriginPolicy.fields[0].items.text_format = "constructor";
  assert.throws(() => verifySchema(invalidFormat), /unknown text format/u);
  const invalidOrdering = structuredClone(schema);
  invalidOrdering.map_rules.OriginPolicy[0].field = "allow_absent";
  assert.throws(() => verifySchema(invalidOrdering), /canonical ordering requires an array/u);
});

test("TLS policy variants retain signed assurance and exact digest ordering", () => {
  const {schema,files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const vector = id => corpus.vectors.find(item => item.id === id);
  const policy = decodeMap(schema,"TLSPolicy",Buffer.from(vector("tls_policy_pin").hex,"hex"));
  const fieldID = name => BigInt(Object.entries(schema.frame_maps.TLSPolicy.fields).find(([,field]) => field.name === name)[0]);
  policy.delete(fieldID("require_consumer_tls13_verification"));
  assert.throws(() => validateMap(schema,"TLSPolicy",policy), /missing_field/u);
  assert.doesNotThrow(() => decodeMap(schema,"TLSPolicy",Buffer.from(vector("tls_policy_ca").hex,"hex")));
  // Four-field map, two two-byte scalar pairs, a kind pair, a pin-array
  // key/header, then sixteen 73-byte pins at their widest uint64 encoding.
  assert.equal(vector("tls_policy_encoding_maximum").hex.length / 2, 1 + 4 + 2 + 2 + 16 * 73);
  for (const item of corpus.vectors.filter(item => item.schema === "TLSPin" || item.schema === "TLSPolicy")) {
    if (item.expected_error) assert.throws(() => decodeMap(schema,item.schema,Buffer.from(item.hex,"hex")), error => error.code === item.expected_error, item.id);
  }
  const badOrdering = structuredClone(schema);
  badOrdering.map_rules.TLSPolicy.at(-1).item_field_id = 1;
  assert.throws(() => verifySchema(badOrdering), /ordered item field must be bytes/u);
});

test("ordered byte sets and durations retain exact uint64 semantics", () => {
  const {schema} = buildArtifacts();
  schema.frame_maps.OrderedWindow = {fields:{
    0:{name:"start",type:"uint64"},1:{name:"end",type:"uint64"},
    2:{name:"digests",type:"array",min_items:1,max_items:16,items:{type:"bytes",length:32}},
  },required:[0,1,2]};
  schema.map_rules.OrderedWindow = [
    {op:"max_difference",left:"start",right:"end",max:100},
    {op:"increasing_bytes",field:"digests"},
  ];
  verifySchema(schema);
  const first = Buffer.alloc(32), next = Buffer.alloc(32); next[31] = 1;
  const start = (1n << 64n) - 101n;
  const validate = (end,digests=[first,next]) => validateMap(schema,"OrderedWindow",new Map([[0n,start],[1n,end],[2n,digests]]));
  assert.doesNotThrow(() => validate(start + 100n));
  assert.throws(() => validate(start - 1n), /field_duration/u);
  assert.throws(() => validate(start + 101n), /integer_range/u);
  assert.throws(() => validate(start,[first,first]), /item_order/u);
  assert.throws(() => validate(start,[next,first]), /item_order/u);
  schema.map_rules.OrderedWindow[0].max = 99;
  assert.throws(() => validate(start + 100n), /field_duration/u);
  schema.map_rules.OrderedWindow[1].item_field_id = 0;
  assert.throws(() => verifySchema(schema), /ordered item requires a map/u);
});

test("text vectors bind exact outputs and all fixed Unicode inputs",()=>{
  const {schema,files}=buildArtifacts(),corpus=JSON.parse(files.get("testdata/transport_v4/text.json"));
  for(const mutate of [
    value=>{value.vectors[0].output="different.example";},
    value=>{value.vectors[0].utf8_hex="00";},
    value=>{value.vectors[0].operation="constructor";},
    value=>{value.vectors[0].expected_error="idna_validity";delete value.vectors[0].output;delete value.vectors[0].utf8_hex;},
    value=>{value.vectors.push({...value.vectors[0]});},
  ]){const changed=structuredClone(corpus);mutate(changed);assert.throws(()=>verifyTextCorpus(changed,schema));}
  for(const name of ["normalization_sources.json","normalization_generated.json","idna_sources.json","idna_generated.json"])
    isolatedArtifacts(root=>{
      const target=path.join(root,"testdata/unicode15_1",name);fs.appendFileSync(target," ");
      assert.throws(()=>buildArtifacts(root),/Unicode input drift/u);
      fs.unlinkSync(target);assert.throws(()=>buildArtifacts(root),/ENOENT/u);
    });
});

test("v4 tooling preserves uint64 values across every encoding-width boundary", () => {
  for (const [decimal, hex] of [
    ["0","00"], ["23","17"], ["24","1818"], ["255","18ff"], ["256","190100"],
    ["65535","19ffff"], ["65536","1a00010000"], ["4294967295","1affffffff"],
    ["4294967296","1b0000000100000000"], ["9007199254740991","1b001fffffffffffff"],
    ["9007199254740992","1b0020000000000000"], ["9223372036854775807","1b7fffffffffffffff"],
    ["9223372036854775809","1b8000000000000001"], ["18446744073709551615","1bffffffffffffffff"],
  ]) {
    assert.equal(encodeCBOR(BigInt(decimal)).toString("hex"), hex);
    assert.equal(decodeCBOR(Buffer.from(hex, "hex")), BigInt(decimal));
  }
  assert.throws(() => encodeCBOR(2 ** 53), /unsafe_integer/u);
  assert.throws(() => encodeCBOR(1n << 64n), /integer_range/u);
  assert.throws(() => encodeCBOR(-1), /integer_range/u);
});

test("canonical parser rejects malformed CBOR before building maps", () => {
  for (const [hex, code] of [
    ["1800","non_shortest_integer"], ["1900ff","non_shortest_integer"], ["1a0000ffff","non_shortest_integer"],
    ["1b00000000ffffffff","non_shortest_integer"], ["5bffffffffffffffff","truncated"],
    ["9bffffffffffffffff","array_limit"], ["a200000001","duplicate_key"], ["a201000000","map_order"],
    ["a1613000","field_id_type"], ["a119ffff00ff","trailing_bytes"], ["bf0000ff","indefinite_length"],
    ["7f6161ff","indefinite_length"], ["62c080","invalid_utf8"], ["63eda080","invalid_utf8"],
    ["c000","unsupported_type"], ["fa00000000","unsupported_type"], ["f6","unsupported_type"],
    ["20","unsupported_type"], ["81818181818181818100","depth_limit"],
  ]) assert.throws(() => decodeCBOR(Buffer.from(hex, "hex")), (err) => err.code === code, hex);
  assert.throws(() => encodeCBOR(new Map([[0,0], [0n,1]])), /duplicate_key/u);
  assert.equal(encodeCBOR("\u00e9").toString("hex"),"62c3a9");
  assert.throws(() => encodeCBOR("e\u0301"), /non_canonical_text/u);
  assert.throws(() => decodeCBOR(Buffer.from("6365cc81","hex")),/non_canonical_text/u);
  assert.throws(() => encodeCBOR(String.fromCodePoint(0x1cc00)),/unassigned_code_point/u);
});

test("draft vectors exercise field validators and digest derivations", () => {
  const {schema, files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  verifyCorpus(schema, corpus);
  assert.ok(corpus.vectors.some((v) => v.expected_error === "variant_required"));
  assert.ok(corpus.vectors.some((v) => v.expected_error === "scope_order"));
  // A negative descriptor without actual failing bytes must fail the validator.
  corpus.vectors.find((v) => v.id === "duplicate").hex = corpus.vectors.find((v) => v.id === "ping_payload").hex;
  assert.throws(() => verifyCorpus(schema, corpus), /expected duplicate_key, got accepted/u);
  const originalCorpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const open = originalCorpus.vectors.find((v) => v.id === "open_fields");
  open.hex = open.hex.slice(0, -64) + "00".repeat(32);
  assert.throws(() => verifyCorpus(schema, originalCorpus), /open_digest_mismatch/u);
  // Registered numeric error codes are accepted; unknown values are rejected.
  const error = mapFromNames(schema, "ERROR", {code:7, target_scope:0});
  assert.doesNotThrow(() => validateMap(schema, "ERROR", decodeCBOR(encodeCBOR(error))));
  const unknownError = mapFromNames(schema, "ERROR", {code:65535, target_scope:0});
  assert.throws(() => validateMap(schema, "ERROR", decodeCBOR(encodeCBOR(unknownError))), /enum_value/u);
  assert.equal(schema.resource_caps.scope_id.max, "9223372036854775807");
  assert.deepEqual(schema.resource_caps.max_pending_open_rule, {operator:"min", arguments:[128,"signed.max_streams"]});
});

test("malformed hex cannot silently become a valid byte string", () => {
  const {schema, files} = buildArtifacts();
  for (const hex of ["0", "zz", "00 ", "0x00", "00".repeat(16) + "not hex"]) {
    assert.throws(() => strictHex(hex), /invalid_hex/u);
    assert.throws(() => mapFromNames(schema, "PING", {nonce:{$bytes:hex}}), /invalid_hex/u);
  }
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  corpus.vectors[0].hex += "not hex";
  assert.throws(() => verifyCorpus(schema, corpus), /invalid_hex/u);
});

test("terminal and credit proofs reject contradictory authenticated frontiers", () => {
  const {schema, files} = buildArtifacts();
  assert.throws(() => decodeMap(schema, "STREAM_ACK_CREDIT", Buffer.from("a500000101020003020401", "hex")), /field_order/u);
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const terminal = decodeMap(schema, "STREAM_ACK_DRAINED", Buffer.from(corpus.vectors.find((v) => v.id === "drained_fields").hex, "hex"));
  assert.notEqual(terminal.get(3n), terminal.get(5n));
  assert.deepEqual(terminal.get(3n), terminal.get(5n));
  terminal.get(5n).set(2n, 63n);
  assert.throws(() => validateMap(schema, "STREAM_ACK_DRAINED", terminal), /field_equality/u);
  assert.throws(() => validateMap(schema, "terminal_tuple", new Map([[0n,0n],[1n,-1n],[2n,0n]])), /integer_range/u);
});

test("handshake structures retain exact embedded bytes and require their original source context", () => {
  const {schema, files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const vector = (id) => corpus.vectors.find((v) => v.id === id);
  const fsb = vector("fsb_fields"), bytes = Buffer.from(fsb.hex, "hex");
  const value = decodeMap(schema, "FSB4", bytes, fsb.limits);
  assert.equal(encodeCBOR(value).toString("hex"), fsb.hex);
  const cert = decodeMap(schema, "IdentityCertificate", value.get(14n));
  assert.deepEqual(encodeCBOR(cert), value.get(14n));
  assert.throws(() => decodeMap(schema, "FSB4", bytes), /context_unresolved/u);
  assert.throws(() => decodeMap(schema, "FSB4", bytes, {activation_source_profile:"preauthorized_pool"}), /map_type/u);
  const pool = vector("activation_pool_fields");
  assert.throws(() => decodeMap(schema, "ActivationAuthorization", Buffer.from(pool.hex, "hex"), {activation_source_profile:"live_authority"}), /field_type/u);
  assert.throws(() => decodeMap(schema, "ClientHello", Buffer.alloc(16385)), /map_size/u);
  assert.equal(Buffer.from(vector("ready_fields").hex,"hex").length, 103);
  assert.equal(Buffer.from(vector("hop_context_fields").hex,"hex").length, 129);
  assert.equal(Buffer.from(vector("rekey_commit_fields").hex,"hex").length, 107);
  assert.equal(Buffer.from(vector("rekey_ack_fields").hex,"hex").length, 107);
});

test("negative map mutations preserve wide headers and isolate the intended violation", () => {
  for (const count of [1,23,24,25,127]) for (const firstID of [0,24,256]) {
    const map = new Map(Array.from({length:count}, (_,i) => [BigInt(firstID+i),0n]));
    const seeds = new Map([["seed",{bytes:encodeCBOR(map),plan:{schema:"test"}}]]);
    const schema = {frame_maps:{test:{fields:Object.fromEntries([...map.keys()].map(id => [id.toString(),{name:`field_${id}`,type:"uint64"}]))}}};
    const mutations = [["duplicate_first_pair","duplicate_key"],["overlong_first_key","non_shortest_integer"],["text_first_key","field_id_type"],["indefinite_map","indefinite_length"]];
    if (count > 1) mutations.push(["reverse_pairs","map_order"]);
    for (const [mutation, error] of mutations) {
      const result = malformed(schema, {id:mutation,source:"seed",mutation,error}, seeds);
      assert.throws(() => decodeCBOR(Buffer.from(result.hex,"hex")), (err) => err.code === error, `${count}/${firstID}/${mutation}`);
    }
  }
});

test("schema audit follows embedded and contextual references and rejects ignored attributes", () => {
  const {schema} = buildArtifacts();
  verifySchema(schema);
  const unknown = structuredClone(schema);
  unknown.frame_maps.ClientHello.fields[10].max_byes = 2048;
  assert.throws(() => verifySchema(unknown), /unknown field attribute/u);
  const dangling = structuredClone(schema);
  dangling.frame_maps.FSB4.fields[14].encoded_schema_ref = "MissingCertificate";
  assert.throws(() => verifySchema(dangling), /dangling encoded_schema_ref/u);
  const contextual = structuredClone(schema);
  contextual.frame_maps.ActivationAuthorization.fields[7].cases.preauthorized_pool.schema_ref = "MissingPool";
  assert.throws(() => verifySchema(contextual), /dangling schema_ref/u);
  const cycle = structuredClone(schema);
  cycle.frame_maps.IdentityCertificate.fields[4].encoded_schema_ref = "IdentityCertificate";
  assert.throws(() => verifySchema(cycle), /recursive schema/u);
  const pathDrift = structuredClone(schema);
  pathDrift.map_rules.FSB4[0].field = "client_certificate.missing_role";
  assert.throws(() => verifySchema(pathDrift), /unresolved rule field/u);
  const ignored = structuredClone(schema);
  ignored.frame_maps.ClientHello.fields[10].pattern_ref = "security_id";
  assert.throws(() => verifySchema(ignored), /unknown field attribute/u);
  const ruleTypo = structuredClone(schema);
  ruleTypo.map_rules.FSA4[1].constans = {code:0};
  assert.throws(() => verifySchema(ruleTypo), /unknown rule attribute/u);
  const droppedRelation = structuredClone(schema);
  const drainedRule = droppedRelation.map_rules.STREAM_ACK_DRAINED[0];
  drainedRule.equals = drainedRule.equal;
  delete drainedRule.equal;
  assert.throws(() => verifySchema(droppedRelation), /unknown rule attribute/u);
  const mapTypo = structuredClone(schema);
  mapTypo.frame_maps.READY.encoded_byes = mapTypo.frame_maps.READY.encoded_bytes;
  delete mapTypo.frame_maps.READY.encoded_bytes;
  assert.throws(() => verifySchema(mapTypo), /unknown map attribute/u);
});

test("every structural seed rejects removed required fields, wrong types and unknown keys", () => {
  const {schema, files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  for (const vector of corpus.vectors.filter((v) => v.schema && !v.expected_error)) {
    const definition = schema.frame_maps[vector.schema];
    const original = decodeCBOR(Buffer.from(vector.hex,"hex"), {schema,name:vector.schema,limits:vector.limits});
    const rejects = (value, mutation) => {
      // Construct malformed bytes outside the assertion so an encoder failure
      // cannot stand in for the decoder's required rejection.
      const encoded = encodeMap(schema,vector.schema,value,vector.limits);
      assert.throws(() => decodeMap(schema,vector.schema,encoded,vector.limits), (err) => typeof err.code === "string", `${vector.id}/${mutation}`);
    };
    for (const id of definition.required) {
      const changed = new Map(original); changed.delete(BigInt(id));
      rejects(changed,`missing_${id}`);
    }
    for (const [id, value] of original) {
      const changed = new Map(original); changed.set(id,typeof value === "boolean" ? 0n : false);
      rejects(changed,`type_${id}`);
    }
    const changed = new Map(original); changed.set(65535n,0n);
    rejects(changed,"unknown_key");
  }
});

test("domain corpus pins exact primitive results and distinguishes external labels", () => {
  const {schema,files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/domains.json"));
  verifyDomainCorpus(schema,corpus);
  const vector = (name) => corpus.vectors.find((v) => v.id === `domain_${name}`);
  const wt = vector("tls_exporter_wt");
  assert.equal(wt.result.label_hex,Buffer.from("EXPORTER-WebTransport","ascii").toString("hex"));
  assert.equal(wt.result.input_hex,"002000000000000415" + Buffer.from("EXPORTER-flowersec-v4","ascii").toString("hex") + "20" + "34".repeat(32));
  assert.equal(wt.result.input_hex.length,126);
  assert.equal(wt.result.output_hex,undefined);
  const raw = vector("tls_exporter_raw");
  assert.equal(raw.result.input_hex,"34".repeat(32));
  assert.equal(raw.result.label_hex,Buffer.from("EXPORTER-flowersec-v4","ascii").toString("hex"));
  const prologue = Buffer.from(vector("noise_prologue").result.input_hex,"hex");
  const prefix = Buffer.from("flowersec/v4/noise-prologue\0\0\0\0\x014","ascii");
  assert.ok(prologue.subarray(0,prefix.length).equals(prefix));
  const initial = vector("initial_root");
  assert.notEqual(initial.result.output_hex,vector("initial_root_p256").result.output_hex);
  const extract = vector("rekey_extract");
  assert.equal(extract.result.input_hex,"");
  assert.equal(extract.result.label_hex,"");
  assert.equal(extract.result.salt_hex,"46".repeat(32));
  assert.equal(extract.result.ikm_hex,"39".repeat(32));
  initial.result.output_hex = "00".repeat(32);
  assert.throws(() => verifyDomainCorpus(schema,corpus),/domain vector drift/u);
});

test("signing projections preserve embedded signatures and full-message digests", () => {
  const {schema,files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/domains.json"));
  const seed = corpus.vectors.find((v) => v.id === "domain_fsb_signature");
  const args = domainArguments(seed.inputs), original = Buffer.from(args.fsb);
  const run = (name,fsb) => evaluateDomain(schema,name,{fsb},seed.context);
  const message = decodeCBOR(args.fsb);
  message.set(15n,Buffer.alloc(64,0x55));
  const changedSignature = encodeCBOR(message);
  assert.deepEqual(run("fsb_signature",changedSignature),run("fsb_signature",original));
  assert.notEqual(run("fsb_digest",changedSignature).output_hex,run("fsb_digest",original).output_hex);
  assert.notEqual(run("admission_binding",changedSignature).output_hex,run("admission_binding",original).output_hex);
  const certificate = decodeCBOR(message.get(14n));
  certificate.set(16n,Buffer.alloc(64,0x56)); message.set(14n,encodeCBOR(certificate));
  assert.notEqual(run("fsb_signature",encodeCBOR(message)).input_hex,run("fsb_signature",original).input_hex);
  assert.deepEqual(args.fsb,original);
  message.delete(15n);
  assert.throws(() => run("fsb_signature",encodeCBOR(message)),/missing_field/u);
  // Projection is never a way to accept an unknown key or trailing bytes.
  assert.throws(() => run("fsb_signature",Buffer.concat([original,Buffer.from([0])])),/trailing_bytes/u);
});

test("rekey phase MAC excludes only its own MAC while transcript includes it", () => {
  const {schema,files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/domains.json"));
  const seed = corpus.vectors.find((v) => v.id === "domain_rekey_confirm_mac");
  const args = domainArguments(seed.inputs), original = Buffer.from(args.message);
  const run = (message) => evaluateDomain(schema,seed.domain,{...args,message},seed.context);
  const init = decodeCBOR(args.message); init.set(5n,Buffer.alloc(32,0x61));
  assert.deepEqual(run(encodeCBOR(init)),run(original));
  const digestSeed = corpus.vectors.find((v) => v.id === "domain_rekey_init_digest");
  const digestArgs = domainArguments(digestSeed.inputs);
  assert.notEqual(evaluateDomain(schema,digestSeed.domain,{...digestArgs,init:encodeCBOR(init)},digestSeed.context).output_hex,digestSeed.result.output_hex);
  init.get(4n)[0].set(1n,3n);
  assert.notEqual(run(encodeCBOR(init)).output_hex,run(original).output_hex);
  assert.deepEqual(args.message,original);
  for (const phase of [3,4]) {
    const marker = corpus.vectors.find((v) => v.id === `domain_rekey_confirm_mac_phase${phase}`);
    const markerArgs = domainArguments(marker.inputs), map = decodeCBOR(markerArgs.message);
    map.set(4n,map.get(4n)-1n);
    assert.notEqual(evaluateDomain(schema,marker.domain,{...markerArgs,message:encodeCBOR(map)},marker.context).output_hex,marker.result.output_hex);
  }
});

test("domain validation rejects malformed definitions and untyped argument coercions", () => {
  const {schema,files} = buildArtifacts();
  verifyDomains(schema);
  const mutate = (name,change,pattern) => {
    const candidate = structuredClone(schema); change(candidate.domains.find((v) => v.name === name));
    assert.throws(() => verifyDomains(candidate),pattern);
  };
  mutate("initial_root",d => { d.input_schema.prk=d.input_schema.key; delete d.input_schema.key; },/unknown attribute/u);
  mutate("certificate_digest",d => { d.operation=["sha256"]; },/string/u);
  mutate("record_key",d => { d.input_schema.parts.find(p => p.name === "direction").encoding=["u8"]; },/string/u);
  mutate("initial_root",d => { d.label_bytes += "00"; },/one NUL/u);
  mutate("initial_root",d => { d.label_bytes += "0a"; },/one NUL/u);
  mutate("initial_root",d => { d.label_bytes = schema.domains.find(v => v.name === "certificate_digest").label_bytes; },/duplicate domain label/u);
  mutate("initial_root",d => { d.input_schema.parts[0].text_enum_ref="absent"; },/assertion|false == true/iu);
  mutate("rekey_confirm_mac",d => { d.input_schema.parts.at(-1).schema_cases[1]="Missing"; },/dangling map/u);
  mutate("certificate_digest",d => { d.input_schema.parts[0].schema_ref="constructor"; },/dangling map/u);
  mutate("rekey_confirm_mac",d => { d.input_schema.parts.at(-1).schema_cases[1]=["REKEY_INIT"]; },/assertion|false == true/iu);
  mutate("rekey_confirm_mac",d => { d.input_schema.parts.at(-1).projection="unsigned"; },/assertion|false == true/iu);
  mutate("rekey_root",d => { d.input_schema.relations[0].rigth=d.input_schema.relations[0].right; },/unknown attribute/u);
  for (const value of [null,false,""]) {
    mutate("initial_root",d => { d.input_schema.key=value; },/invalid input part/u);
    mutate("rekey_extract",d => { d.input_schema.salt=value; },/invalid input part/u);
    mutate("rekey_extract",d => { d.input_schema.ikm=value; },/invalid input part/u);
    mutate("record_key",d => { d.input_schema.parts.find(p => p.name === "direction").enum=value; },/assertion|false == true/iu);
    mutate("initial_root",d => { d.input_schema.parts[0].text_enum_ref=value; },/assertion|false == true/iu);
    mutate("rekey_confirm_key",d => { d.input_schema.relations=value; },/assertion|false == true/iu);
    mutate("rekey_confirm_mac",d => { d.input_schema.parts.at(-1).bindings=value; },/assertion|false == true/iu);
    mutate("rekey_confirm_key",d => { d.input_schema.relations[1].pairs=value; },/assertion|false == true/iu);
  }
  const corpus = JSON.parse(files.get("testdata/transport_v4/domains.json"));
  const seed = corpus.vectors.find((v) => v.id === "domain_record_key"), args=domainArguments(seed.inputs);
  for (const sequence_scope of ["1",true,1.5,Number.MAX_SAFE_INTEGER+1,-1n,1n<<64n]) assert.throws(() => evaluateDomain(schema,seed.domain,{...args,sequence_scope}),/domain_integer/u);
  assert.throws(() => evaluateDomain(schema,seed.domain,{...args,profile:"unknown"}),/domain_enum/u);
  assert.throws(() => evaluateDomain(schema,seed.domain,{...args,epoch_root:new Uint8Array(32)}),/domain_bytes_type/u);
});

test("retirement digest binds exact final handshake, profile, proposer and complete batch bytes", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/domains.json"));
  const cases=corpus.vectors.filter(v=>v.domain==="retirement_batch_digest" && !v.expected_error);
  assert.equal(cases.length,6);
  const lp = bytes => { const prefix=Buffer.alloc(4); prefix.writeUInt32BE(bytes.length); return Buffer.concat([prefix,bytes]); };
  const outputs=new Set();
  for (const vector of cases) {
    const args=domainArguments(vector.inputs);
    const expected=Buffer.concat([Buffer.from("flowersec/v4/retire-batch\0","ascii"),lp(args.handshake_hash),lp(Buffer.from(args.profile,"ascii")),Buffer.from([Number(args.proposer_role)]),lp(args.batch)]);
    assert.equal(vector.result.input_hex,expected.toString("hex"));
    assert.equal(vector.result.output_hex,createHash("sha256").update(expected).digest("hex"));
    outputs.add(vector.result.output_hex);
  }
  assert.equal(outputs.size,cases.length);
  const seed=cases.find(v=>v.id==="domain_retire_client"), args=domainArguments(seed.inputs);
  const changedSequence=decodeCBOR(args.batch); changedSequence.set(1n,2n);
  const changedIDs=decodeCBOR(args.batch); changedIDs.set(2n,[1n,3n,7n]);
  for (const change of [
    {handshake_hash:Buffer.alloc(32,0x32)},
    {profile:"fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"},
    {proposer_role:1},
    {batch:encodeCBOR(changedSequence)},
    {batch:encodeCBOR(changedIDs)},
  ]) assert.notEqual(evaluateDomain(schema,seed.domain,{...args,...change}).output_hex,seed.result.output_hex);
  // The role preimage changes even for identical bytes. Authorizing that role's
  // IDs is a separate runtime obligation, not inferred from this digest probe.
  for (const epoch of [0,1,4294967295]) {
    assert.equal(evaluateDomain(schema,seed.domain,args,{epoch}).output_hex,seed.result.output_hex);
    assert.throws(()=>evaluateDomain(schema,seed.domain,{...args,epoch}),/domain_arguments/u);
  }
  assert.throws(()=>evaluateDomain(schema,seed.domain,args,{crypto_profile_id:"fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"}),/domain_context/u);
});

test("retirement map witnesses retain full uint64 widths and bounded batch cardinality", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  const vector = id => corpus.vectors.find(v=>v.id===id);
  // Map head, variant pair, sequence key/value, array key/head and full-width IDs.
  const batchBytes=1+2+1+9+1+3+1024*9, ackBytes=1+2+1+9+1+2+32;
  for (const [id,size] of [["retire_batch_single",8],["retire_batch_maximum",batchBytes],["retire_ack_fields",40],["retire_ack_maximum",ackBytes]]) {
    const v=vector(id), bytes=strictHex(v.hex);
    assert.equal(bytes.length,size);
    decodeMap(schema,v.schema,bytes);
  }
  const batch=vector("retire_batch_maximum"), map=decodeCBOR(strictHex(batch.hex));
  assert.equal(map.get(1n),(1n<<64n)-1n);
  assert.equal(map.get(2n).length,1024); assert.equal(map.get(2n).at(-1),(1n<<63n)-1n);
  assert.ok(map.get(2n).every(id=>id%2n===1n));
  assert.equal(schema.frame_maps.STREAM_ACK_RETIRE_BATCH.max_encoded_bytes,batchBytes);
  assert.equal(schema.frame_maps.STREAM_ACK_RETIRE_ACK.max_encoded_bytes,ackBytes);
  for (const [name,id] of [["STREAM_ACK_RETIRE_BATCH","retire_batch"],["STREAM_ACK_RETIRE_ACK","retire_ack_fields"]]) {
    const valid=decodeCBOR(strictHex(vector(id).hex));
    for (const [sequence,error] of [[0n,/field_range/u],[1n<<64n,/integer_range/u],[-1n,/integer_range/u]]) {
      const invalid=new Map(valid); invalid.set(1n,sequence);
      assert.throws(()=>validateMap(schema,name,invalid),error);
    }
  }
  const tooMany=vector("retire_too_many_ids");
  assert.ok(strictHex(tooMany.hex).length<batchBytes);
  assert.throws(()=>decodeMap(schema,tooMany.schema,strictHex(tooMany.hex)),/array_length/u);
});

test("retirement ACK projection carries the original batch digest without extra epoch or signature fields", () => {
  const {schema,files}=buildArtifacts(), domains=JSON.parse(files.get("testdata/transport_v4/domains.json"));
  for (const vector of domains.vectors.filter(v=>v.domain==="retirement_batch_digest" && !v.expected_error)) {
    const args=domainArguments(vector.inputs), batch=decodeCBOR(args.batch);
    const ack=mapFromNames(schema,"STREAM_ACK_RETIRE_ACK",{variant:6,batch_seq:batch.get(1n),batch_digest:strictHex(vector.result.output_hex)});
    const encoded=encodeCBOR(ack), decoded=decodeMap(schema,"STREAM_ACK_RETIRE_ACK",encoded);
    assert.deepEqual([...decoded.keys()],[0n,1n,2n]);
    assert.equal(decoded.get(1n),batch.get(1n)); assert.deepEqual(decoded.get(2n),strictHex(vector.result.output_hex));
    assert.ok(encoded.length<=48);
  }
  assert.equal(schema.frame_maps.STREAM_ACK_RETIRE_ACK.signature_field,undefined);
  assert.equal(schema.frame_maps.STREAM_ACK_RETIRE_ACK.mac_field,undefined);
});

test("error registries enforce target attribution, optional hints and normal closure", () => {
  const {schema} = buildArtifacts();
  const check = (name, values) => decodeMap(schema,name,encodeCBOR(mapFromNames(schema,name,values)));
  for (const [name,code] of Object.entries(schema.error_codes)) {
    const policy = schema.error_code_metadata[name];
    if (name === "normal") {
      assert.throws(() => check("ERROR",{code,target_scope:0}),/error_scope/u);
      for (const target_scope of [0,1,(1n<<63n)-1n]) check("CLOSE",{reason:code,target_scope});
      check("GOAWAY",{reason:code,accept_ceiling:0});
      continue;
    }
    const valid = policy.scope === "session" ? {code,target_scope:0} : {code,target_scope:3,stream_id:3};
    check("ERROR",valid);
    for (const retry_after_ms of [0,4294967295]) {
      if (policy.retryable) check("ERROR",{...valid,retry_after_ms});
      else assert.throws(() => check("ERROR",{...valid,retry_after_ms}),/retry_after_forbidden/u);
    }
    assert.throws(() => check("ERROR",{...valid,target_scope:2}),/error_scope/u);
    if (policy.scope === "session") assert.throws(() => check("ERROR",{...valid,stream_id:3}),/error_scope/u);
    else {
      delete valid.stream_id;
      assert.throws(() => check("ERROR",valid),/error_scope/u);
    }
  }
  assert.throws(() => check("CLOSE",{reason:0,target_scope:1n<<63n}),/field_range/u);
  assert.throws(() => check("ERROR",{code:65535,target_scope:0}),/enum_value/u);
  assert.throws(() => check("ERROR",{code:schema.error_codes.resource_exhausted,target_scope:0,retry_after_ms:4294967296}),/integer_range/u);
});

test("every admission and OPEN rejection retains its distinct carrier facts", () => {
  const {schema,files} = buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/errors.json"));
  const read = id => {
    const v=corpus.vectors.find(item=>item.id===id);
    const map=decodeMap(schema,v.schema,strictHex(v.hex),v.limits);
    return Object.fromEntries(Object.entries(schema.frame_maps[v.schema].fields).map(([key,field])=>[field.name,map.get(BigInt(key))]));
  };
  for (const [name,code] of Object.entries(schema.admission_rejection_codes)) {
    const rejected=read(`admission_rejected_${name}`), admitted=read("fsa_admitted_fields");
    assert.equal(rejected.status,1n); assert.equal(rejected.code,BigInt(code)); assert.equal(rejected.server_epoch,0n);
    for (const field of ["reservation_key","admission_binding","transport_context_digest","client_identity_digest","server_identity_digest"]) assert.deepEqual(rejected[field],Buffer.alloc(32));
    for (const field of Object.keys(admitted).filter(field=>!["status","code","server_epoch","reservation_key","admission_binding","transport_context_digest","client_identity_digest","server_identity_digest"].includes(field))) assert.deepEqual(rejected[field],admitted[field]);
  }
  for (const [name,code] of Object.entries(schema.open_rejection_codes)) {
    const value=read(`open_rejected_${name}`);
    assert.equal(value.result,1n); assert.equal(value.reason,BigInt(code));
    assert.equal(value.initial_receive_limit,0n); assert.equal(value.final_offset,0n);
    assert.equal(value.final_epoch,value.open_epoch); assert.equal(value.final_next_sequence,1n);
  }
});

test("error corpus rejects removed, relabeled, duplicate and corrupted evidence", () => {
  const {schema,files}=buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/errors.json"));
  verifyErrorCorpus(schema,corpus);
  for (const mutate of [
    c=>{c.design_sha256="00".repeat(32);},
    c=>{c.schema_revision="other";},
    c=>{c.vectors.pop();},
    c=>{c.vectors=c.vectors.filter(v=>!v.expected_error);},
    c=>{c.vectors.push(c.vectors[0]);},
    c=>{c.vectors[0].hex+="0";},
    c=>{c.vectors.find(v=>v.id==="error_session_protocol_violation").schema="CLOSE";},
    c=>{delete c.vectors.find(v=>v.expected_error).expected_error;},
    c=>{c.vectors.find(v=>v.id==="error_session_protocol_violation").hex=c.vectors.find(v=>v.id==="error_session_framing_error").hex;},
  ]) {
    const invalid=structuredClone(corpus); mutate(invalid);
    assert.throws(()=>verifyErrorCorpus(schema,invalid));
  }
});

test("schema audit rejects missing error rules, incomplete coverage and invalid numeric references", () => {
  const {schema}=buildArtifacts(); verifySchema(schema);
  for (const mutate of [
    s=>{s.map_rules.ERROR=[];},
    s=>{delete s.map_rules.ERROR;},
    s=>{s.map_rules.ERROR.push(s.map_rules.ERROR[0]);},
    s=>{s.map_rules.ERROR[0].when={field:"code",value:1};},
    s=>{s.error_vector_plan.pop();},
    s=>{s.error_vector_plan[1].scope="session";},
    s=>{s.error_vector_plan[0].source="accepted";},
    s=>{s.error_vector_plan[0].replace={nonexistent:1};},
    s=>{s.error_code_metadata.protocol_violation.retry="retry_same_lease";},
    s=>{s.error_code_metadata.protocol_violation.retryable="false";},
    s=>{s.error_code_metadata.protocol_violation.action="reset_stream";},
    s=>{s.error_codes.framing_error=s.error_codes.protocol_violation;},
    s=>{s.frame_maps.ERROR.fields[0].enum_ref="error_code_metadata";},
    s=>{s.map_rules.FSA4.find(rule=>rule.value===1).registered.code="admission_rejection_metadata";},
  ]) {
    const invalid=structuredClone(schema); mutate(invalid);
    assert.throws(()=>verifySchema(invalid));
  }
});

test("four generated SDK error registries preserve one schema and its qualification boundary", () => {
  const {schema,files}=buildArtifacts();
  const declarations=[
    ["flowersec-go/internal/protocolv4/registry_generated.go",/const ErrorCodeRegistryJSON = (.+)/u],
    ["flowersec-rust/src/protocol_v4_registry_generated.rs",/const ERROR_CODE_REGISTRY_JSON: &str = (.+);/u],
    ["flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift",/static let errorCodeRegistryJSON = (.+)/u],
  ];
  const registry=JSON.parse(files.get("flowersec-ts/src/generated/transportV4Registry.ts").match(/export const transportV4ErrorCodes = (.+) as const;/u)[1]);
  for (const [file,pattern] of declarations) assert.deepEqual(JSON.parse(JSON.parse(files.get(file).match(pattern)[1])),registry);
  assert.deepEqual(registry.error_registry_boundary,schema.error_registry_boundary);
  for (const name of ["ERROR","CLOSE","GOAWAY","FSA4","OPEN_ACCEPT"]) {
    assert.deepEqual(registry.frame_maps[name],schema.frame_maps[name]);
    assert.deepEqual(registry.map_rules[name],schema.map_rules[name] ?? []);
  }
});

test("traceability distinguishes future obligations from real schema and vector references", () => {
  const trace = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "stability/transport_v4_traceability.json")));
  const {schema, manifest} = buildArtifacts();
  verifyTraceability(trace, schema, manifest);
  const invalid = structuredClone(trace);
  invalid.entries[0].registry_refs = ["/frame_maps/MISSING"];
  assert.throws(() => verifyTraceability(invalid, schema, manifest), /unresolved registry reference/u);
  invalid.entries[0].registry_refs = [];
  invalid.entries[0].vector_ids = ["unexecuted_future_vector"];
  assert.throws(() => verifyTraceability(invalid, schema, manifest), /missing vector/u);
  invalid.entries[0].vector_ids = [];
  invalid.entries[1].required_test_ids = invalid.entries[0].required_test_ids;
  assert.throws(() => verifyTraceability(invalid, schema, manifest), /duplicate required test ID/u);
});

function isolatedArtifacts(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-v4-tooling-"));
  try {
    for (const file of ["stability/transport_v4_schema.json", "stability/transport_v4_contract.json", "stability/transport_v4_traceability.json", "docs/TRANSPORT_V4_BINDING.md", "testdata/unicode15_1/normalization_sources.json", "testdata/unicode15_1/normalization_generated.json", "testdata/unicode15_1/idna_sources.json", "testdata/unicode15_1/idna_generated.json"]) {
      const target = path.join(root, file); fs.mkdirSync(path.dirname(target), {recursive:true});
      fs.copyFileSync(path.join(repositoryRoot,file), target);
    }
    const {files} = buildArtifacts(root);
    for (const [file, content] of files) {
      const target = path.join(root, file); fs.mkdirSync(path.dirname(target), {recursive:true}); fs.writeFileSync(target, content);
    }
    const trace = JSON.parse(fs.readFileSync(path.join(root,"stability/transport_v4_traceability.json")));
    for (const entry of trace.entries) for (const file of [entry.artifact, ...entry.tests].filter(Boolean)) {
      const target = path.join(root,file);
      if (!fs.existsSync(target)) { fs.mkdirSync(path.dirname(target), {recursive:true}); fs.copyFileSync(path.join(repositoryRoot,file),target); }
    }
    run(root);
  } finally { fs.rmSync(root, {recursive:true}); }
}

test("--check never repairs changed, absent, or unexpected generated files", () => isolatedArtifacts((root) => {
  const corpus = path.join(root,"testdata/transport_v4/corpus.json"), original = fs.readFileSync(corpus);
  checkArtifacts(root);
  fs.writeFileSync(corpus, "tampered\n");
  const before = fs.statSync(corpus).mtimeMs;
  assert.throws(() => checkArtifacts(root), /artifact drift/u);
  assert.equal(fs.readFileSync(corpus,"utf8"), "tampered\n");
  assert.equal(fs.statSync(corpus).mtimeMs, before);
  fs.unlinkSync(corpus);
  assert.throws(() => checkArtifacts(root), /artifact drift/u);
  assert.equal(fs.existsSync(corpus), false);
  fs.writeFileSync(corpus, original);
  const unexpected = path.join(root,"testdata/transport_v4/unregistered.json"); fs.writeFileSync(unexpected, "{}\n");
  assert.throws(() => checkArtifacts(root), /unexpected vector artifact/u);
  assert.equal(fs.readFileSync(unexpected,"utf8"), "{}\n"); fs.unlinkSync(unexpected);
  fs.appendFileSync(path.join(root,"flowersec-go/internal/protocolv4/registry_generated.go"), "// drift\n");
  assert.throws(() => checkArtifacts(root), /artifact drift/u);
}));

test("binding gate requires exact external artifacts and does not invent missing evidence", () => isolatedArtifacts((root) => {
  // Test-only pin. No synthetic review is written into the real binding.
  const contractPath = path.join(root, "stability/transport_v4_contract.json");
  const contract = JSON.parse(fs.readFileSync(contractPath));
  contract.design.review_evidence_status = "pinned";
  contract.design.review_evidence_sha256 = "00".repeat(32);
  fs.writeFileSync(contractPath, JSON.stringify(contract));
  fs.appendFileSync(path.join(root, "docs/TRANSPORT_V4_BINDING.md"), contract.design.review_evidence_sha256);
  const options = {root, designPath:path.join(root,"missing-design.md"), evidencePath:path.join(root,"missing-evidence.md")};
  assert.deepEqual(verifyBinding(options).external, {design:"missing", review_evidence:"missing"});
  assert.throws(() => verifyBinding({...options, requireExternal:true}), /required design unavailable/u);
  const designPath = path.resolve(repositoryRoot, "../flowersec-v4-transport-security-design.zh-CN.md");
  if (fs.existsSync(designPath)) assert.throws(() => verifyBinding({...options, designPath, requireExternal:true}), /required review_evidence unavailable/u);
  fs.writeFileSync(options.designPath, "incorrect design\n");
  assert.throws(() => verifyBinding(options), /external design SHA changed/u);
  assert.equal(fs.readFileSync(options.designPath,"utf8"), "incorrect design\n");
  fs.unlinkSync(options.designPath);
  contract.design.review_evidence_status = "pending_independent_review";
  contract.design.review_evidence_sha256 = null;
  fs.writeFileSync(contractPath, JSON.stringify(contract));
  assert.deepEqual(verifyBinding(options).external, {design:"missing", review_evidence:"unbound"});
  if (fs.existsSync(designPath)) assert.throws(() => verifyBinding({...options, designPath, requireExternal:true}), /has no verified evidence binding/u);
}));

test("binding gate rejects documentation schema revision drift", () => isolatedArtifacts(root => {
  const file=path.join(root,"docs/TRANSPORT_V4_BINDING.md"), binding=fs.readFileSync(file,"utf8");
  verifyBinding({root});
  fs.writeFileSync(file,binding.replace(/\| Schema revision \|[^\n]+/u,"| Schema revision | `outdated` |"));
  assert.throws(()=>verifyBinding({root}),/binding document schema revision drift/u);
}));

test("architecture evidence requires seven distinct same-round reports signing the exact design", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-v4-review-test-"));
  try {
    const designSHA = "12".repeat(32), round = "test-fixture", evidencePath = path.join(root, "evidence.json");
    const reviews = architectureReviewLanes.map((lane) => {
      const report = `SIGNABLE ${designSHA}\nBefore SHA: ${designSHA}\nAfter SHA: ${designSHA}\nRound: ${round}\nReviewer: /root/test_${lane}\nLane: ${lane}\nSynthetic test fixture; not qualification evidence.\n`;
      fs.writeFileSync(path.join(root, `${lane}.md`), report);
      return {lane, reviewer:`/root/test_${lane}`, round, design_before_sha256:designSHA, design_after_sha256:designSHA, verdict:"SIGNABLE", path:`${lane}.md`, sha256:digest(report)};
    });
    const evidence = {format_version:1, design_sha256:designSHA, round, qualification:"architecture_only", reviews};
    const check = (value) => { fs.writeFileSync(evidencePath, JSON.stringify(value)); return verifyArchitectureReviews(evidencePath, designSHA); };
    assert.deepEqual(check(evidence), {round, reviews:7, qualification:"architecture_only"});
    assert.throws(() => check({...evidence, reviews:reviews.slice(0, 3)}), /seven independent reviews required/u);
    for (const [change, error] of [
      [{lane:"crypto"}, /review lane coverage differs/u],
      [{round:"old-round"}, /review round differs/u],
      [{design_before_sha256:"34".repeat(32)}, /review before SHA differs/u],
      [{design_after_sha256:"34".repeat(32)}, /review after SHA differs/u],
      [{verdict:"NOT_SIGNABLE"}, /architecture blocker/u],
      [{path:"../outside.md"}, /invalid external report path/u],
      [{path:"missing.md"}, /review report unavailable/u],
      [{sha256:"00".repeat(32)}, /review report SHA changed/u],
    ]) assert.throws(() => check({...evidence, reviews:[{...reviews[0], ...change}, ...reviews.slice(1)]}), error);
    assert.throws(() => check({...evidence, reviews:[reviews[0], {...reviews[1], reviewer:reviews[0].reviewer}, ...reviews.slice(2)]}), /reviewer reused/u);
    // An index cannot relabel the round, reviewer or lane of a real report.
    const firstPath = path.join(root, reviews[0].path), firstReport = fs.readFileSync(firstPath, "utf8");
    for (const [from, to] of [
      [`Round: ${round}`, "Round: previous-round"],
      ["Reviewer: /root/test_protocol", "Reviewer: /root/another_reviewer"],
      ["Lane: protocol", "Lane: crypto"],
      [`Round: ${round}`, `Round: ${round}\nRound: ${round}`],
    ]) {
      const report = firstReport.replace(from, to);
      fs.writeFileSync(firstPath, report);
      assert.throws(() => check({...evidence, reviews:[{...reviews[0], sha256:digest(report)}, ...reviews.slice(1)]}), /missing or ambiguous/u);
    }
    fs.writeFileSync(firstPath, firstReport);
    const secondPath = path.join(root, reviews[1].path), secondReport = fs.readFileSync(secondPath, "utf8");
    fs.writeFileSync(secondPath, firstReport);
    assert.throws(() => check({...evidence, reviews:[reviews[0], {...reviews[1], sha256:reviews[0].sha256}, ...reviews.slice(2)]}), /report content reused/u);
    fs.writeFileSync(secondPath, secondReport);
    // Matching file hashes alone cannot convert a rejection or an old-SHA vote.
    for (const report of [
      `NOT_SIGNABLE ${designSHA}\nBefore SHA: ${designSHA}\nAfter SHA: ${designSHA}\n`,
      `SIGNABLE ${designSHA}\nBefore SHA: ${designSHA}\nAfter SHA: ${"34".repeat(32)}\n`,
      `${firstReport}NOT_SIGNABLE ${designSHA}\n`,
    ]) {
      fs.writeFileSync(path.join(root, reviews[0].path), report);
      assert.throws(() => check({...evidence, reviews:[{...reviews[0], sha256:digest(report)}, ...reviews.slice(1)]}), /missing or ambiguous|conflicting verdict/u);
      assert.equal(fs.readFileSync(path.join(root, reviews[0].path), "utf8"), report);
    }
  } finally { fs.rmSync(root, {recursive:true}); }
});

import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { decodeMap, encodeCBOR, mapFromNames, VectorError } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";
import { verifyContractTargets, verifyContractSnapshots } from "./transport-v4-contract-query.mjs";
import { verifyQueryCorpus } from "./transport-v4-contract-query-vectors.mjs";

function fixture() {
  const {schema,files}=buildArtifacts(),corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json")),queries=JSON.parse(files.get("testdata/transport_v4/queries.json"));
  return {schema,corpus,queries,bytes:id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex")};
}
const digest=(schema,bytes)=>Buffer.from(evaluateDomain(schema,"service_contract_digest",{contract:bytes}).output_hex,"hex");
const one=(schema,item)=>encodeCBOR(mapFromNames(schema,"ContractSnapshots",{items:[item]}));
const target=(schema,values)=>encodeCBOR(mapFromNames(schema,"ContractTargets",{targets:[{service_namespace:"acme/files",method_type_id:1,...values}]}));
const offer=(schema,contract,start=0n,end=60000n)=>encodeCBOR(new Map([[0n,digest(schema,contract)],[1n,start],[2n,end]]));
const b=bytes=>({$bytes:bytes.toString("hex")});
const variants=["unary_transient","unary_execution","stream_transient","stream_execution","notify_observation","notify_execution"];

test("contract queries match six full/unchanged variants to owned original complete bodies",()=>{
  const {schema,bytes}=fixture();
  for(const suffix of variants) {
    const contract=bytes("service_"+suffix),execution=suffix.endsWith("_execution"),options={offerWindowLimits:[execution?60000n:null]};
    const fullBytes=bytes("contract_snapshots_full_"+suffix),full=verifyContractSnapshots(schema,bytes("contract_targets_plain"),fullBytes,options)[0];
    assert.deepEqual(full.contract_bytes,contract);
    assert.deepEqual(full.contract_digest,digest(schema,contract));
    assert.equal(full.status,"available_full");assert.equal(full.target_index,0);
    assert.deepEqual(full.offer,execution?{not_before_ms:0n,not_after_ms:60000n}:null);
    const known=Buffer.from(contract),unchanged=verifyContractSnapshots(schema,bytes("contract_targets_known_"+suffix),bytes("contract_snapshots_unchanged_"+suffix),{...options,knownContracts:[known]})[0];
    assert.equal(unchanged.status,"available_unchanged");assert.deepEqual(unchanged.contract_bytes,contract);
    assert.deepEqual(Object.keys(unchanged).sort(),["target_index","status","contract_bytes","contract_digest","offer"].sort());
    known.fill(0);fullBytes.fill(0);assert.deepEqual(unchanged.contract_bytes,contract);assert.deepEqual(full.contract_bytes,contract);
    unchanged.contract_bytes.fill(0);assert.deepEqual(contract,bytes("service_"+suffix));
    assert.deepEqual(verifyContractTargets(schema,bytes("contract_targets_both_"+suffix),[contract]),{target_count:1,max_response_bytes:9216});
  }
});

test("query matching rejects false targets, known digests and response count while retaining denied facts",()=>{
  const {schema,bytes}=fixture(),request=bytes("contract_targets_plain"),contract=bytes("service_unary_execution"),knownRequest=bytes("contract_targets_known_unary_execution");
  const response=bytes("contract_snapshots_full_unary_execution"),options={offerWindowLimits:[60000n]};
  for(const change of [{service_namespace:"acme/other"},{method_type_id:2}])assert.throws(()=>verifyContractSnapshots(schema,target(schema,change),response,options),/query_target_mismatch/u);
  for(const fake of [null,undefined,{validated:true,digest:digest(schema,contract)},digest(schema,contract)])assert.throws(()=>verifyContractTargets(schema,knownRequest,[fake]),VectorError);
  assert.throws(()=>verifyContractTargets(schema,knownRequest,[bytes("service_unary_transient")]),/query_known_mismatch/u);
  assert.throws(()=>verifyContractTargets(schema,request,[contract]),/query_unrequested_known/u);
  assert.throws(()=>verifyContractTargets(schema,request,[]),/query_known_count/u);
  assert.throws(()=>verifyContractSnapshots(schema,request,bytes("contract_snapshots_two_denied")),/query_response_count/u);
  for(const status of ["denied","unavailable"])assert.deepEqual(verifyContractSnapshots(schema,request,bytes("contract_snapshots_"+status)),[{target_index:0,status}]);
  // Even a denied response cannot justify a sender advertising known without
  // the original complete immutable baseline.
  assert.throws(()=>verifyContractSnapshots(schema,knownRequest,bytes("contract_snapshots_denied")),/query_contract_body/u);
});

test("known baseline validation and digest use one captured byte snapshot",()=>{
  const {schema,bytes}=fixture(),original=bytes("service_unary_execution");
  const changedMap=decodeMap(schema,"ServiceContract",original);changedMap.set(1n,2n);
  const changed=encodeCBOR(changedMap),request=target(schema,{known_contract_digest:b(digest(schema,changed))});
  const from=Buffer.from;let injected=false;
  try {
    // Inject a change after the first copy to expose validation/hash/return
    // rereads of caller-owned bytes. This is not runtime immutability evidence.
    Buffer.from=function(value,...args) {
      const copied=from.call(Buffer,value,...args);
      if(value===original && !injected) {injected=true;changed.copy(original);}
      return copied;
    };
    assert.throws(()=>verifyContractTargets(schema,request,[original]),/query_known_mismatch/u);
  } finally {Buffer.from=from;}
  assert.equal(injected,true);
  assert.equal(decodeMap(schema,"ServiceContract",original).get(1n),2n);
});

test("query Offer presence follows the matched contract on both full and unchanged responses",()=>{
  const {schema,bytes}=fixture();
  for(const suffix of variants) {
    const contract=bytes("service_"+suffix),execution=suffix.endsWith("_execution");
    for(const status of [0,1]) {
      const request=status===0?bytes("contract_targets_plain"):bytes("contract_targets_known_"+suffix);
      const item={target_index:0,status,...(status===0?{contract:b(contract)}:{contract_digest:b(digest(schema,contract))}),...(!execution?{offer:b(offer(schema,contract))}:{})};
      assert.throws(()=>verifyContractSnapshots(schema,request,one(schema,item),{knownContracts:[status===0?null:contract],offerWindowLimits:[60000n]}),/query_offer_presence/u);
    }
  }
  const contract=bytes("service_unary_execution"),item={target_index:0,status:0,contract:b(contract),offer:b(offer(schema,bytes("service_unary_transient")))};
  assert.throws(()=>verifyContractSnapshots(schema,bytes("contract_targets_plain"),one(schema,item),{offerWindowLimits:[60000n]}),/offer_contract_mismatch/u);
  item.offer=b(offer(schema,contract,0n,(1n<<64n)-1n));
  const response=one(schema,item);
  assert.equal(verifyContractSnapshots(schema,bytes("contract_targets_plain"),response,{offerWindowLimits:[(1n<<64n)-1n]})[0].offer.not_after_ms,(1n<<64n)-1n);
  assert.throws(()=>verifyContractSnapshots(schema,bytes("contract_targets_plain"),response,{offerWindowLimits:[60000n]}),/offer_window/u);
});

test("query maximum encodings include complete nested contracts and preserve eight distinct targets",()=>{
  const {schema,bytes}=fixture();
  for(const [id,size]of [["contract_target_maximum",208],["contract_targets_maximum",1667],["contract_query_execution_maximum",8192],["contract_snapshot_maximum",8260],["contract_snapshots_maximum",66083]])assert.equal(bytes(id).length,size);
  assert.equal(schema.resource_caps.contract_query_response_bytes_per_target,9216);
  const targets=[],items=[];
  for(let i=0;i<8;i++) {
    const contract=decodeMap(schema,"ServiceContract",bytes("contract_query_execution_maximum"));contract.set(1n,BigInt(i+1));
    const encoded=encodeCBOR(contract);assert.equal(encoded.length,8192);
    targets.push({service_namespace:"acme/files",method_type_id:i+1});
    items.push({target_index:i,status:0,contract:b(encoded),offer:b(offer(schema,encoded,(1n<<64n)-2n,(1n<<64n)-1n))});
  }
  const request=encodeCBOR(mapFromNames(schema,"ContractTargets",{targets})),response=encodeCBOR(mapFromNames(schema,"ContractSnapshots",{items}));
  assert.equal(response.length,66083);assert.deepEqual(verifyContractTargets(schema,request),{target_count:8,max_response_bytes:73728});
  const snapshots=verifyContractSnapshots(schema,request,response,{offerWindowLimits:Array(8).fill(1n)});
  assert.equal(snapshots.length,8);assert.equal(new Set(snapshots.map(s=>s.contract_digest.toString("hex"))).size,8);
  assert.throws(()=>verifyContractSnapshots(schema,bytes("contract_targets_plain"),response),/query_response_size/u);
  assert.throws(()=>verifyContractSnapshots(schema,request,Buffer.alloc(73729)),/query_response_size/u);
});

test("query schemas preserve optional selector equality, closed statuses and exact indices",()=>{
  const {schema,bytes,corpus}=fixture(),hash=digest(schema,bytes("service_unary_execution"));
  for(const selectors of [{},{wanted_contract_digest:b(hash)},{known_contract_digest:b(hash)},{wanted_contract_digest:b(hash),known_contract_digest:b(hash)}])decodeMap(schema,"ContractTargets",target(schema,selectors));
  for(const id of ["contract_target_selectors_differ","contract_targets_duplicate","contract_snapshots_nonzero_first","contract_snapshots_repeated","contract_snapshots_reversed","contract_snapshot_missing_body","contract_snapshot_unchanged_body","contract_snapshot_full_digest","contract_snapshot_denied_body","contract_snapshot_unavailable_offer"]) {
    const vector=corpus.vectors.find(v=>v.id===id);
    assert.throws(()=>decodeMap(schema,vector.schema,bytes(id)),new RegExp(vector.expected_error,"u"));
  }
  for(const mutate of [s=>{s.map_rules.ContractTarget[0].right="wanted_contract_digest";},s=>{s.frame_maps.ContractTarget.fields[3].length=16;},s=>{s.map_rules.ContractSnapshots[0].item_field_id=4;},s=>{s.frame_maps.ContractSnapshot.fields[0].type="text";},s=>{s.frame_maps.ContractSnapshot.fields[0].max=6;}]) {
    const changed=structuredClone(schema);mutate(changed);assert.throws(()=>verifySchema(changed));
  }
});

test("query vectors bind original complete sources and reject removed or relabeled evidence",()=>{
  const {schema,corpus,queries}=fixture();verifyQueryCorpus(schema,corpus,queries);
  for(const mutate of [q=>q.vectors.pop(),q=>q.vectors.push(q.vectors[0]),q=>{q.vectors[0].inputs.request_hex="a0";},q=>{q.vectors[1].inputs.known_contracts_hex=[null];},q=>{q.vectors[0].result[0].contract_digest_hex="00";},q=>{delete q.vectors.find(v=>v.expected_error).expected_error;}]) {
    const changed=structuredClone(queries);mutate(changed);assert.throws(()=>verifyQueryCorpus(schema,corpus,changed));
  }
  for(const key of ["schema_revision","design_sha256"])assert.throws(()=>verifyQueryCorpus(schema,{...corpus,[key]:"changed"},{...queries,[key]:"changed"}),/query authority/u);
});

test("nested fixture construction rejects cycles and malformed encodings instead of installing alternate definitions",()=>{
  const {schema}=fixture(),original=fs.readFileSync;
  for(const bad of [{$encoded_map:{schema:"ServiceContract",values:{$fixture:"query_execution_maximum"},extra:true}},{$domain_output:{name:"missing",inputs:{}}},{$encoded_map:{schema:"ContractTarget",values:{service_namespace:"acme/files",method_type_id:0}}},{$fixture:"recursive_query"}]) {
    const changed=structuredClone(schema);changed.vector_plan.fixtures.recursive_query={$encoded_map:{schema:"ServiceContract",values:{$fixture:"recursive_query"}}};
    changed.vector_plan.maps[0].values=bad;
    try {
      fs.readFileSync=function(file,...args){if(String(file).endsWith("stability/transport_v4_schema.json"))return Buffer.from(JSON.stringify(changed));return original.call(this,file,...args);};
      assert.throws(()=>buildArtifacts());
    } finally {fs.readFileSync=original;}
  }
});

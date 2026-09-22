import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { encodeCBOR, decodeMap, mapFromNames } from "./transport-v4-codec.mjs";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { verifyServiceOffer } from "./transport-v4-services.mjs";

function fixture() {
  const {schema,files} = buildArtifacts(), corpus=JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  return {schema,corpus,bytes:id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex")};
}

test("service contracts use one full-map digest across all six method variants", () => {
  const {schema,bytes}=fixture();
  const variants=["unary_transient","unary_execution","stream_transient","stream_execution","notify_observation","notify_execution"];
  const digests=new Set();
  for(const suffix of variants) {
    const contract=bytes("service_"+suffix), prefix=Buffer.alloc(4); prefix.writeUInt32BE(contract.length);
    const input=Buffer.concat([Buffer.from("flowersec/v4/service-contract\0","ascii"),prefix,contract]);
    const result=evaluateDomain(schema,"service_contract_digest",{contract});
    assert.equal(result.input_hex,input.toString("hex"));
    assert.equal(result.output_hex,createHash("sha256").update(input).digest("hex"));
    digests.add(result.output_hex);
    assert.throws(()=>evaluateDomain(schema,"service_contract_digest",{contract,offer:Buffer.alloc(0)}),/domain_arguments/u);
  }
  assert.equal(digests.size,6);
  const contract=decodeMap(schema,"ServiceContract",bytes("service_unary_execution"));
  const original=evaluateDomain(schema,"service_contract_digest",{contract:encodeCBOR(contract)}).output_hex;
  for(const mutate of [m=>m.set(0n,"acme/other"),m=>m.set(1n,2n),m=>m.set(6n,"2"),m=>m.set(10n,4096n),m=>m.set(14n,86400001n),m=>m.delete(15n),m=>m.set(20n,"checkpoint/1"),m=>m.set(23n,0n)]) {
    const changed=decodeMap(schema,"ServiceContract",encodeCBOR(contract)); mutate(changed);
    assert.notEqual(evaluateDomain(schema,"service_contract_digest",{contract:encodeCBOR(changed)}).output_hex,original);
  }
});

test("service contract field applicability separates transient, observation and execution facts", () => {
  const {schema,bytes}=fixture();
  const executionFields=[13n,14n,15n,16n,17n,18n,19n,20n];
  for(const id of ["service_unary_transient","service_stream_transient","service_notify_observation"]) {
    const value=decodeMap(schema,"ServiceContract",bytes(id));
    assert.ok(value.get(11n)>0n);
    for(const field of executionFields) {
      assert.equal(value.has(field),false);
      const changed=new Map(value); changed.set(field,field===20n?"checkpoint/1":1n);
      assert.throws(()=>decodeMap(schema,"ServiceContract",encodeCBOR(changed)),/variant_absent/u);
    }
  }
  for(const id of ["service_unary_execution","service_stream_execution","service_notify_execution"]) {
    const value=decodeMap(schema,"ServiceContract",bytes(id));
    const checkpoint=new Map(value); checkpoint.set(20n,"checkpoint/1");
    decodeMap(schema,"ServiceContract",encodeCBOR(checkpoint));
    for(const field of [13n,14n,16n,17n,18n,19n]) {
      const changed=new Map(value); changed.delete(field);
      assert.throws(()=>decodeMap(schema,"ServiceContract",encodeCBOR(changed)),/variant_required/u);
    }
    for(const field of [11n,12n]) {
      const changed=new Map(value); changed.set(field,1n);
      assert.throws(()=>decodeMap(schema,"ServiceContract",encodeCBOR(changed)),/variant_absent/u);
    }
  }
  decodeMap(schema,"ServiceContract",bytes("service_unary_no_result_retention"));
  for(const id of ["service_notify_observation","service_notify_execution"]) {
    const value=decodeMap(schema,"ServiceContract",bytes(id));
    for(const field of [8n,9n,10n]) {
      assert.equal(value.get(field),0n);
      const changed=new Map(value); changed.set(field,1n);
      assert.throws(()=>decodeMap(schema,"ServiceContract",encodeCBOR(changed)),/variant_constant/u);
    }
  }
});

test("service error catalog ordering and entire contract size bound remain independent", () => {
  const {schema,bytes}=fixture();
  const maximum=bytes("service_catalog_boundary"); assert.equal(maximum.length,8192);
  const value=decodeMap(schema,"ServiceContract",maximum), catalog=value.get(27n);
  assert.equal(catalog.length,64);
  assert.ok(catalog.every(entry=>entry.get(1n).length<=128));
  // The oversize witness changes one still-legal revision byte, preserving
  // all individual field/cardinality/order constraints.
  const over=bytes("service_catalog_over_encoding_cap"); assert.equal(over.length,8193);
  const relaxed=structuredClone(schema); relaxed.frame_maps.ServiceContract.max_encoded_bytes=8193;
  decodeMap(relaxed,"ServiceContract",over);
  assert.throws(()=>decodeMap(schema,"ServiceContract",over),/map_size/u);
  assert.equal(bytes("service_error_maximum").length,1+6+131+6+35);
  assert.equal(decodeMap(schema,"ErrorDefinition",bytes("service_error_empty_payload")).get(2n),0n);
  for(const id of ["service_catalog_repeated_code","service_catalog_reversed_code"]) assert.throws(()=>decodeMap(schema,"ServiceContract",bytes(id)),/item_order/u);
  assert.ok(bytes("service_catalog_too_many").length<8192);
  assert.throws(()=>decodeMap(schema,"ServiceContract",bytes("service_catalog_too_many")),/array_length/u);
  const original=evaluateDomain(schema,"service_contract_digest",{contract:maximum}).output_hex;
  catalog[0].get(3n)[0]^=1;
  assert.notEqual(evaluateDomain(schema,"service_contract_digest",{contract:encodeCBOR(value)}).output_hex,original);
});

test("service content retention and restart policy retain exact variant fields and uint64 values", () => {
  const {schema,bytes}=fixture(), max=(1n<<64n)-1n;
  const content=decodeMap(schema,"StreamContentPolicy",bytes("service_content_maximum"));
  assert.equal(bytes("service_content_maximum").length,1+2+2+30+131+2052);
  for(const field of [2n,3n,4n]) assert.equal(content.get(field),max);
  const none=decodeMap(schema,"StreamContentPolicy",bytes("service_content_none"));
  assert.deepEqual([...none.keys()],[0n]);
  const contract=decodeMap(schema,"ServiceContract",bytes("service_unary_execution"));
  for(const field of [14n,15n,16n,17n,18n])contract.set(field,max);
  const decoded=decodeMap(schema,"ServiceContract",encodeCBOR(contract));
  for(const field of [14n,15n,16n,17n,18n])assert.equal(decoded.get(field),max);
  for(const deadline of [1n,120000n]) {const restart=new Map(contract);restart.set(21n,true);restart.set(22n,deadline);decodeMap(schema,"ServiceContract",encodeCBOR(restart));}
  for(const id of ["service_restart_missing_deadline","service_stream_restart","service_missing_content_policy","service_transient_content_policy","service_content_missing_definition"]) {
    const name=id.startsWith("service_content_")?"StreamContentPolicy":"ServiceContract";
    assert.throws(()=>decodeMap(schema,name,bytes(id)),/variant_/u);
  }
});

test("service Offers bind only their exact execution contract and original bounded interval", () => {
  const {schema,bytes}=fixture();
  const offer=(contract,start=1n,end=60001n)=>encodeCBOR(mapFromNames(schema,"AdmissionOffer",{service_contract_digest:{$bytes:evaluateDomain(schema,"service_contract_digest",{contract}).output_hex},not_before_ms:start,not_after_ms:end}));
  for(const suffix of ["unary_execution","stream_execution","notify_execution"]) {
    const contract=bytes("service_"+suffix), encoded=offer(contract);
    assert.deepEqual(verifyServiceOffer(schema,contract,encoded,60000n),{not_before_ms:1n,not_after_ms:60001n});
    assert.throws(()=>verifyServiceOffer(schema,contract,encoded,59999n),/offer_window/u);
    assert.throws(()=>verifyServiceOffer(schema,contract,bytes("service_offer_fields"),60000n),/offer_contract_mismatch/u);
    const max=(1n<<64n)-1n;
    assert.equal(verifyServiceOffer(schema,contract,offer(contract,max-1n,max),1n).not_after_ms,max);
    for(const policy of [0n,-1n,1n<<64n,1,Number.MAX_SAFE_INTEGER+1,"1",true]) assert.throws(()=>verifyServiceOffer(schema,contract,encoded,policy),/offer_policy_range/u);
  }
  for(const suffix of ["unary_transient","stream_transient","notify_observation"]) {
    const contract=bytes("service_"+suffix);
    assert.throws(()=>verifyServiceOffer(schema,contract,offer(contract),60000n),/offer_not_applicable/u);
  }
  assert.equal(bytes("service_offer_maximum").length,1+35+10+10);
  const contract=bytes("service_unary_execution");
  assert.throws(()=>verifyServiceOffer(schema,contract,offer(contract,1n,1n),1n),/field_order/u);
});

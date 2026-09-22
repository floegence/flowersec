import assert from "node:assert/strict";
import { strictHex, VectorError } from "./transport-v4-codec.mjs";
import { verifyContractTargets, verifyContractSnapshots } from "./transport-v4-contract-query.mjs";

function inputs(plan,corpus) {
  const bytes=(id,name)=>{
    const source=corpus.vectors.find(v=>v.id===id);
    assert.ok(source && source.schema===name,`query source ${id} must be ${name}`);
    return source.hex;
  };
  assert.deepEqual(Object.keys(plan).sort(),["id","request","response","known_contracts","offer_window_limits",...(plan.expected_error ? ["expected_error"] : [])].sort());
  assert.match(plan.id,/^query_[a-z0-9_]+$/u);
  assert.ok(Array.isArray(plan.known_contracts) && plan.known_contracts.length<=8);
  assert.ok(Array.isArray(plan.offer_window_limits) && plan.offer_window_limits.length<=8);
  for(const value of plan.offer_window_limits) assert.ok(value===null || typeof value==="string" && /^(?:0|[1-9][0-9]*)$/u.test(value));
  return {request_hex:bytes(plan.request,"ContractTargets"),response_hex:plan.response===null ? null : bytes(plan.response,"ContractSnapshots"),known_contracts_hex:plan.known_contracts.map(id=>id===null ? null : bytes(id,"ServiceContract")),offer_window_limits:plan.offer_window_limits};
}

function evaluate(schema,input) {
  const request=strictHex(input.request_hex),known=input.known_contracts_hex.map(x=>x===null ? null : strictHex(x));
  if(input.response_hex===null) return verifyContractTargets(schema,request,known);
  const result=verifyContractSnapshots(schema,request,strictHex(input.response_hex),{knownContracts:known,offerWindowLimits:input.offer_window_limits.map(x=>x===null ? null : BigInt(x))});
  return result.map(item=>({target_index:item.target_index,status:item.status,...(item.contract_bytes ? {contract_bytes:item.contract_bytes.length,contract_digest_hex:item.contract_digest.toString("hex"),offer:item.offer===null ? null : {not_before_ms:item.offer.not_before_ms.toString(),not_after_ms:item.offer.not_after_ms.toString()}} : {})}));
}

export function buildQueryCorpus(schema,corpus) {
  const result={schema_revision:schema.schema_revision,design_sha256:schema.design_sha256,schema_sha256:corpus.schema_sha256,coverage:"draft_contract_query_reference_matching",unverified:["Trusted source and current caller authorization","Immutable runtime baseline ownership","Query reservations, input/output and cleanup","ServiceClient installation, provider and cross-SDK qualification"],vectors:[]};
  for(const plan of schema.contract_query_vector_plan) {
    const input=inputs(plan,corpus),vector={id:plan.id,inputs:input};
    if(plan.expected_error) vector.expected_error=plan.expected_error;
    else vector.result=evaluate(schema,input);
    result.vectors.push(vector);
  }
  verifyQueryCorpus(schema,corpus,result);
  return result;
}

export function verifyQueryCorpus(schema,corpus,queries) {
  for(const key of ["schema_revision","design_sha256","schema_sha256"]) assert.equal(queries[key],corpus[key],`query ${key} drift`);
  for(const key of ["schema_revision","design_sha256"]) assert.equal(queries[key],schema[key],`query authority ${key} drift`);
  const plans=new Map(schema.contract_query_vector_plan.map(plan=>[plan.id,plan]));
  assert.equal(plans.size,schema.contract_query_vector_plan.length,"duplicate query plan");
  assert.equal(queries.vectors.length,plans.size,"query coverage drift");
  const seen=new Set();
  for(const vector of queries.vectors) {
    const plan=plans.get(vector.id); assert.ok(plan && !seen.has(vector.id),"query plan drift");seen.add(vector.id);
    assert.deepEqual(Object.keys(vector).sort(),["id","inputs",plan.expected_error ? "expected_error" : "result"].sort());
    assert.deepEqual(vector.inputs,inputs(plan,corpus),"query original source drift");
    assert.equal(vector.expected_error,plan.expected_error,"query expectation drift");
    let actual,error;
    try {actual=evaluate(schema,vector.inputs);} catch(e) {error=e;}
    if(plan.expected_error) assert.ok(error instanceof VectorError && error.code===plan.expected_error,`${vector.id}: expected ${plan.expected_error}, got ${error?.message ?? "accepted"}`);
    else {if(error)throw error;assert.deepEqual(actual,vector.result,`query result drift ${vector.id}`);}
  }
}

import assert from "node:assert/strict";
import { FragmentError } from "./transport-v4-fragments.mjs";
import { StreamState } from "./transport-v4-stream-state.mjs";

const jsonState = value => JSON.parse(JSON.stringify(value, (_, v) => typeof v === "bigint" ? v.toString() : v));
const asBig = value => {
  assert.match(value, /^(0|[1-9][0-9]*)$/u, "vector uint64 decimal");
  return BigInt(value);
};
const asTuple = value => ({epoch:value.epoch,nextSequence:asBig(value.nextSequence),offset:asBig(value.offset)});
const hex = value => { assert.match(value, /^(?:[0-9a-f]{2})*$/u); return Buffer.from(value, "hex"); };
const operations = {
  open: ["opener id initial_receive_limit kind", (s,a)=>s.open(a.opener,asBig(a.id),asBig(a.initial_receive_limit),a.kind)],
  reject_open: ["opener id kind", (s,a)=>s.rejectOpen(a.opener,asBig(a.id),a.kind)],
  outcome: ["opener id result accepted_limit", (s,a)=>s.outcome(a.opener,asBig(a.id),a.result,asBig(a.accepted_limit??"0"))],
  data: ["direction id epoch sequence offset data_hex fin", (s,a)=>s.data(a.direction,asBig(a.id),a.epoch,asBig(a.sequence),asBig(a.offset),hex(a.data_hex??""),a.fin??false)],
  observe: ["direction id tuple", (s,a)=>s.observe(a.direction,asBig(a.id),asTuple(a.tuple))],
  credit: ["direction id ack_offset receive_limit classification", (s,a)=>s.credit(a.direction,asBig(a.id),asBig(a.ack_offset),asBig(a.receive_limit),a.classification)],
  stop: ["direction id", (s,a)=>s.stop(a.direction,asBig(a.id))],
  stopped: ["direction id", (s,a)=>s.stopped(a.direction,asBig(a.id))],
  isolate: ["direction id", (s,a)=>s.isolate(a.direction,asBig(a.id))],
  drained: ["direction id final observed outcome", (s,a)=>s.drained(a.direction,asBig(a.id),asTuple(a.final),asTuple(a.observed),a.outcome)],
  switch_epoch: ["direction epoch", (s,a)=>s.switchEpoch(a.direction,a.epoch)],
  hold: ["id", (s,a)=>s.hold(asBig(a.id))],
  freeze_barrier: ["role id", (s,a)=>s.freezeBarrier(a.role,asBig(a.id))],
  publish_barrier: ["reference", (s,a)=>s.publishBarrier(asBig(a.reference))],
  cancel_barrier: ["reference cause", (s,a)=>s.cancelBarrier(asBig(a.reference),a.cause)],
  release: ["reference", (s,a)=>s.release(asBig(a.reference))],
  retire_batch: ["role ids", (s,a)=>s.retireBatch(a.role,a.ids.map(asBig))],
  retire_ack: ["role batch_seq digest", (s,a)=>s.retireAck(a.role,asBig(a.batch_seq),a.digest)],
  close: ["", s=>s.close()]
};

// Explicit schema-owned JSON-pointer projections are the oracle. Full runtime
// snapshots are emitted for consumers, never copied back into expectations.
function checkProjection(actual, expected, label) {
  assert.ok(expected && typeof expected === "object" && !Array.isArray(expected) && Object.keys(expected).length, `${label}: missing state assertions`);
  for (const [pointer,value] of Object.entries(expected)) {
    assert.match(pointer, /^\/(?:[A-Za-z0-9_]+\/)*[A-Za-z0-9_]+$/u);
    let found=actual;
    for (const key of pointer.slice(1).split("/")) {
      assert.ok(found !== null && typeof found === "object" && Object.hasOwn(found,key), `${label}: unknown path ${pointer}`);
      found=found[key];
    }
    assert.deepEqual(found,value,`${label}: ${pointer}`);
  }
}

export function buildStreamStateCorpus(schema) {
  assert.ok(Array.isArray(schema.stream_state_vector_plan) && schema.stream_state_vector_plan.length, "stream state vectors must be schema-owned");
  const ids=new Set();
  const vectors=schema.stream_state_vector_plan.map(plan=>{
    assert.match(plan.id,/^[a-z][a-z0-9_]*$/u);
    assert.ok(!ids.has(plan.id),`duplicate stream vector ${plan.id}`); ids.add(plan.id);
    assert.ok(Array.isArray(plan.steps) && plan.steps.length,`${plan.id}: missing steps`);
    assert.ok(plan.options,`${plan.id}: missing explicit reference configuration`);
    const o=plan.options;
    const state=new StreamState(schema,{maxDataPayloadBytes:o.max_data_payload_bytes,handshakeHash:hex(o.handshake_hash),cryptoProfile:o.crypto_profile,referenceCapacity:o.reference_capacity,protectedFuture:o.protected_future});
    const steps=[];
    for (const source of plan.steps) {
      assert.ok(Object.hasOwn(operations,source.op),`${plan.id}: unknown operation ${source.op}`);
      assert.notEqual(Object.hasOwn(source,"error"),Object.hasOwn(source,"result"),`${plan.id}: exactly one explicit result or error required`);
      assert.ok(Object.keys(source).every(key=>["op","args","result","error","state"].includes(key)),`${plan.id}: unknown step field`);
      const [keys,run]=operations[source.op], args=source.args??{};
      assert.ok(Object.keys(args).every(key=>keys.split(" ").includes(key)),`${plan.id}: unknown operation argument`);
      const before=state.snapshot(); let result,error;
      try { result=run(state,args); } catch (err) { error=err; }
      if (Object.hasOwn(source,"error")) {
        assert.ok(error instanceof FragmentError && error.code===source.error,`${plan.id}: expected ${source.error}, got ${error?.code??error?.message??"accepted"}`);
        assert.deepEqual(state.snapshot(),before,`${plan.id}: rejected transition mutated state`);
      } else {
        if (error) throw error;
        assert.deepEqual(jsonState(result),source.result,`${plan.id}: result`);
      }
      const current=jsonState(state.snapshot());
      if (source.state) checkProjection(current,source.state,`${plan.id}: step`);
      steps.push({...structuredClone(source),state:current});
    }
    const final=jsonState(state.snapshot());
    for (const path of ["/closed","/next","/epochs","/tokens","/streams/length","/references/length"]) assert.ok(Object.hasOwn(plan.final??{},path),`${plan.id}: missing final ${path}`);
    checkProjection(final,plan.final,`${plan.id}: final`);
    return {id:plan.id,options:structuredClone(o),steps,final,final_assertions:structuredClone(plan.final)};
  });
  return {coverage:"draft_schema_owned_joint_stream_transcripts",unverified:["Peer-local ingress, authentication and OPEN digest checks", "Bootstrap and protected category allocation", "Physical byte/work ownership, batch tails, deadlines and provider cleanup", "Application delivery and complete rekey/retirement runtime", "Production SDK and provider qualification"],vectors};
}

export function verifyStreamStateCorpus(schema,corpus) {
  assert.deepEqual(corpus,buildStreamStateCorpus(schema),"stream state recipe drift");
}

import assert from "node:assert/strict";
import { FragmentError, encodeFragment } from "./transport-v4-fragments.mjs";
import { FragmentState } from "./transport-v4-fragment-state.mjs";

export function buildFragmentStateCorpus(schema) {
  const wire = schema.fragment_registry;
  const vectors = schema.fragment_state_vector_plan.map(plan => ({...structuredClone(plan),steps:plan.steps.map(step => {
    let fragment;
    const message_serial = BigInt(step.serial);
    if (step.op === "request" || step.op === "response") fragment = {kind:wire.kinds.BEGIN.value,message_serial,reply_to_serial:BigInt(step.reply ?? "0"),canonical_header:Buffer.from([0xa0])};
    else if (step.op === "data") fragment = {kind:wire.kinds.DATA.value,message_serial,payload_offset:step.offset,payload_bytes:Buffer.alloc(step.size,0x41)};
    else if (step.op === "abort") fragment = {kind:wire.kinds.ABORT.value,message_serial,next_offset:step.offset};
    else if (step.op === "stop") fragment = {kind:wire.kinds.STOP_OUTPUT.value,request_serial:message_serial};
    else assert.equal(step.op,"validate");
    return {...structuredClone(step),...(fragment ? {hex:encodeFragment(wire,fragment).toString("hex")} : {})};
  })}));
  return {coverage:"draft_fragment_live_association_transitions",header_fixture:"opaque_empty_map_not_an_application_header_qualification",vectors};
}

export function verifyFragmentStateCorpus(schema, corpus) {
  assert.deepEqual(corpus,buildFragmentStateCorpus(schema),"fragment state recipe drift");
  const ids = new Set();
  for (const vector of corpus.vectors) {
    assert.ok(!ids.has(vector.id)); ids.add(vector.id);
    const state = new FragmentState(schema,{requestCapacity:vector.capacity}), owners = new Map();
    for (const step of vector.steps) {
      const before = state.snapshot();
      let result, error;
      try {
        if (step.op === "validate") state.validateRequestInput(step.dir,BigInt(step.serial),owners.get(step.owner));
        else {
          let context;
          if (step.op === "request") context = {type:"request",payload_length:step.length};
          if (step.op === "response") context = {type:"response",payload_length:step.length,request:owners.get(step.owner),response_kind:step.response_kind};
          result = state.accept(step.dir,Buffer.from(step.hex,"hex"),context);
        }
      } catch (err) { error = err; }
      if (step.error) {
        assert.ok(error instanceof FragmentError && error.code === step.error,`${vector.id}: expected ${step.error}, got ${error?.code ?? "accepted"}`);
        assert.deepEqual(state.snapshot(),before,"failed transition changed state");
      } else {
        if (error) throw error;
        if (step.status) assert.equal(result.status,step.status,vector.id);
        if (step.op === "request") owners.set(step.owner,result.request);
      }
    }
    const snapshot = state.snapshot(); snapshot.highwater = snapshot.highwater.map(String);
    assert.deepEqual(snapshot,vector.final,vector.id);
  }
}

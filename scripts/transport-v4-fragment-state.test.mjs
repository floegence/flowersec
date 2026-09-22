import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { FragmentError, encodeFragment } from "./transport-v4-fragments.mjs";
import { FragmentState, advanceBeginSerial } from "./transport-v4-fragment-state.mjs";
import { buildFragmentStateCorpus, verifyFragmentStateCorpus } from "./transport-v4-fragment-state-vectors.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const max = BigInt(schema.fragment_state_registry.serial_max);
const wire = fragment => encodeFragment(schema.fragment_registry, fragment);
const begin = (serial, reply = 0n) => wire({kind:0,message_serial:serial,reply_to_serial:reply,canonical_header:Buffer.from([0xa0])});
const data = (serial, offset, size) => wire({kind:1,message_serial:serial,payload_offset:offset,payload_bytes:Buffer.alloc(size)});
const abort = (serial, offset) => wire({kind:2,message_serial:serial,next_offset:offset});
const stop = serial => wire({kind:3,request_serial:serial});
const request = (state, dir, serial, size = 0) => state.accept(dir,begin(serial),{type:"request",payload_length:size}).request;
const response = (state, dir, serial, reply, token, size = 0, kind = "normal") => state.accept(dir,begin(serial,reply),{type:"response",payload_length:size,request:token,response_kind:kind});
const validate = (state, dir, serial, token) => state.validateRequestInput(dir,serial,token);
const code = (fn, expected) => assert.throws(fn, err => err instanceof FragmentError && err.code === expected);
const unchanged = (state, fn, expected) => { const before = state.snapshot(); code(fn,expected); assert.deepEqual(state.snapshot(),before); };

test("schema-owned transition recipes preserve wire bytes, expected failures and final state", () => {
  const corpus = buildFragmentStateCorpus(schema);
  verifyFragmentStateCorpus(schema,corpus);
  const badWire = structuredClone(corpus); badWire.vectors[0].steps[0].hex += "00";
  assert.throws(()=>verifyFragmentStateCorpus(schema,badWire),/recipe drift/u);
  const missing = structuredClone(corpus); missing.vectors.pop();
  assert.throws(()=>verifyFragmentStateCorpus(schema,missing),/recipe drift/u);
  const changed = structuredClone(corpus); changed.vectors[0].steps[4].status = "stop_requested";
  assert.throws(()=>verifyFragmentStateCorpus(schema,changed),/recipe drift/u);
});

test("BEGIN continuity has no wrap, skipping constructor or rekey reset", () => {
  const registry = schema.fragment_state_registry;
  assert.equal(advanceBeginSerial(registry,0n,1n),1n);
  assert.equal(advanceBeginSerial(registry,max-1n,max),max);
  code(() => advanceBeginSerial(registry,max,1n),"serial_exhausted");
  code(() => advanceBeginSerial(registry,max,max),"serial_exhausted");
  const state = new FragmentState(schema,{requestCapacity:2});
  request(state,0,1n);
  unchanged(state,()=>request(state,0,3n),"serial_gap");
  unchanged(state,()=>request(state,0,1n),"serial_replay");
  request(state,1,1n);
  assert.deepEqual(state.snapshot().highwater,[1n,1n]);
});

test("DATA and ABORT enforce exact incomplete boundaries before mutation", () => {
  const state = new FragmentState(schema,{requestCapacity:1});
  const token = request(state,0,1n,3);
  unchanged(state,()=>state.accept(0,data(1n,1,1)),"offset_mismatch");
  unchanged(state,()=>state.accept(0,data(1n,0,4)),"payload_overrun");
  assert.deepEqual(state.accept(0,data(1n,0,2)),{status:"open",offset:2});
  unchanged(state,()=>state.accept(0,data(1n,0,1)),"offset_mismatch");
  unchanged(state,()=>state.accept(0,abort(1n,1)),"abort_offset");
  assert.deepEqual(state.accept(0,abort(1n,2)),{status:"aborted",offset:2});
  unchanged(state,()=>state.accept(0,data(1n,2,1)),"message_not_open");
  unchanged(state,()=>state.accept(0,abort(1n,2)),"message_not_open");
  unchanged(state,()=>validate(state,0,1n,token),"request_incomplete");
  unchanged(state,()=>state.accept(0,stop(1n)),"stop_ineligible");
  unchanged(state,()=>response(state,1,1n,1n,token),"response_boundary");
  response(state,1,1n,1n,token,0,"request_message_aborted");
  assert.deepEqual(state.snapshot().requests,[0,0]);
  assert.equal(state.accept(0,stop(1n)).status,"ignored");
});

test("STOP uses live validated request association, merges duplicates and ignores stale targets", () => {
  const state = new FragmentState(schema,{requestCapacity:1});
  const token = request(state,0,1n);
  unchanged(state,()=>state.accept(0,stop(1n)),"stop_ineligible");
  unchanged(state,()=>validate(state,0,1n,Object.freeze({})),"request_owner");
  validate(state,0,1n,token);
  assert.equal(state.accept(0,stop(1n)).status,"stop_requested");
  assert.equal(state.accept(0,stop(1n)).status,"coalesced");
  response(state,1,1n,1n,token,2,"response_output_stopped");
  unchanged(state,()=>state.accept(1,stop(1n)),"stop_ineligible");
  unchanged(state,()=>state.accept(0,stop(2n)),"stop_future");
  state.accept(1,data(1n,0,2));
  assert.equal(state.accept(0,stop(1n)).status,"ignored");
  const newer = request(state,0,2n);
  validate(state,0,2n,newer);
  assert.equal(state.accept(0,stop(1n)).status,"ignored");
  assert.equal(state.accept(0,stop(2n)).status,"stop_requested");
  unchanged(state,()=>validate(state,0,2n,token),"request_owner");
});

test("both directions mix requests and responses while preserving exact owner and reply_to", () => {
  const state = new FragmentState(schema,{requestCapacity:2});
  const left = request(state,0,1n), right = request(state,1,1n);
  validate(state,0,1n,left); validate(state,1,1n,right);
  unchanged(state,()=>response(state,0,2n,1n,left),"response_binding");
  response(state,0,2n,1n,right,2);
  response(state,1,2n,1n,left,1);
  unchanged(state,()=>response(state,0,3n,1n,right),"response_duplicate");
  state.accept(0,data(2n,0,2));
  state.accept(1,abort(2n,0));
  assert.deepEqual(state.snapshot().requests,[0,0]);
  assert.deepEqual(state.snapshot().indexed_messages,[0,0]);
  assert.deepEqual(state.snapshot().highwater,[2n,2n]);
  const other = new FragmentState(schema,{requestCapacity:1});
  const otherToken = request(other,0,1n); validate(other,0,1n,otherToken);
  unchanged(other,()=>response(other,1,1n,1n,left),"response_binding");
});

test("local reservation share includes completed and aborted requests until response terminal", () => {
  const state = new FragmentState(schema,{requestCapacity:1});
  const token = request(state,0,1n,1);
  state.accept(0,abort(1n,0));
  unchanged(state,()=>request(state,0,2n),"state_capacity");
  response(state,1,1n,1n,token,1,"request_message_aborted");
  unchanged(state,()=>request(state,0,2n),"state_capacity");
  state.accept(1,data(1n,0,1));
  request(state,0,2n);
  assert.deepEqual(state.snapshot().highwater,[2n,1n]);
  for (const requestCapacity of [0,1025,NaN,Infinity]) code(()=>new FragmentState(schema,{requestCapacity}),"capacity_range");
});

test("early ABORT and sparse STOP do not accumulate serial history during high churn", () => {
  const state = new FragmentState(schema,{requestCapacity:2});
  const old = request(state,0,1n,1); state.accept(0,abort(1n,0));
  for (let serial = 2n; serial <= 10002n; serial++) {
    const token = request(state,0,serial); validate(state,0,serial,token);
    if (serial % 2n === 0n) state.accept(0,stop(serial));
    response(state,1,serial-1n,serial,token);
    assert.deepEqual(state.snapshot().requests,[1,0]);
    assert.deepEqual(state.snapshot().indexed_messages,[1,0]);
  }
  response(state,1,10002n,1n,old,0,"request_message_aborted");
  assert.deepEqual(state.snapshot().indexed_messages,[0,0]);
  assert.equal(state.accept(0,stop(2n)).status,"ignored");
});

test("exact wire validation precedes state changes and close never creates fresh serial space", () => {
  const state = new FragmentState(schema,{requestCapacity:1});
  unchanged(state,()=>state.accept(0,Buffer.from("00000001ff","hex")),"unknown_kind");
  unchanged(state,()=>state.accept(0,begin(1n),{type:"request",payload_length:1048577}),"payload_length");
  const token = request(state,0,1n); validate(state,0,1n,token);
  unchanged(state,()=>state.accept(0,abort(1n,0)),"message_not_open");
  state.close(); state.close();
  assert.deepEqual(state.snapshot(),{highwater:[1n,0n],requests:[0,0],indexed_messages:[0,0],closed:true});
  unchanged(state,()=>request(state,1,1n),"channel_closed");
});

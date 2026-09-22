import fs from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { FragmentError } from "./transport-v4-fragments.mjs";
import { StreamState, advanceStreamSequence } from "./transport-v4-stream-state.mjs";
import { buildStreamStateCorpus } from "./transport-v4-stream-state-vectors.mjs";
const schema=JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json",import.meta.url)));
const options={maxDataPayloadBytes:16,handshakeHash:Buffer.alloc(32,0x31),cryptoProfile:"fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",referenceCapacity:8};
const make=overrides=>new StreamState(schema,{...options,...overrides});
const MAX=0xffffffffffffffffn;
const tuple=(nextSequence,offset=0n,epoch=0)=>({epoch,nextSequence,offset});
const reject=(s,fn,expected)=>{const before=s.snapshot();assert.throws(fn,e=>e instanceof FragmentError&&e.code===expected);assert.deepEqual(s.snapshot(),before,"failed transition is atomic");};
const accepted=(s,opener=0,id=1n)=>{s.open(opener,id,4n);s.outcome(opener,id,"accepted",3n);};
const seal=(s,n,id=1n)=>{const d=s.snapshot().streams.find(v=>v.id===id).directions[n];s.data(n,id,d.epoch,d.sequence,d.offset,Buffer.alloc(0),true);};
const drain=(s,n,id=1n)=>{const f=s.snapshot().streams.find(v=>v.id===id).directions[n].terminal;s.observe(n,id,f);s.drained(n,id,f,f,"drained");};
const retire=(s,role,ids)=>{const b=s.retireBatch(role,ids);s.retireAck(role,b.batchSeq,b.digest);return b;};

test("OPEN grants reverse credit and consumes only opener sequence zero",()=>{
  const s=make();accepted(s);
  assert.deepEqual(s.snapshot().streams[0].directions.map(d=>[d.sequence,d.limit]),[[1n,3n],[0n,4n]]);
  s.data(1,1n,0,0n,0n,Buffer.from("four"));s.data(0,1n,0,1n,0n,Buffer.from("abc"));
  reject(s,()=>s.data(0,1n,0,2n,3n,Buffer.from("x")),"credit_exceeded");
  reject(s,()=>s.outcome(0,1n,"rejected"),"outcome_replay");
});
test("pending cancellation preserves outcome and never manufactures a final",()=>{
  const s=make();s.open(0,1n,0n);s.stop(0,1n);
  assert.equal(s.snapshot().streams[0].directions[0].terminal,null);
  reject(s,()=>s.stopped(0,1n),"stream_not_open");
  reject(s,()=>s.retireBatch(0,[1n]),"retire_proof");
  s.outcome(0,1n,"accepted",0n);assert.equal(s.snapshot().streams[0].directions[0].abortIntent,true);
  assert.equal(s.snapshot().streams[0].directions[0].terminal,null);
});
test("FIN alone cannot retire or cross a completed rekey fence",()=>{
  const s=make();accepted(s);s.data(0,1n,0,1n,0n,Buffer.from("x"),true);
  const f=tuple(2n,1n);
  assert.deepEqual(s.stopped(0,1n),{status:"stopped",terminal:f});
  assert.equal(s.snapshot().streams[0].directions[0].abortIntent,false);
  reject(s,()=>s.drained(0,1n,f,f,"drained"),"observed_frontier");
  reject(s,()=>s.switchEpoch(0,1),"epoch_frontier");
  reject(s,()=>s.retireBatch(0,[1n]),"retire_proof");
  s.observe(0,1n,f);s.drained(0,1n,f,f,"drained");s.switchEpoch(0,1);
  assert.equal(s.snapshot().streams[0].phase,"future");
  s.data(1,1n,0,0n,0n,Buffer.from("ok"));
  assert.deepEqual(s.snapshot().streams[0].directions[0].terminal,f);
});
test("aborted proof requires same-epoch authenticated observation and isolation",()=>{
  const s=make();accepted(s);s.data(0,1n,0,1n,0n,Buffer.from("abc"));s.stop(0,1n);s.stopped(0,1n);
  const f=tuple(2n,3n),o=tuple(1n);
  reject(s,()=>s.drained(0,1n,f,o,"aborted"),"drained_proof");s.isolate(0,1n);
  reject(s,()=>s.drained(0,1n,f,tuple(1n,0n,1),"aborted"),"observed_frontier");
  s.drained(0,1n,f,o,"aborted");s.switchEpoch(0,1);
  reject(s,()=>s.observe(0,1n,f),"receive_closed");
  reject(s,()=>s.drained(0,1n,tuple(3n,3n),o,"aborted"),"terminal_tuple");
});
test("pending OPEN survives epoch changes; rejected proof uses original OPEN epoch",()=>{
  const s=make();s.switchEpoch(1,1);s.open(1,2n,4n);s.stop(1,2n);s.switchEpoch(1,2);
  s.outcome(1,2n,"rejected");const v=s.snapshot();
  assert.deepEqual(v.streams[0].directions.map(d=>d.terminal),[tuple(0n,0n,1),tuple(1n,0n,1)]);
  assert.equal(v.streams[0].phase,"recent");
  assert.deepEqual(s.stop(1,2n),{status:"ignored"});assert.deepEqual(s.snapshot(),v);
});
test("ACCEPT after rekey starts at sequence zero with cumulative offsets",()=>{
  const s=make();s.open(0,1n,4n);s.switchEpoch(0,1);s.outcome(0,1n,"accepted",3n);
  s.data(0,1n,1,0n,0n,Buffer.from("a"));s.observe(0,1n,tuple(1n,1n,1));s.switchEpoch(0,2);
  reject(s,()=>s.data(0,1n,1,1n,1n,Buffer.from("b")),"epoch");
  s.data(0,1n,2,0n,1n,Buffer.from("b"));
  assert.equal(s.snapshot().streams[0].directions[0].offset,2n);
});
test("credit validates new monotonic facts separately from trusted processed ACK",()=>{
  const s=make();accepted(s);s.data(0,1n,0,1n,0n,Buffer.from("abc"));s.credit(0,1n,2n,6n);
  reject(s,()=>s.credit(0,1n,1n,6n),"ack_offset");reject(s,()=>s.credit(0,1n,3n,5n),"receive_limit");
  assert.deepEqual(s.credit(0,1n,1n,3n,"processed"),{status:"ignored"});
  reject(s,()=>s.credit(0,1n,3n,7n,"processed"),"ack_classification");
});
test("outgoing barrier membership excludes peer pending and recent scopes",()=>{
  const s=make();s.open(0,1n,0n);
  reject(s,()=>s.freezeBarrier(1,1n),"barrier_membership");s.freezeBarrier(0,1n);
  s.outcome(0,1n,"rejected");
  reject(s,()=>s.freezeBarrier(0,1n),"barrier_membership");
  reject(s,()=>s.freezeBarrier(1,1n),"barrier_membership");
});
test("retirement waits for publication, preserves held proof and rejects new references",()=>{
  const s=make();accepted(s);seal(s,0);seal(s,1);
  const a=s.freezeBarrier(0,1n);s.publishBarrier(a.reference);
  const b=s.freezeBarrier(1,1n);drain(s,0);drain(s,1);
  const batch=s.retireBatch(0,[1n]);
  reject(s,()=>s.hold(1n),"retire_excluded");
  reject(s,()=>s.retireAck(0,batch.batchSeq,batch.digest),"retire_fence");
  reject(s,()=>s.cancelBarrier(b.reference,"client_prepare_cancelled"),"barrier_cancellation");
  reject(s,()=>s.cancelBarrier(b.reference,"session_closed"),"barrier_cancellation");
  reject(s,()=>s.retireAck(0,batch.batchSeq,batch.digest),"retire_fence");
  s.publishBarrier(b.reference);s.retireAck(0,batch.batchSeq,batch.digest);
  assert.deepEqual(s.snapshot().tokens,{future:0,recent:0,held:1,rejectInUse:0,rejectFree:128});
  reject(s,()=>s.freezeBarrier(1,1n),"stream_stable");s.release(a.reference);assert.equal(s.snapshot().tokens.held,1);
  s.release(b.reference);assert.equal(s.snapshot().tokens.held,0);assert.equal(s.snapshot().streams.length,0);
});
test("only a trusted eligible client cancellation releases a live publication fence",()=>{
  const s=make();s.open(0,1n,0n);const ref=s.freezeBarrier(0,1n);s.outcome(0,1n,"rejected");
  reject(s,()=>s.retireBatch(0,[1n]),"retire_fence");
  for (const cause of [undefined,"manual_wait_cancelled","session_closed",true]) reject(s,()=>s.cancelBarrier(ref.reference,cause),"barrier_cancellation");
  s.cancelBarrier(ref.reference,"client_prepare_cancelled");
  assert.equal(s.snapshot().references.length,1);
  reject(s,()=>s.publishBarrier(ref.reference),"barrier_publication");
  reject(s,()=>s.cancelBarrier(ref.reference,"client_prepare_cancelled"),"barrier_publication");
  retire(s,0,[1n]);assert.equal(s.snapshot().tokens.held,1);s.release(ref.reference);
  assert.equal(s.snapshot().tokens.held,0);
  const t=make();t.open(0,1n,0n);const published=t.freezeBarrier(0,1n);t.publishBarrier(published.reference);
  reject(t,()=>t.cancelBarrier(published.reference,"client_prepare_cancelled"),"barrier_publication");
});
test("closed Session cancellation releases server references without reopening protocol work",()=>{
  const s=make();accepted(s);const a=s.freezeBarrier(0,1n);s.publishBarrier(a.reference);
  const b=s.freezeBarrier(1,1n);s.close();
  reject(s,()=>s.cancelBarrier(b.reference,"client_prepare_cancelled"),"session_closed");
  s.cancelBarrier(b.reference,"session_closed");s.release(a.reference);s.release(b.reference);
  assert.equal(s.snapshot().references.length,0);assert.equal(s.snapshot().tokens.future,1);
  reject(s,()=>s.retireBatch(0,[1n]),"session_closed");
  reject(s,()=>s.publishBarrier(b.reference),"session_closed");
});
test("batch digest uses original H, crypto profile, proposer and complete canonical map",()=>{
  const lp=b=>{const n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([n,b]);};
  // Independent canonical encoding of {0:5,1:1,2:[1]}.
  const bytes=Buffer.from("a300050101028101","hex");
  const digest=createHash("sha256").update(Buffer.concat([Buffer.from("flowersec/v4/retire-batch\0"),lp(options.handshakeHash),lp(Buffer.from(options.cryptoProfile)),Buffer.from([0]),lp(bytes)])).digest("hex");
  const s=make();s.rejectOpen(0,1n);assert.equal(s.retireBatch(0,[1n]).digest,digest);
  reject(s,()=>s.retireAck(0,1n,"00".repeat(32)),"retire_digest");
  reject(s,()=>s.retireAck(1,1n,digest),"retire_ack");s.switchEpoch(0,1);s.retireAck(0,1n,digest);
  assert.deepEqual(s.retireAck(0,1n,digest),{status:"ignored"});
  reject(s,()=>s.retireAck(0,1n,"00".repeat(32)),"retire_digest");
  reject(s,()=>s.retireAck(0,2n,digest),"retire_ack");
});
test("batch role, ordering, single flight and non-reuse are strict",()=>{
  const s=make();s.rejectOpen(0,1n);s.rejectOpen(0,3n);
  reject(s,()=>s.retireBatch(1,[1n]),"retire_owner");reject(s,()=>s.retireBatch(0,[3n,1n]),"retire_order");
  reject(s,()=>s.retireBatch(0,[1n,1n]),"retire_order");const b=s.retireBatch(0,[1n]);
  assert.deepEqual(s.retireBatch(0,[1n]),b);reject(s,()=>s.retireBatch(0,[3n]),"retire_pending");
  s.retireAck(0,1n,b.digest);reject(s,()=>s.retireBatch(0,[1n]),"stream_stable");
  assert.equal(retire(s,0,[3n]).batchSeq,2n);assert.deepEqual(s.retireAck(0,1n,"00".repeat(32)),{status:"ignored"});
  reject(s,()=>s.open(0,1n,0n),"stream_replay");
});
test("stable maintenance ignores only validated known allocated IDs",()=>{
  const s=make();s.rejectOpen(0,1n);retire(s,0,[1n]);const before=s.snapshot();
  for (const fn of [()=>s.outcome(0,1n,"accepted",0n),()=>s.credit(0,1n,0n,0n),()=>s.stop(0,1n),()=>s.stopped(0,1n),()=>s.drained(0,1n,tuple(1n),tuple(1n),"aborted")]) assert.equal(fn().status,"ignored");
  assert.deepEqual(s.snapshot(),before);
  reject(s,()=>s.outcome(1,1n,"accepted",0n),"open_owner");reject(s,()=>s.outcome(0,1n,"rejected",1n),"receive_limit");
  reject(s,()=>s.stop(0,3n),"unknown_stream");
});
test("positive admission cannot borrow the rejection share; held tokens retain source",()=>{
  const s=make({protectedFuture:3967});s.open(0,1n,0n);reject(s,()=>s.open(0,3n,0n),"terminal_capacity");
  s.rejectOpen(0,3n);const ref=s.hold(3n);retire(s,0,[3n]);
  assert.equal(s.snapshot().tokens.rejectFree,127);assert.equal(s.snapshot().tokens.held,1);
  s.release(ref.reference);assert.equal(s.snapshot().tokens.rejectFree,128);
  s.outcome(0,1n,"rejected");retire(s,0,[1n]);s.open(0,5n,0n);
});
test("full rejection share has bounded exhaustion and actual recovery",()=>{
  const s=make({protectedFuture:3968});for(let i=1n;i<=128n;i++)s.rejectOpen(0,i*2n-1n);
  assert.deepEqual(s.snapshot().tokens,{future:3968,recent:128,held:0,rejectInUse:128,rejectFree:0});
  reject(s,()=>s.rejectOpen(0,257n),"terminal_capacity");retire(s,0,[1n]);s.rejectOpen(0,257n);
});
test("pending capacity and class/role quotas reject before allocation",()=>{
  const s=make();for(let i=1n;i<=128n;i++)s.open(0,i*2n-1n,0n);reject(s,()=>s.open(0,257n,0n),"pending_capacity");
  const m=make();for(let i=1n;i<=16n;i++)m.rejectOpen(0,i*2n-1n,"management");
  reject(m,()=>m.open(0,33n,0n,"management"),"stream_quota");reject(m,()=>m.open(1,2n,0n,"management"),"stream_quota");
  m.open(0,33n,0n,"business");reject(m,()=>m.open(1,1n,0n),"stream_parity");reject(m,()=>m.open(1,4n,0n),"stream_gap");
});
test("Close preserves unknown outcomes while cleanup remains possible",()=>{
  const s=make();s.open(0,1n,0n);const ref=s.freezeBarrier(0,1n);s.close();
  assert.equal(s.snapshot().streams[0].status,"pending");assert.equal(s.snapshot().tokens.future,1);
  reject(s,()=>s.publishBarrier(ref.reference),"session_closed");s.cancelBarrier(ref.reference,"session_closed");s.release(ref.reference);
  assert.equal(s.snapshot().references.length,0);reject(s,()=>s.outcome(0,1n,"rejected"),"session_closed");
});
test("snapshots, constructor inputs and returned terminal tuples cannot mutate owned state",()=>{
  const local=structuredClone(schema),o={...options,handshakeHash:Buffer.from(options.handshakeHash)},s=new StreamState(local,o);accepted(s);s.stop(0,1n);const t=s.stopped(0,1n);
  t.terminal.offset=99n;const v=s.snapshot();v.streams[0].directions[0].terminal.offset=99n;v.next[0]=99n;local.stream_state_registry.terminal_capacity=0;o.handshakeHash.fill(0);
  assert.deepEqual(s.snapshot().streams[0].directions[0].terminal,tuple(1n));assert.equal(s.snapshot().next[0],3n);
});
test("DATA and tuple bounds fail atomically and uint64 sequences never wrap",()=>{
  const s=make();accepted(s);
  for(const [fn,c] of [[()=>s.data(0,1n,0,0n,0n,Buffer.from("a")),"sequence_replay"],[()=>s.data(0,1n,0,2n,0n,Buffer.from("a")),"sequence_gap"],[()=>s.data(0,1n,0,1n,1n,Buffer.from("a")),"offset_gap"],[()=>s.data(0,1n,0,1n,0n,Buffer.alloc(17)),"payload"],[()=>s.data(0,1n,0,1n,0n,Buffer.alloc(0),1),"boolean"],[()=>s.observe(0,1n,tuple(1n,1n)),"observed_frontier"]])reject(s,fn,c);
  assert.equal(advanceStreamSequence(MAX-1n),MAX);assert.throws(()=>advanceStreamSequence(MAX),e=>e.code==="sequence_exhausted");
});
test("schema transcript oracles reject omissions, duplicate IDs and changed expectations",()=>{
  assert.ok(buildStreamStateCorpus(schema).vectors.length>=5);
  for(const mutate of [s=>delete s.stream_state_vector_plan[0].steps[0].result,s=>delete s.stream_state_vector_plan[0].final,s=>s.stream_state_vector_plan.push(s.stream_state_vector_plan[0]),s=>s.stream_state_vector_plan[0].steps[0].result.status="wrong",s=>s.stream_state_vector_plan[0].steps[0].args.ignored=true]) {
    const bad=structuredClone(schema);mutate(bad);assert.throws(()=>buildStreamStateCorpus(bad));
  }
});

import assert from "node:assert/strict";
import { FragmentError } from "./transport-v4-fragments.mjs";
import { encodeCBOR, mapFromNames } from "./transport-v4-codec.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";

// Joint transcript reference, not a peer-input parser or a Session runtime.
// open records allocation at the opener followed by authenticating that OPEN;
// it does not constrain arrival order on independent native streams. outcome
// records committed AND verified ACCEPT. observe records a decoder's already
// authenticated frontier. switchEpoch and isolate record completed owner fences.
// freezeBarrier projects one scope reference from an externally established
// snapshot; it does not implement the Session submission freeze or authenticate
// INIT. publishBarrier records irrevocable maintenance-sequence publication,
// not provider delivery. client_prepare_cancelled records an external owner's
// completed pre-INIT cancellation gate, including absence of peer/security
// responsibility; it is not a request that can authorize that cancellation.
// Authentication, OPEN digest verification, active/category reservations, real
// byte/work charges, deadlines, provider cleanup and application delivery must
// be enforced by their production owners before supplying these events.
export function verifyStreamStateRegistry(registry) {
  assert.deepEqual(registry, {
    first_sequence: 0, first_offset: 0,
    client_ordinals: 2097168, server_ordinals: 2097152,
    business_lifetime: 1048576, internal_lifetime: 1048576, management_lifetime: 16,
    pending_per_role: 128, terminal_capacity: 4096, rejection_reserve: 128,
    data_limit: "trusted_effective_reliable_limit",
    credit: "monotonic_ack_and_receive_limit", opening: "pending_until_explicit_outcome",
    rejected_receive_limit: "exact_zero", sequence: "uint64_no_wrap",
    terminal: "immutable_per_direction_tuple", retirement: "authenticated_batch_ack_only",
    barrier_cancellation: "trusted_client_prepare_or_closed_session",
    bootstrap: {profiles:["services", "execution"], scope:1, opener:0,
      kind:"flowersec.rpc.v4", metadata_bytes:0, initial_receive_limit:16384,
      creation:"bootstrap_ready"}
  }, "stream state registry drift");
}
const fail = code => { throw new FragmentError(code); };
const MAX = 0xffffffffffffffffn;
const dir = value => { if (value !== 0 && value !== 1) fail("direction"); return value; };
const u64 = value => { if (typeof value !== "bigint" || value < 0n || value > MAX) fail("integer"); return value; };
const epochValue = value => { if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) fail("epoch"); return value; };
const limitValue = value => { if (typeof value !== "bigint" || value < 0n || value > MAX) fail("receive_limit"); return value; };
const boolean = value => { if (typeof value !== "boolean") fail("boolean"); return value; };
const frontier = d => ({epoch:d.epoch, nextSequence:d.sequence, offset:d.offset});
const tuple = t => {
  if (!t || Object.keys(t).sort().join() !== "epoch,nextSequence,offset") fail("terminal_tuple");
  return {epoch:epochValue(t.epoch), nextSequence:u64(t.nextSequence), offset:u64(t.offset)};
};
const same = (a,b) => a.epoch === b.epoch && a.nextSequence === b.nextSequence && a.offset === b.offset;
export function advanceStreamSequence(sequence) { const n=u64(sequence); if (n===MAX) fail("sequence_exhausted"); return n+1n; }

export class StreamState {
  #schema; #registry; #options; #streams=new Map(); #next=[1n,2n]; #epochs=[0,0]; #closed=false;
  #lifetime=[{business:0,internal:0,management:0},{business:0,internal:0,management:0}];
  #batches=[null,null]; #last=[null,null]; #references=new Map(); #nextReference=0n;
  constructor(schema, {maxDataPayloadBytes, handshakeHash, cryptoProfile, referenceCapacity, protectedFuture=0}={}) {
    verifyStreamStateRegistry(schema.stream_state_registry);
    if (!Number.isSafeInteger(maxDataPayloadBytes) || maxDataPayloadBytes<0 || maxDataPayloadBytes>schema.envelope.layout[0].max ||
        !Buffer.isBuffer(handshakeHash) || handshakeHash.length!==32 || !Object.hasOwn(schema.crypto_profiles,cryptoProfile) ||
        !Number.isSafeInteger(referenceCapacity) || referenceCapacity<0 || referenceCapacity>65536 ||
        !Number.isInteger(protectedFuture) || protectedFuture<0 || protectedFuture>schema.stream_state_registry.terminal_capacity-schema.stream_state_registry.rejection_reserve) fail("configuration_capacity");
    this.#schema=structuredClone(schema); this.#registry=this.#schema.stream_state_registry;
    this.#options={maxDataPayloadBytes,handshakeHash:Buffer.from(handshakeHash),cryptoProfile,referenceCapacity,protectedFuture};
  }
  snapshot() {
    return structuredClone({closed:this.#closed,next:this.#next,epochs:this.#epochs,lifetime:this.#lifetime,
      tokens:this.#tokens(),streams:[...this.#streams.values()],batches:this.#batches,last:this.#last,
      references:[...this.#references.values()],nextReference:this.#nextReference});
  }
  #tokens() {
    const counts={future:this.#options.protectedFuture,recent:0,held:0,rejectInUse:0};
    for (const s of this.#streams.values()) { counts[s.phase]++; if (s.reserve==="rejection") counts.rejectInUse++; }
    counts.rejectFree=this.#registry.rejection_reserve-counts.rejectInUse;
    return counts;
  }
  #active() { if (this.#closed) fail("session_closed"); }
  #lookup(id) {
    this.#active(); u64(id);
    const role=Number((id&1n)===0n);
    if (id<1n || id>=this.#next[role]) fail("unknown_stream");
    return this.#streams.get(id); // Absent allocated IDs are permanently stable.
  }
  #live(id) { const s=this.#lookup(id); if (!s || s.phase==="held") fail("stream_stable"); return s; }
  #allocation(opener,id,kind) {
    this.#active(); dir(opener); u64(id);
    if (id<1n || (id&1n)!==BigInt(1-opener)) fail("stream_parity");
    if (id!==this.#next[opener]) fail(id<this.#next[opener]?"stream_replay":"stream_gap");
    const maximum=opener===0?this.#registry.client_ordinals:this.#registry.server_ordinals;
    if ((id+1n)/2n>BigInt(maximum)) fail("stream_quota");
    const cap={business:this.#registry.business_lifetime,internal:this.#registry.internal_lifetime,management:opener===0?this.#registry.management_lifetime:0};
    if (!Object.hasOwn(cap,kind) || this.#lifetime[opener][kind]>=cap[kind]) fail("stream_quota");
  }
  // kind is the trusted allocator's classification, never a peer-supplied label.
  open(opener,id,initialReceiveLimit,kind="business") {
    this.#allocation(opener,id,kind); limitValue(initialReceiveLimit);
    if ([...this.#streams.values()].filter(s=>s.opener===opener && s.status==="pending").length>=this.#registry.pending_per_role) fail("pending_capacity");
    this.#reserve(false);
    const s=this.#create(opener,id,initialReceiveLimit,kind,"positive");
    return {status:s.status,id};
  }
  // A preauthorized direct rejection uses the protected rejection share and
  // creates no accepted/positive stream slot. Ordinary pending rejection keeps
  // its original positive token via outcome; it never takes a second token.
  rejectOpen(opener,id,kind="business") {
    this.#allocation(opener,id,kind); this.#reserve(true);
    const s=this.#create(opener,id,0n,kind,"rejection"); this.#reject(s);
    return {status:s.status,id};
  }
  #reserve(rejection) {
    const t=this.#tokens();
    if (rejection ? t.rejectFree===0 : t.future+t.recent+t.held+t.rejectFree>=this.#registry.terminal_capacity) fail("terminal_capacity");
  }
  #create(opener,id,limit,kind,reserve) {
    const directions=this.#epochs.map(epoch=>({epoch,sequence:0n,offset:0n,limit:0n,ack:0n,
      observed:{epoch,nextSequence:0n,offset:0n},abortIntent:false,isolated:false,terminal:null,wire:null}));
    directions[opener].sequence=1n; directions[opener].observed.nextSequence=1n;
    directions[1-opener].limit=limit;
    const s={id,opener,openEpoch:this.#epochs[opener],status:"pending",phase:"future",reserve,directions,excluded:[false,false]};
    this.#next[opener]+=2n; this.#lifetime[opener][kind]++; this.#streams.set(id,s); return s;
  }
  outcome(opener,id,result,acceptedLimit=0n) {
    dir(opener); u64(id);
    if ((id&1n)!==BigInt(1-opener)) fail("open_owner");
    if (result!=="accepted" && result!=="rejected") fail("outcome");
    limitValue(acceptedLimit); if (result==="rejected" && acceptedLimit!==0n) fail("receive_limit");
    const s=this.#lookup(id);
    if (!s || s.phase==="held") return {status:"ignored"};
    if (s.status!=="pending") fail("outcome_replay");
    if (result==="rejected") this.#reject(s);
    else { s.status="accepted"; s.directions[opener].limit=acceptedLimit; }
    return {status:s.status};
  }
  #reject(s) {
    s.status="rejected"; s.phase="recent";
    for (let i=0;i<2;i++) {
      const d=s.directions[i]; d.limit=0n;
      d.terminal={epoch:s.openEpoch,nextSequence:i===s.opener?1n:0n,offset:0n};
      d.observed={...d.terminal}; d.wire="rejected";
    }
  }
  data(direction,id,epoch,sequence,offset,bytes,fin=false) {
    const n=dir(direction), e=epochValue(epoch), seq=u64(sequence), off=u64(offset); boolean(fin);
    if (!Buffer.isBuffer(bytes) || bytes.length>this.#options.maxDataPayloadBytes) fail("payload");
    const s=this.#lookup(id);
    if (e>this.#epochs[n]) fail("epoch");
    if (!s || s.phase==="held") return {status:"ignored"};
    const d=s.directions[n];
    if (s.status!=="accepted") fail("stream_not_open");
    if (d.terminal) fail("stream_terminal");
    if (e!==d.epoch) fail("epoch");
    if (seq!==d.sequence) fail(seq<d.sequence?"sequence_replay":"sequence_gap");
    if (off!==d.offset) fail(off<d.offset?"offset_replay":"offset_gap");
    const next=d.offset+BigInt(bytes.length); if (next>MAX) fail("offset_overflow");
    if (next>d.limit) fail("credit_exceeded");
    const nextSequence=advanceStreamSequence(seq);
    d.offset=next; d.sequence=nextSequence;
    if (fin) d.terminal=frontier(d); // FIN seals the sender; it is not DRAINED.
    return {status:fin?"fin":"committed",offset:next,sequence:nextSequence};
  }
  observe(direction,id,value) {
    const n=dir(direction), observed=tuple(value), s=this.#live(id), d=s.directions[n];
    if (s.status!=="accepted" || d.isolated || d.wire) fail("receive_closed");
    if (observed.epoch!==d.epoch || observed.epoch!==d.observed.epoch) fail("epoch");
    if (observed.nextSequence<d.observed.nextSequence || observed.nextSequence>d.sequence || observed.offset<d.observed.offset || observed.offset>d.offset ||
        (observed.nextSequence===d.observed.nextSequence && observed.offset!==d.observed.offset) ||
        (observed.nextSequence===d.sequence && observed.offset!==d.offset)) fail("observed_frontier");
    d.observed=observed; return {status:"observed"};
  }
  credit(direction,id,ackOffset,receiveLimit,classification="new") {
    const n=dir(direction), ack=u64(ackOffset), limit=limitValue(receiveLimit), s=this.#lookup(id);
    if (!["new","processed"].includes(classification)) fail("ack_classification");
    if (!s || s.phase==="held") return {status:"ignored"};
    const d=s.directions[n];
    if (s.status!=="accepted") fail("stream_not_open");
    if (classification==="processed") {
      // Only a trusted maintenance-order classifier may label an old ACK.
      if (ack>d.ack || limit>d.limit || limit<ack) fail("ack_classification");
      return {status:"ignored"};
    }
    if (ack<d.ack || ack>d.offset) fail("ack_offset");
    if (limit<d.limit || limit<ack) fail("receive_limit");
    if (d.terminal || d.abortIntent) return {status:"ignored"};
    d.ack=ack; d.limit=limit; return {status:"credited"};
  }
  stop(direction,id) {
    const n=dir(direction), s=this.#lookup(id); if (!s || s.phase==="held") return {status:"ignored"};
    if (s.directions[n].wire) return {status:"ignored"};
    // This is receiver cancellation intent, including while OPEN is pending.
    // It never manufactures the sender's final frontier or erases its outcome.
    s.directions[n].abortIntent=true; return {status:s.status==="pending"?"pending":"stop_requested"};
  }
  stopped(direction,id) {
    const n=dir(direction), s=this.#lookup(id); if (!s || s.phase==="held") return {status:"ignored"};
    if (s.directions[n].wire) return {status:"ignored"};
    if (s.status!=="accepted") fail("stream_not_open");
    const d=s.directions[n];
    // Repeating an already committed FIN frontier does not turn graceful EOF
    // into cancellation. A new sender stop seals an actual abort frontier.
    if (!d.terminal) { d.abortIntent=true; d.terminal=frontier(d); }
    return {status:"stopped",terminal:{...d.terminal}};
  }
  isolate(direction,id) {
    const n=dir(direction), s=this.#live(id), d=s.directions[n];
    if (s.status!=="accepted" || !d.abortIntent) fail("isolation_order");
    d.isolated=true; return {status:"isolated"};
  }
  drained(direction,id,final,observed,outcome) {
    const n=dir(direction), f=tuple(final), o=tuple(observed), s=this.#lookup(id);
    if (!["drained","aborted"].includes(outcome)) fail("outcome");
    if (!s || s.phase==="held") return {status:"ignored"};
    const d=s.directions[n];
    if (s.status!=="accepted" || !d.terminal || !same(f,d.terminal)) fail("terminal_tuple");
    if (!same(o,d.observed) || o.epoch!==f.epoch || o.nextSequence>f.nextSequence || o.offset>f.offset) fail("observed_frontier");
    if (outcome==="drained" ? !same(o,f) : !d.abortIntent || !d.isolated) fail("drained_proof");
    if (d.wire && d.wire!==outcome) fail("terminal_conflict");
    d.wire=outcome;
    if (s.directions.every(value=>value.wire)) s.phase="recent";
    return {status:outcome};
  }
  switchEpoch(direction,epoch) {
    this.#active(); const n=dir(direction), e=epochValue(epoch);
    if (e!==this.#epochs[n]+1) fail("epoch");
    // Trusted completed rekey fence; continuing directions must have their old
    // sender frontier authenticated. Sealed directions retain their old tuple.
    for (const s of this.#streams.values()) {
      const d=s.directions[n];
      if (!d.terminal) { if (!same(frontier(d),d.observed)) fail("epoch_frontier"); continue; }
      // A sealed sender frontier is not itself a completed rekey fence. It
      // must carry authenticated DRAINED evidence (or an isolated ABORTED
      // proof) before the direction may advance epoch.
      if (!d.wire) fail("epoch_frontier");
      if (d.wire === "drained" && !same(d.observed,d.terminal)) fail("epoch_frontier");
      if (d.wire === "aborted" && (!d.isolated || d.observed.epoch!==d.terminal.epoch || d.observed.nextSequence>d.terminal.nextSequence || d.observed.offset>d.terminal.offset)) fail("epoch_frontier");
    }
    this.#epochs[n]=e;
    for (const s of this.#streams.values()) {
      const d=s.directions[n]; if (!d.terminal) { d.epoch=e; d.sequence=0n; d.observed=frontier(d); }
    }
    return {status:"switched",epoch:e};
  }
  hold(id) { return this.#hold(id,"task",null); }
  freezeBarrier(role,id) {
    const r=dir(role), s=this.#live(id);
    // Outgoing barriers may reference only locally-ticketed pending OPENs or
    // live accepted scopes. Recent/stable proofs and opposite-role pending
    // ingress are registered through the authenticated receive path instead.
    if ((s.status==="pending" && s.opener!==r) || s.status==="rejected" || s.phase!=="future") fail("barrier_membership");
    return this.#hold(id,"barrier",r);
  }
  #hold(id,kind,role) {
    const s=this.#live(id);
    if (kind==="barrier" ? s.excluded[role] : s.excluded.some(Boolean)) fail("retire_excluded");
    if (this.#references.size>=this.#options.referenceCapacity) fail("reference_capacity");
    if (kind==="barrier" && [...this.#references.values()].some(r=>r.id===id && r.kind===kind && r.role===role)) fail("barrier_exists");
    const ref=advanceStreamSequence(this.#nextReference);
    this.#references.set(ref,{ref,id,kind,role,publication:kind==="barrier"?"frozen":null}); this.#nextReference=ref;
    return {status:"held",reference:ref};
  }
  publishBarrier(reference) { return this.#publication(reference,"published"); }
  cancelBarrier(reference,cause) { return this.#publication(reference,"cancelled",cause); }
  #publication(reference,value,cause) {
    if (value==="published") this.#active();
    const r=this.#references.get(u64(reference));
    if (!r || r.kind!=="barrier" || r.publication!=="frozen") fail("barrier_publication");
    if (value==="cancelled") {
      if (cause==="client_prepare_cancelled") {
        this.#active();
        if (r.role!==0) fail("barrier_cancellation");
      } else if (cause==="session_closed") {
        if (!this.#closed) fail("barrier_cancellation");
      } else fail("barrier_cancellation");
    }
    r.publication=value; return {status:value};
  }
  release(reference) {
    const r=this.#references.get(u64(reference));
    if (!r || r.publication==="frozen") fail("reference_release");
    this.#references.delete(reference);
    if (this.#streams.get(r.id)?.phase==="held" && ![...this.#references.values()].some(v=>v.id===r.id)) this.#streams.delete(r.id);
    return {status:"released"};
  }
  #unpublished(role,ids) { return [...this.#references.values()].some(r=>r.kind==="barrier" && r.role===role && r.publication==="frozen" && ids.includes(r.id)); }
  retireBatch(role,ids) {
    this.#active(); dir(role);
    if (!Array.isArray(ids) || ids.length<1 || ids.length>this.#schema.resource_caps.retire_batch_items) fail("retire_batch");
    for (let i=0;i<ids.length;i++) { u64(ids[i]); if ((ids[i]&1n)!==BigInt(1-role)) fail("retire_owner"); if (i && ids[i]<=ids[i-1]) fail("retire_order"); }
    const current=this.#batches[role];
    if (current) { if (current.ids.length===ids.length && current.ids.every((v,i)=>v===ids[i])) return {status:"pending",batchSeq:current.seq,digest:current.digest}; fail("retire_pending"); }
    const seq=advanceStreamSequence(this.#last[role]?.seq??0n);
    for (const id of ids) { const s=this.#live(id); if (s.phase!=="recent") fail("retire_proof"); }
    if (this.#unpublished(role,ids)) fail("retire_fence");
    const bytes=encodeCBOR(mapFromNames(this.#schema,"STREAM_ACK_RETIRE_BATCH",{variant:5,batch_seq:seq,scope_ids:ids}));
    const digest=evaluateDomain(this.#schema,"retirement_batch_digest",{handshake_hash:this.#options.handshakeHash,profile:this.#options.cryptoProfile,proposer_role:role,batch:bytes}).output_hex;
    for (const id of ids) this.#streams.get(id).excluded[role]=true;
    this.#batches[role]={seq,ids:[...ids],digest}; return {status:"pending",batchSeq:seq,digest};
  }
  retireAck(role,seq,digest) {
    this.#active(); dir(role); u64(seq);
    if (seq===0n || typeof digest!=="string" || !/^[0-9a-f]{64}$/u.test(digest)) fail("retire_ack");
    const last=this.#last[role];
    if (last && seq<=last.seq) {
      if (seq===last.seq && digest!==last.digest) fail("retire_digest");
      return {status:"ignored"};
    }
    const batch=this.#batches[role];
    if (!batch || batch.seq!==seq) fail("retire_ack");
    if (batch.digest!==digest) fail("retire_digest");
    if (this.#unpublished(1-role,batch.ids)) fail("retire_fence");
    for (const id of batch.ids) {
      const s=this.#streams.get(id); s.excluded=[true,true];
      if ([...this.#references.values()].some(r=>r.id===id)) s.phase="held"; else this.#streams.delete(id);
    }
    this.#last[role]={seq,digest}; this.#batches[role]=null; return {status:"retired"};
  }
  close() {
    // Sealing is not physical cleanup. Preserve proven facts, unknown pending
    // outcomes, held tokens and actual references for the cleanup owner.
    this.#closed=true; return {status:"session_aborted"};
  }
}

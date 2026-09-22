import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ApiResultError, apiFixture, buildApiCorpus, validateApiResult, verifyApiSchema } from "./transport-v4-api-results.mjs";
import { generateApiTypes } from "./transport-v4-api-types.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const MAX = 0xffffffffffffffffn;
const error = {code:"stream_data_invalid",scope:"stream",retry_disposition:"preserve_facts"};
const raw = (length, status="open", wait="ready") => ({data:new Uint8Array(length),progress:{offset:100n+BigInt(length),filled:BigInt(length)},wait_status:wait,stream_status:status,...(status==="error"?{error}:{})});
const ordinary = (length=0, status="open") => ({method:"read",start_offset:100n,transferred:BigInt(length),stream_status:status,...(status==="error"?{stream_error:error}:{}),max_bytes:32n});
const goal = (method, transferred, target, status="open", extra={}) => ({method,start_offset:100n,transferred:BigInt(transferred),stream_status:status,...(status==="error"?{stream_error:error}:{}),cursor_kind:"exact",target:BigInt(target),...extra});
const targeted = (result, target) => ({...result,progress:{...result.progress,target:BigInt(target)}});
const invalid = (type, value, code, context) => assert.throws(() => validateApiResult(schema,type,value,context), caught => caught instanceof ApiResultError && caught.code===code);

test("v4.api_result_reference.wait_matrix: ordinary waits preserve distinct terminal and cancellation facts", () => {
  for (const status of ["open","eof","aborted","error"]) for (const wait of ["ready","blocked","wait_canceled"]) for (const length of [0,1]) {
    const result=raw(length,status,wait), context=ordinary(length,status);
    const legal=wait==="ready" ? length>0 || status!=="open" : length===0 && status==="open";
    if (legal) assert.doesNotThrow(() => validateApiResult(schema,"ReadResult",result,context));
    else assert.throws(() => validateApiResult(schema,"ReadResult",result,context), ApiResultError);
  }
  invalid("ReadResult",raw(0,"eof"),"read_terminal_fact",ordinary(0,"open"));
  invalid("ReadResult",{...raw(0,"eof"),error},"read_error_presence",ordinary(0,"eof"));
  const missing=raw(0,"error"); delete missing.error;
  invalid("ReadResult",missing,"read_error_presence",ordinary(0,"error"));
});

test("v4.api_result_reference.cursor_frontier: canceled wait and public handoff share the retained cursor frontier", () => {
  const context=goal("read_exactly",3,8);
  const canceled=targeted({...raw(0,"open","wait_canceled"),progress:{offset:103n,filled:0n}},8);
  const before=structuredClone(context);
  validateApiResult(schema,"ReadResult",canceled,context);
  assert.deepEqual(context,before,"result validation changed original progress");
  const prefix=targeted(raw(3),8), take={...context,method:"take_prefix"};
  validateApiResult(schema,"ReadResult",prefix,take);
  invalid("ReadResult",{...prefix,progress:{...prefix.progress,offset:106n}},"read_offset",take);
  invalid("ReadResult",{...canceled,progress:{...canceled.progress,offset:100n}},"read_offset",context);
  invalid("ReadResult",{...canceled,progress:{...canceled.progress,filled:3n}},"read_filled",context);
  // The absolute frontier can be much greater than the relative target.
  validateApiResult(schema,"ReadResult",{...prefix,progress:{...prefix.progress,offset:MAX}},{...take,start_offset:MAX-3n});
  invalid("ReadResult",{...prefix,progress:{...prefix.progress,offset:MAX}},"read_offset_overflow",{...take,start_offset:MAX-2n});
});

test("empty successes require original exact-zero or TakePrefix method context", () => {
  validateApiResult(schema,"ReadResult",targeted(raw(0),0),goal("read_exactly",0,0));
  validateApiResult(schema,"ReadResult",targeted(raw(0),8),goal("take_prefix",0,8));
  invalid("ReadResult",raw(0),"read_empty_ready",ordinary());
  invalid("ReadResult",targeted(raw(0),8),"read_empty_ready",goal("read_exactly",0,8));
  invalid("ReadResult",targeted(raw(0),0),"read_target",ordinary());
  invalid("ReadResult",targeted(raw(0),0),"api_object");
  invalid("ReadResult",targeted(raw(0),0),"read_terminal_fact",goal("read_exactly",0,0,"eof"));
  validateApiResult(schema,"ReadResult",targeted(raw(0,"eof"),0),goal("read_exactly",0,0,"eof"));
  validateApiResult(schema,"ReadResult",targeted(raw(0,"open","wait_canceled"),0),goal("read_exactly",0,0));
  invalid("ReadResult",raw(0),"read_parameters",{...ordinary(),max_bytes:0n});
  // An ordinary requested upper bound can exceed the actual local piece size.
  validateApiResult(schema,"ReadResult",raw(1),{...ordinary(1),max_bytes:MAX});
});

test("v4.api_result_reference.target_failures: exact/until results retain partial bytes and true terminal status", () => {
  const partial=targeted({...raw(2,"eof"),cause:"unexpected_eof"},8);
  validateApiResult(schema,"ReadResult",partial,goal("read_exactly",2,8,"eof"));
  validateApiResult(schema,"ReadResult",partial,goal("read_until",2,8,"eof",{cursor_kind:"until",delimiter:new Uint8Array([10])}));
  invalid("ReadResult",targeted(raw(2,"eof"),8),"read_cause",goal("read_exactly",2,8,"eof"));
  invalid("ReadResult",targeted(raw(2),8),"read_goal_incomplete",goal("read_exactly",2,8));
  for (const status of ["aborted","error"]) validateApiResult(schema,"ReadResult",targeted(raw(2,status),8),goal("read_exactly",2,8,status));
  const context=goal("read_until",4,4,"open",{cursor_kind:"until",delimiter:new Uint8Array([10])});
  const noMatch=targeted({...raw(4),cause:"delimiter_not_found"},4);
  validateApiResult(schema,"ReadResult",noMatch,context);
  invalid("ReadResult",targeted(raw(4),4),"read_cause",context);
  const atCap=targeted({...raw(4),data:new Uint8Array([1,2,3,10])},4);
  validateApiResult(schema,"ReadResult",atCap,context);
  invalid("ReadResult",{...atCap,cause:"delimiter_not_found"},"read_cause",context);
  invalid("ReadResult",{...atCap,data:new Uint8Array([1,10,3,10])},"read_delimiter_suffix",context);
});

test("TakePrefix keeps original targets and established causes without creating target failure", () => {
  const prefix=targeted(raw(2),8), context=goal("take_prefix",2,8);
  validateApiResult(schema,"ReadResult",prefix,context);
  invalid("ReadResult",{...prefix,cause:"unexpected_eof"},"read_cause",context);
  const eof=targeted({...raw(2,"eof"),cause:"unexpected_eof"},8);
  validateApiResult(schema,"ReadResult",eof,goal("take_prefix",2,8,"eof",{target_cause:"unexpected_eof"}));
  invalid("ReadResult",targeted(raw(2,"eof"),8),"read_cause",goal("take_prefix",2,8,"eof",{target_cause:"unexpected_eof"}));
  // Early prefix selection need not itself turn a later EOF into target failure.
  validateApiResult(schema,"ReadResult",targeted(raw(2,"eof"),8),goal("take_prefix",2,8,"eof"));
  const cap=goal("take_prefix",4,4,"open",{cursor_kind:"until",delimiter:new Uint8Array([10]),target_cause:"delimiter_not_found"});
  validateApiResult(schema,"ReadResult",targeted({...raw(4),cause:"delimiter_not_found"},4),cap);
  invalid("ReadResult",targeted(raw(4),4),"read_cause",cap);
});

test("cursor method and delimiter constraints are checked before accepting contextual exceptions", () => {
  const result=targeted(raw(0),8);
  for (const delimiter of [new Uint8Array(),new Uint8Array(33),new Uint8Array(9)]) invalid("ReadResult",result,"read_parameters",goal("take_prefix",0,8,"open",{cursor_kind:"until",delimiter}));
  invalid("ReadResult",result,"read_parameters",goal("read_until",0,8));
  invalid("ReadResult",result,"read_parameters",goal("read_line",0,8,"open",{cursor_kind:"until",delimiter:new Uint8Array([13])}));
  invalid("ReadResult",result,"read_parameters",goal("take_prefix",0,8,"open",{target_cause:"unexpected_eof"}));
  invalid("ReadResult",result,"read_parameters",goal("take_prefix",0,8,"open",{max_bytes:8n}));
});

test("v4.api_result_reference.method_failure: refusal metadata binds original cursor facts without payload", () => {
  const cursor={offset:103n,transferred_bytes:3n,target:8n,stream_status:"eof",target_cause:"unexpected_eof",complete:true,frozen:false,delivered:false,closed:false};
  const context={reason:"time_pending",cursor_exists:true,start_offset:100n,transferred_bytes:3n,target:8n,stream_status:"eof",target_cause:"unexpected_eof",complete:true,frozen:false,delivered:false,closed:false,waiting:false};
  const failure={reason:"time_pending",cursor};
  validateApiResult(schema,"ReadMethodFailure",failure,context);
  for (const [field,value] of Object.entries({offset:3n,target:9n,transferred_bytes:2n,stream_status:"open",complete:false,frozen:true,delivered:true,closed:true})) {
    assert.throws(()=>validateApiResult(schema,"ReadMethodFailure",{...failure,cursor:{...cursor,[field]:value}},context),ApiResultError,field);
  }
  invalid("ReadMethodFailure",{...failure,data:new Uint8Array()},"api_unknown_field",context);
  invalid("ReadMethodFailure",{...failure,wait_status:"blocked"},"api_unknown_field",context);
  invalid("ReadMethodFailure",{reason:"time_pending"},"read_failure_owner",context);
  invalid("ReadMethodFailure",{...failure,reason:"already_delivered"},"read_failure_gate",{...context,reason:"already_delivered"});
  const delivered={...cursor,delivered:true};
  validateApiResult(schema,"ReadMethodFailure",{reason:"already_delivered",cursor:delivered},{...context,reason:"already_delivered",delivered:true});
  invalid("ReadMethodFailure",failure,"read_offset_overflow",{...context,start_offset:MAX});
  validateApiResult(schema,"ReadMethodFailure",{reason:"invalid_argument"},{...context,reason:"invalid_argument",cursor_exists:false});
  invalid("ReadMethodFailure",{reason:"invalid_argument"},"api_error_projection",{...context,reason:"invalid_argument",cursor_exists:false,stream_error:{code:"stream_data_invalid",scope:"session",retry_disposition:"preserve_facts"}});
  invalid("ReadMethodFailure",{reason:"closed"},"read_failure_creation",{...context,reason:"closed",cursor_exists:false});
});

test("read errors and failure metadata preserve the exact original typed cause", () => {
  const result=raw(1,"error"), context=ordinary(1,"error");
  validateApiResult(schema,"ReadResult",result,context);
  const substituted={code:"stream_sequence_error",scope:"stream",retry_disposition:"preserve_facts"};
  invalid("ReadResult",{...result,error:substituted},"read_error_fact",context);
  const cursor={offset:101n,transferred_bytes:1n,target:8n,stream_status:"error",stream_error:error,complete:true,frozen:false,delivered:false,closed:true};
  const failure={reason:"closed",cursor};
  const owner={reason:"closed",cursor_exists:true,start_offset:100n,transferred_bytes:1n,target:8n,stream_status:"error",stream_error:error,complete:true,frozen:false,delivered:false,closed:true,waiting:false};
  validateApiResult(schema,"ReadMethodFailure",failure,owner);
  invalid("ReadMethodFailure",{...failure,cursor:{...cursor,stream_error:substituted}},"read_failure_owner",owner);
});

test("v4.api_result_reference.cleanup_facts: send/read terminals are independent of real cleanup progress", () => {
  for (const send_drained of [false,true]) for (const read_terminal of ["eof","abandoned","open","unknown"]) for (const direction of ["c2s","s2c"]) {
    const cleanup_status={status:"cleanup_incomplete",core_cleanup:"complete",pending_callbacks:1n};
    const result={direction,send_drained,read_terminal,cleanup_status,first_error:error};
    validateApiResult(schema,"CloseResult",result);
    const done={...result,cleanup_status:{status:"complete",core_cleanup:"complete",pending_callbacks:0n}};
    validateApiResult(schema,"CloseResult",done);
    assert.equal(done.send_drained,send_drained); assert.equal(done.read_terminal,read_terminal);
  }
  for (const [core_cleanup,pending_callbacks] of [["pending",0n],["complete",1n],["pending",1n]]) {
    invalid("CleanupStatus",{status:"complete",core_cleanup,pending_callbacks},"cleanup_progress");
    for (const status of ["pending","cleanup_incomplete"]) validateApiResult(schema,"CleanupStatus",{status,core_cleanup,pending_callbacks});
  }
  invalid("CleanupStatus",{status:"cleanup_incomplete",core_cleanup:"complete",pending_callbacks:0n},"cleanup_progress");
});

test("v4.api_result_reference.strict_shapes: no lossy integers, arbitrary tuples, hidden properties or raw error chains", () => {
  for (const offset of [0,1,Number.MAX_SAFE_INTEGER+1,-1n,MAX+1n,"1",null]) invalid("ReadProgress",{offset,filled:0n},"api_uint64");
  validateApiResult(schema,"ReadProgress",{offset:MAX,filled:0n,target:MAX});
  for (const [code,entry] of Object.entries(schema.error_code_metadata)) {
    if (entry.scope==="none") continue;
    validateApiResult(schema,"TypedError",{code,scope:entry.scope,retry_disposition:entry.retry});
    invalid("TypedError",{code,scope:entry.scope==="stream"?"session":"stream",retry_disposition:entry.retry},"api_error_projection");
  }
  invalid("TypedError",{...error,cause:new Error("private")},"api_unknown_field");
  invalid("TypedError",{...error,retry_disposition:"retryable"},"api_enum");
  const hidden={...error}; Object.defineProperty(hidden,"cause",{value:"private"});
  invalid("TypedError",hidden,"api_unknown_field");
  const symbolic={...error,[Symbol("raw")]:"private"}; invalid("TypedError",symbolic,"api_unknown_field");
  const accessor={...error}; Object.defineProperty(accessor,"code",{get(){throw Error("getter must not run");},enumerable:true});
  invalid("TypedError",accessor,"api_data_property");
  invalid("TypedError",Object.assign(new Error("private"),error),"api_object");
  invalid("ReadResult",{...raw(1),error:undefined},"api_object",ordinary(1));
  invalid("ReadResult",{...raw(1),data:[0]},"api_bytes",ordinary(1));
});

test("v4.api_result_reference.branded_bytes: shadow metadata cannot forge empty payloads or delimiter contents", () => {
  const hidden=new Uint8Array([42]); Object.defineProperty(hidden,"length",{value:0});
  invalid("ReadResult",{...raw(0,"open","wait_canceled"),data:hidden},"api_bytes",ordinary());
  const substituted=new Uint8Array([42]); Object.defineProperty(substituted,"buffer",{value:new Uint8Array([10]).buffer});
  const until=goal("read_until",1,1,"open",{cursor_kind:"until",delimiter:new Uint8Array([10])});
  invalid("ReadResult",targeted({...raw(1),data:substituted},1),"api_bytes",until);
  for (const name of ["length","buffer","byteOffset","byteLength"]) {
    const data=new Uint8Array([10]); Object.defineProperty(data,name,{get(){throw Error("metadata accessor must not run");}});
    invalid("ReadResult",targeted({...raw(1),data},1),"api_bytes",until);
    invalid("ReadResult",targeted({...raw(1),data:new Uint8Array([10])},1),"api_bytes",{...until,delimiter:data});
  }
  for (const data of [new Proxy(new Uint8Array([1]),{}),new (class extends Uint8Array {})([1])]) invalid("ReadResult",{...raw(1),data},"api_bytes",ordinary(1));
  for (const data of [new Uint8Array([10]),Buffer.from([10])]) validateApiResult(schema,"ReadResult",targeted({...raw(1),data},1),until);
});

test("record and byte proxies are rejected before invoking caller traps", () => {
  let calls=0;
  const trapped=(target,replacements={})=>new Proxy(target,{
    get(object,key) { calls++; return Object.hasOwn(replacements,key)?replacements[key]:Reflect.get(object,key); },
    getPrototypeOf(object) { calls++; return Reflect.getPrototypeOf(object); },
    ownKeys(object) { calls++; return Reflect.ownKeys(object); },
    getOwnPropertyDescriptor(object,key) { calls++; return Reflect.getOwnPropertyDescriptor(object,key); }
  });
  const canceled={...raw(0,"open","wait_canceled"),data:new Uint8Array([42])};
  invalid("ReadResult",trapped(canceled,{data:new Uint8Array()}),"api_object",ordinary());
  invalid("ReadResult",raw(0,"open","wait_canceled"),"api_object",trapped(ordinary(1),{transferred:0n}));
  invalid("TypedError",trapped({...error,scope:"session"},{scope:"stream"}),"api_object");
  invalid("ReadResult",{...raw(0,"error"),error:trapped({...error,scope:"session"},{scope:"stream"})},"api_object",ordinary(0,"error"));
  invalid("ReadResult",{...raw(1),progress:trapped({offset:101n,filled:0n},{filled:1n})},"api_object",ordinary(1));
  invalid("ReadResult",{...raw(1),data:trapped(new Uint8Array([42]))},"api_bytes",ordinary(1));
  const revoked=Proxy.revocable({},{}); revoked.revoke();
  invalid("TypedError",revoked.proxy,"api_object");
  invalid("ReadResult",{...raw(1),data:revoked.proxy},"api_bytes",ordinary(1));
  assert.equal(calls,0,"validation invoked a caller-controlled proxy trap");
});

test("backing metadata cannot execute code or replace the actual payload bytes", () => {
  for (const backing of [new ArrayBuffer(8),new SharedArrayBuffer(8)]) {
    const data=new Uint8Array(backing,2,1); data[0]=10;
    let calls=0;
    const trap=()=>{calls++;throw Error("backing metadata must not run");};
    for (const key of ["byteLength","constructor","valueOf",Symbol.toPrimitive]) Object.defineProperty(backing,key,{get:trap});
    Object.setPrototypeOf(backing,new Proxy(Object.getPrototypeOf(backing),{get:trap,getPrototypeOf:trap}));
    const context=goal("read_until",1,1,"open",{cursor_kind:"until",delimiter:new Uint8Array([10])});
    validateApiResult(schema,"ReadResult",targeted({...raw(1),data},1),context);
    invalid("ReadResult",{...raw(0,"open","wait_canceled"),data},"read_filled",ordinary());
    assert.equal(calls,0);
  }
});

test("schema-owned API corpus has explicit independent oracles and rejects drift", () => {
  const corpus=buildApiCorpus(schema);
  assert.equal(corpus.vectors.length,schema.api_vector_plan.length);
  for (const plan of corpus.vectors.filter(plan=>plan.accept)) assert.doesNotThrow(() => validateApiResult(schema,plan.type,apiFixture(plan.input),apiFixture(plan.context)));
  const ambiguous=structuredClone(schema); ambiguous.api_vector_plan[0].expected_error="read_filled";
  assert.throws(() => buildApiCorpus(ambiguous),/explicit API oracle/u);
  const missing=structuredClone(schema); delete missing.api_vector_plan[0].accept;
  assert.throws(() => buildApiCorpus(missing),/explicit API oracle/u);
  const stale=structuredClone(schema); stale.api_vector_plan.find(v=>v.id==="api_read_owned_prefix").input.progress.filled={$bigint:"0"};
  assert.throws(() => buildApiCorpus(stale),ApiResultError);
});

test("v4.api_result_reference.generated_types: four internal type surfaces derive from the native schema", () => {
  const sha="ab".repeat(32), files=generateApiTypes(schema,sha);
  assert.equal(files.size,4);
  for (const content of files.values()) {
    assert.ok(content.includes(sha)); assert.ok(content.includes("V4ReadResult"));
    assert.ok(content.includes("V4WriteProgress")); assert.ok(content.includes("V4TransferProgress"));
    assert.ok(!content.includes("TransferContext"));
    assert.ok(!content.includes("read_eof_or_abandoned")); assert.ok(!content.includes("ReadContext"));
  }
  const ts=files.get("flowersec-ts/src/generated/transportV4APIResults.ts");
  assert.match(ts,/readonly offset: bigint/u); assert.match(ts,/readonly data: Uint8Array/u);
  assert.match(ts,/readonly target\?: bigint/u); assert.doesNotMatch(ts,/\bnumber\b/u);
  const modified=structuredClone(schema); modified.api_schema.types.ReadProgress.fields.target.optional=undefined;
  delete modified.api_schema.types.ReadProgress.fields.target.optional;
  assert.match(generateApiTypes(modified,sha).get("flowersec-ts/src/generated/transportV4APIResults.ts"),/readonly target: bigint/u);
  for (const mutation of [s=>s.api_schema.types.ReadProgress.fields.offset.type="unknown",s=>s.api_schema.types.ReadProgress.rules.push("unknown_rule"),s=>s.api_schema.types.ReadProgress.fields.offset.type="ReadProgress",s=>s.api_schema.types.ReadProgress.fields.offset.type="ReadContext"]) {
    const broken=structuredClone(schema); mutation(broken); assert.throws(() => verifyApiSchema(broken));
  }
});


test("v4.connection_requirements.schema: finite requirements and semantic guarantees share one schema", () => {
  const defaults = {independent_reliable_read_progress:false, bound_stream_input_isolation:false, datagram:false, local_consumer_tls13_verification:false};
  validateApiResult(schema, "ConnectionRequirements", defaults);
  for (const application_profile of ["transport", "services", "execution"]) validateApiResult(schema, "ConnectionRequirements", {...defaults, application_profile});
  invalid("ConnectionRequirements", {...defaults, application_profile:"auto"}, "api_enum");
  invalid("ConnectionRequirements", {...defaults, datagram:1}, "api_bool");
  invalid("ConnectionRequirements", {...defaults, required_guarantees:[]}, "api_unknown_field");
  for (const value of Object.values(schema.connection_assurance_registry.entries)) {
    validateApiResult(schema, "ConnectionGuarantees", value);
    validateApiResult(schema, "SessionInfo", {application_profile:"transport", selected_features:0n, guarantees:value});
    invalid("ConnectionGuarantees", {...value, endpoint:"hidden"}, "api_unknown_field");
    invalid("ConnectionGuarantees", {...value, local_consumer_tls13_verification:"unknown"}, "api_enum");
  }
  const native = generateApiTypes(schema, "test-schema");
  assert.equal(native.size, 4);
  for (const text of native.values()) {
    assert.ok(text.includes("native_websocket_tls13"));
    assert.ok(text.includes("controlled_terminator") || text.includes("ControlledTerminator"));
  }
});


test("v4.connection_requirements.registry: shared WebSocket definitions cannot assert independent progress", () => {
 for (const [name, value] of Object.entries(schema.connection_assurance_registry.entries)) {
   assert.equal(value.reliable_progress, "shared_ordered");
   assert.equal(value.bound_stream_input_isolation, "shared_failure_scope");
   assert.equal(value.datagram, false);
   assert.equal(value.scope, "complete_direct_path");
   assert.equal(value.assumptions, "authenticated_peer_within_transport_profile");
   const tls = {native_websocket_tls13:"consumer_enforced",native_websocket_loopback:"not_applicable",accepted_websocket:"not_applicable",browser_websocket_terminator:"controlled_terminator"};
   assert.equal(value.local_consumer_tls13_verification, tls[name]);
 }
});

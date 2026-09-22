import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { cborHead, encodeCBOR, decodeCBOR, decodeMap, mapFromNames } from "./transport-v4-codec.mjs";
import { buildArtifacts, verifyCorpus } from "./generate-transport-v4-vectors.mjs";
import { evaluateDomain } from "./transport-v4-domains.mjs";
import { decodeStreamMetadata, composeTypedMetadata, verifyTypedMetadata } from "./transport-v4-metadata.mjs";
import { verifySchema } from "./check-transport-v4-schema.mjs";

function fixture() {
  const {schema,files} = buildArtifacts();
  const corpus = JSON.parse(files.get("testdata/transport_v4/corpus.json"));
  return {schema,corpus,bytes:id=>Buffer.from(corpus.vectors.find(v=>v.id===id).hex,"hex")};
}

test("typed definition digest binds the complete opener-relative definition under its own exact domain", () => {
  const {schema,bytes} = fixture(), definition = bytes("typed_definition_fields");
  const prefix = Buffer.alloc(4); prefix.writeUInt32BE(definition.length);
  const input = Buffer.concat([Buffer.from("flowersec/v4/typed-message-definition\0","ascii"),prefix,definition]);
  const expected = createHash("sha256").update(input).digest("hex");
  const digest = value => evaluateDomain(schema,"typed_message_definition_digest",{definition:encodeCBOR(value)}).output_hex;
  assert.equal(evaluateDomain(schema,"typed_message_definition_digest",{definition}).input_hex,input.toString("hex"));
  assert.equal(evaluateDomain(schema,"typed_message_definition_digest",{definition}).output_hex,expected);
  assert.notEqual(createHash("sha256").update(definition).digest("hex"),expected);
  for (const change of [
    m=>m.set(0n,"other/messages"), m=>m.set(1n,"2"),
    m=>{ const left=m.get(2n); m.set(2n,m.get(3n)); m.set(3n,left); },
    ...[2n,3n].flatMap(side=>[m=>m.get(side).set(0n,Buffer.alloc(32,0x77)),m=>m.get(side).set(1n,"other/1"),m=>m.get(side).set(2n,1n)]),
  ]) { const value=decodeMap(schema,"MessageStreamDefinition",definition); change(value); assert.notEqual(digest(value),expected); }
  // A server opener uses the same two directions; client/server identity is
  // neither a definition field nor a caller-selectable digest argument.
  for (const role of [0,1]) assert.throws(()=>evaluateDomain(schema,"typed_message_definition_digest",{definition,role}),/domain_arguments/u);
  assert.equal(bytes("typed_definition_maximum").length,1+2*(1+2+128)+2*(1+(1+35+131+6)));
});

test("metadata text keys use length-first canonical order only inside their declared schema", () => {
  const {schema,bytes} = fixture(), encoded=bytes("metadata_key_order");
  const value=decodeMap(schema,"StreamMetadata",encoded), values=value.get(2n);
  assert.deepEqual([...values.keys()],["z","aa","é"]);
  assert.throws(()=>decodeCBOR(encoded),/field_id_type/u);
  const fixed=new Map([[0n,new Map([["x",0n]])]]);
  assert.throws(()=>decodeMap(schema,"PING",encodeCBOR(fixed)),/field_id_type/u);
  value.set(2n,new Map([[0n,Buffer.alloc(0)]]));
  assert.throws(()=>decodeMap(schema,"StreamMetadata",encodeCBOR(value)),/field_id_type/u);
  for (const invalid of ["metadata_reverse_text_keys","metadata_duplicate_text_key","typed_metadata_duplicate_value","typed_metadata_reverse_values"]) {
    assert.throws(()=>decodeStreamMetadata(schema,bytes(invalid)),/map_order|duplicate_key/u);
  }
  // Replace one NFC key with its decomposed equivalent without running the
  // encoder, which independently rejects noncanonical source strings.
  const key=Buffer.from("62c3a9","hex"), at=encoded.indexOf(key);
  assert.ok(at>0);
  const decomposed=Buffer.concat([encoded.subarray(0,at),Buffer.from("6365cc81","hex"),encoded.subarray(at+key.length)]);
  assert.throws(()=>decodeStreamMetadata(schema,decomposed),/non_canonical_text/u);
  const prototypeKeys=mapFromNames(schema,"StreamMetadata",{namespace:"acme/chat",version:1,values:JSON.parse('{"__proto__":{"$bytes":""},"constructor":{"$bytes":"00"}}')});
  assert.equal(decodeMap(schema,"StreamMetadata",encodeCBOR(prototypeKeys)).get(2n).size,2);
});

test("ordinary and composed metadata enforce independent item, value and whole-object limits", () => {
  const {schema,bytes}=fixture(), definition=bytes("typed_definition_fields");
  for (const n of [4006,4007,4096]) {
    const application=bytes("metadata_"+n); assert.equal(application.length,n);
    decodeMap(schema,"StreamMetadata",application);
    if(n===4006) assert.equal(composeTypedMetadata(schema,definition,application).length,4096);
    else assert.throws(()=>composeTypedMetadata(schema,definition,application),/map_size/u);
  }
  assert.equal(composeTypedMetadata(schema,definition,Buffer.alloc(0)).length,88);
  assert.deepEqual(decodeStreamMetadata(schema,Buffer.alloc(0)),{schema:undefined,value:undefined});
  assert.equal(decodeStreamMetadata(schema,bytes("metadata_empty_values")).schema,"StreamMetadata");
  for (const id of ["metadata_65_keys","metadata_value_overflow","metadata_over_encoding_cap","typed_metadata_4007","typed_metadata_4096"]) assert.throws(()=>decodeStreamMetadata(schema,bytes(id)),/map_length|field_length|map_size/u);
  decodeStreamMetadata(schema,bytes("metadata_64_keys"));
  decodeStreamMetadata(schema,bytes("metadata_maximum_key"));
});

test("typed metadata composition binds the definition and preserves owned original application bytes", () => {
  const {schema,corpus,bytes}=fixture(), definition=bytes("typed_definition_fields"), original=Buffer.from(definition);
  for (const application of [Buffer.alloc(0),bytes("metadata_empty_values"),bytes("metadata_4006")]) {
    const saved=Buffer.from(application), wrapped=composeTypedMetadata(schema,definition,application);
    assert.equal(wrapped.buffer.byteLength,wrapped.length);
    const received=verifyTypedMetadata(schema,wrapped,definition);
    assert.equal(received.buffer.byteLength,received.length); assert.deepEqual(received,saved);
    received.fill(0); assert.deepEqual(application,saved);
    assert.deepEqual(verifyTypedMetadata(schema,wrapped,definition),saved);
    application.fill(0); assert.deepEqual(verifyTypedMetadata(schema,wrapped,definition),saved);
  }
  assert.deepEqual(definition,original);
  for (const id of ["typed_metadata_bound_empty","typed_metadata_bound_maximum"]) {
    const vector=corpus.vectors.find(v=>v.id===id);
    assert.deepEqual(composeTypedMetadata(schema,Buffer.from(vector.typed_derivation.definition_hex,"hex"),Buffer.from(vector.typed_derivation.application_hex,"hex")),bytes(id));
  }
  const forged=structuredClone(corpus);
  forged.vectors.find(v=>v.id==="typed_metadata_bound_empty").typed_derivation.definition_hex=bytes("typed_definition_maximum").toString("hex");
  assert.throws(()=>verifyCorpus(schema,forged),/typed derivation source drift/u);
  const removed=structuredClone(corpus); delete removed.vectors.find(v=>v.id==="typed_metadata_bound_empty").typed_derivation;
  assert.throws(()=>verifyCorpus(schema,removed),/typed derivation presence drift/u);
  assert.throws(()=>verifyTypedMetadata(schema,bytes("typed_metadata_bound_empty"),bytes("typed_definition_maximum")),/typed_definition_mismatch/u);
  assert.throws(()=>verifyTypedMetadata(schema,Buffer.alloc(0),definition),/typed_metadata_required/u);
  assert.throws(()=>composeTypedMetadata(schema,definition,bytes("typed_metadata_empty")),/reserved_namespace/u);
});

test("metadata internal rejection does not become an OPEN outer schema failure", () => {
  const {schema,corpus,bytes}=fixture();
  const seed=corpus.vectors.find(v=>v.schema==="OPEN_STREAM"&&!v.expected_error);
  const value=decodeMap(schema,"OPEN_STREAM",Buffer.from(seed.hex,"hex"),seed.limits);
  for(const id of ["metadata_bad_namespace_0","metadata_value_wrong_type","typed_metadata_nested_wrapper","typed_metadata_missing_application"]) {
    const metadata=bytes(id); value.set(6n,metadata);
    // Recompute the complete OPEN digest without trying to repair metadata.
    value.set(8n,Buffer.from(evaluateDomain(schema,"open_digest",{open:encodeCBOR(value)}).output_hex,"hex"));
    decodeMap(schema,"OPEN_STREAM",encodeCBOR(value),seed.limits);
    assert.throws(()=>decodeStreamMetadata(schema,metadata));
  }
  const missing=Buffer.from("a0","hex");
  assert.throws(()=>decodeStreamMetadata(schema,missing),/missing_field/u);
  // Unknown or mixed keys cannot become an alternative values grammar.
  const shell=decodeMap(schema,"TypedMessageMetadata",bytes("typed_metadata_empty"));
  const pairs=[Buffer.concat([encodeCBOR("definition"),encodeCBOR(Buffer.alloc(32))]),Buffer.concat([encodeCBOR(0n),encodeCBOR(Buffer.alloc(0))])];
  const outer=Buffer.concat([cborHead(5,3),...[[0n,shell.get(0n)],[1n,shell.get(1n)]].flatMap(([k,v])=>[encodeCBOR(k),encodeCBOR(v)]),encodeCBOR(2n),cborHead(5,2),...pairs]);
  assert.throws(()=>decodeStreamMetadata(schema,outer),/field_id_type/u);
});

test("metadata schema audit rejects ambiguous text maps and recursive embedded application", () => {
  const {schema}=fixture();
  const rejects=(change,pattern)=>{ const copy=structuredClone(schema); change(copy); assert.throws(()=>verifySchema(copy),pattern); };
  rejects(s=>{s.frame_maps.StreamMetadata.fields[2].entries={};},/one value schema/u);
  rejects(s=>{delete s.frame_maps.StreamMetadata.fields[2].values;},/one value schema/u);
  rejects(s=>{s.frame_maps.StreamMetadata.fields[2].keys={type:"uint16"};},/text/u);
  rejects(s=>{s.frame_maps.TypedMessageMetadata.fields[2].entries.application.encoded_schema_ref="TypedMessageMetadata";},/recursive schema/u);
  rejects(s=>{delete s.frame_maps.TypedMessageMetadata.fields[2].entries.application.encoded_schema_ref;},/empty sentinel/u);
  rejects(s=>{s.frame_maps.StreamMetadata.fields[2].max_items=65;},/assertion|false == true/iu);
});

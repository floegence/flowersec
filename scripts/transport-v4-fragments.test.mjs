import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { repositoryRoot } from "./generate-transport-v4-vectors.mjs";
import { decodeFragment, encodeFragment, FragmentError, verifyFragmentCorpus, verifyFragmentRegistry } from "./transport-v4-fragments.mjs";

function fixture() {
  const {schema,files} = buildArtifacts();
  return {schema, registry:schema.fragment_registry, corpus:JSON.parse(files.get("testdata/transport_v4/fragments.json"))};
}

test("fragment registry fixes exact binary lengths and four kind values", () => {
  const {registry}=fixture();
  verifyFragmentRegistry(registry);
  assert.deepEqual(Object.fromEntries(Object.entries(registry.kinds).map(([name,item])=>[name,item.value])), {BEGIN:0,DATA:1,ABORT:2,STOP_OUTPUT:3});
  assert.equal(registry.max_fragment_bytes,16384);
  assert.equal(registry.kinds.DATA.payload_max_bytes,16367);
});

test("fragment codec round trips each registered variant with owned byte payloads", () => {
  const {registry}=fixture();
  const cases=[
    {kind:0,message_serial:1n,reply_to_serial:0xffffffffffffffffn,canonical_header:Buffer.from([0,1,2])},
    {kind:1,message_serial:2n,payload_offset:7,payload_bytes:Buffer.from([3,4,5])},
    {kind:2,message_serial:3n,next_offset:8},
    {kind:3,request_serial:4n},
  ];
  for(const original of cases){
    const encoded=encodeFragment(registry,original), decoded=decodeFragment(registry,encoded);
    if (original.canonical_header || original.payload_bytes) assert.notEqual(decoded.canonical_header ?? decoded.payload_bytes, original.canonical_header ?? original.payload_bytes);
    assert.deepEqual(decoded,original);
  }
});

test("fragment codec enforces truncation, exact lengths, serials and payload caps", () => {
  const {registry}=fixture();
  const positive=encodeFragment(registry,{kind:1,message_serial:1n,payload_offset:0,payload_bytes:Buffer.from([1])});
  for(const bytes of [positive.subarray(0,4),Buffer.concat([positive,Buffer.from([0])]),Buffer.from("00000001ff","hex")]) assert.throws(()=>decodeFragment(registry,bytes),FragmentError);
  assert.throws(()=>encodeFragment(registry,{kind:1,message_serial:1n,payload_offset:0,payload_bytes:Buffer.alloc(16368)}),/payload_length/u);
  assert.throws(()=>encodeFragment(registry,{kind:1,message_serial:1n,payload_offset:0,payload_bytes:"x"}),/payload_type/u);
  assert.throws(()=>encodeFragment(registry,{kind:0,message_serial:1n,reply_to_serial:0n,canonical_header:"x"}),/header_type/u);
  assert.throws(()=>encodeFragment(registry,{kind:0,message_serial:0n,reply_to_serial:1n,canonical_header:Buffer.from([0])}),/message_serial_range/u);
  assert.throws(()=>encodeFragment(registry,{kind:0,message_serial:1n,reply_to_serial:1n,canonical_header:Buffer.alloc(513)}),/header_length/u);
});

test("generated fragment corpus covers positive boundaries and malformed framing", () => {
  const {schema,registry,corpus}=fixture();
  verifyFragmentCorpus(registry,corpus);
  assert.equal(corpus.schema_revision,schema.schema_revision);
  assert.ok(corpus.vectors.some(v=>v.id==="fragment_data_maximum" && v.hex.length/2===16384));
  assert.ok(corpus.vectors.some(v=>v.id==="fragment_unknown_kind" && v.expected_error==="unknown_kind"));
});

test("fragment vectors are present in the generated manifest and traceability", () => {
  const manifest=JSON.parse(fs.readFileSync(path.join(repositoryRoot,"testdata/transport_v4/manifest.json")));
  const trace=JSON.parse(fs.readFileSync(path.join(repositoryRoot,"stability/transport_v4_traceability.json")));
  const ids=new Set(manifest.fragment_vectors.map(vector=>vector.id));
  const entry=trace.entries.find(item=>item.id==="application_fragment_framing");
  assert.ok(entry);
  for(const id of entry.vector_ids) assert.ok(ids.has(id),`missing manifest fragment ${id}`);
  assert.deepEqual(entry.registry_refs,["/fragment_registry"]);
});

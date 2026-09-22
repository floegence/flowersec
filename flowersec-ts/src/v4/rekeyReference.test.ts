// Public fixed transactions only. Expected-byte matching is not a receiver
// codec, barrier proof, epoch installation, clock or single-publisher gate.
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { expand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { gcm } from "@noble/ciphers/aes.js";
import { transportV4Domains, transportV4RekeyRegistry, transportV4RecordRegistry, transportV4Registry } from "../generated/transportV4Registry.js";

type Bytes = Uint8Array;
type Values = Record<string, Bytes | bigint | Values[]>;
type Context = { profile: string; handshake_hash_hex: string; context_digest_hex: string; epoch: number; next_epoch: number; rekey_id_hex: string };
type Phase = { id: string; schema: string; phase: number; role: number; base_hex: string; message_hex: string;
  unsigned_hex: string; key_info_hex: string; key_hex: string; mac_message_hex: string; confirmation_mac_hex: string;
  expected: Record<string, string>; record: { epoch: number; direction: number; sequence: string; wire_hex: string } };
type Round = { id: string; context: Context; input: {client_private_hex: string; server_private_hex: string;
  client_barrier: Record<string, string>[]; server_barrier: Record<string, string>[]; client_old_sequence: string; server_old_sequence: string};
  old_root_hex: string; new_root_hex: string; secret_hex: string; dh_hex: string; prk_hex: string;
  init_digest_hex: string; transcript_hex: string; phases: Phase[] };
type Field = { name: string; type: string; length?: number; const?: number; profile_public_key?: boolean; items?: {schema_ref: string} };
type Definition = { sender_role: number; mac_field: number; fields: Record<string, Field> };
type Layout = readonly {name: string; type: string; const?: number; max?: number}[];
type Part = { name: string; encoding: string; length?: number };
const reg = transportV4RekeyRegistry as unknown as Record<string, Definition>;
const records = transportV4RecordRegistry as { envelope: {layout: Layout}; header: Layout; nonce: Layout; profiles: Record<string, {dh_algorithm: number; dh_public_bytes: number; record_aead: string; tag_bytes: number}> };
const domains = transportV4Domains as unknown as {name: string; label_bytes: string; input_schema: {parts: Part[]}}[];
const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/rekey.json", import.meta.url), "utf8")) as {
  schema_sha256: string; rounds: Round[]; negatives: {id: string; source: string; message_hex: string; base_hex: string; context_patch: Partial<Context>; expected: Record<string,string>}[];
};
const bytes = (s: string): Bytes => Uint8Array.from(Buffer.from(s,"hex"));
const join = (...parts: Bytes[]): Bytes => Uint8Array.from(Buffer.concat(parts));
const ascii = (s: string): Bytes => new TextEncoder().encode(s);
function uint(n: bigint, width: number): Bytes {
  if (n < 0n || n >= 1n << BigInt(8*width)) throw new Error("integer overflow");
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0,n); return b.slice(8-width);
}
function head(major: number, n: bigint): Bytes {
  if (n < 24n) return Uint8Array.of(major*32+Number(n));
  for (const [width,ai] of [[1,24],[2,25],[4,26],[8,27]] as const) if (n < 1n << BigInt(width*8)) return join(Uint8Array.of(major*32+ai),uint(n,width));
  throw new Error("CBOR overflow");
}
function encode(name: string, profile: string, values: Values, unsigned = false): Bytes {
  const def=reg[name]; if (!def) throw new Error("missing schema");
  const fields=Object.entries(def.fields).sort(([a],[b])=>Number(a)-Number(b)).filter(([id])=>!unsigned||Number(id)!==def.mac_field);
  return join(head(5,BigInt(fields.length)),...fields.flatMap(([id,f])=>{
    const v=values[f.name]; let b: Bytes;
    if (f.type.startsWith("uint")) {
      if (typeof v!=="bigint"||v<0n||v>=1n<<BigInt(f.type.slice(4))||(f.const!==undefined&&v!==BigInt(f.const))) throw new Error("integer field");
      b=head(0,v);
    } else if (f.type==="bytes") {
      const length=f.profile_public_key?records.profiles[profile]?.dh_public_bytes:f.length;
      if (!(v instanceof Uint8Array)||v.length!==length) throw new Error("byte field");
      b=join(head(2,BigInt(v.length)),v);
    } else if (f.type==="array") {
      if (!Array.isArray(v)||!f.items) throw new Error("array field");
      b=join(head(4,BigInt(v.length)),...v.map(item=>encode(f.items!.schema_ref,profile,item)));
    } else throw new Error("unsupported field");
    return [head(0,BigInt(id)),b];
  }));
}
function domain(name: string, c: Context, phase=0, role=0, extra: Record<string,Bytes> = {}): Bytes {
  const spec=domains.find(d=>d.name===name); if (!spec) throw new Error("domain");
  const values: Record<string,Bytes>={profile:ascii(c.profile),handshake_hash:bytes(c.handshake_hash_hex),context_digest:bytes(c.context_digest_hex),rekey_id:bytes(c.rekey_id_hex),...extra};
  const ints: Record<string,number>={epoch:c.epoch,next_epoch:c.next_epoch,phase,role};
  return join(bytes(spec.label_bytes),...spec.input_schema.parts.map(p=>{
    if (p.encoding.startsWith("lp-")) {const v=values[p.name];if (!v||(p.length!==undefined&&v.length!==p.length)) throw new Error("domain bytes");return join(uint(BigInt(v.length),4),v);}
    const width=({u8:1,u32:4,u64:8} as Record<string,number>)[p.encoding];
    if (!width||ints[p.name]===undefined) throw new Error("domain integer");return uint(BigInt(ints[p.name]!),width);
  }));
}
function message(c: Context,p: Phase,base: Bytes,values: Values) {
  if (c.next_epoch!==c.epoch+1||c.next_epoch>0xffffffff||base.length!==32) throw new Error("epoch/base");
  const v={...values,phase:BigInt(p.phase),next_epoch:BigInt(c.next_epoch),rekey_id:bytes(c.rekey_id_hex)};
  const role=reg[p.schema]!.sender_role, unsigned=encode(p.schema,c.profile,v,true);
  const info=domain("rekey_confirm_key",c,p.phase,role),key=expand(sha256,base,info,32);
  const macMessage=domain("rekey_confirm_mac",c,p.phase,role,{message:unsigned}),mac=hmac(sha256,key,macMessage);
  return {wire:encode(p.schema,c.profile,{...v,confirmation_mac:mac}),unsigned_hex:unsigned,key_info_hex:info,key_hex:key,mac_message_hex:macMessage,confirmation_mac_hex:mac};
}
function layout(fields: Layout, values: Record<string,bigint>): Bytes {
  return join(...fields.map(f=>{const n=f.const!==undefined?BigInt(f.const):values[f.name],width=({uint8:1,uint16_be:2,uint32_be:4,uint64_be:8} as Record<string,number>)[f.type];if(n===undefined||!width||(f.max!==undefined&&n>BigInt(f.max)))throw new Error("layout");return uint(n,width);}));
}
function recordDomain(name: string,c: Context,integers: Record<string,bigint>,values: Record<string,Bytes>): Bytes {
  const d=domains.find(d=>d.name===name)!;
  return join(bytes(d.label_bytes),...d.input_schema.parts.map(p=>{
    const v={profile:ascii(c.profile),handshake_hash:bytes(c.handshake_hash_hex),...values}[p.name];
    if(p.encoding==="raw")return v!;
    if(p.encoding.startsWith("lp-"))return join(uint(BigInt(v!.length),4),v!);
    return uint(integers[p.name]!,({u8:1,u32:4,u64:8} as Record<string,number>)[p.encoding]!);
  }));
}

it("v4.rekey.ts_reference: independently composes DH, full messages, roots and records",()=>{
  expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);expect(corpus.rounds).toHaveLength(4);
  const previous=new Map<string,string>(), phases=new Map<string,{c:Context;p:Phase;values:Values}>();
  for(const r of corpus.rounds){
    const c=r.context,spec=records.profiles[c.profile]!,x=spec.dh_algorithm===0;
    const cp=x?x25519.getPublicKey(bytes(r.input.client_private_hex)):p256.getPublicKey(bytes(r.input.client_private_hex),false);
    const sp=x?x25519.getPublicKey(bytes(r.input.server_private_hex)):p256.getPublicKey(bytes(r.input.server_private_hex),false);
    const dh=(key:string,pub:Bytes)=>x?x25519.getSharedSecret(bytes(key),pub):p256.getSharedSecret(bytes(key),pub,false).slice(1,33);
    const shared=dh(r.input.client_private_hex,sp);expect(shared.some(b=>b!==0)).toBe(true);expect(shared).toEqual(dh(r.input.server_private_hex,cp));expect(shared).toEqual(bytes(r.dh_hex));
    if(c.epoch>0)expect(r.old_root_hex).toBe(previous.get(c.profile));
    const secret=expand(sha256,bytes(r.old_root_hex),domain("rekey_secret",c),32);expect(secret).toEqual(bytes(r.secret_hex));
    const barrier=(list:Record<string,string>[]):Values[]=>list.map(item=>Object.fromEntries(Object.entries(item).map(([k,v])=>[k,BigInt(v)])));
    const values:Values[]=[{client_ephemeral:cp,client_barrier:barrier(r.input.client_barrier)},{server_ephemeral:sp,server_barrier:barrier(r.input.server_barrier)},{},{}];
    let init:Bytes=new Uint8Array(),reply:Bytes=new Uint8Array(),root:Bytes=new Uint8Array(),t:Bytes=new Uint8Array();
    for(const [i,p] of r.phases.entries()){
      const v=values[i]!;
      if(i===1){v.init_digest=sha256(domain("rekey_init_digest",c,0,0,{init}));expect(v.init_digest).toEqual(bytes(r.init_digest_hex));}
      if(i===2){t=sha256(domain("rekey_transcript",c,0,0,{init,reply}));expect(t).toEqual(bytes(r.transcript_hex));const prk=hmac(sha256,secret,shared);expect(prk).toEqual(bytes(r.prk_hex));root=expand(sha256,prk,domain("rekey_root",c,0,0,{transcript_digest:t}),32);expect(root).toEqual(bytes(r.new_root_hex));}
      const oldSequence=BigInt(p.role===0?r.input.client_old_sequence:r.input.server_old_sequence);
      if(i>=2){v.transcript_digest=t;v.old_maintenance_next_sequence=oldSequence+1n;}
      const base=i<2?secret:root,m=message(c,p,base,v);expect(base).toEqual(bytes(p.base_hex));expect(m.wire).toEqual(bytes(p.message_hex));
      for(const field of ["unsigned_hex","key_info_hex","key_hex","mac_message_hex","confirmation_mac_hex"] as const)expect(m[field],p.id).toEqual(bytes(p[field]));
      if(i===0)init=m.wire;if(i===1)reply=m.wire;phases.set(p.id,{c,p,values:v});
      const epoch=i<2?c.epoch:c.next_epoch,sequence=i<2?oldSequence:0n,ints={epoch:BigInt(epoch),sequence,direction:BigInt(p.role),sequence_scope:0n};
      expect(p.record.epoch).toBe(epoch);expect(p.record.direction).toBe(reg[p.schema]!.sender_role);expect(p.record.sequence).toBe(String(sequence));
      const header=layout(records.header,ints),nonce=layout(records.nonce,ints),envelope=layout(records.envelope.layout,{payload_length:BigInt(header.length+m.wire.length+spec.tag_bytes),frame_type:BigInt(transportV4Registry.frameTypes.REKEY)});
      const key=expand(sha256,i<2?bytes(r.old_root_hex):root,recordDomain("record_key",c,ints,{}),32),aad=recordDomain("record_aad",c,ints,{envelope_header:envelope,record_header:header});
      const cipher=()=>x?chacha20poly1305(key,nonce,aad):gcm(key,nonce,aad),sealed=cipher().encrypt(m.wire);
      expect(join(envelope,header,sealed)).toEqual(bytes(p.record.wire_hex));expect(cipher().decrypt(sealed)).toEqual(m.wire);
    }
    previous.set(c.profile,r.new_root_hex);
  }
  expect(corpus.negatives.length).toBeGreaterThan(0);
  for(const n of corpus.negatives){
    const source=phases.get(n.source)!;expect(source).toBeDefined();const v={...source.values};
    for(const [k,value] of Object.entries(n.expected))v[k]=k==="old_maintenance_next_sequence"?BigInt(value):bytes(value);
    let matched=false;
    try{matched=Buffer.from(message({...source.c,...n.context_patch},source.p,bytes(n.base_hex),v).wire).equals(Buffer.from(bytes(n.message_hex)));}catch{ /* Invalid expected context has no admissible encoding. */ }
    expect(matched,n.id).toBe(false);
  }
});

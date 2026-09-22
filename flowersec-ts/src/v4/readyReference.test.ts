// Public fixture composition, not authenticated credentials or Session authority.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { expand } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { strictEd25519Reference, strictEd25519SignReference } from "./strictEd25519Reference.js";
import { transportV4Domains, transportV4ReadyRegistry, transportV4RecordRegistry, transportV4Registry } from "../generated/transportV4Registry.js";

type Context = Record<string, string | number>;
type Field = { name: string; type: string; length?: number; bitmask?: number; enum?: Record<string, number> };
type Part = { name: string; encoding: string; length?: number; enum?: number[] };
type Domain = { name: string; label_bytes: string; input_schema: { parts: Part[] } };
type Vector = { id: string; context: Context; signing_seed_hex: string; identity_proof_hex: string; ready_hex: string; wire_hex: string; envelope_header_hex: string } & Record<string, unknown>;
type Negative = { id: string; source: string; ready_hex: string; context_patch: Context; expected_error: string };
const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/ready.json", import.meta.url), "utf8")) as { schema_sha256: string; vectors: Vector[]; negatives: Negative[] };
const maps = transportV4ReadyRegistry as unknown as Record<string, { fields: Record<string, Field> }>;
const domains = transportV4Domains as unknown as Domain[];
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const join = (...values: Uint8Array[]) => Uint8Array.from(Buffer.concat(values));
const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const text = (value: string) => new TextEncoder().encode(value);
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((byte, i) => byte === b[i]);

function unsigned(value: bigint, width: number): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(8 * width)) throw new Error("integer range");
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) { out[i] = Number(value & 255n); value >>= 8n; }
  return out;
}
function head(major: number, value: bigint): Uint8Array {
  if (value < 24n && value >= 0n) return new Uint8Array([major * 32 + Number(value)]);
  for (const [width, ai] of [[1,24],[2,25],[4,26],[8,27]] as const) {
    if (value < 1n << BigInt(width * 8)) return join(new Uint8Array([major * 32 + ai]), unsigned(value,width));
  }
  throw new Error("CBOR uint64 overflow");
}
function fields(name: string) { return Object.entries(maps[name]!.fields).sort(([a],[b]) => Number(a)-Number(b)); }
function map(name: string, context: Context): Uint8Array {
  const entries = fields(name);
  return join(head(5,BigInt(entries.length)), ...entries.map(([id,f]) => {
    let value: Uint8Array;
    if (f.type === "bytes") {
      const raw = bytes(String(context[f.name + "_hex"]));
      if (raw.length !== f.length) throw new Error("byte length");
      value = join(head(2,BigInt(raw.length)),raw);
    } else if (f.type === "text") {
      const profile = String(context[f.name]);
      if (!Object.hasOwn(transportV4RecordRegistry.profiles,profile)) throw new Error("profile");
      const raw = text(profile); value = join(head(3,BigInt(raw.length)),raw);
    } else if (f.type === "uint8" || f.type === "uint64") {
      const supplied = context[f.name];
      if (typeof supplied !== "number" || !Number.isSafeInteger(supplied)) throw new Error("integer");
      const n = BigInt(supplied);
      if (n < 0n || (f.type === "uint8" && n > 255n) || (f.enum && !Object.values(f.enum).includes(supplied)) || (f.bitmask !== undefined && (n & ~BigInt(f.bitmask)) !== 0n)) throw new Error("integer constraint");
      value = head(0,n);
    } else throw new Error("READY field");
    return join(head(0,BigInt(id)),value);
  }));
}
function decode(wire: Uint8Array): Context {
  let cursor = 0;
  const take = (expected: Uint8Array) => {
    if (!equal(wire.slice(cursor,cursor+expected.length),expected)) throw new Error("noncanonical READY");
    cursor += expected.length;
  };
  const entries=fields("READY"), out: Context={}; take(head(5,BigInt(entries.length)));
  for (const [id,f] of entries) {
    if (f.type !== "bytes" || f.length === undefined) throw new Error("READY registry");
    take(head(0,BigInt(id))); take(head(2,BigInt(f.length)));
    if (cursor + f.length > wire.length) throw new Error("short READY");
    out[f.name + "_hex"]=hex(wire.slice(cursor,cursor+f.length)); cursor+=f.length;
  }
  if (cursor !== wire.length) throw new Error("READY suffix");
  return out;
}
function domain(name: string, values: Record<string,Uint8Array>, role: number): Uint8Array {
  const spec = domains.find(d=>d.name===name)!;
  return join(bytes(spec.label_bytes), ...spec.input_schema.parts.map(part=> {
    if (part.encoding === "u8") {
      if (part.enum && !part.enum.includes(role)) throw new Error("role");
      return unsigned(BigInt(role),1);
    }
    if (!["lp-map","lp-ascii","lp-bytes"].includes(part.encoding)) throw new Error("READY domain");
    const value=values[part.name]!;
    if (part.length !== undefined && value.length !== part.length) throw new Error("domain length");
    return join(unsigned(BigInt(value.length),4),value);
  }));
}
function material(context: Context, proof: Uint8Array): Record<string,Uint8Array> {
  const role=Number(context.role), proofInput=map("ReadyProofInput",context);
  const message=domain("ready_identity",{proof:proofInput},role);
  const info=domain("ready_key",{profile:text(String(context.crypto_profile_id)),handshake_hash:bytes(String(context.handshake_hash_hex)),context_digest:bytes(String(context.transport_context_digest_hex))},role);
  const root=bytes(String(context.epoch_root_hex)); if(root.length!==32) throw new Error("root length");
  const key=expand(sha256,root,info,32);
  const macInput=map("ReadyMACInput",{...context,identity_proof_hex:hex(proof)});
  const macMessage=domain("ready_mac",{mac_input:macInput},role), mac=hmac(sha256,key,macMessage);
  return {proof_input_hex:proofInput,signature_message_hex:message,key_info_hex:info,key_hex:key,mac_input_hex:macInput,mac_message_hex:macMessage,confirmation_mac_hex:mac};
}
function verify(context: Context, wire: Uint8Array): boolean {
  try {
    const received=decode(wire), proof=bytes(String(received.identity_proof_hex)), m=material(context,proof);
    return equal(bytes(String(received.confirmation_mac_hex)),m.confirmation_mac_hex!) && strictEd25519Reference(proof,m.signature_message_hex!,bytes(String(context.public_key_hex)));
  } catch { return false; }
}

describe("v4.ready.ts_reference",()=> {
  it("independently encodes, derives, signs and verifies the shared composition",()=> {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    expect(corpus.vectors).toHaveLength(8); expect(corpus.negatives.length).toBeGreaterThan(0);
    for (const v of corpus.vectors) {
      const proof=bytes(v.identity_proof_hex), m=material(v.context,proof);
      for (const [name,value] of Object.entries(m)) expect(hex(value),v.id+name).toBe(v[name]);
      expect(strictEd25519SignReference(m.signature_message_hex!,bytes(v.signing_seed_hex))).toEqual(proof);
      const ready=map("READY",{identity_proof_hex:hex(proof),confirmation_mac_hex:hex(m.confirmation_mac_hex!)});
      const values: Record<string,number>={payload_length:ready.length,frame_type:transportV4Registry.frameTypes.READY};
      const envelope=join(...transportV4RecordRegistry.envelope.layout.map(f=> {
        const field=f as {name:string;type:string;const?:number};
        return unsigned(BigInt(field.const??values[field.name]!),({uint8:1,uint16_be:2,uint32_be:4} as Record<string,number>)[field.type]!);
      }));
      expect(hex(ready)).toBe(v.ready_hex); expect(hex(envelope)).toBe(v.envelope_header_hex); expect(hex(join(envelope,ready))).toBe(v.wire_hex);
      expect(verify(v.context,ready),v.id).toBe(true);
    }
    const byID=new Map(corpus.vectors.map(v=>[v.id,v]));
    for (const n of corpus.negatives) {
      expect(n.expected_error).toBe("ready_rejected");
      expect(verify({...byID.get(n.source)!.context,...n.context_patch},bytes(n.ready_hex)),n.id).toBe(false);
    }
  });
});

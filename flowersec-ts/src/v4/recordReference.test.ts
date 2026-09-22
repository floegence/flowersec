// Fixed public fixtures; no runtime READY, sequence/replay or key-use authority.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { gcm } from "@noble/ciphers/aes.js";
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { transportV4Domains, transportV4RecordRegistry, transportV4Registry } from "../generated/transportV4Registry.js";

type Field = { name: string; type: string; const?: number; max?: number };
type Part = { name: string; encoding: string; length?: number; enum?: readonly number[] };
type Domain = { name: string; label_bytes: string; input_schema: { parts: Part[] } };
type Vector = {
  id: string; profile: string; algorithm: string; epoch: number; direction: number;
  sequence_scope: string; sequence: string; frame_type: number; epoch_root_hex: string; handshake_hash_hex: string;
  key_info_hex: string; key_hex: string; nonce_hex: string; envelope_header_hex: string; record_header_hex: string;
  aad_hex: string; plaintext_hex: string; ciphertext_hex: string; wire_hex: string;
};
type Negative = { id: string; source: string; field: "key" | "nonce" | "aad" | "ciphertext"; value_hex: string; expected_error: string };
const corpus = JSON.parse(readFileSync(new URL("../../../testdata/transport_v4/records.json", import.meta.url), "utf8")) as {
  schema_sha256: string; vectors: Vector[]; negatives: Negative[];
};
const registry = transportV4RecordRegistry as { header: readonly Field[]; nonce: readonly Field[]; envelope: { layout: readonly Field[] }; profiles: Record<string, { record_aead: string; tag_bytes: number }> };
const domains = transportV4Domains as unknown as Domain[];
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const join = (...values: Uint8Array[]) => Uint8Array.from(Buffer.concat(values));
const text = (value: string) => new TextEncoder().encode(value);

function layout(fields: readonly Field[], values: Record<string, number | bigint>): Uint8Array {
  return join(...fields.map(field => {
    const width = ({ uint8: 1, uint16_be: 2, uint32_be: 4, uint64_be: 8 } as Record<string, number>)[field.type];
    const supplied = field.const ?? values[field.name];
    if (!width || supplied === undefined || (typeof supplied === "number" && !Number.isSafeInteger(supplied))) throw new Error("invalid record integer");
    const value = BigInt(supplied);
    if (value < 0n || value >= 1n << BigInt(width * 8) || (field.max !== undefined && value > BigInt(field.max))) throw new Error("record integer range");
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, value, false);
    return out.slice(8 - width);
  }));
}

function domain(name: string, values: Record<string, Uint8Array>, integers: Record<string, number | bigint>): Uint8Array {
  const spec = domains.find(d => d.name === name);
  if (!spec) throw new Error("missing domain");
  return join(bytes(spec.label_bytes), ...spec.input_schema.parts.map(part => {
    if (["raw", "lp-bytes", "lp-ascii"].includes(part.encoding)) {
      const value = values[part.name];
      if (!value || (part.length !== undefined && part.length !== value.length)) throw new Error("invalid domain bytes");
      if (part.encoding === "lp-ascii" && value.some(b => b > 127)) throw new Error("non-ascii profile");
      return part.encoding === "raw" ? value : join(layout([{ name: "length", type: "uint32_be" }], { length: value.length }), value);
    }
    const type = ({ u8: "uint8", u32: "uint32_be", u64: "uint64_be" } as Record<string, string>)[part.encoding];
    if (!type || (part.enum && !part.enum.some(n => BigInt(n) === BigInt(integers[part.name]!)))) throw new Error("invalid domain integer");
    return layout([{ name: part.name, type }], integers);
  }));
}

function cipher(algorithm: string, key: Uint8Array, nonce: Uint8Array, aad: Uint8Array) {
  if (key.length !== 32) throw new Error("record key length");
  switch (algorithm) {
    case "chacha20-poly1305": return chacha20poly1305(key, nonce, aad);
    case "aes-256-gcm": return gcm(key, nonce, aad);
    default: throw new Error("unknown record algorithm");
  }
}

describe("v4.record.ts_reference", () => {
  it("compares independent encodings, key derivation and both AEAD profiles", () => {
    expect(corpus.schema_sha256).toBe(transportV4Registry.schemaSHA256);
    expect(corpus.vectors.length).toBeGreaterThan(0);
    for (const v of corpus.vectors) {
      const spec = registry.profiles[v.profile]!;
      expect(spec.record_aead).toBe(v.algorithm);
      const integers = { epoch: v.epoch, direction: v.direction, sequence_scope: BigInt(v.sequence_scope), sequence: BigInt(v.sequence) };
      const header = layout(registry.header, integers), nonce = layout(registry.nonce, integers), plaintext = bytes(v.plaintext_hex);
      const envelope = layout(registry.envelope.layout, { payload_length: header.length + plaintext.length + spec.tag_bytes, frame_type: v.frame_type });
      const info = domain("record_key", { profile: text(v.profile), handshake_hash: bytes(v.handshake_hash_hex) }, integers);
      const key = expand(sha256, bytes(v.epoch_root_hex), info, 32);
      const aad = domain("record_aad", { profile: text(v.profile), envelope_header: envelope, record_header: header }, integers);
      const ciphertext = cipher(spec.record_aead, key, nonce, aad).encrypt(plaintext);
      for (const [actual, expected] of [[header, v.record_header_hex], [nonce, v.nonce_hex], [envelope, v.envelope_header_hex],
        [info, v.key_info_hex], [key, v.key_hex], [aad, v.aad_hex], [ciphertext, v.ciphertext_hex],
        [join(envelope, header, ciphertext), v.wire_hex]] as const) expect(actual, v.id).toEqual(bytes(expected));
      expect(cipher(spec.record_aead, key, nonce, aad).decrypt(ciphertext), v.id).toEqual(plaintext);
    }
  });

  it("rejects every generated authentication mutation", () => {
    expect(corpus.negatives.length).toBeGreaterThan(0);
    const byID = new Map(corpus.vectors.map(v => [v.id, v]));
    for (const n of corpus.negatives) {
      expect(n.expected_error).toBe("record_authentication_failed");
      expect(["key", "nonce", "aad", "ciphertext"]).toContain(n.field);
      const original = byID.get(n.source);
      expect(original).toBeDefined();
      const v = { ...original!, [`${n.field}_hex`]: n.value_hex };
      expect(() => cipher(v.algorithm, bytes(v.key_hex), bytes(v.nonce_hex), bytes(v.aad_hex)).decrypt(bytes(v.ciphertext_hex)), n.id).toThrow();
    }
  });
});

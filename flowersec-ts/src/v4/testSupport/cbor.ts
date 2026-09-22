// Independent test-only canonical syntax reference. No field or live authority.
import { transportV4CBORRegistryJSON } from "../../generated/transportV4Registry.js";
import { NFC, V4Failure } from "./unicode.js";

export type Value =
  | { kind: "uint"; value: bigint }
  | { kind: "bytes"; value: Uint8Array }
  | { kind: "text"; value: string }
  | { kind: "bool"; value: boolean }
  | { kind: "null" }
  | { kind: "array"; value: Value[] }
  | { kind: "map"; value: [Value, Value][] };
export type Field = {
  name?: string; type?: string; schema_ref?: string; encoded_schema_ref?: string; nullable?: boolean;
  allow_empty?: boolean; max_items_ref?: string; items?: Field;
  entries?: Record<string, Field>; values?: Field; keys?: Field;
  context?: string; cases?: Record<string, Field>;
  min?: number | string; max?: number | string; const?: unknown; bitmask?: number;
  enum?: Record<string, number>; enum_ref?: string;
  min_bytes?: number; max_bytes?: number; length?: number; nonzero?: boolean;
  min_items?: number; max_items?: number; max_ref?: string;
  const_ref?: string; pattern_ref?: string; text_enum_ref?: string;
  profile_public_key?: boolean; forbidden_prefix?: string; text_format?: string;
  [key: string]: unknown;
};
export type MapDescriptor = {
  fields: Record<string, Field>; required: number[]; context_fields?: Record<string, string>;
  max_encoded_bytes?: number; max_encoded_bytes_ref?: string; encoded_bytes?: number;
  signature_field?: number; mac_field?: number;
};
export type Registry = {
  encoding: { max_depth: number; max_map_entries: number; ordinary_array_items: number; max_field_id: number };
  frame_maps: Record<string, MapDescriptor>;
  field_registries: Record<string, unknown>;
  variant_rules: Record<string, Record<string, unknown>[]>;
  relation_rules: Record<string, Record<string, unknown>[]>;
  text_rules: Record<string, Record<string, unknown>[]>;
  map_projections: Record<string, { source: string; target: string; fields: string[] }>;
  unicode: { nfc_data: { path: string; sha256: string }; idna_data: { path: string; sha256: string } };
};
export type Limits = Readonly<Record<string, bigint>>;
type Counter = { nodes: number };
export type Decoded = { ok: true; value: Value; nodes: number } | { ok: false; error: string; nodes: number };
export const utf8 = new TextEncoder();
export const uint = (value: bigint): Value => ({ kind: "uint", value });
export const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);
export function compare(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}
export function join(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((n, part) => n + part.length, 0);
  if (!Number.isSafeInteger(length)) throw new V4Failure("map_size");
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
export function head(major: number, value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new V4Failure("integer_range");
  if (value < 24n) return Uint8Array.of(major << 5 | Number(value));
  const [ai, width] = value <= 255n ? [24, 1] : value <= 65535n ? [25, 2] : value <= 0xffffffffn ? [26, 4] : [27, 8];
  const out = new Uint8Array(1 + width!); out[0] = major << 5 | ai!;
  for (let i = width!; i > 0; i--) { out[i] = Number(value & 255n); value >>= 8n; }
  return out;
}
export function encode(value: Value): Uint8Array {
  switch (value.kind) {
    case "uint": return head(0, value.value);
    case "bytes": return join([head(2, BigInt(value.value.length)), value.value]);
    case "text": { const raw = utf8.encode(value.value); return join([head(3, BigInt(raw.length)), raw]); }
    case "bool": return Uint8Array.of(value.value ? 0xf5 : 0xf4);
    case "null": return Uint8Array.of(0xf6);
    case "array": return join([head(4, BigInt(value.value.length)), ...value.value.map(encode)]);
    case "map": return join([head(5, BigInt(value.value.length)), ...value.value.flatMap(([key, item]) => [encode(key), encode(item)])]);
  }
}
export function own<T>(object: Record<string, T> | undefined, key: string): T | undefined {
  return object && Object.hasOwn(object, key) ? object[key] : undefined;
}

export class Reference {
  readonly registry = JSON.parse(transportV4CBORRegistryJSON) as Registry;
  readonly nfc = new NFC(this.registry.unicode.nfc_data.path, this.registry.unicode.nfc_data.sha256);

  decode(input: Uint8Array, schema = "", limits: Limits = {}, cap: bigint): Decoded {
    const count: Counter = { nodes: 0 };
    try { return { ok: true, value: this.document(input, schema, limits, cap, count), nodes: count.nodes }; }
    catch (error) {
      if (!(error instanceof V4Failure)) throw error;
      return { ok: false, error: error.code, nodes: count.nodes };
    }
  }

  documentField(length: bigint, schema: string, limits: Limits, cap: bigint): Field {
    if (cap <= 0n) throw new V4Failure("limit_unresolved");
    let field: Field = {};
    if (schema !== "") {
      const map = own(this.registry.frame_maps, schema);
      if (!map) throw new V4Failure("unknown_schema");
      if (map.max_encoded_bytes !== undefined) cap = cap < BigInt(map.max_encoded_bytes) ? cap : BigInt(map.max_encoded_bytes);
      if (map.max_encoded_bytes_ref) {
        const bound = own(limits, map.max_encoded_bytes_ref);
        if (bound === undefined || bound <= 0n) throw new V4Failure("limit_unresolved");
        cap = cap < bound ? cap : bound;
      }
      field = { type: "map", schema_ref: schema };
    }
    if (length > cap) throw new V4Failure("map_size");
    return field;
  }

  document(input: Uint8Array, schema: string, limits: Limits, cap: bigint, count: Counter): Value {
    // No input copy or parsed node before the caller/schema byte cap.
    const field = this.documentField(BigInt(input.length), schema, limits, cap);
    const reader = new Reader(this, input, limits, count), value = reader.item(0, field);
    if (reader.offset !== input.length) throw new V4Failure("trailing_bytes");
    return value;
  }
}

class Reader {
  offset = 0;
  private readonly decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  constructor(private readonly reference: Reference, private readonly input: Uint8Array, private readonly limits: Limits, private readonly count: Counter) {}

  private take(n: bigint): Uint8Array {
    if (n > BigInt(this.input.length - this.offset)) throw new V4Failure("truncated");
    const start = this.offset; this.offset += Number(n);
    return this.input.subarray(start, this.offset);
  }

  item(depth: number, field: Field = {}): Value {
    const policy = this.reference.registry.encoding;
    if (depth > policy.max_depth) throw new V4Failure("depth_limit");
    const byte = this.take(1n)[0]!, major = byte >> 5, ai = byte & 31;
    if (ai === 31) throw new V4Failure("indefinite_length");
    if (major === 7) {
      let value: Value;
      if (ai === 20 || ai === 21) value = { kind: "bool", value: ai === 21 };
      else if (ai === 22 && field.type === "uint64" && field.nullable) value = { kind: "null" };
      else throw new V4Failure("unsupported_type");
      this.count.nodes += 1; return value;
    }
    if (![0, 2, 3, 4, 5].includes(major)) throw new V4Failure("unsupported_type");
    if (ai > 27) throw new V4Failure("invalid_header");
    let n = BigInt(ai);
    if (ai >= 24) {
      n = this.take(1n << BigInt(ai - 24)).reduce((value, byte) => value << 8n | BigInt(byte), 0n);
      if (n < [24n, 256n, 65536n, 4294967296n][ai - 24]!) throw new V4Failure("non_shortest_integer");
    }
    if (major === 0) { this.count.nodes += 1; return uint(n); }
    if (major === 2 || major === 3) {
      if (major === 2 && field.encoded_schema_ref && !(field.allow_empty && n === 0n)) {
        // Declared embedded length is checked before extraction/copying.
        this.reference.documentField(n, field.encoded_schema_ref, this.limits, n > 0n ? n : 1n);
      }
      const raw = this.take(n);
      let value: Value;
      if (major === 3) {
        let text: string;
        try { text = this.decoder.decode(raw); }
        catch { throw new V4Failure("invalid_utf8"); }
        for (const scalar of text) if (!this.reference.nfc.assigned(scalar.codePointAt(0)!)) throw new V4Failure("unassigned_code_point");
        if (!equal(utf8.encode(this.reference.nfc.normalize(text)), raw)) throw new V4Failure("non_canonical_text");
        value = { kind: "text", value: text };
      } else {
        if (field.encoded_schema_ref && !(field.allow_empty && raw.length === 0)) this.reference.document(raw, field.encoded_schema_ref, this.limits, BigInt(raw.length) + 1n, this.count);
        value = { kind: "bytes", value: new Uint8Array(raw) };
      }
      this.count.nodes += 1; return value;
    }
    if (major === 4) {
      let cap = BigInt(policy.ordinary_array_items);
      if (field.max_items_ref) {
        const bound = own(this.limits, field.max_items_ref);
        if (bound === undefined || bound < 0n || bound > 0xffffffffn) throw new V4Failure("limit_unresolved");
        cap = bound;
      }
      if (n > cap) throw new V4Failure("array_limit");
      if (n > BigInt(this.input.length - this.offset)) throw new V4Failure("truncated");
      this.count.nodes += 1;
      const value: Value[] = [];
      for (let i = 0; i < Number(n); i++) value.push(this.item(depth + 1, field.items));
      return { kind: "array", value };
    }
    if (n > BigInt(policy.max_map_entries)) throw new V4Failure("map_limit");
    if (n > BigInt(Math.floor((this.input.length - this.offset) / 2))) throw new V4Failure("truncated");
    this.count.nodes += 1;
    const value: [Value, Value][] = [], seen = new Set<string>();
    let previous: Uint8Array | undefined;
    for (let i = 0; i < Number(n); i++) {
      const start = this.offset, key = this.item(depth + 1);
      let child: Field | undefined;
      if (key.kind === "uint" && field.type !== "text_map" && key.value <= BigInt(policy.max_field_id)) child = own(own(this.reference.registry.frame_maps, field.schema_ref ?? "")?.fields, key.value.toString());
      else if (key.kind === "text" && field.type === "text_map") child = own(field.entries, key.value) ?? field.values;
      else throw new V4Failure("field_id_type");
      const raw = this.input.subarray(start, this.offset), identity = Buffer.from(raw).toString("hex");
      if (seen.has(identity)) throw new V4Failure("duplicate_key");
      if (previous && compare(previous, raw) >= 0) throw new V4Failure("map_order");
      seen.add(identity); previous = raw;
      value.push([key, this.item(depth + 1, child)]);
    }
    return { kind: "map", value };
  }
}

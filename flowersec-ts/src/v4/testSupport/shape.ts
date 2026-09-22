// Generated field validation only; variants, relations and live authority are separate.
import { Reference, encode, equal, own, utf8 } from "./cbor.js";
import type { Field, Limits, MapDescriptor, Value } from "./cbor.js";
import { V4Failure } from "./unicode.js";

export type Context = { readonly limits: Limits; readonly selectors: Readonly<Record<string, string>> };
export const emptyContext = (): Context => ({ limits: {}, selectors: {} });
export function integer(value: unknown): bigint {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value)) {
    const n = BigInt(value); if (n <= 0xffffffffffffffffn) return n;
  }
  throw new V4Failure("registry_unresolved");
}
export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new V4Failure("registry_unresolved");
  return value as Record<string, unknown>;
}
function text(value: unknown): string {
  if (typeof value !== "string") throw new V4Failure("registry_unresolved"); return value;
}
export function lookup(value: Value, id: bigint): Value | undefined {
  if (value.kind !== "map") return undefined;
  return value.value.find(([key]) => key.kind === "uint" && key.value === id)?.[1];
}

export class Shape {
  readonly syntax = new Reference();
  readonly registry = this.syntax.registry;
  private readonly patterns = new Map(Object.entries(record(this.fieldRegistry("text_patterns"))).map(([key, pattern]) => [key, new RegExp(text(pattern), "u")]));

  decode(input: Uint8Array, name = "", context: Context = emptyContext(), cap: bigint): Value {
    const result = this.syntax.decode(input, name, context.limits, cap);
    if (!result.ok) throw new V4Failure(result.error);
    if (name) this.checkMap(name, result.value, context);
    return result.value;
  }

  descriptor(name: string): MapDescriptor {
    const map = own(this.registry.frame_maps, name);
    if (!map) throw new V4Failure("unknown_schema"); return map;
  }

  fieldRegistry(name: string): unknown {
    const value = own(this.registry.field_registries, name);
    if (value === undefined) throw new V4Failure("registry_unresolved"); return value;
  }

  mapContext(map: MapDescriptor, value: Value, original: Context): Context {
    // Containing discriminators affect only descendants, not caller or siblings.
    const selectors = { ...original.selectors };
    for (const [selector, name] of Object.entries(map.context_fields ?? {})) {
      const entry = Object.entries(map.fields).find(([, field]) => field.name === name);
      if (!entry) throw new V4Failure("registry_unresolved");
      const [id, field] = entry, actual = lookup(value, BigInt(id));
      if (!actual) throw new V4Failure("missing_field");
      if (actual.kind !== "uint") throw new V4Failure("integer_type");
      const label = Object.entries(field.enum ?? {}).find(([, n]) => integer(n) === actual.value)?.[0];
      if (label === undefined) throw new V4Failure("context_unresolved");
      selectors[selector] = label;
    }
    return { limits: original.limits, selectors };
  }

  checkMap(name: string, value: Value, original: Context): void {
    const map = this.descriptor(name);
    if (value.kind !== "map") throw new V4Failure("map_type");
    const context = this.mapContext(map, value, original);
    for (const [key, item] of value.value) {
      if (key.kind !== "uint") throw new V4Failure("field_id_type");
      const field = own(map.fields, key.value.toString());
      if (!field) throw new V4Failure("unknown_field");
      this.checkField(field, item, context);
    }
    for (const id of map.required) if (lookup(value, integer(id)) === undefined) throw new V4Failure("missing_field");
    const count = BigInt(encode(value).length);
    if (map.max_encoded_bytes !== undefined && count > integer(map.max_encoded_bytes)) throw new V4Failure("map_size");
    if (map.encoded_bytes !== undefined && count !== integer(map.encoded_bytes)) throw new V4Failure("map_size");
    if (map.max_encoded_bytes_ref) {
      const bound = own(context.limits, map.max_encoded_bytes_ref);
      if (bound === undefined || bound <= 0n) throw new V4Failure("limit_unresolved");
      if (count > bound) throw new V4Failure("map_size");
    }
  }

  private bounded(n: bigint, min: unknown, max: unknown, exact: unknown, code: string): void {
    if (min !== undefined && n < integer(min) || max !== undefined && n > integer(max) || exact !== undefined && n !== integer(exact)) throw new V4Failure(code);
  }

  checkField(field: Field, value: Value, context: Context): void {
    const kind = field.type;
    if (kind === "context_variant") {
      const selected = field.context ? own(context.selectors, field.context) : undefined;
      const descriptor = selected === undefined ? undefined : own(field.cases, selected);
      if (!descriptor) throw new V4Failure("context_unresolved");
      return this.checkField(descriptor, value, context);
    }
    if (kind === "uint64" && field.nullable && value.kind === "null") return;
    if (["uint8", "uint16", "uint32", "uint64"].includes(kind ?? "")) {
      if (value.kind !== "uint") throw new V4Failure("integer_type");
      const n = value.value, width = BigInt(kind!.slice(4));
      if (n < 0n || n >= 1n << width) throw new V4Failure("integer_range");
      this.bounded(n, field.min, field.max, undefined, "field_range");
      if (field.bitmask !== undefined && (n & ~integer(field.bitmask)) !== 0n) throw new V4Failure("unknown_bits");
      if (field.const !== undefined && n !== integer(field.const)) throw new V4Failure("constant_mismatch");
      if (field.enum && !Object.values(field.enum).some(item => integer(item) === n)) throw new V4Failure("enum_value");
      if (field.enum_ref) {
        const items = Object.values(record(this.fieldRegistry(field.enum_ref)));
        if (!items.some(item => integer(typeof item === "object" && item !== null ? record(item).code : item) === n)) throw new V4Failure("enum_value");
      }
      return;
    }
    if (kind === "bytes" || kind === "text") {
      if (value.kind !== kind) throw new V4Failure("field_type");
      const raw = value.kind === "bytes" ? value.value : utf8.encode(value.value), n = BigInt(raw.length);
      this.bounded(n, field.min_bytes, field.max_bytes, field.length, "field_length");
      if (field.nonzero && raw.every(byte => byte === 0)) throw new V4Failure("field_nonzero");
      if (field.profile_public_key) {
        const name = own(context.selectors, "crypto_profile_id");
        const profileValue = name === undefined ? undefined : own(record(this.fieldRegistry("crypto_profiles")), name);
        if (!profileValue) throw new V4Failure("context_unresolved");
        const profile = record(profileValue);
        if (n !== integer(profile.dh_public_bytes)) throw new V4Failure("field_length");
        if (integer(profile.dh_algorithm) === 1n && raw[0] !== 4) throw new V4Failure("field_prefix");
      }
      if (field.const !== undefined && !equal(raw, utf8.encode(text(field.const)))) throw new V4Failure("constant_mismatch");
      if (field.const_ref && !equal(raw, utf8.encode(text(this.fieldRegistry(field.const_ref))))) throw new V4Failure("constant_mismatch");
      if (field.pattern_ref) {
        const pattern = this.patterns.get(field.pattern_ref);
        if (!pattern) throw new V4Failure("pattern_unresolved");
        const input = value.kind === "text" ? value.value : new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
        const match = pattern.exec(input);
        if (!match || match.index !== 0 || match[0].length !== input.length) throw new V4Failure("text_pattern");
      }
      if (field.text_enum_ref && (value.kind !== "text" || !Object.hasOwn(record(this.fieldRegistry(field.text_enum_ref)), value.value))) throw new V4Failure("enum_value");
      if (field.forbidden_prefix && value.kind === "text" && value.value.startsWith(field.forbidden_prefix)) throw new V4Failure("reserved_namespace");
      if (field.encoded_schema_ref && !(field.allow_empty && raw.length === 0)) this.decode(raw, field.encoded_schema_ref, context, n + 1n);
      if (field.max_ref) {
        const bound = own(context.limits, field.max_ref);
        if (bound === undefined || bound < 0n) throw new V4Failure("limit_unresolved");
        if (n > bound) throw new V4Failure("field_length");
      }
      return;
    }
    if (kind === "bool") {
      if (value.kind !== "bool") throw new V4Failure("field_type");
      if (field.const !== undefined && field.const !== value.value) throw new V4Failure("field_equality");
    } else if (kind === "map") {
      if (!field.schema_ref) throw new V4Failure("registry_unresolved");
      this.checkMap(field.schema_ref, value, context);
    } else if (kind === "text_map") {
      if (value.kind !== "map") throw new V4Failure("map_type");
      if (field.min_items === undefined || field.max_items === undefined || !field.keys) throw new V4Failure("schema_type_unresolved");
      this.bounded(BigInt(value.value.length), field.min_items, field.max_items, undefined, "map_length");
      for (const [key, item] of value.value) {
        this.checkField(field.keys, key, context);
        if (key.kind !== "text") throw new V4Failure("field_type");
        const child = field.entries ? own(field.entries, key.value) : field.values;
        if (!child) throw new V4Failure(field.entries ? "unknown_field" : "schema_type_unresolved");
        this.checkField(child, item, context);
      }
      for (const key of Object.keys(field.entries ?? {})) if (!value.value.some(([actual]) => actual.kind === "text" && actual.value === key)) throw new V4Failure("missing_field");
    } else if (kind === "array" || kind === "array<uint64>") {
      if (value.kind !== "array") throw new V4Failure("field_type");
      let max = integer(field.max_items ?? this.registry.encoding.ordinary_array_items);
      if (field.max_items_ref) {
        const bound = own(context.limits, field.max_items_ref);
        if (bound === undefined || bound < 0n || bound > 0xffffffffn) throw new V4Failure("limit_unresolved"); max = bound;
      }
      if (field.min_items === undefined) throw new V4Failure("schema_type_unresolved");
      if (BigInt(value.value.length) < integer(field.min_items) || BigInt(value.value.length) > max) throw new V4Failure("array_length");
      const child: Field | undefined = kind === "array<uint64>" ? { type: "uint64" } : field.items;
      if (!child) throw new V4Failure("schema_type_unresolved");
      for (const item of value.value) this.checkField(child, item, context);
    } else throw new V4Failure("schema_type_unresolved");
  }
}

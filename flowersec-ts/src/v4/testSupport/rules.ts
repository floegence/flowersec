// Stateless generated-rule traversal over shape-checked original input.
import { encode, equal, own } from "./cbor.js";
import type { Field, Value } from "./cbor.js";
import { Shape, emptyContext, integer, lookup, record } from "./shape.js";
import type { Context } from "./shape.js";
import { V4Failure } from "./unicode.js";

export type Rule = Record<string, unknown>;
export type Check = (name: string, value: Value, context: Context) => void;
export function string(value: unknown): string {
  if (typeof value !== "string") throw new V4Failure("rule_unresolved"); return value;
}
export function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new V4Failure("rule_unresolved"); return value;
}
export function hex(value: unknown): Uint8Array {
  const input = string(value);
  if (input.length % 2 || /[^0-9a-f]/iu.test(input)) throw new V4Failure("registry_unresolved");
  return new Uint8Array(Buffer.from(input, "hex"));
}
export function unsigned(value: Value | undefined): bigint {
  if (value?.kind !== "uint") throw new V4Failure("integer_type"); return value.value;
}
export function rawEqual(value: Value | undefined, expected: unknown): boolean {
  if (value?.kind === "uint") return typeof expected === "number" || typeof expected === "string" ? value.value === integer(expected) : false;
  return value?.kind === "bool" || value?.kind === "text" ? value.value === expected : false;
}
export function same(a: Value | undefined, b: Value | undefined): boolean {
  return a === undefined || b === undefined ? a === b : equal(encode(a), encode(b));
}

export class Rules extends Shape {
  selectedField(field: Field, context: Context): Field {
    if (field.type !== "context_variant") return field;
    const selector = field.context ? own(context.selectors, field.context) : undefined;
    const selected = selector === undefined ? undefined : own(field.cases, selector);
    if (!selected) throw new V4Failure("context_unresolved"); return selected;
  }

  path(name: string, value: Value, path: string, context: Context): Value | undefined {
    return this.pathField({ type: "map", schema_ref: name }, value, path.split("."), context);
  }

  private pathField(original: Field, value: Value, parts: string[], context: Context): Value | undefined {
    if (!parts.length) return value;
    const field = this.selectedField(original, context), [part, ...rest] = parts;
    if (field.type === "array" || field.type === "array<uint64>") {
      if (value.kind !== "array" || !part || /[^0-9]/u.test(part) || part.length > 1 && part[0] === "0") throw new V4Failure("unknown_rule_field");
      const index = BigInt(part!);
      if (index > 0xffffffffffffffffn) throw new V4Failure("unknown_rule_field");
      if (index >= BigInt(value.value.length)) return undefined;
      const child = field.type === "array<uint64>" ? { type: "uint64" } : field.items;
      if (!child) throw new V4Failure("registry_unresolved");
      return this.pathField(child, value.value[Number(index)]!, rest, context);
    }
    let name: string, mapValue: Value;
    if (field.encoded_schema_ref) {
      if (value.kind !== "bytes") throw new V4Failure("unknown_rule_field");
      name = field.encoded_schema_ref;
      mapValue = this.decode(value.value, name, context, BigInt(value.value.length) + 1n);
    } else {
      if (!field.schema_ref) throw new V4Failure("unknown_rule_field");
      name = field.schema_ref; mapValue = value;
    }
    const descriptor = this.descriptor(name), local = this.mapContext(descriptor, mapValue, context);
    const entry = Object.entries(descriptor.fields).find(([, child]) => child.name === part);
    if (!entry) throw new V4Failure("unknown_rule_field");
    const [id, child] = entry, actual = lookup(mapValue, BigInt(id));
    return actual === undefined ? undefined : this.pathField(child, actual, rest, local);
  }

  walk(name: string, value: Value, context: Context, check: Check): void {
    const descriptor = this.descriptor(name), local = this.mapContext(descriptor, value, context);
    if (value.kind !== "map") throw new V4Failure("map_type");
    for (const [key, item] of value.value) {
      if (key.kind !== "uint") throw new V4Failure("field_id_type");
      const field = own(descriptor.fields, key.value.toString());
      if (!field) throw new V4Failure("unknown_field");
      this.walkField(field, item, local, check);
    }
    check(name, value, local);
  }

  private walkField(original: Field, value: Value, context: Context, check: Check): void {
    const field = this.selectedField(original, context);
    if (field.type === "map") {
      if (!field.schema_ref) throw new V4Failure("registry_unresolved");
      this.walk(field.schema_ref, value, context, check);
    } else if (field.type === "array") {
      if (value.kind !== "array" || !field.items) throw new V4Failure("field_type");
      for (const item of value.value) this.walkField(field.items, item, context, check);
    } else if (field.type === "text_map") {
      if (value.kind !== "map") throw new V4Failure("map_type");
      for (const [key, item] of value.value) {
        if (key.kind !== "text") throw new V4Failure("field_type");
        const child = field.entries ? own(field.entries, key.value) : field.values;
        if (!child) throw new V4Failure("registry_unresolved");
        this.walkField(child, item, context, check);
      }
    } else if (field.type === "bytes" && field.encoded_schema_ref) {
      if (value.kind !== "bytes") throw new V4Failure("field_type");
      if (!(field.allow_empty && value.value.length === 0)) {
        const nested = this.decode(value.value, field.encoded_schema_ref, context, BigInt(value.value.length) + 1n);
        this.walk(field.encoded_schema_ref, nested, context, check);
      }
    }
  }

  applies(name: string, value: Value, condition: unknown, context: Context): boolean {
    if (condition === undefined) return true;
    const when = record(condition);
    if (when.context !== undefined) {
      const selected = own(context.selectors, string(when.context));
      if (selected === undefined) throw new V4Failure("context_unresolved"); return selected === when.value;
    }
    return rawEqual(this.path(name, value, string(when.field), context), when.value);
  }

  variants(input: Uint8Array, name = "", context: Context = emptyContext(), cap: bigint): Value {
    const value = this.decode(input, name, context, cap);
    if (name) this.walk(name, value, context, (name, value, ctx) => this.checkVariants(name, value, ctx));
    return value;
  }

  private validateBranch(branch: Rule): void {
    const allowed = new Set(["absent", "required", "constants", "enum_values", "equal", "less_or_equal", "nonzero", "zero_bytes", "byte_lengths", "byte_prefixes", "registered"]);
    for (const key of Object.keys(branch)) if (!allowed.has(key)) throw new V4Failure("rule_unresolved");
    for (const key of ["absent", "required", "nonzero", "zero_bytes"]) if (branch[key] !== undefined) array(branch[key]).forEach(string);
    for (const key of ["equal", "less_or_equal"]) if (branch[key] !== undefined) for (const pair of array(branch[key])) {
      const paths = array(pair); if (paths.length !== 2) throw new V4Failure("rule_unresolved"); paths.forEach(string);
    }
    for (const key of ["constants", "enum_values", "byte_lengths", "byte_prefixes", "registered"]) if (branch[key] !== undefined) record(branch[key]);
    for (const values of Object.values(record(branch.enum_values ?? {}))) array(values).forEach(integer);
    Object.values(record(branch.byte_lengths ?? {})).forEach(integer);
    for (const key of ["byte_prefixes", "registered"]) Object.values(record(branch[key] ?? {})).forEach(string);
  }

  checkVariants(name: string, value: Value, context: Context): void {
    const metadata = new Set(["op", "when", "field", "min", "max", "discriminator", "value", "context", "cases"]);
    for (const rule of own(this.registry.variant_rules, name) ?? []) {
      const branch = Object.fromEntries(Object.entries(rule).filter(([key]) => !metadata.has(key)));
      this.validateBranch(branch);
      for (const item of Object.values(record(rule.cases ?? {}))) this.validateBranch(record(item));
      if (!this.applies(name, value, rule.when, context)) continue;
      if (rule.op === "range") {
        const actual = this.path(name, value, string(rule.field), context);
        if (actual?.kind !== "uint" || actual.value < integer(rule.min) || actual.value > integer(rule.max)) throw new V4Failure("field_range");
      } else if (rule.op === "variant") {
        if (rawEqual(this.path(name, value, string(rule.discriminator), context), rule.value)) this.checkBranch(name, value, branch, context);
      } else if (rule.op === "context_variant") {
        const selected = own(context.selectors, string(rule.context));
        const branch = selected === undefined ? undefined : own(record(rule.cases), selected);
        if (!branch) throw new V4Failure("context_unresolved");
        this.checkBranch(name, value, record(branch), context);
      } else throw new V4Failure("rule_unresolved");
    }
  }

  private checkBranch(name: string, value: Value, branch: Rule, context: Context): void {
    const get = (path: unknown): Value | undefined => this.path(name, value, string(path), context);
    for (const path of array(branch.absent ?? [])) if (get(path) !== undefined) throw new V4Failure("variant_absent");
    for (const path of array(branch.required ?? [])) if (get(path) === undefined) throw new V4Failure("variant_required");
    for (const [path, expected] of Object.entries(record(branch.constants ?? {}))) if (!rawEqual(get(path), expected)) throw new V4Failure("variant_constant");
    for (const [path, expected] of Object.entries(record(branch.enum_values ?? {}))) {
      const actual = get(path);
      if (actual?.kind !== "uint" || !array(expected).some(item => integer(item) === actual.value)) throw new V4Failure("enum_value");
    }
    for (const pair of array(branch.equal ?? [])) {
      const [a, b] = array(pair); if (!same(get(a), get(b))) throw new V4Failure("field_equality");
    }
    for (const pair of array(branch.less_or_equal ?? [])) {
      const [a, b] = array(pair), left = get(a), right = get(b);
      if (left?.kind !== "uint" || right?.kind !== "uint" || left.value > right.value) throw new V4Failure("field_order");
    }
    for (const path of array(branch.nonzero ?? [])) {
      const actual = get(path);
      if (!(actual?.kind === "uint" && actual.value > 0n || actual?.kind === "bytes" && actual.value.some(byte => byte !== 0))) throw new V4Failure("variant_nonzero");
    }
    for (const path of array(branch.zero_bytes ?? [])) {
      const actual = get(path); if (actual?.kind !== "bytes" || actual.value.some(byte => byte !== 0)) throw new V4Failure("variant_zero_bytes");
    }
    for (const [path, length] of Object.entries(record(branch.byte_lengths ?? {}))) {
      const actual = get(path); if (actual?.kind !== "bytes" || BigInt(actual.value.length) !== integer(length)) throw new V4Failure("field_length");
    }
    for (const [path, prefix] of Object.entries(record(branch.byte_prefixes ?? {}))) {
      const actual = get(path), raw = hex(prefix);
      if (actual?.kind !== "bytes" || !equal(actual.value.subarray(0, raw.length), raw)) throw new V4Failure("field_prefix");
    }
    for (const [path, registry] of Object.entries(record(branch.registered ?? {}))) {
      const actual = get(path), items = Object.values(record(this.fieldRegistry(string(registry))));
      if (actual?.kind !== "uint" || !items.some(item => rawEqual(actual, typeof item === "object" && item !== null ? record(item).code : item))) throw new V4Failure("enum_value");
    }
  }
}

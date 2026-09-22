// Test-only independent domain input construction from the generated registry.
// Signing bytes and exporter parameters confer no trust or provider authority.
import { createHash, createHmac } from "node:crypto";
import { transportV4Domains } from "../../generated/transportV4Registry.js";
import { encode, equal, join, own, utf8 } from "./cbor.js";
import type { Value } from "./cbor.js";
import { emptyContext, integer, record } from "./shape.js";
import type { Context } from "./shape.js";
import { array, hex, string } from "./rules.js";
import { Oracles } from "./oracles.js";
import { V4Failure } from "./unicode.js";

type Part = Record<string, unknown>;
export type DomainResult = { label: Uint8Array; input: Uint8Array; output?: Uint8Array; salt?: Uint8Array; ikm?: Uint8Array; outputLength?: number };
function argumentInteger(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  throw new V4Failure("domain_integer_type");
}
export function fixedUnsigned(value: unknown, width: 1 | 4 | 8): Uint8Array {
  let n = argumentInteger(value);
  if (n < 0n || n >= 1n << BigInt(width * 8)) throw new V4Failure("domain_integer_range");
  const output = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index--) { output[index] = Number(n & 255n); n >>= 8n; }
  return output;
}
function lp(input: Uint8Array): Uint8Array { return join([fixedUnsigned(input.length, 4), input]); }
function matches(value: Value, expected: unknown): boolean {
  if (value.kind === "bytes") return expected instanceof Uint8Array && equal(value.value, expected);
  if (value.kind === "uint") return (typeof expected === "bigint" || typeof expected === "number" && Number.isSafeInteger(expected)) && value.value === BigInt(expected);
  return value.kind === "text" && value.value === expected;
}

export class Domains extends Oracles {
  readonly domains = new Map((transportV4Domains as readonly unknown[]).map(raw => { const domain = record(raw); return [string(domain.name), domain]; }));

  private mapPart(part: Part, input: Uint8Array, args: Record<string, unknown>, context: Context, cap: bigint): Uint8Array {
    let name: string;
    if (part.schema_ref !== undefined) name = string(part.schema_ref);
    else {
      const selector = argumentInteger(own(args, string(part.selector)));
      const selected = own(record(part.schema_cases), selector.toString());
      if (selected === undefined) throw new V4Failure("domain_variant"); name = string(selected);
    }
    const value = this.wireMap(input, name, context, cap);
    if (value.kind !== "map") throw new V4Failure("map_type");
    for (const [field, argument] of Object.entries(record(part.bindings ?? {}))) {
      if (!matches(this.requiredValue(name, value, field), own(args, string(argument)))) throw new V4Failure("domain_binding");
    }
    for (const [argument, fields] of Object.entries(record(part.one_of_bindings ?? {}))) {
      if (!array(fields).some(field => matches(this.requiredValue(name, value, string(field)), own(args, argument)))) throw new V4Failure("domain_binding");
    }
    if (part.projection === "full") return lp(input);
    const descriptor = this.descriptor(name);
    let excluded: bigint[];
    switch (part.projection) {
      case "without_signature": excluded = [integer(descriptor.signature_field)]; break;
      case "without_mac": excluded = [integer(descriptor.mac_field)]; break;
      case "without_open_digest": excluded = [this.namedField(name, "open_digest")[0]]; break;
      case "without_fields": case "without_fields_raw": excluded = array(part.fields).map(field => this.namedField(name, string(field))[0]); break;
      default: throw new V4Failure("domain_projection");
    }
    if (new Set(excluded).size !== excluded.length || excluded.some(id => !value.value.some(([key]) => key.kind === "uint" && key.value === id))) throw new V4Failure("domain_projection");
    // IDs and received order survive projection unchanged. No zero placeholders.
    const projected = encode({ kind: "map", value: value.value.filter(([key]) => key.kind !== "uint" || !excluded.includes(key.value)) });
    return part.projection === "without_fields_raw" ? projected : lp(projected);
  }

  private part(part: Part, args: Record<string, unknown>, context: Context, cap: bigint): Uint8Array {
    if (part.encoding === "hex") return hex(part.hex);
    const value = part.const_ref !== undefined ? this.fieldRegistry(string(part.const_ref)) : part.const !== undefined ? part.const : own(args, string(part.name));
    const width = part.encoding === "u8" ? 1 : part.encoding === "u32" ? 4 : part.encoding === "u64" ? 8 : undefined;
    if (width !== undefined) {
      const output = fixedUnsigned(value, width), n = argumentInteger(value);
      if (part.enum !== undefined && !array(part.enum).some(item => integer(item) === n)) throw new V4Failure("domain_enum");
      if (part.min !== undefined && n < integer(part.min) || part.max !== undefined && n > integer(part.max)) throw new V4Failure("domain_integer_range");
      if (part.multiple_of !== undefined) {
        const divisor = integer(part.multiple_of);
        if (!divisor) throw new V4Failure("registry_unresolved");
        if (n % divisor !== 0n) throw new V4Failure("domain_integer_multiple");
      }
      return output;
    }
    if (part.encoding === "lp-ascii") {
      if (typeof value !== "string" || !value.length || /[^\x00-\x7f]/u.test(value)) throw new V4Failure("domain_ascii");
      if (part.text_enum_ref !== undefined && !Object.hasOwn(record(this.fieldRegistry(string(part.text_enum_ref))), value)) throw new V4Failure("domain_enum");
      return lp(utf8.encode(value));
    }
    if (!(value instanceof Uint8Array)) throw new V4Failure("domain_bytes_type");
    if (part.encoding === "lp-map") return this.mapPart(part, value, args, context, cap);
    if (part.encoding !== "raw" && part.encoding !== "lp-bytes") throw new V4Failure("registry_unresolved");
    if (part.length !== undefined ? BigInt(value.length) !== integer(part.length) : BigInt(value.length) > integer(part.max_length)) throw new V4Failure("domain_bytes_length");
    if (part.nonzero && !value.some(byte => byte !== 0)) throw new V4Failure("domain_zero_secret");
    return part.encoding === "raw" ? new Uint8Array(value) : lp(value);
  }

  evaluate(name: string, argumentsValue: unknown, context: Context = emptyContext(), cap: bigint): DomainResult {
    if (cap <= 0n) throw new V4Failure("limit_unresolved");
    const domain = this.domains.get(name); if (!domain) throw new V4Failure("domain_unknown");
    const spec = record(domain.input_schema), parts = array(spec.parts).map(record);
    const all = [...parts, ...["key", "salt", "ikm"].filter(key => spec[key] !== undefined).map(key => record(spec[key]))];
    const expected = all.filter(part => part.name !== undefined).map(part => string(part.name));
    if (!argumentsValue || typeof argumentsValue !== "object" || Array.isArray(argumentsValue)) throw new V4Failure("domain_arguments");
    const args = argumentsValue as Record<string, unknown>;
    if (Object.keys(args).length !== expected.length || !expected.every(key => Object.hasOwn(args, key))) throw new V4Failure("domain_arguments");
    const profile = own(args, "profile");
    if (profile !== undefined) {
      if (context.selectors.crypto_profile_id !== undefined && context.selectors.crypto_profile_id !== profile) throw new V4Failure("domain_context");
      if (typeof profile !== "string") throw new V4Failure("domain_ascii");
      context = { limits: context.limits, selectors: { ...context.selectors, crypto_profile_id: profile } };
    }
    const label = hex(domain.label_bytes), content = join(parts.map(part => this.part(part, args, context, cap)));
    for (const raw of array(spec.relations ?? [])) {
      const rule = record(raw), left = argumentInteger(own(args, string(rule.left))), right = argumentInteger(own(args, string(rule.right)));
      let valid: boolean;
      if (rule.op === "successor") valid = left + 1n === right;
      else if (rule.op === "allowed_pairs") valid = array(rule.pairs).some(pair => { const values = array(pair); return values.length === 2 && integer(values[0]) === left && integer(values[1]) === right; });
      else throw new V4Failure("registry_unresolved");
      if (!valid) throw new V4Failure("domain_relation");
    }
    const input = domain.operation === "tls-exporter" || domain.operation === "sha256-raw" ? content : join([label, content]);
    const result: DomainResult = { label, input };
    switch (domain.operation) {
      case "sha256": case "sha256-raw":
        if (integer(domain.output_length) !== 32n) throw new V4Failure("registry_unresolved");
        result.output = new Uint8Array(createHash("sha256").update(input).digest()); break;
      case "hmac-sha256": case "hkdf-expand": {
        if (integer(domain.output_length) !== 32n) throw new V4Failure("registry_unresolved");
        const key = this.part(record(spec.key), args, context, cap), mac = createHmac("sha256", key).update(input);
        // One RFC5869 block, no prior T and no extra Extract step.
        if (domain.operation === "hkdf-expand") mac.update(Uint8Array.of(1));
        result.output = new Uint8Array(mac.digest()); break;
      }
      case "hkdf-extract":
        if (integer(domain.output_length) !== 32n || label.length || parts.length) throw new V4Failure("registry_unresolved");
        result.salt = this.part(record(spec.salt), args, context, cap); result.ikm = this.part(record(spec.ikm), args, context, cap);
        result.output = new Uint8Array(createHmac("sha256", result.salt).update(result.ikm).digest()); break;
      case "tls-exporter": result.outputLength = Number(integer(domain.output_length)); break;
      case "ed25519": case "aead-aad": case "noise-prologue": break;
      default: throw new V4Failure("registry_unresolved");
    }
    return result;
  }
}

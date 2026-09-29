import { sha256 } from "@noble/hashes/sha2.js";
import { transportV4CBORSyntaxLimits } from "../../generated/transportV4Registry.js";
import type { CBORDocument } from "./cbor.js";
import { WireHostWorkspace, hostWorkspaceBackingBytes } from "./host.js";
import { fieldPattern, namedField, own, table, unsignedField, wireDomains, wireLimitNames, wireMaps, wireRelations, wireSelectorNames, wireTextRules, wireVariants,
  type WireBranch, type WireField, type WireMap, type WireRule } from "./schemaRegistry.js";

export type SchemaFailure = "configuration_capacity" | "unknown_schema" | "unknown_schema_field" | "schema_type_unresolved" | "context_unresolved" | "limit_unresolved" |
  "map_type" | "map_size" | "integer_type" | "integer_range" | "field_type" | "field_range" | "unknown_bits" | "enum_value" |
  "field_length" | "field_nonzero" | "field_prefix" | "text_pattern" | "reserved_namespace" | "array_length" | "map_length" |
  "unknown_field" | "missing_field" | "constant_mismatch" | "registry_unresolved" | "pattern_unresolved" | "rule_unresolved" |
  "unknown_rule_field" | "field_null" | "field_presence" | "field_equality" | "field_distinctness" | "field_order" | "field_duration" |
  "feature_subset" | "feature_policy" | "profile_algorithm" | "field_pair" | "field_tuple" | "carrier_tuple" | "error_scope" | "retry_after_forbidden" |
  "variant_absent" | "variant_required" | "variant_constant" | "variant_nonzero" | "variant_zero_bytes" | "item_index" | "item_identity" |
  "item_order" | "scope_order" | "item_exclusive" | "origin_endpoint" | "domain_projection" | "map_digest_mismatch" | "text_format_unresolved";
export class SchemaValidationError extends Error {
  readonly code: SchemaFailure;
  constructor(code: SchemaFailure) { super(code); this.name = "SchemaValidationError"; this.code = code; }
}
function reject(code: SchemaFailure): never { throw new SchemaValidationError(code); }
function requireThat(condition: boolean, code: SchemaFailure): void { if (!condition) reject(code); }

export interface DecodeContext {
  readonly limits?: Readonly<Record<string, number>>;
  readonly selectors?: Readonly<Record<string, string>>;
}
export interface CapturedDecodeContext {
  readonly limits: Readonly<Record<string, number>>;
  readonly selectors: Readonly<Record<string, string>>;
}
export function captureDecodeContext(context: DecodeContext): CapturedDecodeContext {
  const limits: Record<string, number> = Object.create(null) as Record<string, number>;
  const selectors: Record<string, string> = Object.create(null) as Record<string, string>;
  const inputLimits = context.limits, inputSelectors = context.selectors;
  for (const name of wireLimitNames) {
    const v = inputLimits?.[name];
    if (v !== undefined) { requireThat(Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff, "limit_unresolved"); limits[name] = v; }
  }
  for (const name of wireSelectorNames) {
    const v = inputSelectors?.[name];
    if (v !== undefined) { requireThat(typeof v === "string" && v.length <= 128, "context_unresolved"); selectors[name] = v; }
  }
  return Object.freeze({ limits: Object.freeze(limits), selectors: Object.freeze(selectors) });
}
function limit(context: CapturedDecodeContext, name: string, positive = false): number {
  const value = own(context.limits, name);
  if (value === undefined || positive && value === 0) reject("limit_unresolved");
  return value;
}
export function preflightMap(schema: string, bytes: number, context: CapturedDecodeContext): WireMap {
  const spec = own(wireMaps, schema);
  if (spec === undefined) reject("unknown_schema");
  if (spec.max_encoded_bytes !== undefined && bytes > spec.max_encoded_bytes || spec.encoded_bytes !== undefined && bytes !== spec.encoded_bytes ||
    spec.max_encoded_bytes_ref !== undefined && bytes > limit(context, spec.max_encoded_bytes_ref, true)) reject("map_size");
  return spec;
}
interface Context {
  readonly external: CapturedDecodeContext;
  readonly parent?: Context;
  readonly schema?: string;
  readonly spec?: WireMap;
  readonly node?: number;
}
interface ContractShapeEntry { readonly node: number; readonly field: WireField; readonly context: Context }
interface ContractTraversal {
  readonly doc: CBORDocument;
  readonly envelope: boolean;
  readonly plan: (ContractShapeEntry | undefined)[];
  planned: number; shaped: number; ruleAt: number; ruleGroup: number; ruleIndex: number;
}
interface Profile { readonly dh_public_bytes: number; readonly dh_algorithm: number }
type RegistryCode = number | { readonly code: number };
const emptyRules: readonly WireRule[] = Object.freeze([]);
const mapFields: Readonly<Record<string, WireField>> = Object.freeze(Object.fromEntries(Object.keys(wireMaps).map(schema => [schema, Object.freeze({ type: "map", schema_ref: schema })])));
function mapField(schema: string | undefined): WireField {
  const field = schema === undefined ? undefined : own(mapFields, schema);
  if (field === undefined) reject("unknown_schema");
  return field;
}
function codes(field: WireField): Readonly<Record<string, RegistryCode>> | undefined {
  if (field.enum !== undefined) return field.enum;
  if (field.enum_ref === undefined) return undefined;
  const entries = table<Readonly<Record<string, RegistryCode>>>(field.enum_ref);
  if (entries === undefined) reject("registry_unresolved");
  return entries;
}
function code(entry: RegistryCode): bigint { return BigInt(typeof entry === "number" ? entry : entry.code); }
function constant(doc: CBORDocument, node: number, value: unknown): boolean {
  if (node < 0) return false;
  if (typeof value === "number") return doc.kind(node) === "uint" && doc.uint(node) === BigInt(value);
  if (typeof value === "boolean") return doc.kind(node) === "bool" && doc.boolean(node) === value;
  return typeof value === "string" && doc.kind(node) === "text" && doc.text(node) === value;
}
function equal(doc: CBORDocument, a: number, b: number): boolean { return a < 0 || b < 0 ? a === b : doc.compare(a, b) === 0; }
function uint(doc: CBORDocument, n: number): bigint { if (n < 0 || doc.kind(n) !== "uint") reject("integer_type"); return doc.uint(n); }
function nonzero(doc: CBORDocument, n: number): boolean {
  if (n < 0) return false;
  if (doc.kind(n) === "uint") return doc.uint(n) > 0n;
  if (doc.kind(n) !== "bytes") return false;
  for (let i = 0; i < doc.size(n); i++) if (doc.payloadByte(n, i) !== 0) return true;
  return false;
}
function compare(doc: CBORDocument, a: number, b: number): number {
  if (a < 0 || b < 0) reject("field_type");
  if (doc.kind(a) === "uint" && doc.kind(b) === "uint") { const x = doc.uint(a), y = doc.uint(b); return x < y ? -1 : x > y ? 1 : 0; }
  if (doc.kind(a) === "bytes" && doc.kind(b) === "bytes") return doc.compare(a, b, true);
  return reject("field_type");
}

// This exact typed backing is charged by the containing CBOR decoder. Qualified
// runtimeBytes must additionally cover the fixed hash state, traversal stack,
// descriptor contexts and temporary UTF-16 strings (bounded by the input cap).
export const schemaWorkspaceBackingBytes = hostWorkspaceBackingBytes + 256 + 32;
export class SchemaWorkspace {
  readonly #host = new WireHostWorkspace();
  readonly #chunk = new Uint8Array(256);
  readonly #digest = new Uint8Array(32);
  readonly #contractPlan: (ContractShapeEntry | undefined)[] | undefined;
  #contract: ContractTraversal | undefined;
  constructor(contractScratch = false) {
    if (contractScratch) this.#contractPlan = Array<ContractShapeEntry | undefined>(384).fill(undefined);
  }
  validate(doc: CBORDocument, schema: string, external: CapturedDecodeContext): void {
    if (this.#contract !== undefined) reject("configuration_capacity");
    try { this.#field(doc, 0, mapField(schema), { external }); }
    finally { this.clear(); }
  }
  // Only these two closed graphs have a qualified bounded traversal. Snapshot
  // embedded bodies are deliberately deferred; the decoder never brands this
  // envelope as a completely validated ContractSnapshots document.
  beginContract(doc: CBORDocument, schema: "ServiceContract" | "ContractSnapshots", external: CapturedDecodeContext): void {
    if (this.#contract !== undefined || this.#contractPlan === undefined || schema !== "ServiceContract" && schema !== "ContractSnapshots") reject("configuration_capacity");
    const plan = this.#contractPlan;
    plan[0] = { node: 0, field: mapField(schema), context: { external } };
    this.#contract = { doc, envelope: schema === "ContractSnapshots", plan, planned: 1, shaped: 0, ruleAt: 0, ruleGroup: 0, ruleIndex: 0 };
  }
  stepContract(): boolean {
    const c = this.#contract;
    if (c === undefined) reject("configuration_capacity");
    if (c.shaped < c.planned) {
      const entry = c.plan[c.shaped++]!;
      this.#field(c.doc, entry.node, entry.field, entry.context); return false;
    }
    if (c.ruleAt === c.planned) { this.clear(); return true; }
    const entry = c.plan[c.ruleAt]!;
    if (entry.field.type !== "map") { c.ruleAt++; return false; }
    const schema = entry.field.schema_ref!, groups = [wireVariants, wireRelations, wireTextRules];
    while (c.ruleGroup < groups.length && c.ruleIndex === (own(groups[c.ruleGroup], schema) ?? emptyRules).length) { c.ruleGroup++; c.ruleIndex = 0; }
    if (c.ruleGroup === groups.length) { c.ruleAt++; c.ruleGroup = 0; c.ruleIndex = 0; return false; }
    const rule = own(groups[c.ruleGroup], schema)![c.ruleIndex++]!;
    if (rule.op !== "variant" && rule.op !== "less_or_equal" && rule.op !== "increasing" && rule.op !== "ordinal_indices") reject("configuration_capacity");
    this.#rule(c.doc, entry.node, entry.field, { external: entry.context.external, parent: entry.context, schema,
      spec: own(wireMaps, schema)!, node: entry.node }, rule);
    return false;
  }
  #child(doc: CBORDocument, node: number, field: WireField | undefined, context: Context): void {
    const c = this.#contract;
    if (c === undefined) { this.#field(doc, node, field, context); return; }
    if (field === undefined || c.planned === c.plan.length) reject("configuration_capacity");
    c.plan[c.planned++] = { node, field, context };
  }
  #selector(doc: CBORDocument, context: Context, name: string): string {
    for (let c: Context | undefined = context; c !== undefined; c = c.parent) {
      const fieldName = own(c.spec?.context_fields, name);
      if (fieldName !== undefined) {
        const id = namedField(c.schema!, fieldName);
        if (id === undefined || c.node === undefined) reject("context_unresolved");
        const field = own(c.spec!.fields, String(id))!, n = doc.field(c.node, id), entries = codes(field);
        const actual = uint(doc, n);
        for (const [label, entry] of Object.entries(entries ?? {})) if (code(entry) === actual) return label;
        return reject("context_unresolved");
      }
    }
    const label = own(context.external.selectors, name);
    if (label === undefined) reject("context_unresolved");
    return label;
  }
  #resolve(doc: CBORDocument, field: WireField | undefined, context: Context): WireField {
    if (field === undefined) reject("schema_type_unresolved");
    if (field.type !== "context_variant") return field;
    const result = own(field.cases, this.#selector(doc, context, field.context!));
    if (result === undefined) reject("context_unresolved");
    return result;
  }
  #field(doc: CBORDocument, node: number, original: WireField | undefined, context: Context): void {
    const f = this.#resolve(doc, original, context), kind = doc.kind(node);
    if (this.#contract !== undefined && (f.type === "context_variant" || f.type === "text_map" || f.max_items_ref !== undefined ||
        f.text_format !== undefined || f.profile_public_key === true)) reject("configuration_capacity");
    if (kind === "null" && f.type === "uint64" && f.nullable === true) return;
    if (f.type === "uint8" || f.type === "uint16" || f.type === "uint32" || f.type === "uint64") {
      const v = uint(doc, node), width = Number(f.type.slice(4));
      requireThat(v < 1n << BigInt(width), "integer_range");
      if (f.min !== undefined && v < BigInt(f.min) || f.max !== undefined && v > BigInt(f.max)) reject("field_range");
      if (f.bitmask !== undefined && (v & ~BigInt(f.bitmask)) !== 0n) reject("unknown_bits");
      const entries = codes(f);
      if (entries !== undefined && !Object.values(entries).some(entry => code(entry) === v)) reject("enum_value");
    } else if (f.type === "bytes" || f.type === "text") {
      requireThat(kind === f.type, "field_type");
      const n = doc.size(node);
      if (this.#contract !== undefined && n > 4096 && (f.type === "text" || f.nonzero === true || f.const !== undefined || f.const_ref !== undefined)) reject("configuration_capacity");
      if (f.length !== undefined && n !== f.length || f.min_bytes !== undefined && n < f.min_bytes || f.max_bytes !== undefined && n > f.max_bytes ||
        f.max_ref !== undefined && n > limit(context.external, f.max_ref)) reject("field_length");
      if (f.nonzero === true && !nonzero(doc, node)) reject("field_nonzero");
      if (f.profile_public_key === true) {
        const profile = own(table<Readonly<Record<string, Profile>>>("crypto_profiles"), this.#selector(doc, context, "crypto_profile_id"));
        if (profile === undefined) reject("context_unresolved");
        requireThat(n === profile.dh_public_bytes, "field_length");
        if (profile.dh_algorithm === 1) requireThat(doc.payloadByte(node, 0) === 4, "field_prefix");
      }
      if (f.type === "text") {
        const text = doc.text(node);
        if (f.text_enum_ref !== undefined) {
          const entries = table<Readonly<Record<string, unknown>>>(f.text_enum_ref);
          if (entries === undefined) reject("registry_unresolved");
          requireThat(Object.hasOwn(entries, text), "enum_value");
        }
        if (f.pattern_ref !== undefined) {
          const pattern = fieldPattern(f.pattern_ref); if (pattern === undefined) reject("pattern_unresolved");
          const match = pattern.exec(text); requireThat(match !== null && match[0] === text, "text_pattern");
        }
        if (f.forbidden_prefix !== undefined) requireThat(!text.startsWith(f.forbidden_prefix), "reserved_namespace");
        if (f.text_format !== undefined) this.#textFormat(f.text_format, text);
      }
      if (f.encoded_schema_ref !== undefined && !(f.allow_empty === true && n === 0)) {
        preflightMap(f.encoded_schema_ref, n, context.external);
        if (this.#contract !== undefined) {
          if (!this.#contract.envelope || context.schema !== "ContractSnapshot" ||
              f.encoded_schema_ref !== "ServiceContract" && f.encoded_schema_ref !== "AdmissionOffer") reject("configuration_capacity");
        } else this.#field(doc, doc.embedded(node), mapField(f.encoded_schema_ref), context);
      }
    } else if (f.type === "bool") requireThat(kind === "bool", "field_type");
    else if (f.type === "map") {
      requireThat(kind === "map", "map_type");
      const schema = f.schema_ref!, spec = preflightMap(schema, doc.encodedSize(node), context.external);
      const child: Context = { external: context.external, parent: context, schema, spec, node };
      for (let key = doc.firstChild(node); key >= 0;) {
        requireThat(doc.kind(key) === "uint", "unknown_field");
        const field = own(spec.fields, String(doc.uint(key))), value = doc.nextSibling(key);
        if (field === undefined) reject("unknown_field");
        this.#child(doc, value, field, child); key = doc.nextSibling(value);
      }
      for (const id of spec.required) requireThat(doc.field(node, id) >= 0, "missing_field");
      if (this.#contract === undefined) for (const group of [wireVariants, wireRelations, wireTextRules]) for (const rule of own(group, schema) ?? emptyRules) this.#rule(doc, node, f, child, rule);
    } else if (f.type === "array" || f.type === "array<uint64>") {
      requireThat(kind === "array", "field_type");
      const max = f.max_items_ref === undefined ? f.max_items ?? transportV4CBORSyntaxLimits.ordinaryArrayItems : limit(context.external, f.max_items_ref);
      requireThat(f.min_items !== undefined, "schema_type_unresolved");
      requireThat(doc.size(node) >= f.min_items! && doc.size(node) <= max, "array_length");
      for (let item = doc.firstChild(node); item >= 0; item = doc.nextSibling(item)) this.#child(doc, item, f.type === "array<uint64>" ? unsignedField : f.items, context);
    } else if (f.type === "text_map") {
      requireThat(kind === "map", "map_type");
      requireThat(f.min_items !== undefined && f.max_items !== undefined, "schema_type_unresolved");
      requireThat(doc.size(node) >= f.min_items! && doc.size(node) <= f.max_items!, "map_length");
      if (f.entries !== undefined) requireThat(doc.size(node) === Object.keys(f.entries).length, "missing_field");
      for (let key = doc.firstChild(node); key >= 0;) {
        this.#field(doc, key, f.keys, context);
        const field = f.entries === undefined ? f.values : own(f.entries, doc.text(key));
        if (field === undefined) reject("unknown_field");
        const value = doc.nextSibling(key); this.#field(doc, value, field, context); key = doc.nextSibling(value);
      }
    } else reject("schema_type_unresolved");
    if (f.const !== undefined || f.const_ref !== undefined) {
      const expected = f.const_ref === undefined ? f.const : table<unknown>(f.const_ref);
      if (expected === undefined) reject("registry_unresolved");
      requireThat(constant(doc, node, expected), "constant_mismatch");
    }
  }
  #path(doc: CBORDocument, node: number, f: WireField, path: string, context: Context): readonly [number, WireField, Context] {
    let at = 0;
    while (at < path.length && node >= 0) {
      const dot = path.indexOf(".", at), part = path.slice(at, dot < 0 ? path.length : dot); at = dot < 0 ? path.length : dot + 1;
      f = this.#resolve(doc, f, context);
      if (f.type === "array" || f.type === "array<uint64>") {
        requireThat(/^(?:0|[1-9][0-9]*)$/u.test(part) && Number.isSafeInteger(Number(part)), "unknown_rule_field");
        let index = Number(part);
        node = index >= doc.size(node) ? -1 : doc.firstChild(node);
        while (index-- > 0 && node >= 0) node = doc.nextSibling(node);
        f = f.items ?? unsignedField;
      } else {
        const schema = f.encoded_schema_ref ?? f.schema_ref;
        const spec = schema === undefined ? undefined : own(wireMaps, schema), id = schema === undefined ? undefined : namedField(schema, part);
        if (spec === undefined || id === undefined) reject("unknown_rule_field");
        if (f.encoded_schema_ref !== undefined) node = doc.embedded(node);
        context = { external: context.external, parent: context, schema: schema!, spec, node };
        f = own(spec.fields, String(id))!; node = doc.field(node, id);
      }
    }
    return [node, f, context];
  }
  #rule(doc: CBORDocument, root: number, f: WireField, context: Context, r: WireRule): void {
    const get = (path: string): number => this.#path(doc, root, f, path, context)[0];
    if (r.when !== undefined) {
      if (r.when.context !== undefined) { if (this.#selector(doc, context, r.when.context) !== r.when.value) return; }
      else if (!constant(doc, get(r.when.field!), r.when.value)) return;
    }
    switch (r.op) {
      case "variant": if (constant(doc, get(r.discriminator), r.value)) this.#branch(doc, get, r); return;
      case "context_variant": {
        const branch = own(r.cases, this.#selector(doc, context, r.context));
        if (branch === undefined) reject("context_unresolved");
        this.#branch(doc, get, branch); return;
      }
      case "range": { const n = uint(doc, get(r.field)); requireThat(n >= BigInt(r.min) && n <= BigInt(r.max), "field_range"); return; }
      case "is_null": { const n = get(r.field); requireThat(n >= 0 && doc.kind(n) === "null", "field_null"); return; }
      case "at_least_one": requireThat(r.fields.some(path => get(path) >= 0), "field_presence"); return;
      case "equal": case "equal_if_present": case "not_equal": {
        const a = get(r.left), b = get(r.right);
        if (r.op === "equal_if_present" && (a < 0 || b < 0)) return;
        const same = equal(doc, a, b);
        requireThat(r.op === "not_equal" ? !same : same, r.op === "not_equal" ? "field_distinctness" : "field_equality"); return;
      }
      case "less_than": case "less_or_equal": case "max_difference": case "bit_subset": {
        const a = uint(doc, get(r.left)), b = uint(doc, get(r.right));
        if (r.op === "bit_subset") requireThat((a & ~b) === 0n, "feature_subset");
        else if (r.op === "max_difference") requireThat(a <= b && b - a <= BigInt(r.max), "field_duration");
        else requireThat(r.op === "less_than" ? a < b : a <= b, "field_order");
        return;
      }
      case "allowed_pairs": case "allowed_tuples": {
        const fields = r.op === "allowed_pairs" ? [r.left, r.right] : r.fields, rows = r.op === "allowed_pairs" ? r.pairs : r.rows;
        requireThat(rows.some(row => row.length === fields.length && row.every((n, i) => constant(doc, get(fields[i]!), n))), r.op === "allowed_pairs" ? "field_pair" : "field_tuple"); return;
      }
      case "feature_bit": {
        const bit = own(table<Readonly<Record<string, { readonly bit: number }>>>("feature_registry"), r.feature)?.bit;
        if (bit === undefined || bit < 0 || bit > 63) reject("registry_unresolved");
        requireThat(((uint(doc, get(r.field)) & 1n << BigInt(bit)) !== 0n) === r.present, "feature_policy"); return;
      }
      case "profile_algorithm": {
        const profile = own(table<Readonly<Record<string, Profile>>>("crypto_profiles"), doc.text(get(r.profile)));
        if (profile === undefined) reject("enum_value");
        requireThat(uint(doc, get(r.algorithm)) === BigInt(profile.dh_algorithm), "profile_algorithm"); return;
      }
      case "error_scope": this.#errorScope(doc, get, r); return;
      case "registry_tuple": this.#registryTuple(doc, root, f, context, r); return;
      case "map_digest": this.#mapDigest(doc, get(r.source), get(r.field), r.domain); return;
      case "text_format": this.#textFormat(r.format, doc.text(get(r.field))); return;
      case "origin_endpoint": {
        const host = doc.text(get(r.host)), port = uint(doc, get(r.port));
        const scheme = own(table<Readonly<Record<string, { readonly default_port: number }>>>("origin_schemes"), r.scheme);
        if (scheme === undefined) reject("registry_unresolved");
        const expected = r.scheme + "://" + (host.includes(":") ? "[" + host + "]" : host) + (port === BigInt(scheme.default_port) ? "" : ":" + port);
        requireThat(doc.text(get(r.origin)) === expected, "origin_endpoint"); return;
      }
      case "unique_by": case "ordinal_indices": case "increasing": case "increasing_tuple": case "increasing_bytes": case "increasing_cbor": case "increasing_scopes": case "exclusive_item":
        this.#arrayRule(doc, root, f, context, r); return;
      default: reject("rule_unresolved");
    }
  }
  #branch(doc: CBORDocument, get: (path: string) => number, b: WireBranch): void {
    for (const path of b.absent ?? []) requireThat(get(path) < 0, "variant_absent");
    for (const path of b.required ?? []) requireThat(get(path) >= 0, "variant_required");
    for (const [path, value] of Object.entries(b.constants ?? {})) requireThat(constant(doc, get(path), value), "variant_constant");
    for (const [path, values] of Object.entries(b.enum_values ?? {})) requireThat(values.some(n => constant(doc, get(path), n)), "enum_value");
    for (const [a, z] of b.equal ?? []) requireThat(equal(doc, get(a), get(z)), "field_equality");
    for (const [a, z] of b.less_or_equal ?? []) requireThat(uint(doc, get(a)) <= uint(doc, get(z)), "field_order");
    for (const path of b.nonzero ?? []) requireThat(nonzero(doc, get(path)), "variant_nonzero");
    for (const path of b.zero_bytes ?? []) { const n = get(path); requireThat(n >= 0 && doc.kind(n) === "bytes" && !nonzero(doc, n), "variant_zero_bytes"); }
    for (const [path, length] of Object.entries(b.byte_lengths ?? {})) { const n = get(path); requireThat(n >= 0 && doc.kind(n) === "bytes" && doc.size(n) === length, "field_length"); }
    for (const [path, hex] of Object.entries(b.byte_prefixes ?? {})) {
      const n = get(path); requireThat(n >= 0 && doc.kind(n) === "bytes" && doc.size(n) >= hex.length / 2, "field_prefix");
      for (let i = 0; i < hex.length / 2; i++) requireThat(doc.payloadByte(n, i) === Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16), "field_prefix");
    }
    for (const [path, name] of Object.entries(b.registered ?? {})) {
      const entries = table<Readonly<Record<string, RegistryCode>>>(name); if (entries === undefined) reject("registry_unresolved");
      const n = uint(doc, get(path)); requireThat(Object.values(entries).some(v => code(v) === n), "enum_value");
    }
  }
  #arrayRule(doc: CBORDocument, root: number, f: WireField, context: Context, r: WireRule): void {
    const [array, original, childContext] = this.#path(doc, root, f, r.field, context);
    if (array < 0 && (r.op === "increasing_bytes" || r.op === "increasing_cbor")) return;
    requireThat(array >= 0 && doc.kind(array) === "array", "field_type");
    const field = this.#resolve(doc, original, childContext), itemField = field.items ?? unsignedField;
    let previous = -1, index = 0;
    const pick = (node: number): number => r.item_field_id === undefined ? node : doc.field(node, r.item_field_id);
    for (let item = doc.firstChild(array); item >= 0; item = doc.nextSibling(item)) {
      const value = pick(item);
      if (value < 0) reject("unknown_rule_field");
      switch (r.op) {
        case "ordinal_indices": requireThat(uint(doc, value) === BigInt(index), "item_index"); break;
        case "increasing": case "increasing_scopes": {
          const n = uint(doc, value);
          if (r.op === "increasing_scopes") {
            const maximum = table<{ readonly scope_id: { readonly max: string } }>("resource_caps")?.scope_id.max;
            if (maximum === undefined) reject("registry_unresolved");
            requireThat(n > 0n && n <= BigInt(maximum), "scope_order");
          }
          if (previous >= 0) requireThat(uint(doc, pick(previous)) < n, "item_order"); break;
        }
        case "increasing_bytes": case "increasing_cbor":
          if (r.op === "increasing_bytes") requireThat(doc.kind(value) === "bytes", "field_type");
          if (previous >= 0) requireThat(doc.compare(pick(previous), value, r.op === "increasing_bytes") < 0, "item_order");
          break;
        case "unique_by": case "increasing_tuple":
          // Uniqueness only applies to the small schema-bounded candidate sets.
          // Large histories use ordered tuples; no peer-sized Set is allocated.
          for (let prior = r.op === "unique_by" ? doc.firstChild(array) : previous; prior >= 0 && prior !== item; prior = doc.nextSibling(prior)) {
            let order = 0;
            for (const path of r.item_fields) {
              const a = this.#path(doc, prior, itemField, path, childContext)[0], b = this.#path(doc, item, itemField, path, childContext)[0];
              if (a < 0 || b < 0) reject("unknown_rule_field");
              order = r.op === "unique_by" ? (equal(doc, a, b) ? 0 : 1) : compare(doc, a, b);
              if (order !== 0) break;
            }
            requireThat(r.op === "unique_by" ? order !== 0 : order < 0, r.op === "unique_by" ? "item_identity" : "item_order");
          }
          break;
        case "exclusive_item":
          if (constant(doc, this.#path(doc, item, itemField, r.item_field, childContext)[0], r.value)) requireThat(doc.size(array) === 1, "item_exclusive");
          break;
        default: reject("rule_unresolved");
      }
      previous = item; index++;
    }
  }
  #registryTuple(doc: CBORDocument, root: number, f: WireField, context: Context, r: WireRule): void {
    let tuple = table<unknown>(r.registry);
    if (tuple === undefined) reject("registry_unresolved");
    for (const selector of r.selectors) {
      let label: string | undefined;
      if (selector.context !== undefined) label = this.#selector(doc, context, selector.context);
      else {
        const [node, field] = this.#path(doc, root, f, selector.field!, context), value = uint(doc, node);
        label = Object.entries(codes(field) ?? {}).find(([, n]) => code(n) === value)?.[0];
      }
      if (label === undefined || tuple === null || typeof tuple !== "object" || !Object.hasOwn(tuple, label)) reject("context_unresolved");
      tuple = (tuple as Readonly<Record<string, unknown>>)[label];
    }
    if (tuple === null || typeof tuple !== "object") reject("registry_unresolved");
    for (const path of r.fields) requireThat(Object.hasOwn(tuple, path) && constant(doc, this.#path(doc, root, f, path, context)[0], (tuple as Readonly<Record<string, unknown>>)[path]), "carrier_tuple");
  }
  #errorScope(doc: CBORDocument, get: (path: string) => number, r: WireRule): void {
    const n = uint(doc, get(r.code_field)), entries = table<Readonly<Record<string, number>>>("error_codes");
    const name = Object.entries(entries ?? {}).find(([, c]) => BigInt(c) === n)?.[0];
    if (name === undefined) reject("enum_value");
    const policy = own(table<Readonly<Record<string, { readonly scope: string; readonly retryable?: boolean }>>>("error_code_metadata"), name);
    if (policy === undefined) reject("registry_unresolved");
    const target = uint(doc, get(r.target_scope_field)), stream = get(r.stream_id_field);
    if (policy.scope === "session") requireThat(target === 0n && stream < 0, "error_scope");
    else if (policy.scope === "stream") requireThat(target > 0n && stream >= 0 && uint(doc, stream) === target, "error_scope");
    else reject("error_scope");
    if (policy.retryable !== true) requireThat(get(r.retry_after_field) < 0, "retry_after_forbidden");
  }
  #mapDigest(doc: CBORDocument, source: number, expected: number, name: string): void {
    const domain = wireDomains.find(d => d.name === name);
    if (domain === undefined || domain.operation !== "sha256" || domain.input_schema.parts.length !== 1) reject("domain_projection");
    const part = domain.input_schema.parts[0]!;
    if (part.encoding !== "lp-map" || part.projection !== "full") reject("domain_projection");
    requireThat(source >= 0 && expected >= 0 && doc.kind(expected) === "bytes" && doc.size(expected) === 32, "map_digest_mismatch");
    const payload = doc.kind(source) === "bytes", size = payload ? doc.size(source) : doc.encodedSize(source);
    requireThat(payload || doc.kind(source) === "map", "domain_projection");
    const hash = sha256.create();
    try {
      const label = domain.label_bytes;
      if (label.length > this.#chunk.length * 2) reject("domain_projection");
      for (let i = 0; i < label.length / 2; i++) this.#chunk[i] = Number.parseInt(label.slice(i * 2, i * 2 + 2), 16);
      hash.update(this.#chunk.subarray(0, label.length / 2));
      this.#chunk[0] = size >>> 24; this.#chunk[1] = size >>> 16; this.#chunk[2] = size >>> 8; this.#chunk[3] = size;
      hash.update(this.#chunk.subarray(0, 4));
      for (let offset = 0; offset < size;) {
        const count = doc.copyRange(source, offset, this.#chunk, payload); hash.update(this.#chunk.subarray(0, count)); offset += count;
      }
      hash.digestInto(this.#digest);
      let difference = 0; for (let i = 0; i < 32; i++) difference |= this.#digest[i]! ^ doc.payloadByte(expected, i);
      requireThat(difference === 0, "map_digest_mismatch");
    } finally { hash.destroy(); this.#chunk.fill(0); this.#digest.fill(0); }
  }
  #textFormat(format: string, value: string): void {
    if (format === "host") this.#host.host(value);
    else if (format === "loopback_host") this.#host.loopback(value);
    else if (format === "origin") {
      const schemes = table<Readonly<Record<string, { readonly default_port: number }>>>("origin_schemes");
      if (schemes === undefined) reject("registry_unresolved");
      this.#host.origin(value, schemes);
    } else reject("text_format_unresolved");
  }
  clear(): void { this.#contract?.plan.fill(undefined); this.#contract = undefined; this.#host.clear(); this.#chunk.fill(0); this.#digest.fill(0); }
}
Object.freeze(SchemaWorkspace.prototype); Object.freeze(SchemaWorkspace);

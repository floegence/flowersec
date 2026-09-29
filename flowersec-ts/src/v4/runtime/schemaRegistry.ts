import { transportV4CBORRegistryJSON, transportV4DomainsJSON } from "../../generated/transportV4Registry.js";

export type WireBound = number | string;
export interface WireField {
  readonly name?: string;
  readonly type: string;
  readonly schema_ref?: string;
  readonly encoded_schema_ref?: string;
  readonly allow_empty?: boolean;
  readonly nullable?: boolean;
  readonly nonzero?: boolean;
  readonly min?: WireBound;
  readonly max?: WireBound;
  readonly bitmask?: WireBound;
  readonly length?: number;
  readonly min_bytes?: number;
  readonly max_bytes?: number;
  readonly min_items?: number;
  readonly max_items?: number;
  readonly max_items_ref?: string;
  readonly max_ref?: string;
  readonly items?: WireField;
  readonly keys?: WireField;
  readonly values?: WireField;
  readonly entries?: Readonly<Record<string, WireField>>;
  readonly context?: string;
  readonly cases?: Readonly<Record<string, WireField>>;
  readonly const?: string | number | boolean;
  readonly const_ref?: string;
  readonly enum?: Readonly<Record<string, number>>;
  readonly enum_ref?: string;
  readonly text_enum_ref?: string;
  readonly pattern_ref?: string;
  readonly text_format?: string;
  readonly forbidden_prefix?: string;
  readonly profile_public_key?: boolean;
}
export interface WireMap {
  readonly fields: Readonly<Record<string, WireField>>;
  readonly required: readonly number[];
  readonly context_fields?: Readonly<Record<string, string>>;
  readonly max_encoded_bytes?: number;
  readonly max_encoded_bytes_ref?: string;
  readonly encoded_bytes?: number;
  readonly signature_field?: number;
  readonly mac_field?: number;
}
export interface WireBranch {
  readonly absent?: readonly string[];
  readonly required?: readonly string[];
  readonly constants?: Readonly<Record<string, boolean | number>>;
  readonly enum_values?: Readonly<Record<string, readonly number[]>>;
  readonly equal?: readonly (readonly [string, string])[];
  readonly less_or_equal?: readonly (readonly [string, string])[];
  readonly nonzero?: readonly string[];
  readonly zero_bytes?: readonly string[];
  readonly byte_lengths?: Readonly<Record<string, number>>;
  readonly byte_prefixes?: Readonly<Record<string, string>>;
  readonly registered?: Readonly<Record<string, string>>;
}
// These are trusted generated descriptors, never peer-supplied objects. Each
// operator consumes only its registered operands. Generator validation and the
// decoder's default rejection keep an unimplemented operator fail-closed.
export interface WireRule extends WireBranch {
  readonly op: string;
  readonly field: string;
  readonly fields: readonly string[];
  readonly left: string;
  readonly right: string;
  readonly when?: { readonly field?: string; readonly context?: string; readonly value: string | number | boolean };
  readonly discriminator: string;
  readonly value: string | boolean | number;
  readonly context: string;
  readonly cases: Readonly<Record<string, WireBranch>>;
  readonly min: WireBound;
  readonly max: WireBound;
  readonly pairs: readonly (readonly [number, number])[];
  readonly rows: readonly (readonly number[])[];
  readonly profile: string;
  readonly algorithm: string;
  readonly feature: string;
  readonly present: boolean;
  readonly source: string;
  readonly domain: string;
  readonly registry: string;
  readonly selectors: readonly { readonly field?: string; readonly context?: string }[];
  readonly code_field: string;
  readonly target_scope_field: string;
  readonly stream_id_field: string;
  readonly retry_after_field: string;
  readonly item_field_id?: number;
  readonly item_field: string;
  readonly item_fields: readonly string[];
  readonly format: string;
  readonly host: string;
  readonly port: string;
  readonly origin: string;
  readonly scheme: string;
}
interface Registry {
  readonly frame_maps: Readonly<Record<string, WireMap>>;
  readonly field_registries: Readonly<Record<string, unknown>>;
  readonly variant_rules: Readonly<Record<string, readonly WireRule[]>>;
  readonly relation_rules: Readonly<Record<string, readonly WireRule[]>>;
  readonly text_rules: Readonly<Record<string, readonly WireRule[]>>;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
// This one process-wide read-only registry is built from the generated literal.
// It cannot be extended per Environment, material, document, or connection.
const registry = freeze(JSON.parse(transportV4CBORRegistryJSON) as Registry);
export const wireMaps = registry.frame_maps;
export const wireVariants = registry.variant_rules;
export const wireRelations = registry.relation_rules;
export const wireTextRules = registry.text_rules;
export interface WireDomain {
  readonly name: string;
  readonly operation: string;
  readonly label_bytes: string;
  readonly input_schema: { readonly parts: readonly {
    readonly name: string; readonly encoding: string; readonly projection?: string; readonly schema_ref?: string;
    readonly length?: number; readonly enum?: readonly number[];
  }[] };
}
export const wireDomains: readonly WireDomain[] = freeze(JSON.parse(transportV4DomainsJSON) as WireDomain[]);
export function table<T>(name: string): T | undefined {
  return Object.hasOwn(registry.field_registries, name) ? registry.field_registries[name] as T : undefined;
}
export function own<T>(values: Readonly<Record<string, T>> | undefined, key: string): T | undefined {
  return values !== undefined && Object.hasOwn(values, key) ? values[key] : undefined;
}
const byName: Record<string, Record<string, number>> = Object.create(null) as Record<string, Record<string, number>>;
const patterns: Record<string, RegExp> = Object.create(null) as Record<string, RegExp>;
const limitNames = new Set<string>(), selectorNames = new Set<string>(["crypto_profile_id"]);
function visit(f: WireField): void {
  if (f.max_items_ref !== undefined) limitNames.add(f.max_items_ref);
  if (f.max_ref !== undefined) limitNames.add(f.max_ref);
  if (f.context !== undefined) selectorNames.add(f.context);
  for (const child of [f.items, f.keys, f.values]) if (child !== undefined) visit(child);
  for (const children of [f.entries, f.cases]) if (children !== undefined) for (const child of Object.values(children)) visit(child);
}
for (const [name, spec] of Object.entries(wireMaps)) {
  const names: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const [id, field] of Object.entries(spec.fields)) { if (field.name !== undefined) names[field.name] = Number(id); visit(field); }
  byName[name] = names;
  if (spec.max_encoded_bytes_ref !== undefined) limitNames.add(spec.max_encoded_bytes_ref);
  for (const context of Object.keys(spec.context_fields ?? {})) selectorNames.add(context);
}
for (const rules of [wireVariants, wireRelations, wireTextRules]) for (const list of Object.values(rules)) for (const rule of list) {
  if (rule.context !== undefined) selectorNames.add(rule.context);
  if (rule.when?.context !== undefined) selectorNames.add(rule.when.context);
  for (const selector of rule.selectors ?? []) if (selector.context !== undefined) selectorNames.add(selector.context);
}
for (const [name, text] of Object.entries(table<Record<string, string>>("text_patterns") ?? {})) patterns[name] = new RegExp(text, "u");
freeze(byName); freeze(patterns);
export const wireLimitNames: readonly string[] = Object.freeze([...limitNames]);
export const wireSelectorNames: readonly string[] = Object.freeze([...selectorNames]);
export function namedField(schema: string, name: string): number | undefined { return own(own(byName, schema), name); }
export function fieldPattern(name: string): RegExp | undefined { return own(patterns, name); }
export const unsignedField: WireField = Object.freeze({ type: "uint64" });

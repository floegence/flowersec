// Independent test-only L1 arithmetic. No real reservation, transfer or authority.
import { types } from "node:util";
import { transportV4CBORRegistryJSON, transportV4ResourceCompositionRegistry as spec } from "../../generated/transportV4Registry.js";

type Charge = { key: string; binding: string; boundary: string; vector: Record<string, bigint> };
export type ResourceTotals = Record<string, Record<string, string>>;
const featureRegistry = (JSON.parse(transportV4CBORRegistryJSON) as { field_registries: { feature_registry: Record<string, unknown> } }).field_registries.feature_registry;
const features = Object.keys(featureRegistry).sort();
const maximum = BigInt(spec.quantity_max);
function must(condition: unknown, error: string): asserts condition { if (!condition) throw new Error(error); }
function object(input: unknown, fields: readonly string[], required: readonly string[] = fields): Record<string, unknown> {
  must(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [null, Object.prototype as unknown].includes(Object.getPrototypeOf(input)), "resource_object");
  const properties = Object.getOwnPropertyDescriptors(input), captured: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(properties)) {
    must(typeof key === "string" && fields.includes(key), "resource_field");
    const property = properties[key]!;
    must(Object.hasOwn(property, "value") && property.enumerable, "resource_data_property");
    captured[key] = property.value as unknown;
  }
  must(required.every(key => Object.hasOwn(captured, key)), "resource_missing_field"); return captured;
}
export { object as captureResourceObject };
function array(input: unknown, cap: number): unknown[] {
  must(!types.isProxy(input) && Array.isArray(input) && Object.getPrototypeOf(input) === Array.prototype, "resource_array");
  const length = Object.getOwnPropertyDescriptor(input, "length")!.value as number;
  must(length <= cap, "resource_reference_limit");
  const properties = Object.getOwnPropertyDescriptors(input);
  must(Reflect.ownKeys(properties).length === length + 1, "resource_array_fields");
  const values: unknown[] = [];
  for (let i = 0; i < length; i++) {
    const property = properties[String(i)];
    must(property && Object.hasOwn(property, "value") && property.enumerable, "resource_data_property"); values.push(property.value as unknown);
  }
  return values;
}
// Length-prefix original JS strings, with no delimiter ambiguity or normalization.
const tuple = (parts: string[]): string => parts.map(part => `${part.length}:${part}`).join("");
function charge(input: unknown): Charge {
  const value = object(input, [...spec.owner_key_fields, ...spec.binding_fields, "control_boundary", "vector"]);
  const identity = (key: string): string => {
    const text = value[key]; must(typeof text === "string" && text.length > 0 && text.length <= 256, "resource_identity"); return text;
  };
  const boundary = value.control_boundary;
  must(typeof boundary === "string" && (spec.control_boundaries as readonly string[]).includes(boundary), "resource_control_boundary");
  const vector = object(value.vector, spec.dimensions), quantities: Record<string, bigint> = {}, amounts: string[] = [];
  for (const dimension of spec.dimensions) {
    const text = vector[dimension]; must(typeof text === "string" && /^(0|[1-9][0-9]{0,19})$/u.test(text), "resource_quantity");
    const n = BigInt(text); must(n <= maximum, "resource_quantity"); quantities[dimension] = n; amounts.push(text);
  }
  return { key: tuple(spec.owner_key_fields.map(identity)), binding: tuple([...spec.binding_fields.map(identity), boundary, ...amounts]), boundary, vector: quantities };
}

export function resourceMinimum(input: unknown): ResourceTotals {
  const plan = object(input, ["reference_limit", "base", "features", "legal_selections"]);
  must(typeof plan.reference_limit === "number" && Number.isSafeInteger(plan.reference_limit) && plan.reference_limit > 0, "resource_reference_limit");
  const base = object(plan.base, spec.base_components), featureInputs = object(plan.features, features, []);
  must(features.length <= 16, "resource_feature_registry");
  const alternatives = array(plan.legal_selections, 2 ** features.length);
  must(alternatives.length > 0, "resource_legal_selections_missing");
  const alternativesSeen = new Set<string>();
  const selections = alternatives.map(input => {
    const names: string[] = [];
    for (const name of array(input, features.length)) {
      must(typeof name === "string" && features.includes(name), "resource_feature_unknown");
      must(!names.includes(name), "resource_feature_duplicate"); names.push(name);
    }
    names.sort(); const key = tuple(names);
    must(!alternativesSeen.has(key), "resource_selection_duplicate"); alternativesSeen.add(key);
    must(names.every(name => Object.hasOwn(featureInputs, name)), "resource_feature_missing"); return names;
  });
  let remaining = plan.reference_limit;
  const registered = new Map<string, string>();
  const capture = (input: unknown): Charge[] => {
    const values = array(input, remaining); remaining -= values.length;
    return values.map(input => {
      const item = charge(input), previous = registered.get(item.key);
      must(previous === undefined || previous === item.binding, "resource_owner_conflict"); registered.set(item.key, item.binding); return item;
    });
  };
  const common = spec.base_components.flatMap(name => capture(base[name]));
  const featureCharges = new Map(features.filter(name => Object.hasOwn(featureInputs, name)).map(name => [name, capture(featureInputs[name])]));
  const result: ResourceTotals = Object.fromEntries(spec.control_boundaries.map(boundary =>
    [boundary, Object.fromEntries(spec.dimensions.map(dimension => [dimension, "0"]))]));
  for (const selection of selections) {
    const union = new Map(common.map(item => [item.key, item]));
    for (const name of selection) for (const item of featureCharges.get(name)!) union.set(item.key, item);
    for (const boundary of spec.control_boundaries) for (const dimension of spec.dimensions) {
      let sum = 0n;
      for (const item of union.values()) if (item.boundary === boundary) { sum += item.vector[dimension]!; must(sum <= maximum, "resource_sum_overflow"); }
      if (sum > BigInt(result[boundary]![dimension]!)) result[boundary]![dimension] = sum.toString();
    }
  }
  return result;
}

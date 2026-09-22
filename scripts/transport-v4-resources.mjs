import assert from "node:assert/strict";
import { types } from "node:util";

const requireThat = (condition, code) => { if (!condition) throw new Error(code); };
const has = (object, key) => Object.hasOwn(object, key);

export function verifyResourceCompositionRegistry(registry) {
  assert.deepEqual(registry, {
    status: "reference_owner_union_only",
    owner_key_fields: ["resource_profile_revision", "environment_id", "owner_kind", "owner_instance_id", "backing_id", "direction"],
    binding_fields: ["backing_lifetime_id", "charge_binding_id"],
    control_boundaries: ["sdk_owned", "provider_controlled", "provider_observable", "host_unobservable"],
    dimensions: ["bytes", "work", "items"], quantity_max: "18446744073709551615",
    base_components: ["transport_core", "reject_only", "enabled", "actual_shared_refs"],
    composition: "owner_union_then_componentwise_max",
    transfer: "cross_owner_deduplication_not_implemented",
  });
}

// Only own, ordinary data properties are captured. Configuration references
// cannot invoke getters, proxy traps, iterators or string conversion hooks.
function record(value, allowed, required = allowed) {
  requireThat(value !== null && typeof value === "object" && !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value)), "resource_object");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result = Object.create(null);
  for (const name of Reflect.ownKeys(descriptors)) {
    requireThat(typeof name === "string" && allowed.includes(name), "resource_field");
    const descriptor = descriptors[name];
    requireThat(has(descriptor, "value") && descriptor.enumerable, "resource_data_property");
    result[name] = descriptor.value;
  }
  requireThat(required.every(name => has(result, name)), "resource_missing_field");
  return result;
}

export { record as captureResourceRecord };

function list(value, limit) {
  requireThat(!types.isProxy(value) && Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype, "resource_array");
  const length = Object.getOwnPropertyDescriptor(value, "length").value;
  requireThat(length <= limit, "resource_reference_limit");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  requireThat(Reflect.ownKeys(descriptors).length === length + 1, "resource_array_fields");
  const result = [];
  for (let i = 0; i < length; i++) {
    const descriptor = descriptors[i];
    requireThat(descriptor && has(descriptor, "value") && descriptor.enumerable, "resource_data_property");
    result.push(descriptor.value);
  }
  return result;
}

const identity = value => typeof value === "string" && value.length > 0 && value.length <= 256;
const zero = registry => Object.fromEntries(registry.control_boundaries.map(boundary =>
  [boundary, Object.fromEntries(registry.dimensions.map(dimension => [dimension, 0n]))]));
const projection = totals => Object.fromEntries(Object.entries(totals).map(([boundary, vector]) =>
  [boundary, Object.fromEntries(Object.entries(vector).map(([dimension, value]) => [dimension, value.toString()]))]));

function captureCharge(registry, input) {
  const charge = record(input, [...registry.owner_key_fields, ...registry.binding_fields, "control_boundary", "vector"]);
  requireThat([...registry.owner_key_fields, ...registry.binding_fields].every(name => identity(charge[name])), "resource_identity");
  requireThat(registry.control_boundaries.includes(charge.control_boundary), "resource_control_boundary");
  const vector = record(charge.vector, registry.dimensions);
  for (const dimension of registry.dimensions) {
    requireThat(typeof vector[dimension] === "string" && /^(0|[1-9][0-9]{0,19})$/u.test(vector[dimension]), "resource_quantity");
    requireThat(BigInt(vector[dimension]) <= BigInt(registry.quantity_max), "resource_quantity");
  }
  const key = JSON.stringify(registry.owner_key_fields.map(name => charge[name]));
  const binding = JSON.stringify([...registry.binding_fields.map(name => charge[name]), charge.control_boundary,
    ...registry.dimensions.map(dimension => vector[dimension])]);
  return { key, binding, boundary: charge.control_boundary, vector };
}

// Stateless L1 arithmetic reference over trusted, complete owner obligations
// and legal selections. It neither derives legality/charges from capabilities
// nor reserves or releases resources. A configured reference_limit bounds input
// references, not real memory. Only exact original owner keys deduplicate;
// registered transfers, ownership lifetimes and provider measurements remain
// separate work. An owner transfer must not be erased from input as an alias.
export function readyMinimumReference(schema, input) {
  const registry = schema.resource_composition_registry;
  verifyResourceCompositionRegistry(registry);
  const featureNames = Object.keys(schema.feature_registry);
  requireThat(featureNames.length <= 16, "resource_feature_registry");
  const plan = record(input, ["reference_limit", "base", "features", "legal_selections"]);
  requireThat(Number.isSafeInteger(plan.reference_limit) && plan.reference_limit > 0, "resource_reference_limit");
  const base = record(plan.base, registry.base_components);
  const features = record(plan.features, featureNames, []);
  const selections = list(plan.legal_selections, 2 ** featureNames.length);
  requireThat(selections.length > 0, "resource_legal_selections_missing");
  const seenSelections = new Set();
  const legalSelections = selections.map(selection => {
    const names = list(selection, featureNames.length);
    requireThat(names.every(name => typeof name === "string" && featureNames.includes(name)), "resource_feature_unknown");
    requireThat(new Set(names).size === names.length, "resource_feature_duplicate");
    const ordered = featureNames.filter(name => names.includes(name));
    const key = JSON.stringify(ordered);
    requireThat(!seenSelections.has(key), "resource_selection_duplicate");
    seenSelections.add(key);
    requireThat(ordered.every(name => has(features, name)), "resource_feature_missing");
    return ordered;
  });
  // Capture all declared obligations once, with an aggregate bound. Validate
  // duplicate owner bindings across alternatives too: one actual allocation
  // cannot change its charge or control boundary when another feature wins.
  let references = 0;
  const owners = new Map();
  const capture = values => list(values, plan.reference_limit - references).map(value => {
    references++;
    const charge = captureCharge(registry, value);
    requireThat(!owners.has(charge.key) || owners.get(charge.key) === charge.binding, "resource_owner_conflict");
    owners.set(charge.key, charge.binding);
    return charge;
  });
  const baseCharges = registry.base_components.flatMap(name => capture(base[name]));
  const featureCharges = Object.fromEntries(Object.entries(features).map(([name, values]) => [name, capture(values)]));
  const maximum = zero(registry);
  const bySelection = legalSelections.map(names => {
    const totals = zero(registry), used = new Set();
    for (const charge of [...baseCharges, ...names.flatMap(name => featureCharges[name])]) {
      if (used.has(charge.key)) continue;
      used.add(charge.key);
      for (const dimension of registry.dimensions) {
        const next = totals[charge.boundary][dimension] + BigInt(charge.vector[dimension]);
        requireThat(next <= BigInt(registry.quantity_max), "resource_sum_overflow");
        totals[charge.boundary][dimension] = next;
      }
    }
    for (const boundary of registry.control_boundaries) for (const dimension of registry.dimensions) {
      if (totals[boundary][dimension] > maximum[boundary][dimension]) maximum[boundary][dimension] = totals[boundary][dimension];
    }
    return { features: names, totals: projection(totals) };
  });
  // Provider-controlled/observable/host figures deliberately remain separate.
  // Their sum is never exposed as an SDK hard-memory guarantee.
  return { by_selection: bySelection, ready_min: projection(maximum) };
}

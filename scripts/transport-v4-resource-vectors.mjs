import assert from "node:assert/strict";
import { readyMinimumReference, verifyResourceCompositionRegistry } from "./transport-v4-resources.mjs";

export function buildResourceCompositionCorpus(schema) {
  const registry = schema.resource_composition_registry, plan = schema.resource_composition_vector_plan;
  verifyResourceCompositionRegistry(registry);
  const fixture = name => {
    assert.ok(Object.hasOwn(plan.fixtures, name), "missing resource fixture");
    return structuredClone({ ...plan.fixture_context, ...plan.fixtures[name] });
  };
  const ids = new Set();
  const vectors = plan.cases.map(spec => {
    assert.match(spec.id, /^resources_[a-z0-9_]+$/u);
    assert.ok(!ids.has(spec.id), "duplicate resource vector"); ids.add(spec.id);
    for (const component of Object.keys(spec.base)) assert.ok(registry.base_components.includes(component));
    const input = {
      reference_limit: spec.reference_limit ?? 64,
      base: Object.fromEntries(registry.base_components.map(name => [name, (spec.base[name] ?? []).map(fixture)])),
      features: Object.fromEntries(Object.entries(spec.features).map(([name, refs]) => [name, refs.map(fixture)])),
      legal_selections: structuredClone(spec.legal_selections),
    };
    if (spec.expected_error) {
      assert.equal(spec.expected, undefined);
      assert.throws(() => readyMinimumReference(schema, input), { message: spec.expected_error });
      return { id: spec.id, input, expected_error: spec.expected_error };
    }
    const expected = spec.expected;
    for (const boundary of Object.keys(expected)) {
      assert.ok(registry.control_boundaries.includes(boundary));
      assert.equal(expected[boundary].length, registry.dimensions.length);
    }
    const readyMin = Object.fromEntries(registry.control_boundaries.map(boundary => [boundary,
      Object.fromEntries(registry.dimensions.map((dimension, index) => [dimension, expected[boundary]?.[index] ?? "0"]))]));
    assert.deepEqual(readyMinimumReference(schema, input).ready_min, readyMin);
    return { id: spec.id, input, expected_ready_min: readyMin };
  });
  return { status: "draft", coverage: "synthetic_resource_owner_composition_only", schema_revision: schema.schema_revision,
    design_sha256: schema.design_sha256, unverified: ["Complete authenticated legal selections and actual component charges",
      "Registered atomic transfers, reservations, owner lifetimes and cleanup", "Physical memory, provider limits and production SDK integration"], vectors };
}

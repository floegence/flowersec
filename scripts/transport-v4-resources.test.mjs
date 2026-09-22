import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { readyMinimumReference, verifyResourceCompositionRegistry } from "./transport-v4-resources.mjs";
import { buildResourceCompositionCorpus } from "./transport-v4-resource-vectors.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = buildResourceCompositionCorpus(schema);
const fixture = id => structuredClone(corpus.vectors.find(vector => vector.id === id));
const basic = () => fixture("resources_empty_features").input;
const solve = input => readyMinimumReference(schema, input);

test("resource corpus has fixed synthetic owner sums and rejection reasons", () => {
  for (const vector of corpus.vectors) {
    if (vector.expected_error) assert.throws(() => solve(vector.input), { message: vector.expected_error });
    else assert.deepEqual(solve(vector.input).ready_min, vector.expected_ready_min);
  }
  assert.equal(corpus.vectors.length, 19);
});

test("resource combinations sum independent obligations before taking per-dimension maxima", () => {
  const input = fixture("resources_combined_features").input;
  const result = solve(input);
  assert.deepEqual(result.by_selection.map(item => item.totals.sdk_owned), [
    { bytes: "100", work: "10", items: "1" }, { bytes: "140", work: "12", items: "3" },
    { bytes: "160", work: "17", items: "2" }, { bytes: "200", work: "19", items: "4" },
  ]);
  // A constrained legal set has different maxima in different dimensions.
  input.legal_selections = [["datagram"], ["application_progress_resume"]];
  input.features.datagram[0].vector = { bytes: "80", work: "1", items: "9" };
  input.features.application_progress_resume[0].vector = { bytes: "60", work: "7", items: "1" };
  assert.deepEqual(solve(input).ready_min.sdk_owned, { bytes: "180", work: "17", items: "10" });
  input.legal_selections.reverse();
  assert.deepEqual(solve(input).ready_min.sdk_owned, { bytes: "180", work: "17", items: "10" });
});

test("resource owner identity requires every key coordinate and immutable charge binding", () => {
  for (const field of schema.resource_composition_registry.owner_key_fields) {
    const input = basic(), other = structuredClone(input.base.transport_core[0]);
    other[field] += "-other"; input.base.actual_shared_refs.push(other);
    assert.deepEqual(solve(input).ready_min.sdk_owned, { bytes: "200", work: "20", items: "2" }, field);
  }
  for (const field of schema.resource_composition_registry.binding_fields) {
    const input = basic(), other = structuredClone(input.base.transport_core[0]);
    other[field] += "-other"; input.base.actual_shared_refs.push(other);
    assert.throws(() => solve(input), /resource_owner_conflict/u, field);
  }
  const input = basic(), other = structuredClone(input.base.transport_core[0]);
  other.control_boundary = "provider_controlled"; input.base.actual_shared_refs.push(other);
  assert.throws(() => solve(input), /resource_owner_conflict/u);
  // Different selection alternatives cannot silently rebind the same owner.
  input.base.actual_shared_refs = [];
  input.features = { datagram: [other] };
  input.legal_selections = [[], ["datagram"]];
  assert.throws(() => solve(input), /resource_owner_conflict/u);
});

test("resource identity tuple encoding cannot collide through delimiter-like content", () => {
  const input = basic(), first = input.base.transport_core[0], other = structuredClone(first);
  first.environment_id = "a|b"; first.owner_kind = "c";
  other.environment_id = "a"; other.owner_kind = "b|c";
  input.base.actual_shared_refs.push(other);
  assert.equal(solve(input).ready_min.sdk_owned.bytes, "200");
});

test("resource control boundaries never enter the SDK hard sum", () => {
  const input = basic();
  for (const control_boundary of schema.resource_composition_registry.control_boundaries.slice(1)) {
    const charge = structuredClone(input.base.transport_core[0]);
    charge.control_boundary = control_boundary; charge.owner_instance_id = control_boundary;
    input.base.actual_shared_refs.push(charge);
  }
  const result = solve(input);
  for (const total of Object.values(result.ready_min)) assert.deepEqual(total, { bytes: "100", work: "10", items: "1" });
});

test("resource quantities reject lossy/coerced arithmetic and overflow in every dimension", () => {
  for (const dimension of schema.resource_composition_registry.dimensions) {
    for (const bad of [1, 1n, -1, "-1", "01", "1.0", "1e3", "18446744073709551616", "9".repeat(100), {}, null]) {
      const input = basic(); input.base.transport_core[0].vector[dimension] = bad;
      assert.throws(() => solve(input), /resource_quantity/u);
    }
    const input = fixture("resources_distinct_owner").input;
    input.base.transport_core[0].vector[dimension] = "18446744073709551615";
    input.base.actual_shared_refs[0].vector[dimension] = "1";
    assert.throws(() => solve(input), /resource_sum_overflow/u);
  }
});

test("resource plans require explicit components, dimensions, legality and finite reference counts", () => {
  for (const component of schema.resource_composition_registry.base_components) {
    const input = basic(); delete input.base[component];
    assert.throws(() => solve(input), /resource_missing_field/u);
  }
  for (const dimension of schema.resource_composition_registry.dimensions) {
    const input = basic(); delete input.base.transport_core[0].vector[dimension];
    assert.throws(() => solve(input), /resource_missing_field/u);
  }
  for (const limit of [0, -1, Infinity, Number.MAX_SAFE_INTEGER + 1, "64"]) {
    const input = basic(); input.reference_limit = limit;
    assert.throws(() => solve(input), /resource_reference_limit/u);
  }
  const input = basic(); input.transfer = { old_key: "old", new_key: "new" };
  assert.throws(() => solve(input), /resource_field/u);
  // Missing transfer registration cannot authorize cross-owner alias dedup.
  assert.equal(solve(fixture("resources_distinct_owner").input).ready_min.sdk_owned.bytes, "200");
});

test("resource object, array and vector validation never invokes caller hooks", () => {
  let calls = 0;
  const hook = () => { calls++; throw new Error("caller hook invoked"); };
  const mutations = [
    input => new Proxy(input, { ownKeys: hook, getPrototypeOf: hook, get: hook }),
    input => { Object.defineProperty(input, "features", { get: hook }); return input; },
    input => { Object.setPrototypeOf(input, new Proxy({}, { getPrototypeOf: hook })); return input; },
    input => { Object.defineProperty(input.base.transport_core[0].vector, "bytes", { get: hook }); return input; },
    input => { Object.defineProperty(input.legal_selections, "0", { get: hook }); return input; },
    input => { input.base.transport_core = new Proxy([], { get: hook }); return input; },
    input => { input.base.transport_core[0].vector.bytes = { toString: hook }; return input; },
    input => { input.legal_selections[Symbol.iterator] = hook; return input; },
  ];
  for (const mutate of mutations) { assert.throws(() => solve(mutate(basic())), /resource_/u); assert.equal(calls, 0); }
  const { proxy, revoke } = Proxy.revocable([], {}); revoke();
  const input = basic(); input.legal_selections = proxy;
  assert.throws(() => solve(input), /resource_array/u); assert.equal(calls, 0);
  input.legal_selections = new Array(4); assert.throws(() => solve(input), /resource_array_fields/u);
});

test("resource capture preserves caller configuration and results own their projections", () => {
  const input = fixture("resources_shared_owner").input, original = structuredClone(input);
  const result = solve(input); assert.deepEqual(input, original);
  result.by_selection[0].features.push("unknown");
  result.ready_min.sdk_owned.bytes = "0";
  assert.deepEqual(solve(input).ready_min, fixture("resources_shared_owner").expected_ready_min);
});

test("resource union matches independent set enumeration for every pair of three-owner feature memberships", () => {
  const source = fixture("resources_combined_features").input;
  const charges = [source.base.transport_core[0], source.features.datagram[0], source.features.application_progress_resume[0]];
  const selections = [[], ["datagram"], ["application_progress_resume"], ["datagram", "application_progress_resume"]];
  for (let left = 0; left < 8; left++) for (let right = 0; right < 8; right++) for (let selectionMask = 1; selectionMask < 16; selectionMask++) {
    const input = basic(); input.base.transport_core = [];
    input.features = { datagram: charges.filter((_, i) => left & (1 << i)), application_progress_resume: charges.filter((_, i) => right & (1 << i)) };
    input.legal_selections = selections.filter((_, i) => selectionMask & (1 << i));
    const expected = { bytes: 0n, work: 0n, items: 0n };
    for (const selection of input.legal_selections) {
      let mask = 0; for (const name of selection) mask |= name === "datagram" ? left : right;
      for (const dimension of Object.keys(expected)) {
        const total = charges.reduce((sum, charge, i) => sum + (mask & (1 << i) ? BigInt(charge.vector[dimension]) : 0n), 0n);
        if (total > expected[dimension]) expected[dimension] = total;
      }
    }
    assert.deepEqual(solve(input).ready_min.sdk_owned, Object.fromEntries(Object.entries(expected).map(([key, value]) => [key, value.toString()])));
  }
});

test("resource registry rejects weakened key, boundary, dimension or composition rules", () => {
  const changes = [r => r.owner_key_fields.pop(), r => r.control_boundaries.pop(), r => r.dimensions.pop(),
    r => r.quantity_max = "999", r => r.composition = "maximum_before_sum", r => r.transfer = "implicit"];
  for (const change of changes) { const r = structuredClone(schema.resource_composition_registry); change(r); assert.throws(() => verifyResourceCompositionRegistry(r)); }
});

import assert from "node:assert/strict";
import { types } from "node:util";
import { VectorError } from "./transport-v4-codec.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const operationFields = {
  elapsed: ["delta_ms", "rate_numerator", "rate_denominator", "quantization_ms"],
  network_anchor: ["sample_ms", "source_error_ms", "delta_ms", "rate_numerator", "rate_denominator", "quantization_ms", "max_round_trip_ms", "max_width_ms"],
  advance_anchor: ["lower_ms", "upper_ms", "delta_ms", "rate_numerator", "rate_denominator", "quantization_ms", "max_age_ms", "max_width_ms"],
  deadline_delta: ["upper_ms", "deadline_ms", "rate_numerator", "rate_denominator", "quantization_ms"],
  prove_delta: ["lower_ms", "bound_ms", "rate_numerator", "rate_denominator", "quantization_ms"],
};

export function verifyTimeArithmeticRegistry(schema) {
  const registry = schema.time_arithmetic_registry;
  assert.equal(registry.status, "reference_arithmetic_only");
  assert.equal(registry.source, "3.3.1");
  assert.equal(registry.unit, "integer_milliseconds");
  assert.equal(registry.quantity_max, "18446744073709551615");
  assert.equal(registry.intermediate_max, "340282366920938463463374607431768211455");
  assert.equal(registry.rate, "rho=rate_numerator/rate_denominator; 0<=numerator<denominator");
  assert.equal(registry.rounding, "lower_floor_upper_ceiling");
  assert.equal(registry.quantization, "abs(observed_delta_ms-ideal_monotonic_delta_ms)<=quantization_ms; applied_before_drift_conversion");
  assert.deepEqual(registry.operations, operationFields);
  assert.match(registry.qualification, /no clock/u);
}

// This decimal-string interface is for shared arithmetic vectors, not a Clock
// API. Inputs must represent independently qualified original source/monotonic
// facts. source_error_ms includes source encoding/sampling error; quantization_ms
// bounds the observed minus ideal monotonic increment, before drift conversion.
// Neither is extra authorization skew.
// This helper authenticates no nonce/source, samples no time, installs no anchor
// or timer, and cannot establish clock/owner continuity or restore a closed gate.
export function timeArithmeticReference(schema, operation, input) {
  verifyTimeArithmeticRegistry(schema);
  const registry = schema.time_arithmetic_registry;
  requireThat(typeof operation === "string" && Object.hasOwn(registry.operations, operation), "time_operation");
  const names = registry.operations[operation];
  requireThat(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)), "time_input_object");
  const keys = Reflect.ownKeys(input);
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "time_input_fields");
  const maximum = BigInt(registry.quantity_max), wideMaximum = BigInt(registry.intermediate_max);
  const values = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "time_input_data");
    const value = descriptor.value;
    requireThat(typeof value === "string" && value.length <= registry.quantity_max.length && /^(?:0|[1-9][0-9]*)$/u.test(value), "time_integer");
    values[name] = BigInt(value);
    requireThat(values[name] <= maximum, "time_integer");
  }
  const checked = value => { requireThat(value >= 0n && value <= maximum, "time_overflow"); return value; };
  const wide = value => { requireThat(value >= 0n && value <= wideMaximum, "time_overflow"); return value; };
  const ceil = (a, b) => a / b + (a % b === 0n ? 0n : 1n);
  const { rate_numerator: n, rate_denominator: d, quantization_ms: q } = values;
  requireThat(d > 0n && n < d, "time_rate");
  const elapsed = delta => {
    const lowerProduct = wide((delta > q ? delta - q : 0n) * d);
    const upperProduct = wide(checked(delta + q) * d);
    return { lower: lowerProduct / wide(d + n), upper: checked(ceil(upperProduct, d - n)) };
  };
  const width = (lower, upper) => {
    requireThat(lower <= upper, "time_interval");
    requireThat(values.max_width_ms > 0n && upper - lower <= values.max_width_ms, "time_width");
  };
  let result;
  if (operation === "elapsed") {
    const e = elapsed(values.delta_ms);
    result = { elapsed_lower_ms: e.lower, elapsed_upper_ms: e.upper };
  } else if (operation === "network_anchor") {
    const e = elapsed(values.delta_ms);
    requireThat(values.max_round_trip_ms > 0n && e.upper <= values.max_round_trip_ms, "time_round_trip");
    const lower = checked(values.sample_ms - values.source_error_ms);
    const upper = checked(values.sample_ms + values.source_error_ms + e.upper);
    width(lower, upper);
    result = { lower_ms: lower, upper_ms: upper };
  } else if (operation === "advance_anchor") {
    requireThat(values.lower_ms <= values.upper_ms, "time_interval");
    const e = elapsed(values.delta_ms);
    requireThat(values.max_age_ms > 0n && e.upper <= values.max_age_ms, "time_anchor_age");
    const lower = checked(values.lower_ms + e.lower), upper = checked(values.upper_ms + e.upper);
    width(lower, upper);
    result = { lower_ms: lower, upper_ms: upper };
  } else if (operation === "deadline_delta") {
    requireThat(values.upper_ms < values.deadline_ms, "time_expired");
    const slack = values.deadline_ms - values.upper_ms;
    const observedBudget = wide(slack * (d - n)) / d;
    requireThat(q <= observedBudget, "time_deadline_unrepresentable");
    // Greatest d_m with ceil((d_m+q)/(1-rho)) <= D-t_upper.
    // This schedules the conservative timer; actual use still requires strict
    // t_upper<D. An existing owner's installed deadline must never be extended.
    result = { delta_ms: checked(observedBudget - q) };
  } else {
    // A wakeup only requests another complete trusted sample/validation; it
    // does not establish validity or extend the original owner's deadline.
    if (values.bound_ms <= values.lower_ms) result = { delta_ms: 0n };
    else {
      const gap = values.bound_ms - values.lower_ms;
      result = { delta_ms: checked(ceil(wide(gap * wide(d + n)), d) + q) };
    }
  }
  return Object.freeze(Object.fromEntries(Object.entries(result).map(([key, value]) => [key, value.toString()])));
}

export function buildTimeArithmeticCorpus(schema) {
  verifyTimeArithmeticRegistry(schema);
  const ids = new Set();
  const vectors = schema.time_arithmetic_vector_plan.map(spec => {
    assert.match(spec.id, /^time_[a-z0-9_]+$/u);
    assert.ok(!ids.has(spec.id), "duplicate time vector"); ids.add(spec.id);
    const input = structuredClone(spec.input);
    if (spec.expected_error) {
      assert.equal(spec.expected, undefined);
      assert.throws(() => timeArithmeticReference(schema, spec.operation, input), error => error instanceof VectorError && error.code === spec.expected_error);
      return { id: spec.id, operation: spec.operation, input, expected_error: spec.expected_error };
    }
    const expected = timeArithmeticReference(schema, spec.operation, input);
    assert.deepEqual(expected, spec.expected, spec.id);
    return { id: spec.id, operation: spec.operation, input, expected };
  });
  return { status: "draft", schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: "trusted_time_arithmetic_only", qualification: schema.time_arithmetic_registry.qualification, vectors };
}

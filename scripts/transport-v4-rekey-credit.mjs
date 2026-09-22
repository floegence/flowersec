import assert from "node:assert/strict";
import { types } from "node:util";
import { VectorError } from "./transport-v4-codec.mjs";
import { verifyCryptoUsageRegistry } from "./transport-v4-crypto-usage.mjs";
import { timeArithmeticReference } from "./transport-v4-time.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const rateFields = ["rate_numerator", "rate_denominator", "quantization_ms"];
const creditFields = ["burst_rounds", "refill_period_ms", "base_credit", "delta_ms", ...rateFields];
const operations = {
  service: ["burst_rounds", "refill_period_ms", "request_start_budget_ms", "issued_at_ms", "session_not_after_ms", ...rateFields],
  initial_credit: ["burst_rounds", "refill_period_ms"],
  client_credit: creditFields,
  server_credit: creditFields,
};

export function verifyRekeyCreditRegistry(schema) {
  const registry = schema.rekey_credit_registry;
  assert.equal(registry.status, "reference_arithmetic_only");
  assert.equal(registry.source, "3.8");
  assert.equal(registry.quantity_max, schema.time_arithmetic_registry.quantity_max);
  assert.equal(registry.intermediate_max, schema.time_arithmetic_registry.intermediate_max);
  assert.deepEqual(registry.operations, operations);
  assert.equal(registry.additional_authorization_tolerance_ms, "0");
  assert.equal(registry.service_error, "configuration_capacity");
  assert.equal(registry.error_allowance, "ceil(2*eta/(1-rho))+1");
  assert.equal(registry.service_rounds, "floor((B*R+B*((1+rho)/(1-rho))*T)/(R-B*e))");
  assert.deepEqual(registry.elapsed_bound, { client_credit: "elapsed_lower_ms", server_credit: "elapsed_upper_ms" });
  assert.match(registry.qualification, /no live owner/u);
  verifyCryptoUsageRegistry(schema);
  const fields = schema.frame_maps.RekeyEnvelope.fields;
  assert.deepEqual(Object.values(fields).map(field => [field.name, field.type, field.min]),
    [["burst_rounds", "uint16", 1], ["refill_period_ms", "uint32", 1], ["request_start_budget_ms", "uint32", 1]]);
}

// Pure decimal-string projections; neither a credit mutation nor an INIT permit.
// Runtime owns the original authenticated Artifact/TimeProfile, retained base,
// causal ACK anchor, once-only INIT deduction and real service/cleanup reserves.
// A pending round cannot accrue credit; ACK preserves post_charge unchanged.
export function rekeyCreditReference(schema, profile, operation, input) {
  verifyRekeyCreditRegistry(schema);
  const registry = schema.rekey_credit_registry;
  requireThat(typeof profile === "string" && Object.hasOwn(schema.crypto_usage_registry.profiles, profile), "rekey_credit_profile");
  requireThat(typeof operation === "string" && Object.hasOwn(registry.operations, operation), "rekey_credit_operation");
  requireThat(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)), "rekey_credit_input");
  const names = registry.operations[operation], keys = Reflect.ownKeys(input);
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "rekey_credit_fields");
  const maximum = BigInt(registry.quantity_max), wideMaximum = BigInt(registry.intermediate_max);
  const values = Object.create(null);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "rekey_credit_data");
    const value = descriptor.value;
    requireThat(typeof value === "string" && value.length <= registry.quantity_max.length && /^(?:0|[1-9][0-9]*)$/u.test(value), "rekey_credit_integer");
    values[name] = BigInt(value);
    requireThat(values[name] <= maximum, "rekey_credit_integer");
  }
  const capacity = condition => requireThat(condition, registry.service_error);
  const wide = value => { capacity(value >= 0n && value <= wideMaximum); return value; };
  const ceil = (a, b) => a / b + (a % b === 0n ? 0n : 1n);
  for (const field of Object.values(schema.frame_maps.RekeyEnvelope.fields)) {
    if (!Object.hasOwn(values, field.name)) continue;
    const bits = Number(field.type.slice(4));
    capacity(values[field.name] >= BigInt(field.min) && values[field.name] < (1n << BigInt(bits)));
  }
  const B = values.burst_rounds, R = values.refill_period_ms, C = wide(B * R);
  const maxEpochs = BigInt(schema.crypto_usage_registry.profiles[profile].max_epochs);
  capacity(B < maxEpochs);
  let result;
  if (operation === "service") {
    const { rate_numerator: n, rate_denominator: d, quantization_ms: q } = values;
    capacity(d > 0n && n < d && values.issued_at_ms < values.session_not_after_ms);
    const minus = d - n, plus = wide(d + n), T = values.session_not_after_ms - values.issued_at_ms;
    // R>B*e bounds e before computing 2*q*d, avoiding an overflowing
    // intermediate for inputs that cannot possibly fit the service envelope.
    const maxError = (R - 1n) / B;
    capacity(maxError >= 1n);
    capacity(q <= wide((maxError - 1n) * minus) / wide(2n * d));
    const e = ceil(wide(wide(2n * q) * d), minus) + 1n;
    const denominatorMs = R - B * e;
    capacity(denominatorMs > 0n);
    const denominator = wide(denominatorMs * minus), initial = wide(C * minus), coefficient = wide(B * plus);
    // floor(numerator/denominator)<maxEpochs iff numerator<maxEpochs*denominator.
    // Bound T first. Accepted products then fit uint128 even for uint64 rates.
    const exclusiveLimit = wide(maxEpochs * denominator);
    capacity(initial < exclusiveLimit);
    capacity(T <= (exclusiveLimit - 1n - initial) / coefficient);
    const numerator = wide(initial + wide(coefficient * T));
    const rounds = numerator / denominator;
    capacity(rounds > 0n && rounds < maxEpochs);
    result = { service_ms: T, error_allowance_ms: e, denominator_ms: denominatorMs,
      capacity_credit: C, max_rounds: rounds, required_epochs: rounds + 1n };
  } else {
    let available = C;
    if (operation !== "initial_credit") {
      capacity(values.base_credit <= C);
      const elapsed = timeArithmeticReference(schema, "elapsed", Object.fromEntries(
        ["delta_ms", ...rateFields].map(name => [name, values[name].toString()])));
      const u = BigInt(elapsed[registry.elapsed_bound[operation]]);
      // Saturate before multiplication; never multiply a huge measured idle.
      if (u < R) {
        const refill = wide(B * u);
        available = refill >= C - values.base_credit ? C : values.base_credit + refill;
      }
    }
    result = { capacity_credit: C, available_credit: available, post_charge_credit: available >= R ? available - R : null };
  }
  return Object.freeze(Object.fromEntries(Object.entries(result).map(([key, value]) => [key, value === null ? null : value.toString()])));
}

export function buildRekeyCreditCorpus(schema) {
  verifyRekeyCreditRegistry(schema);
  const ids = new Set(), vectors = [];
  for (const profile of Object.keys(schema.crypto_usage_registry.profiles)) {
    for (const spec of schema.rekey_credit_vector_plan) {
      assert.match(spec.id, /^[a-z][a-z0-9_]*$/u);
      const id = `rekey_credit_${schema.crypto_profiles[profile].dh_algorithm}_${spec.id}`;
      assert.ok(!ids.has(id)); ids.add(id);
      const input = structuredClone(spec.input);
      if (spec.expected_error) {
        assert.equal(spec.expected, undefined);
        assert.throws(() => rekeyCreditReference(schema, profile, spec.operation, input), error => error instanceof VectorError && error.code === spec.expected_error, id);
        vectors.push({ id, profile, operation: spec.operation, input, expected_error: spec.expected_error });
      } else {
        const expected = rekeyCreditReference(schema, profile, spec.operation, input);
        assert.deepEqual(expected, spec.expected, id);
        vectors.push({ id, profile, operation: spec.operation, input, expected });
      }
    }
  }
  return { status: "draft", schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: "rekey_full_session_service_and_credit_arithmetic_only", qualification: schema.rekey_credit_registry.qualification, vectors };
}

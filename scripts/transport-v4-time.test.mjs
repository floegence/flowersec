import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { timeArithmeticReference } from "./transport-v4-time.mjs";
import { VectorError } from "./transport-v4-codec.mjs";

const { schema, files, manifest } = buildArtifacts();
const corpus = JSON.parse(files.get("testdata/transport_v4/time_arithmetic.json"));
const rate = { rate_numerator: "1", rate_denominator: "10000", quantization_ms: "0" };
const run = (operation, fields) => timeArithmeticReference(schema, operation, fields);
const elapsed = (delta, n, d, q = 0n) => {
  const result = run("elapsed", { delta_ms: String(delta), rate_numerator: String(n), rate_denominator: String(d), quantization_ms: String(q) });
  return { lower: BigInt(result.elapsed_lower_ms), upper: BigInt(result.elapsed_upper_ms) };
};
const fail = (fn, code) => assert.throws(fn, error => error instanceof VectorError && error.code === code);

test("v4.time.vectors: common registry supplies all operations and four generated declarations", () => {
  assert.equal(corpus.vectors.length, 37);
  assert.equal(manifest.time_arithmetic_vectors.length, corpus.vectors.length);
  assert.deepEqual([...new Set(corpus.vectors.map(v => v.operation))].sort(), Object.keys(schema.time_arithmetic_registry.operations).sort());
  for (const vector of corpus.vectors) {
    if (vector.expected_error) fail(() => run(vector.operation, vector.input), vector.expected_error);
    else assert.deepEqual(run(vector.operation, vector.input), vector.expected);
  }
  for (const path of ["flowersec-go/internal/protocolv4/registry_generated.go", "flowersec-rust/src/protocol_v4_registry_generated.rs",
    "flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", "flowersec-ts/src/generated/transportV4Registry.ts"]) {
    assert.match(files.get(path), /reference_arithmetic_only/u);
    assert.match(files.get(path), /lower_floor_upper_ceiling/u);
  }
});

test("v4.time.rounding: outward integer bounds contain both rational extremes", () => {
  for (let d = 1n; d <= 12n; d++) for (let n = 0n; n < d; n++) for (let delta = 0n; delta <= 40n; delta++) {
    for (const q of [0n, 1n, 3n]) {
      const { lower, upper } = elapsed(delta, n, d, q);
      const lowerProduct = (delta > q ? delta - q : 0n) * d;
      const upperProduct = (delta + q) * d;
      assert.ok(lower >= 0n && lower <= upper);
      assert.ok(lower * (d + n) <= lowerProduct);
      assert.ok((lower + 1n) * (d + n) > lowerProduct);
      assert.ok(upper * (d - n) >= upperProduct);
      if (upper > 0n) assert.ok((upper - 1n) * (d - n) < upperProduct);
    }
  }
});

test("v4.time.inverse: deadline projection is latest safe and proving wakeup is earliest sufficient", () => {
  for (let d = 1n; d <= 8n; d++) for (let n = 0n; n < d; n++) for (let gap = 1n; gap <= 30n; gap++) {
    for (const q of [0n, 1n, 2n]) {
      const config = { rate_numerator: String(n), rate_denominator: String(d), quantization_ms: String(q) };
      if (q <= gap * (d - n) / d) {
        const latest = BigInt(run("deadline_delta", { ...config, upper_ms: "100", deadline_ms: String(100n + gap) }).delta_ms);
        assert.ok(elapsed(latest, n, d, q).upper <= gap);
        assert.ok(elapsed(latest + 1n, n, d, q).upper > gap);
      } else fail(() => run("deadline_delta", { ...config, upper_ms: "100", deadline_ms: String(100n + gap) }), "time_deadline_unrepresentable");
      const earliest = BigInt(run("prove_delta", { ...config, lower_ms: "100", bound_ms: String(100n + gap) }).delta_ms);
      assert.ok(elapsed(earliest, n, d, q).lower >= gap);
      assert.ok(elapsed(earliest - 1n, n, d, q).lower < gap);
    }
  }
});

test("v4.time.measurement: quantization bounds ideal monotonic increments before rate conversion", () => {
  // Actual elapsed 24 ms at rate 1/2 produces ideal monotonic 12 ms;
  // an allowed -2 ms measurement error observes 10 ms. Post-conversion
  // addition would incorrectly cap actual elapsed at 22 ms.
  assert.deepEqual(elapsed(10n, 1n, 2n, 2n), { lower: 5n, upper: 24n });
  const config = { rate_numerator: "1", rate_denominator: "2", quantization_ms: "2" };
  assert.deepEqual(run("deadline_delta", { ...config, upper_ms: "100", deadline_ms: "120" }), { delta_ms: "8" });
  assert.deepEqual(run("prove_delta", { ...config, lower_ms: "100", bound_ms: "120" }), { delta_ms: "32" });
  fail(() => run("deadline_delta", { ...config, upper_ms: "100", deadline_ms: "103" }), "time_deadline_unrepresentable");
});

test("v4.time.network: full asymmetric RTT and independent source/elapsed errors are counted once", () => {
  const input = { ...rate, sample_ms: "100000", source_error_ms: "100", delta_ms: "1000", quantization_ms: "1", max_round_trip_ms: "1002", max_width_ms: "1202" };
  const result = run("network_anchor", input);
  assert.deepEqual(result, { lower_ms: "99900", upper_ms: "101102" });
  // All delay on the response path is admissible. A half-RTT upper bound
  // would miss this true time even though the source signature is valid.
  assert.ok(BigInt(result.upper_ms) >= 100000n + 100n + 1002n);
  fail(() => run("network_anchor", { ...input, max_round_trip_ms: "1001" }), "time_round_trip");
  fail(() => run("network_anchor", { ...input, max_width_ms: "1201" }), "time_width");
});

test("v4.time.advance: original uncertainty grows with drift and cannot outlive either profile cap", () => {
  const input = { ...rate, lower_ms: "100000", upper_ms: "101200", delta_ms: "86400000", max_age_ms: "86408641", max_width_ms: "18481" };
  assert.deepEqual(run("advance_anchor", input), { lower_ms: "86491360", upper_ms: "86509841" });
  fail(() => run("advance_anchor", { ...input, max_age_ms: "86408640" }), "time_anchor_age");
  fail(() => run("advance_anchor", { ...input, max_width_ms: "18480" }), "time_width");
});

test("v4.time.wide: uint64 boundary products remain exact and unrepresentable results reject", () => {
  const max = 0xffffffffffffffffn;
  assert.deepEqual(elapsed(max, 0n, max), { lower: max, upper: max });
  assert.deepEqual(elapsed(1n, max - 1n, max), { lower: 0n, upper: max });
  fail(() => elapsed(2n, max - 1n, max), "time_overflow");
  assert.deepEqual(run("deadline_delta", { rate_numerator: "0", rate_denominator: String(max), quantization_ms: "0", upper_ms: "0", deadline_ms: String(max) }), { delta_ms: String(max) });
  assert.deepEqual(run("prove_delta", { rate_numerator: "0", rate_denominator: String(max), quantization_ms: "0", lower_ms: "0", bound_ms: String(max) }), { delta_ms: String(max) });
});

test("v4.time.inputs: exact primitive quantities and inert own-data inputs forbid coercion and fallback", () => {
  let called = 0;
  const trap = () => { called++; throw new Error("caller hook"); };
  const input = { ...rate, delta_ms: "1000" };
  for (const value of [1000, 1000n, true, null, "", "-1", "+1", "01", "1.0", " 1", "1e3", "9".repeat(21), { toString: trap }]) {
    fail(() => run("elapsed", { ...input, delta_ms: value }), "time_integer");
  }
  fail(() => run({ toString: trap }, input), "time_operation");
  fail(() => run("elapsed", new Proxy(input, { ownKeys: trap, getPrototypeOf: trap })), "time_input_object");
  const accessor = { ...input }; Object.defineProperty(accessor, "delta_ms", { get: trap });
  fail(() => run("elapsed", accessor), "time_input_data");
  fail(() => run("elapsed", { ...input, skew_ms: "1" }), "time_input_fields");
  fail(() => run("elapsed", Object.create(input)), "time_input_object");
  const copy = { ...input }, result = run("elapsed", copy); copy.delta_ms = "1";
  assert.ok(Object.isFrozen(result)); assert.equal(result.elapsed_lower_ms, "999");
  assert.equal(called, 0);
});

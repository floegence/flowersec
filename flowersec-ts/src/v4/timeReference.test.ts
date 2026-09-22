import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { timeArithmetic } from "./testSupport/time.js";
import { root } from "./testSupport/unicode.js";

const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/time_arithmetic.json", root), "utf8")) as {
  vectors: { id: string; operation: string; input: Record<string, unknown>; expected?: Record<string, string>; expected_error?: string }[];
};
it("v4.ts_time consumes every shared arithmetic vector independently", () => {
  expect(corpus.vectors).toHaveLength(37);
  for (const vector of corpus.vectors) {
    const before = structuredClone(vector.input);
    if (vector.expected_error) expect(() => timeArithmetic(vector.operation, vector.input), vector.id).toThrow(vector.expected_error);
    else expect(timeArithmetic(vector.operation, vector.input), vector.id).toEqual(vector.expected);
    expect(vector.input).toEqual(before);
  }
});
it("v4.ts_time proves outward rounding and inverse extrema over rational rates", () => {
  for (let d = 1n; d <= 8n; d++) for (let n = 0n; n < d; n++) for (let gap = 1n; gap <= 20n; gap++) for (const q of [0n, 1n, 2n]) {
    const config = { rate_numerator: String(n), rate_denominator: String(d), quantization_ms: String(q) };
    const elapsed = (delta: bigint) => timeArithmetic("elapsed", { ...config, delta_ms: String(delta) });
    const e = elapsed(gap), lo = BigInt(e.elapsed_lower_ms!), hi = BigInt(e.elapsed_upper_ms!);
    expect(lo * (d + n) <= (gap > q ? gap - q : 0n) * d).toBe(true);
    expect(hi * (d - n) >= (gap + q) * d).toBe(true);
    if (q <= gap * (d - n) / d) {
      const delta = BigInt(timeArithmetic("deadline_delta", { ...config, upper_ms: "0", deadline_ms: String(gap) }).delta_ms!);
      expect(BigInt(elapsed(delta).elapsed_upper_ms!)).toBeLessThanOrEqual(gap);
      expect(BigInt(elapsed(delta + 1n).elapsed_upper_ms!)).toBeGreaterThan(gap);
    } else expect(() => timeArithmetic("deadline_delta", { ...config, upper_ms: "0", deadline_ms: String(gap) })).toThrow("time_deadline_unrepresentable");
    const delta = BigInt(timeArithmetic("prove_delta", { ...config, lower_ms: "0", bound_ms: String(gap) }).delta_ms!);
    expect(BigInt(elapsed(delta).elapsed_lower_ms!)).toBeGreaterThanOrEqual(gap);
    expect(BigInt(elapsed(delta - 1n).elapsed_lower_ms!)).toBeLessThan(gap);
  }
});
it("v4.ts_time rejects caller hooks, extra fields, coercion and noncanonical integers", () => {
  let calls = 0;
  const trap = (): never => { calls++; throw new Error("caller hook"); };
  const input = { delta_ms: "1", rate_numerator: "0", rate_denominator: "1", quantization_ms: "0" };
  expect(() => timeArithmetic("elapsed", new Proxy(input, { getPrototypeOf: trap, ownKeys: trap }))).toThrow("time_input_object");
  expect(() => timeArithmetic({ toString: trap }, input)).toThrow("time_operation");
  expect(() => timeArithmetic("elapsed", { ...input, extra: "0" })).toThrow("time_input_fields");
  expect(() => timeArithmetic("elapsed", Object.defineProperty({ ...input }, "delta_ms", { get: trap }))).toThrow("time_input_data");
  for (const value of [1, 1n, true, null, "", "01", "+1", "-1", "1.0", "1\n", "١", "18446744073709551616", { toString: trap }]) {
    expect(() => timeArithmetic("elapsed", { ...input, delta_ms: value })).toThrow("time_integer");
  }
  const result = timeArithmetic("elapsed", input); input.delta_ms = "3";
  expect(Object.isFrozen(result)).toBe(true); expect(result.elapsed_upper_ms).toBe("1"); expect(calls).toBe(0);
});

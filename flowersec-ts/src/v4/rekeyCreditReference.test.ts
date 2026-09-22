import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { rekeyCredit } from "./testSupport/rekeyCredit.js";
import { root } from "./testSupport/unicode.js";
import { transportV4CryptoUsageRegistry as usage } from "../generated/transportV4Registry.js";

const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/rekey_credit.json", root), "utf8")) as {
  vectors: { id: string; profile: string; operation: string; input: Record<string, unknown>; expected?: Record<string, string | null>; expected_error?: string }[];
};
const profile = Object.keys(usage.profiles)[0]!;
it("v4.ts_rekey_credit consumes every shared service/credit vector independently", () => {
  expect(corpus.vectors).toHaveLength(48);
  for (const v of corpus.vectors) {
    const before = structuredClone(v.input), run = () => rekeyCredit(v.profile, v.operation, v.input);
    if (v.expected_error) expect(run, v.id).toThrow(v.expected_error); else expect(run(), v.id).toEqual(v.expected);
    expect(v.input).toEqual(before);
  }
});
it("v4.ts_rekey_credit checks retained partial balances and exact service floor boundaries", () => {
  for (let T = 1n; T <= 120n; T++) {
    const result = rekeyCredit(profile, "service", { burst_rounds: "2", refill_period_ms: "30", request_start_budget_ms: "5",
      issued_at_ms: "0", session_not_after_ms: String(T), rate_numerator: "1", rate_denominator: "2", quantization_ms: "2" });
    const N = BigInt(result.max_rounds!);
    expect(N * 12n <= 60n + 6n * T && (N + 1n) * 12n > 60n + 6n * T).toBe(true);
  }
  const input = { burst_rounds: "2", refill_period_ms: "30", base_credit: "10", delta_ms: "9", rate_numerator: "0", rate_denominator: "1", quantization_ms: "0" };
  const peek = rekeyCredit(profile, "client_credit", input);
  expect(peek.available_credit).toBe("28"); expect(peek.post_charge_credit).toBeNull();
  for (let i = 0; i < 50; i++) expect(rekeyCredit(profile, "client_credit", input)).toEqual(peek);
  input.delta_ms = "10"; expect(rekeyCredit(profile, "client_credit", input).post_charge_credit).toBe("0");
  expect(Object.isFrozen(peek)).toBe(true); expect(peek.available_credit).toBe("28");
});
it("v4.ts_rekey_credit rejects coercion and caller hooks", () => {
  let calls = 0; const trap = (): never => { calls++; throw new Error("caller hook"); };
  const input = { burst_rounds: "2", refill_period_ms: "30" };
  const run = (i: unknown) => rekeyCredit(profile, "initial_credit", i);
  expect(() => run(new Proxy(input, { getPrototypeOf: trap }))).toThrow("rekey_credit_input");
  expect(() => run(Object.defineProperty({ ...input }, "burst_rounds", { get: trap }))).toThrow("rekey_credit_data");
  expect(() => run({ ...input, extra: "1" })).toThrow("rekey_credit_fields");
  expect(() => rekeyCredit({ toString: trap }, "initial_credit", input)).toThrow("rekey_credit_profile");
  for (const value of [1, 1n, true, null, "", "01", "+1", "-1", "1.0", "1\n", "١", "18446744073709551616", { toString: trap }]) {
    expect(() => run({ ...input, burst_rounds: value })).toThrow("rekey_credit_integer");
  }
  expect(calls).toBe(0);
});

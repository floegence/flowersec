// Independent test arithmetic, not a live credit owner or service reservation.
import { types } from "node:util";
import { transportV4RekeyCreditRegistry as spec, transportV4CryptoUsageRegistry as usage } from "../../generated/transportV4Registry.js";
import { timeArithmetic } from "./time.js";

function must(condition: unknown, code = "configuration_capacity"): asserts condition { if (!condition) throw new Error(code); }
const wide = (n: bigint): bigint => { must(n >= 0n && n <= BigInt(spec.intermediate_max)); return n; };
const ceil = (n: bigint, d: bigint): bigint => n / d + (n % d ? 1n : 0n);

export function rekeyCredit(profile: unknown, operation: unknown, input: unknown): Readonly<Record<string, string | null>> {
  must(typeof profile === "string" && Object.hasOwn(usage.profiles, profile), "rekey_credit_profile");
  must(typeof operation === "string" && Object.hasOwn(spec.operations, operation), "rekey_credit_operation");
  const fields: readonly string[] = spec.operations[operation as keyof typeof spec.operations];
  must(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [null, Object.prototype as unknown].includes(Object.getPrototypeOf(input)), "rekey_credit_input");
  const keys = Reflect.ownKeys(input);
  must(keys.length === fields.length && keys.every(k => typeof k === "string" && fields.includes(k)), "rekey_credit_fields");
  const values: Record<string, bigint> = Object.create(null) as Record<string, bigint>;
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    must(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "rekey_credit_data");
    const s: unknown = descriptor.value;
    must(typeof s === "string" && s.length <= spec.quantity_max.length && /^(0|[1-9][0-9]*)$/u.test(s), "rekey_credit_integer");
    const n = BigInt(s); must(n <= BigInt(spec.quantity_max), "rekey_credit_integer"); values[key] = n;
  }
  const v = (key: string): bigint => values[key]!;
  for (const field of Object.values(spec.envelope_fields)) if (Object.hasOwn(values, field.name)) {
    must(v(field.name) >= BigInt(field.min) && v(field.name) < (1n << BigInt(field.type.slice(4))));
  }
  const B = v("burst_rounds"), R = v("refill_period_ms"), cap = wide(B * R);
  const epochs = BigInt(usage.profiles[profile as keyof typeof usage.profiles].max_epochs);
  must(B < epochs);
  let result: Record<string, bigint | null>;
  if (operation === "service") {
    const n = v("rate_numerator"), d = v("rate_denominator"), q = v("quantization_ms");
    must(d > 0n && n < d && v("issued_at_ms") < v("session_not_after_ms"));
    const dm = d - n, dp = wide(d + n), T = v("session_not_after_ms") - v("issued_at_ms");
    const errorLimit = (R - 1n) / B; must(errorLimit >= 1n);
    must(q <= wide((errorLimit - 1n) * dm) / wide(2n * d));
    const e = ceil(wide(wide(2n * q) * d), dm) + 1n, period = R - B * e;
    must(period > 0n);
    const divisor = wide(period * dm), initial = wide(cap * dm), rate = wide(B * dp), limit = wide(epochs * divisor);
    must(initial < limit); must(T <= (limit - 1n - initial) / rate);
    const N = wide(initial + wide(rate * T)) / divisor;
    must(N > 0n && N < epochs);
    result = { service_ms: T, error_allowance_ms: e, denominator_ms: period, capacity_credit: cap, max_rounds: N, required_epochs: N + 1n };
  } else {
    let available = cap;
    if (operation !== "initial_credit") {
      const base = v("base_credit"); must(base <= cap);
      const timeInput = Object.fromEntries(["delta_ms", "rate_numerator", "rate_denominator", "quantization_ms"].map(k => [k, String(v(k))]));
      const elapsed = timeArithmetic("elapsed", timeInput);
      const bound = spec.elapsed_bound[operation as keyof typeof spec.elapsed_bound];
      const u = BigInt(elapsed[bound]!);
      if (u < R) { const refill = wide(B * u); available = refill >= cap - base ? cap : base + refill; }
    }
    result = { capacity_credit: cap, available_credit: available, post_charge_credit: available < R ? null : available - R };
  }
  return Object.freeze(Object.fromEntries(Object.entries(result).map(([key, n]) => [key, n === null ? null : String(n)])));
}

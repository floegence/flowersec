// Independent test-only arithmetic. No clock sampling, authentication, owner,
// timer installation or authorization. All quantities come from trusted facts.
import { types } from "node:util";
import { transportV4TimeArithmeticRegistry as spec } from "../../generated/transportV4Registry.js";

const maximum = BigInt(spec.quantity_max), wideMaximum = BigInt(spec.intermediate_max);
function must(condition: unknown, code: string): asserts condition { if (!condition) throw new Error(code); }
function bounded(n: bigint, max = maximum): bigint { must(n >= 0n && n <= max, "time_overflow"); return n; }
function ceiling(n: bigint, d: bigint): bigint { return n / d + (n % d ? 1n : 0n); }

export function timeArithmetic(operation: unknown, input: unknown): Readonly<Record<string, string>> {
  must(typeof operation === "string" && Object.hasOwn(spec.operations, operation), "time_operation");
  const fields: readonly string[] = spec.operations[operation as keyof typeof spec.operations];
  must(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [null, Object.prototype as unknown].includes(Object.getPrototypeOf(input)), "time_input_object");
  const keys = Reflect.ownKeys(input);
  must(keys.length === fields.length && keys.every(key => typeof key === "string" && fields.includes(key)), "time_input_fields");
  const captured: Record<string, bigint> = Object.create(null) as Record<string, bigint>;
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    must(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "time_input_data");
    const value: unknown = descriptor.value;
    must(typeof value === "string" && value.length <= spec.quantity_max.length && /^(0|[1-9][0-9]*)$/u.test(value), "time_integer");
    const n = BigInt(value); must(n <= maximum, "time_integer"); captured[field] = n;
  }
  const get = (key: string): bigint => captured[key]!;
  const numerator = get("rate_numerator"), denominator = get("rate_denominator"), q = get("quantization_ms");
  must(denominator !== 0n && numerator < denominator, "time_rate");
  const elapsed = (): readonly [bigint, bigint] => {
    const delta = get("delta_ms"), low = delta > q ? delta - q : 0n;
    const lowProduct = bounded(low * denominator, wideMaximum);
    const highProduct = bounded(bounded(delta + q) * denominator, wideMaximum);
    return [lowProduct / (denominator + numerator), bounded(ceiling(highProduct, denominator - numerator))];
  };
  const interval = (lower: bigint, upper: bigint): Record<string, string> => {
    bounded(lower); bounded(upper);
    must(lower <= upper, "time_interval");
    must(get("max_width_ms") > 0n && upper - lower <= get("max_width_ms"), "time_width");
    return { lower_ms: String(lower), upper_ms: String(upper) };
  };
  let result: Record<string, string>;
  switch (operation) {
    case "elapsed": {
      const [lower, upper] = elapsed();
      result = { elapsed_lower_ms: String(lower), elapsed_upper_ms: String(upper) }; break;
    }
    case "network_anchor": {
      const [, upper] = elapsed();
      must(get("max_round_trip_ms") > 0n && upper <= get("max_round_trip_ms"), "time_round_trip");
      result = interval(get("sample_ms") - get("source_error_ms"), get("sample_ms") + get("source_error_ms") + upper); break;
    }
    case "advance_anchor": {
      must(get("lower_ms") <= get("upper_ms"), "time_interval");
      const [lower, upper] = elapsed();
      must(get("max_age_ms") > 0n && upper <= get("max_age_ms"), "time_anchor_age");
      result = interval(get("lower_ms") + lower, get("upper_ms") + upper); break;
    }
    case "deadline_delta": {
      must(get("upper_ms") < get("deadline_ms"), "time_expired");
      const slack = get("deadline_ms") - get("upper_ms");
      const budget = bounded(slack * (denominator - numerator), wideMaximum) / denominator;
      must(budget >= q, "time_deadline_unrepresentable");
      result = { delta_ms: String(bounded(budget - q)) }; break;
    }
    case "prove_delta": {
      const gap = get("bound_ms") - get("lower_ms");
      result = { delta_ms: gap <= 0n ? "0" : String(bounded(ceiling(bounded(gap * (denominator + numerator), wideMaximum), denominator) + q)) }; break;
    }
    default: throw new Error("time_operation");
  }
  return Object.freeze(result);
}

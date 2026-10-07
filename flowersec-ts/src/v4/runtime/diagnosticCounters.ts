import { diagnosticDimensions, diagnosticMetrics, type DiagnosticCounts, type DiagnosticFields, type DiagnosticMetric } from "../diagnostics.js";

const dimensions = ["state", "phase", "code", "duration_bucket", "attempt_bucket"] as const;
const width = 1 + dimensions.reduce((n, key) => n + diagnosticDimensions[key].length, 0);
export const diagnosticCounterBytes = BigInt(diagnosticMetrics.length * width * 8 + 256);
const maximum = 0xffffffffffffffffn;
export function diagnosticFields(input: Partial<DiagnosticFields>): DiagnosticFields {
  const field = <K extends keyof DiagnosticFields>(key: K): DiagnosticFields[K] => {
    const values: readonly string[] = diagnosticDimensions[key], value = input[key];
    return (typeof value === "string" && values.includes(value) ? value : "other") as DiagnosticFields[K];
  };
  return Object.freeze({ state: field("state"), phase: field("phase"), code: field("code"), duration_bucket: field("duration_bucket"), attempt_bucket: field("attempt_bucket"), retry_disposition: field("retry_disposition") });
}
export function diagnosticDuration(start: number): DiagnosticFields["duration_bucket"] {
  const n = performance.now() - start;
  return n < 0 ? "other" : n < 10 ? "lt_10ms" : n < 100 ? "10_99ms" : n < 1000 ? "100_999ms" : n < 10000 ? "1_9s" : "gte_10s";
}
export interface DiagnosticFailure { readonly metric: DiagnosticMetric; readonly code: DiagnosticFields["code"] }
export function diagnosticFailure(error: unknown): DiagnosticFailure {
  // Only fixed SDK codes are projected; raw messages and causes never survive.
  let code: unknown;
  try { if (error instanceof Error) code = error.message; } catch { /* Unknown host errors remain other. */ }
  switch (code) {
    case "spent_unknown": case "spend_unknown": case "admission_unknown": return { metric: "spend_unknown", code: "spend_unknown" };
    case "storage_failure": case "storage_unavailable": case "storage_format": case "storage_format_incompatible": case "fenced": case "history_unknown": return { metric: "store_failure", code: "store_unavailable" };
    case "resource_exhausted": case "configuration_capacity": return { metric: "resource_rejection", code: "resource_exhausted" };
    case "reservation_conflict": case "relay_conflict": case "admission_conflict": case "spend_conflict": return { metric: "reservation_conflict", code: "reservation_conflict" };
    case "tls_rejected": case "tls_verification_failed": return { metric: "tls_rejection", code: "tls_rejected" };
    case "credential_binding": case "authentication_failed": case "credential_untrusted": return { metric: "identity_rejection", code: "identity_rejected" };
    case "slow_consumer": return { metric: "slow_consumer", code: "slow_consumer" };
    case "deadline_exceeded": case "time_expired": case "completion_deadline": return { metric: "other", code: "timeout" };
    case "canceled": return { metric: "other", code: "cancelled" };
    default: return { metric: "other", code: "other" };
  }
}
/** Fixed marginal histograms, never a map keyed by application values. */
export class DiagnosticCounters {
  readonly #values = new BigUint64Array(diagnosticMetrics.length * width);
  observe(metric: DiagnosticMetric, input: Partial<DiagnosticFields> = {}): void {
    const fields = diagnosticFields(input), index = Math.max(0, (diagnosticMetrics as readonly string[]).indexOf(metric));
    let at = index * width;
    const add = (position: number): void => { if (this.#values[position]! < maximum) this.#values[position] = this.#values[position]! + 1n; };
    add(at++);
    for (const key of dimensions) {
      add(at + Math.max(0, (diagnosticDimensions[key] as readonly string[]).indexOf(fields[key]))); at += diagnosticDimensions[key].length;
    }
  }
  snapshot(metric: DiagnosticMetric): DiagnosticCounts {
    let at = Math.max(0, (diagnosticMetrics as readonly string[]).indexOf(metric)) * width;
    const total = this.#values[at++]!;
    const take = (key: typeof dimensions[number]): readonly bigint[] => {
      const values = Object.freeze(Array.from(this.#values.subarray(at, at + diagnosticDimensions[key].length))); at += diagnosticDimensions[key].length; return values;
    };
    return Object.freeze({ total, state: take("state"), phase: take("phase"), code: take("code"), duration_bucket: take("duration_bucket"), attempt_bucket: take("attempt_bucket") });
  }
}

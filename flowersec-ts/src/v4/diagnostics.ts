import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { OperationOptions } from "../public/contract.js";

export const diagnosticDimensions = Object.freeze({
  state: Object.freeze(["other", "starting", "ready", "draining", "closed", "failed"] as const),
  phase: Object.freeze(["other", "material", "prepare", "spend", "activate", "handshake", "application", "rekey_prepare", "rekey_switch", "rekey_retire", "cleanup", "rekey_local_prepare", "rekey_protocol_prepare", "rekey_confirmation"] as const),
  code: Object.freeze(["other", "ok", "tls_rejected", "identity_rejected", "spend_unknown", "store_unavailable", "reservation_conflict", "resource_exhausted", "slow_consumer", "timeout", "current_datagram_dropped", "old_datagram_dropped", "diagnostic_dropped", "cleanup_incomplete", "cancelled", "revoked", "freshness_expired", "future_datagram_dropped"] as const),
  duration_bucket: Object.freeze(["other", "lt_10ms", "10_99ms", "100_999ms", "1_9s", "gte_10s"] as const),
  attempt_bucket: Object.freeze(["other", "1", "2_3", "4_7", "8_plus"] as const),
  retry_disposition: Object.freeze(["other", "preserve_facts"] as const),
});
export const diagnosticMetrics = Object.freeze(["other", "connection_attempt", "connection_failure", "tls_rejection", "identity_rejection", "spend_unknown", "store_failure", "reservation_conflict", "resource_rejection", "slow_consumer", "rekey_started", "rekey_succeeded", "rekey_timeout", "current_datagram_drop", "old_datagram_drop", "diagnostic_drop", "cleanup_timeout", "future_datagram_drop", "rekey_phase_completed"] as const);
export type DiagnosticMetric = typeof diagnosticMetrics[number];
export type DiagnosticFields = { readonly [K in keyof typeof diagnosticDimensions]: typeof diagnosticDimensions[K][number] };
export interface DiagnosticEvent extends DiagnosticFields {
  /** Exactly sixteen independent random bytes, encoded as lowercase hex. */
  readonly correlation_id: string;
}
export interface DiagnosticCounts {
  readonly total: bigint;
  readonly state: readonly bigint[];
  readonly phase: readonly bigint[];
  readonly code: readonly bigint[];
  readonly duration_bucket: readonly bigint[];
  readonly attempt_bucket: readonly bigint[];
}
export interface DiagnosticSinkOptions {
  /** Application-owned copies have their own retention policy. */
  readonly callback: (event: DiagnosticEvent, options: Readonly<{ signal: AbortSignal }>) => void | Promise<void>;
  /** Defaults to 100 basis points (1%); accepted range is 0 through 100. */
  readonly sampleBasisPoints?: number;
  readonly operationSlots?: number;
  readonly queueEvents?: number;
  /** Declared callback/runtime allowance for each of six delivery positions. */
  readonly runtimeBytes: bigint;
}
export interface DiagnosticSink {
  close(): Promise<V4CleanupStatus>;
  waitCleanup(options?: OperationOptions): Promise<V4CleanupStatus>;
  cleanupStatus(): V4CleanupStatus;
}

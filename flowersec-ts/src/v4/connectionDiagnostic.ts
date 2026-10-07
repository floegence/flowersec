import { connectionLocalReport, type LocalReport } from "./localReport.js";
import type { V4CleanupStatus, V4RetryDisposition } from "../generated/transportV4APIResults.js";

/** Detached monitoring values. They carry no connection or execution authority. */
export type ConnectionDiagnosticState = "idle" | "connecting" | "connected" | "waiting" | "failed" | "closed";
export type ConnectionFailurePhase = "controller" | "connect" | "session";
export type ConnectionFailureCode =
  | "controller_failed" | "initialization_failed" | "crypto_busy" | "would_block" | "canceled" | "closed" | "busy" | "invalid_argument"
  | "configuration_capacity" | "resource_exhausted" | "required_guarantee_unavailable" | "retirement_capacity"
  | "owner_unavailable" | "runtime_unavailable" | "source_unavailable"
  | "source_exhausted" | "source_contract_invalid" | "spent_unknown" | "admission_rejected" | "live_authorization_failed" | "material_unavailable" | "connection_requirement_unavailable"
  | "initialization_blocked" | "not_ready" | "session_draining" | "expired"
  | "deadline_exceeded" | "permission_denied" | "authentication_failed"
  | "protocol_violation" | "framing_error" | "sequence_error" | "replay_detected"
  | "crypto_failure" | "rekey_failed" | "stream_sequence_error" | "stream_data_invalid";
export interface ConnectionDiagnosticFailure {
  readonly phase: ConnectionFailurePhase;
  readonly code: ConnectionFailureCode;
}
export type ConnectionPhase = "not_started" | "spent_not_admitted" | "admitted_not_ready" | "ready" | "unknown";
export interface ConnectionAttemptFacts {
  readonly phase: ConnectionPhase;
  readonly spent: boolean | "unknown";
  readonly spendState: "unspent" | "spent" | "unknown";
  readonly admissionState: "not_started" | "in_flight" | "admitted" | "unknown";
  readonly networkReady: "not_started" | "ready" | "unknown";
  readonly applicationPublish: "not_started" | "published" | "failed" | "unknown";
  readonly sourceProfile?: "preauthorized_pool" | "live_authority";
  readonly queryAvailability: "unavailable";
}
export interface ConnectionDiagnostic {
  readonly state: ConnectionDiagnosticState;
  readonly attempt: bigint;
  readonly failure?: ConnectionDiagnosticFailure;
  readonly connection?: ConnectionAttemptFacts;
  readonly cleanup?: V4CleanupStatus;
  /** Preserve the original facts; this value does not authorize reacquisition. */
  readonly retryDisposition?: V4RetryDisposition;
}
const codes: ReadonlySet<string> = new Set<ConnectionFailureCode>([
  "controller_failed", "initialization_failed", "crypto_busy", "would_block", "canceled", "closed", "busy", "invalid_argument",
  "configuration_capacity", "resource_exhausted", "required_guarantee_unavailable", "retirement_capacity",
  "owner_unavailable", "runtime_unavailable", "source_unavailable", "source_exhausted", "source_contract_invalid", "spent_unknown", "admission_rejected", "live_authorization_failed",
  "material_unavailable", "connection_requirement_unavailable", "initialization_blocked",
  "not_ready", "session_draining", "expired", "deadline_exceeded", "permission_denied",
  "authentication_failed", "protocol_violation", "framing_error", "sequence_error",
  "replay_detected", "crypto_failure", "rekey_failed", "stream_sequence_error", "stream_data_invalid",
]);
/** Only a closed vocabulary crosses the public failure boundary. */
export function controllerFailureCode(error: unknown): ConnectionFailureCode {
  try {
    if (error instanceof Error && codes.has(error.message)) return error.message as ConnectionFailureCode;
  } catch { /* Host errors and getters do not become diagnostic payloads. */ }
  return "controller_failed";
}
export function sameConnectionDiagnostic(a: ConnectionDiagnostic, b: ConnectionDiagnostic): boolean {
  return a.state === b.state && a.attempt === b.attempt && a.failure?.phase === b.failure?.phase &&
    a.failure?.code === b.failure?.code && a.retryDisposition === b.retryDisposition &&
    a.connection?.spendState === b.connection?.spendState && a.connection?.admissionState === b.connection?.admissionState &&
    a.connection?.networkReady === b.connection?.networkReady && a.connection?.applicationPublish === b.connection?.applicationPublish &&
    a.connection?.sourceProfile === b.connection?.sourceProfile && a.cleanup?.status === b.cleanup?.status &&
    a.cleanup?.core_cleanup === b.cleanup?.core_cleanup && a.cleanup?.pending_callbacks === b.cleanup?.pending_callbacks;
}

/** Failure snapshots do not retain the original material, source or provider. */
export class ConnectionError extends Error {
  readonly code: ConnectionFailureCode;
  readonly connection: ConnectionAttemptFacts;
  readonly cleanup: V4CleanupStatus;
  constructor(code: ConnectionFailureCode, connection: ConnectionAttemptFacts, cleanup: V4CleanupStatus) {
    super(code); this.name = "ConnectionError";
    this.code = code;
    this.connection = Object.freeze({ phase: connection.phase, spent: connection.spent, spendState: connection.spendState,
      admissionState: connection.admissionState, networkReady: connection.networkReady, applicationPublish: connection.applicationPublish,
      ...(connection.sourceProfile === undefined ? {} : { sourceProfile: connection.sourceProfile }), queryAvailability: connection.queryAvailability });
    this.cleanup = Object.freeze({ status: cleanup.status, core_cleanup: cleanup.core_cleanup, pending_callbacks: cleanup.pending_callbacks });
    Object.setPrototypeOf(this, new.target.prototype);
  }
  localReport(): LocalReport { return connectionLocalReport(this.code, this.connection, this.cleanup); }
  LocalReport(): LocalReport { return this.localReport(); }
}

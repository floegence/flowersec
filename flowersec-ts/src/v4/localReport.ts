import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { ConnectionAttemptFacts, ConnectionFailureCode } from "./connectionDiagnostic.js";

/** A controller may be queried before it has recorded a failure. */
export type LocalReportCode = ConnectionFailureCode | "unknown";

/** An explanation of an already observed local result. Obtaining it reserves no work. */
export interface LocalReport {
  readonly code: LocalReportCode;
  readonly constraint: "configuration" | "resource" | "source" | "connection" | "unavailable";
  /** Absent numeric evidence is explicit; this report performs no capacity check. */
  readonly required: bigint | null;
  readonly available: bigint | null;
  readonly reservation: "not_reserved";
  readonly connection: ConnectionAttemptFacts;
  readonly cleanup: V4CleanupStatus;
  readonly actions: readonly ("inspect_configuration" | "end_connection")[];
}
export function connectionLocalReport(code: LocalReportCode, connection: ConnectionAttemptFacts, cleanup: V4CleanupStatus): LocalReport {
  const constraint = code === "configuration_capacity" || code === "invalid_argument" ||
      code === "connection_requirement_unavailable" || code === "required_guarantee_unavailable" ? "configuration" :
    code === "resource_exhausted" || code === "would_block" || code === "crypto_busy" || code === "retirement_capacity" ? "resource" :
    code === "source_unavailable" || code === "source_exhausted" || code === "source_contract_invalid" ? "source" :
    code === "controller_failed" || code === "unknown" ? "unavailable" : "connection";
  const actions: LocalReport["actions"] = Object.freeze(constraint === "configuration" ? ["inspect_configuration"] :
    code === "unknown" || connection.phase === "not_started" ? [] : ["end_connection"]);
  return Object.freeze({ code, constraint, required: null, available: null, reservation: "not_reserved", connection, cleanup, actions });
}

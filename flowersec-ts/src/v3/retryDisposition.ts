import type { SessionErrorCode } from "./contract.js";
import type { PublicConnectErrorCodeV3 } from "./security.js";

export type RetryDisposition =
  | Readonly<{ kind: "terminal" }>
  | Readonly<{ kind: "retryable" }>
  | Readonly<{ kind: "retry_after"; notBeforeUnixMilliseconds: number }>;

export function retryDispositionForConnectError(
  error: Readonly<{ code: PublicConnectErrorCodeV3 }>,
): RetryDisposition {
  switch (error.code) {
    case "expired_artifact":
    case "connection_failed":
      return Object.freeze({ kind: "retryable" });
    default:
      return Object.freeze({ kind: "terminal" });
  }
}
export function retryDispositionForSessionError(error: Readonly<{ code: SessionErrorCode }>): RetryDisposition {
  switch (error.code) {
    case "closed":
    case "going_away":
    case "timeout":
    case "resource_exhausted":
    case "stream_reset":
    case "rekey_failed":
    case "liveness_failed":
      return Object.freeze({ kind: "retryable" });
    default:
      return Object.freeze({ kind: "terminal" });
  }
}

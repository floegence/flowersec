import type { SessionErrorCode } from "./contract.js";
import type { ConnectErrorCode } from "../utils/errors.js";

export type RetryDisposition =
  | Readonly<{ kind: "terminal" }>
  | Readonly<{ kind: "retryable" }>
  | Readonly<{ kind: "retry_after"; notBeforeUnixMilliseconds: number }>;

export function retryDispositionForConnectError(error: Readonly<{ code: ConnectErrorCode }>): RetryDisposition {
  switch (error.code) {
    case "expired_artifact":
    case "resolve_failed":
    case "credential_spend_failed":
    case "connection_failed":
    case "timeout":
    case "handshake_failed":
    case "rpc_failed":
    case "resource_exhausted":
    case "not_connected":
      return { kind: "retryable" };
    default:
      return { kind: "terminal" };
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
      return { kind: "retryable" };
    default:
      return { kind: "terminal" };
  }
}

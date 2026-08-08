export type ConnectErrorCode =
  | "invalid_input"
  | "invalid_options"
  | "expired_artifact"
  | "resolve_failed"
  | "credential_spend_failed"
  | "connection_failed"
  | "timeout"
  | "canceled"
  | "handshake_failed"
  | "rpc_failed"
  | "resource_exhausted"
  | "not_connected";

/** A stable connection failure that retains no carrier or credential details. */
export class ConnectError extends Error {
  constructor(readonly code: ConnectErrorCode) {
    super(`Flowersec connection failed (code=${code})`);
    this.name = "ConnectError";
  }
}

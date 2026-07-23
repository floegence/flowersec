export class TimeoutError extends Error {
  constructor(message = "timeout") {
    super(message);
    this.name = "TimeoutError";
  }
}

export class AbortError extends Error {
  constructor(message = "aborted") {
    super(message);
    this.name = "AbortError";
  }
}

export type ConnectErrorPath = "auto" | "tunnel" | "direct";

export type ConnectErrorStage =
  | "validate"
  | "connect"
  | "session"
  | "rpc"
  | "close";

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

/** @internal */
export type FlowersecPath = ConnectErrorPath;

/** @internal */
export type FlowersecStage =
  | "validate"
  | "connect"
  | "attach"
  | "handshake"
  | "secure"
  | "yamux"
  | "rpc"
  | "close";

/** @internal */
export type FlowersecErrorCode =
  | "timeout"
  | "canceled"
  | "invalid_version"
  | "invalid_input"
  | "invalid_option"
  | "invalid_endpoint_instance_id"
  | "invalid_psk"
  | "invalid_suite"
  | "missing_grant"
  | "missing_connect_info"
  | "missing_conn"
  | "missing_handler"
  | "missing_stream_kind"
  | "role_mismatch"
  | "missing_tunnel_url"
  | "missing_ws_url"
  | "missing_origin"
  | "missing_channel_id"
  | "missing_token"
  | "missing_init_exp"
  | "timestamp_after_init_exp"
  | "timestamp_out_of_skew"
  | "auth_tag_mismatch"
  | "resolve_failed"
  | "transport_policy_denied"
  | "credential_commit_failed"
  | "random_failed"
  | "upgrade_failed"
  | "dial_failed"
  | "attach_failed"
  | "too_many_connections"
  | "expected_attach"
  | "invalid_attach"
  | "invalid_token"
  | "channel_mismatch"
  | "init_exp_mismatch"
  | "idle_timeout_mismatch"
  | "token_replay"
  | "tenant_mismatch"
  | "policy_denied"
  | "policy_error"
  | "replace_rate_limited"
  | "handshake_failed"
  | "ping_failed"
  | "rekey_failed"
  | "mux_failed"
  | "accept_stream_failed"
  | "open_stream_failed"
  | "stream_hello_failed"
  | "rpc_failed"
  | "resource_exhausted"
  | "not_connected";

/** @internal */
export type FlowersecCandidateDiagnostic = Readonly<{
  candidateId: string;
  carrier: string;
  stage: FlowersecStage;
  code: FlowersecErrorCode;
  message: string;
}>;

/** @internal */
export type ConnectErrorDetailsInternal = Readonly<{
  code: FlowersecErrorCode;
  stage: FlowersecStage;
  cause?: unknown;
  diagnostics: readonly FlowersecCandidateDiagnostic[];
}>;

const internalDetails = new WeakMap<ConnectError, ConnectErrorDetailsInternal>();

/** @internal */
export function createConnectErrorInternal(args: Readonly<{
  code: FlowersecErrorCode;
  stage: FlowersecStage;
  path: FlowersecPath;
  cause?: unknown;
  diagnostics?: readonly FlowersecCandidateDiagnostic[];
}>): ConnectError {
  const error = new ConnectError(publicCode(args.code));
  internalDetails.set(error, Object.freeze({
    code: args.code,
    stage: args.stage,
    ...(args.cause === undefined ? {} : { cause: args.cause }),
    diagnostics: Object.freeze((args.diagnostics ?? []).map((diagnostic) =>
      Object.freeze({ ...diagnostic }))),
  }));
  return error;
}

/** @internal */
export function connectErrorDetailsInternal(error: ConnectError): ConnectErrorDetailsInternal {
  return internalDetails.get(error) ?? Object.freeze({
    code: internalCode(error.code),
    stage: "connect",
    diagnostics: Object.freeze([]),
  });
}

/** @internal */
export function isTimeoutError(e: unknown): e is TimeoutError {
  return e instanceof TimeoutError;
}

/** @internal */
export function isAbortError(e: unknown): e is AbortError {
  return e instanceof AbortError;
}

/** @internal */
export function isConnectError(e: unknown): e is ConnectError {
  return e instanceof ConnectError;
}

/** @internal */
export function throwIfAborted(signal?: AbortSignal, message?: string): void {
  if (signal?.aborted) throw new AbortError(message);
}

function publicCode(code: FlowersecErrorCode): ConnectErrorCode {
  switch (code) {
    case "timeout": return "timeout";
    case "canceled": return "canceled";
    case "resolve_failed": return "resolve_failed";
    case "credential_commit_failed": return "credential_spend_failed";
    case "handshake_failed": return "handshake_failed";
    case "rpc_failed": return "rpc_failed";
    case "resource_exhausted": return "resource_exhausted";
    case "not_connected": return "not_connected";
    case "invalid_option": return "invalid_options";
    case "timestamp_after_init_exp": return "expired_artifact";
    case "dial_failed":
    case "upgrade_failed":
    case "attach_failed":
    case "transport_policy_denied":
    case "too_many_connections":
    case "policy_denied":
    case "policy_error":
    case "replace_rate_limited":
    case "ping_failed":
    case "rekey_failed":
    case "mux_failed":
    case "accept_stream_failed":
    case "open_stream_failed":
    case "stream_hello_failed":
      return "connection_failed";
    default:
      return "invalid_input";
  }
}

function internalCode(code: ConnectErrorCode): FlowersecErrorCode {
  switch (code) {
    case "invalid_input": return "invalid_input";
    case "invalid_options": return "invalid_option";
    case "expired_artifact": return "timestamp_after_init_exp";
    case "resolve_failed": return "resolve_failed";
    case "credential_spend_failed": return "credential_commit_failed";
    case "connection_failed": return "dial_failed";
    case "timeout": return "timeout";
    case "canceled": return "canceled";
    case "handshake_failed": return "handshake_failed";
    case "rpc_failed": return "rpc_failed";
    case "resource_exhausted": return "resource_exhausted";
    case "not_connected": return "not_connected";
  }
}

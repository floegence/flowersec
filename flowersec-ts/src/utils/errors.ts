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

export type FlowersecPath = "auto" | "tunnel" | "direct";

export type FlowersecStage = "validate" | "connect" | "attach" | "handshake" | "secure" | "yamux" | "rpc" | "close";

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
  | "random_failed"
  | "upgrade_failed"
  | "dial_failed"
  | "attach_failed"
  | "handshake_failed"
  | "ping_failed"
  | "mux_failed"
  | "accept_stream_failed"
  | "open_stream_failed"
  | "stream_hello_failed"
  | "not_connected";

export class FlowersecError extends Error {
  readonly code: FlowersecErrorCode;
  readonly stage: FlowersecStage;
  readonly path?: FlowersecPath;
  override readonly cause?: unknown;

  constructor(args: Readonly<{ code: FlowersecErrorCode; stage: FlowersecStage; message?: string; path?: FlowersecPath; cause?: unknown }>) {
    super(args.message ?? `${args.stage} failed`, args.cause !== undefined ? { cause: args.cause } : undefined);
    this.name = "FlowersecError";
    this.code = args.code;
    this.stage = args.stage;
    if (args.path !== undefined) this.path = args.path;
    if (args.cause !== undefined) this.cause = args.cause;
  }
}

export function isTimeoutError(e: unknown): e is TimeoutError {
  return e instanceof TimeoutError;
}

export function isAbortError(e: unknown): e is AbortError {
  return e instanceof AbortError;
}

export function isFlowersecError(e: unknown): e is FlowersecError {
  return e instanceof FlowersecError;
}

export function throwIfAborted(signal?: AbortSignal, message?: string): void {
  if (signal?.aborted) throw new AbortError(message);
}

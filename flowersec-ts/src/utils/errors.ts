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
  | "auth_tag_mismatch"
  | "canceled"
  | "handshake_failed"
  | "invalid_input"
  | "invalid_option"
  | "invalid_connect_info"
  | "invalid_endpoint_instance_id"
  | "invalid_grant"
  | "invalid_psk"
  | "invalid_suite"
  | "missing_attach"
  | "missing_channel_id"
  | "missing_connect_info"
  | "missing_grant"
  | "missing_init_exp"
  | "missing_origin"
  | "missing_stream_kind"
  | "missing_token"
  | "missing_tunnel_url"
  | "missing_ws_url"
  | "open_stream_failed"
  | "origin_mismatch"
  | "ping_failed"
  | "role_mismatch"
  | "send_failed"
  | "stream_hello_failed"
  | "timestamp_after_init_exp"
  | "timestamp_out_of_skew"
  | "timeout"
  | "invalid_version"
  | "websocket_closed"
  | "websocket_error"
  | "websocket_init_failed"
  | "ws_factory_required";

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

import type { StreamMetadata } from "./streamMetadata.js";

export type CarrierKind = "websocket" | "raw_quic" | "webtransport";

export type PathKind = "direct" | "tunnel";

export type JsonPrimitive = null | boolean | number | string;

export type JsonValue = JsonPrimitive | JsonObject | readonly JsonValue[];

export type JsonObject = Readonly<{ [key: string]: JsonValue }>;

export type OperationOptions = Readonly<{
  signal?: AbortSignal;
}>;

export type UnreliableMessageSendOptions = OperationOptions & Readonly<{
  expiresAtUnixMs: number;
}>;

export type UnreliableMessageSendResult =
  | "accepted"
  | "dropped_budget"
  | "dropped_expired"
  | "dropped_carrier";

export interface UnreliableMessageChannel {
  readonly maxMessageSize: number;
  send(
    message: Uint8Array,
    options: UnreliableMessageSendOptions,
  ): Promise<UnreliableMessageSendResult>;
  receive(options?: OperationOptions): Promise<Uint8Array>;
}

export class UnreliableMessageError extends Error {
  constructor(readonly code: "invalid_message" | "closed" | "operation_failed") {
    super(`Flowersec unreliable message failed (code=${code})`);
    this.name = "UnreliableMessageError";
  }
}

export type StreamOpenOptions = OperationOptions & Readonly<{
  metadata?: StreamMetadata;
}>;

export type SessionErrorCode =
  | "canceled"
  | "timeout"
  | "closed"
  | "going_away"
  | "resource_exhausted"
  | "stream_rejected"
  | "stream_reset"
  | "rekey_failed"
  | "liveness_failed"
  | "unreliable_unavailable"
  | "unreliable_too_large"
  | "unreliable_dropped"
  | "operation_failed";

/** A closed, carrier-neutral session failure with no internal cause or peer detail. */
export class SessionError extends Error {
  constructor(readonly code: SessionErrorCode) {
    super(`Flowersec session failed (code=${code})`);
    this.name = "SessionError";
  }
}

export type RpcResult<Response = unknown> =
  | Readonly<{ ok: true; payload: Response }>
  | Readonly<{ ok: false; error: Readonly<{ code: number; message?: string }> }>;

export interface RpcPeer {
  call<Request = unknown, Response = unknown>(
    typeId: number,
    payload: Request,
    decodeResponse: (payload: JsonValue) => Response,
    options?: OperationOptions,
  ): Promise<RpcResult<Response>>;
  notify<Payload = unknown>(typeId: number, payload: Payload, options?: OperationOptions): Promise<void>;
  onNotify<Payload = unknown>(typeId: number, handler: (payload: Payload) => void): () => void;
}

export interface ByteStream {
  readonly kind: string;
  readonly terminalError: SessionError | undefined;

  read(options?: OperationOptions): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptions): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface IncomingStream {
  readonly kind: string;
  readonly metadata: StreamMetadata;
  readonly stream: ByteStream;
}

export type SessionTermination = Readonly<{
  error: SessionError;
}>;

export interface Session {
  readonly rpc: RpcPeer;
  readonly unreliableMessages?: UnreliableMessageChannel;

  openStream(kind: string, options?: StreamOpenOptions): Promise<ByteStream>;
  acceptStream(options?: OperationOptions): Promise<IncomingStream>;
  rekey(options?: OperationOptions): Promise<void>;
  probeLiveness(options?: OperationOptions): Promise<number>;
  waitTermination(): Promise<SessionTermination>;
  waitTermination(options: OperationOptions): Promise<SessionTermination>;
  close(): Promise<void>;
}

export type RetryDisposition =
  | Readonly<{ kind: "terminal" }>
  | Readonly<{ kind: "retryable" }>
  | Readonly<{ kind: "retry_after"; notBeforeUnixMilliseconds: number }>;

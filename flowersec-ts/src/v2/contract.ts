import type { RpcClient } from "../rpc/client.js";

export type CarrierKind = "websocket" | "raw_quic" | "webtransport";

export type PathKind = "direct" | "tunnel";

export type JsonPrimitiveV2 = null | boolean | number | string;

export type JsonValueV2 = JsonPrimitiveV2 | JsonObjectV2 | readonly JsonValueV2[];

export type JsonObjectV2 = Readonly<{ [key: string]: JsonValueV2 }>;

export type OperationOptionsV2 = Readonly<{
  signal?: AbortSignal;
}>;

export type StreamOpenOptionsV2 = OperationOptionsV2 &
  Readonly<{
    metadata?: JsonObjectV2;
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
  | "operation_failed";

/** A closed, carrier-neutral session failure with no internal cause or peer detail. */
export class SessionError extends Error {
  constructor(readonly code: SessionErrorCode) {
    super(`Flowersec session failed (code=${code})`);
    this.name = "SessionError";
  }
}

export type RpcResultV2 = Readonly<{
  payload: unknown;
  error?: Readonly<{ code: number; message?: string }>;
}>;

export interface RpcPeerV2 {
  call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<RpcResultV2>;
  notify(typeId: number, payload: unknown): Promise<void>;
  onNotify(typeId: number, handler: (payload: unknown) => void): () => void;
}

export interface ByteStreamV2 {
  readonly kind: string;
  readonly terminalError: SessionError | undefined;

  read(options?: OperationOptionsV2): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV2): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface IncomingStreamV2 {
  readonly kind: string;
  readonly metadata: JsonObjectV2;
  readonly stream: ByteStreamV2;
}

export type SessionTerminationV2 = Readonly<{
  error: SessionError;
}>;

export interface SessionV2 {
  readonly rpc: RpcPeerV2;
  readonly termination: Promise<SessionTerminationV2>;

  openStream(kind: string, options?: StreamOpenOptionsV2): Promise<ByteStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<IncomingStreamV2>;
  rekey(options?: OperationOptionsV2): Promise<void>;
  probeLiveness(options?: OperationOptionsV2): Promise<number>;
  waitClosed(): Promise<SessionTerminationV2>;
  close(): Promise<void>;
}

export interface InternalByteStreamV2 {
  readonly id: bigint;
  readonly kind: string;
  readonly terminalError: Error | undefined;

  read(options?: OperationOptionsV2): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV2): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface InternalIncomingStreamV2 {
  readonly id: bigint;
  readonly kind: string;
  readonly metadata: JsonObjectV2;
  readonly stream: InternalByteStreamV2;
}

export interface InternalSessionV2 {
  readonly path: PathKind;
  readonly endpointInstanceId: string | undefined;
  readonly rpc: RpcClient;
  readonly termination: Promise<Readonly<{ error: Error }>>;

  openStream(kind: string, options?: StreamOpenOptionsV2): Promise<InternalByteStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<InternalIncomingStreamV2>;
  rekey(options?: OperationOptionsV2): Promise<void>;
  probeLiveness(options?: OperationOptionsV2): Promise<number>;
  waitClosed(): Promise<Readonly<{ error: Error }>>;
  close(): Promise<void>;
}

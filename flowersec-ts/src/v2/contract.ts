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

export interface ByteStreamV2 {
  readonly id: bigint;
  readonly kind: string;
  readonly terminalError: Error | undefined;

  read(options?: OperationOptionsV2): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV2): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface IncomingStreamV2 {
  readonly id: bigint;
  readonly kind: string;
  readonly metadata: JsonObjectV2;
  readonly stream: ByteStreamV2;
}

export type SessionTerminationV2 = Readonly<{
  error: Error;
}>;

export interface SessionV2 {
  readonly path: PathKind;
  readonly chosenCarrier: CarrierKind;
  readonly endpointInstanceId: string | undefined;
  readonly rpc: RpcClient;
  readonly termination: Promise<SessionTerminationV2>;

  openStream(kind: string, options?: StreamOpenOptionsV2): Promise<ByteStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<IncomingStreamV2>;
  rekey(options?: OperationOptionsV2): Promise<void>;
  probeLiveness(options?: OperationOptionsV2): Promise<number>;
  waitClosed(): Promise<SessionTerminationV2>;
  close(): Promise<void>;
}

import type { RpcError } from "../rpc/wire.js";
import type {
  ByteStream,
  CarrierKind as PublicCarrierKind,
  IncomingStream,
  JsonObject,
  JsonPrimitive,
  JsonValue,
  OperationOptions,
  PathKind as PublicPathKind,
  RpcPeer,
  RpcResult,
  Session,
  SessionTermination,
  StreamOpenOptions,
  UnreliableMessageChannel,
  UnreliableMessageSendOptions,
  UnreliableMessageSendResult,
} from "../public/contract.js";
// Package exports keep this module private, but its declarations must remain in
// the emitted closure because other internal declaration files import them.
export { SessionError } from "../public/contract.js";
export type { SessionErrorCode } from "../public/contract.js";
export type CarrierKind = PublicCarrierKind;
export type PathKind = PublicPathKind;

export type JsonPrimitiveV3 = JsonPrimitive;
export type JsonValueV3 = JsonValue;
export type JsonObjectV3 = JsonObject;
export type OperationOptionsV3 = OperationOptions;
export type UnreliableMessageSendOptionsV3 = UnreliableMessageSendOptions;
export type UnreliableMessageSendResultV3 = UnreliableMessageSendResult;
export type UnreliableMessageChannelV3 = UnreliableMessageChannel;
export type StreamOpenOptionsV3 = StreamOpenOptions;
export type RpcResultV3<Response = unknown> = RpcResult<Response>;
export type RpcPeerV3 = RpcPeer;
export type ByteStreamV3 = ByteStream;
export type IncomingStreamV3 = IncomingStream;
export type SessionTerminationV3 = SessionTermination;
export type SessionV3 = Session;

export interface InternalByteStreamV3 {
  readonly id: bigint;
  readonly kind: string;
  readonly terminalError: Error | undefined;

  read(options?: OperationOptionsV3): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV3): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  close(): Promise<void>;
}

export interface InternalIncomingStreamV3 {
  readonly id: bigint;
  readonly kind: string;
  readonly metadata: JsonObjectV3;
  readonly stream: InternalByteStreamV3;
}

export interface InternalSessionV3 {
  readonly path: PathKind;
  readonly endpointInstanceId: string | undefined;
  readonly rpc: InternalRpcPeerV3;
  readonly termination: Promise<Readonly<{ error: Error }>>;
  readonly unreliableMessages?: UnreliableMessageChannelV3 | undefined;

  openStream(kind: string, options?: InternalStreamOpenOptionsV3): Promise<InternalByteStreamV3>;
  acceptStream(options?: OperationOptionsV3): Promise<InternalIncomingStreamV3>;
  rekey(options?: OperationOptionsV3): Promise<void>;
  probeLiveness(options?: OperationOptionsV3): Promise<number>;
  waitTermination(): Promise<Readonly<{ error: Error }>>;
  close(): Promise<void>;
}

export interface InternalRpcPeerV3 {
  call(typeId: number, payload: unknown, signal?: AbortSignal): Promise<{ payload: unknown; error?: RpcError }>;
  notify(typeId: number, payload: unknown): Promise<void>;
  onNotify(typeId: number, handler: (payload: unknown) => void): () => void;
  close(): void;
}

export type InternalStreamOpenOptionsV3 = OperationOptionsV3 & Readonly<{
  metadata?: JsonObjectV3;
}>;

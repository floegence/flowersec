import type { RpcClient } from "../rpc/client.js";
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
/** @internal */ export { SessionError } from "../public/contract.js";
/** @internal */ export type { SessionErrorCode } from "../public/contract.js";
/** @internal */ export type CarrierKind = PublicCarrierKind;
/** @internal */ export type PathKind = PublicPathKind;

/** @internal */ export type JsonPrimitiveV2 = JsonPrimitive;
/** @internal */ export type JsonValueV2 = JsonValue;
/** @internal */ export type JsonObjectV2 = JsonObject;
/** @internal */ export type OperationOptionsV2 = OperationOptions;
/** @internal */ export type UnreliableMessageSendOptionsV2 = UnreliableMessageSendOptions;
/** @internal */ export type UnreliableMessageSendResultV2 = UnreliableMessageSendResult;
/** @internal */ export type UnreliableMessageChannelV2 = UnreliableMessageChannel;
/** @internal */ export type StreamOpenOptionsV2 = StreamOpenOptions;
/** @internal */ export type RpcResultV2<Response = unknown> = RpcResult<Response>;
/** @internal */ export type RpcPeerV2 = RpcPeer;
/** @internal */ export type ByteStreamV2 = ByteStream;
/** @internal */ export type IncomingStreamV2 = IncomingStream;
/** @internal */ export type SessionTerminationV2 = SessionTermination;
/** @internal */ export type SessionV2 = Session;

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
  readonly unreliableMessages?: UnreliableMessageChannelV2 | undefined;

  openStream(kind: string, options?: InternalStreamOpenOptionsV2): Promise<InternalByteStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<InternalIncomingStreamV2>;
  rekey(options?: OperationOptionsV2): Promise<void>;
  probeLiveness(options?: OperationOptionsV2): Promise<number>;
  waitTermination(): Promise<Readonly<{ error: Error }>>;
  close(): Promise<void>;
}

export type InternalStreamOpenOptionsV2 = OperationOptionsV2 & Readonly<{
  metadata?: JsonObjectV2;
}>;

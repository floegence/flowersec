import type { Session as PublicSession } from "./public/contract.js";
import type {
  ConnectionControllerSnapshotV3 as CoreConnectionControllerSnapshotV3,
  ConnectionControllerV3 as CoreConnectionControllerV3,
} from "./v3/connectionController.js";

export * as v2 from "./v2/index.js";

export type {
  ByteStream,
  IncomingStream,
  JsonObject,
  JsonPrimitive,
  JsonValue,
  OperationOptions,
  RpcPeer,
  RpcResult,
  SessionErrorCode,
  StreamOpenOptions,
  UnreliableMessageChannel,
  UnreliableMessageSendOptions,
  UnreliableMessageSendResult,
  SessionTermination,
  Session,
} from "./public/contract.js";
export { SessionError, UnreliableMessageError } from "./public/contract.js";
export { createStreamMetadata, StreamMetadataError } from "./public/streamMetadata.js";
export type { StreamMetadata } from "./public/streamMetadata.js";
export {
  HandlerRegistrationError,
  StreamHandlers,
} from "./public/streamHandlers.js";
export type {
  StreamHandler,
  StreamHandlerOptions,
} from "./public/streamHandlers.js";
export {
  ArtifactHandleV3 as Artifact,
  ArtifactHandleV3,
  ArtifactParseErrorV3 as ArtifactError,
  ArtifactParseErrorV3,
  createArtifactLeaseV3 as createArtifactLease,
  createArtifactLeaseV3,
  parseArtifactV3 as parseArtifact,
  parseArtifactV3,
} from "./v3/publicApi.js";
export type {
  ArtifactParseErrorCodeV3 as ArtifactErrorCode,
  ArtifactParseErrorCodeV3,
} from "./v3/publicApi.js";
export {
  ArtifactLeaseV3 as ArtifactLease,
  ArtifactLeaseV3,
  ArtifactLeaseV3Error as ArtifactLeaseError,
  ArtifactLeaseV3Error,
} from "./v3/artifactLease.js";
export type {
  ArtifactSourceResultV3 as ArtifactSourceResult,
  ArtifactSourceResultV3,
  ArtifactSourceV3 as ArtifactSource,
  ArtifactSourceV3,
  ConnectionControllerFailureV3 as ConnectionControllerFailure,
  ConnectionControllerFailureV3,
  ConnectionControllerSnapshotV3,
  ConnectionControllerStateV3 as ConnectionState,
  ConnectionControllerStateV3,
  ConnectionControllerV3,
} from "./v3/connectionController.js";
export type ConnectionController = CoreConnectionControllerV3<PublicSession>;
export type ConnectionSnapshot = CoreConnectionControllerSnapshotV3<PublicSession>;
export type ConnectionControllerOptions = Readonly<{ maximumAttempts?: number }>;
export {
  ConnectionControllerV3Error as ConnectionControllerError,
  ConnectionControllerV3Error,
} from "./v3/connectionController.js";
export { ConnectErrorV3 as ConnectError, ConnectErrorV3 } from "./v3/security.js";
export type {
  PublicConnectErrorCodeV3 as ConnectErrorCode,
  PublicConnectErrorCodeV3,
  RetryDispositionV3 as RetryDisposition,
  RetryDispositionV3,
} from "./v3/security.js";

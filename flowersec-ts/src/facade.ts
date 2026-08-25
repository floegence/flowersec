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
  UnreliableMessageErrorCode,
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
  ArtifactParseErrorV3 as ArtifactError,
  createArtifactLeaseV3 as createArtifactLease,
  parseArtifactV3 as parseArtifact,
} from "./v3/publicApi.js";
export type {
  ArtifactParseErrorCodeV3 as ArtifactErrorCode,
} from "./v3/publicApi.js";
/** @deprecated Use Artifact, ArtifactError, createArtifactLease, and parseArtifact. */
export {
  ArtifactHandleV3,
  ArtifactParseErrorV3,
  createArtifactLeaseV3,
  parseArtifactV3,
} from "./v3/publicApi.js";
/** @deprecated Use ArtifactErrorCode. */
export type { ArtifactParseErrorCodeV3 } from "./v3/publicApi.js";
export {
  ArtifactLeaseV3 as ArtifactLease,
  ArtifactLeaseV3Error as ArtifactLeaseError,
} from "./v3/artifactLease.js";
/** @deprecated Use ArtifactLease and ArtifactLeaseError. */
export { ArtifactLeaseV3, ArtifactLeaseV3Error } from "./v3/artifactLease.js";
export type {
  ArtifactSourceResultV3 as ArtifactSourceResult,
  ArtifactSourceV3 as ArtifactSource,
  ConnectionDiagnosticV3 as ConnectionDiagnostic,
  ConnectionControllerFailureV3 as ConnectionControllerFailure,
  ConnectionControllerStateV3 as ConnectionState,
} from "./v3/connectionController.js";
/** @deprecated Use the corresponding unversioned controller types. */
export type {
  ArtifactSourceResultV3,
  ArtifactSourceV3,
  ConnectionDiagnosticV3,
  ConnectionControllerFailureV3,
  ConnectionControllerSnapshotV3,
  ConnectionControllerStateV3,
  ConnectionControllerV3,
} from "./v3/connectionController.js";
export { connectionDiagnosticV3 as connectionDiagnostic } from "./v3/connectionController.js";
/** @deprecated Use connectionDiagnostic. */
export { connectionDiagnosticV3 } from "./v3/connectionController.js";
export type ConnectionController = CoreConnectionControllerV3<PublicSession>;
export type ConnectionSnapshot = CoreConnectionControllerSnapshotV3<PublicSession>;
export type ConnectionControllerOptions = Readonly<{ maximumAttempts?: number }>;
export {
  ConnectionControllerV3Error as ConnectionControllerError,
} from "./v3/connectionController.js";
/** @deprecated Use ConnectionControllerError. */
export { ConnectionControllerV3Error } from "./v3/connectionController.js";
export { ConnectErrorV3 as ConnectError } from "./v3/security.js";
/** @deprecated Use ConnectError. */
export { ConnectErrorV3 } from "./v3/security.js";
export type {
  PublicConnectErrorCodeV3 as ConnectErrorCode,
  RetryDispositionV3 as RetryDisposition,
} from "./v3/security.js";
/** @deprecated Use ConnectErrorCode and RetryDisposition. */
export type { PublicConnectErrorCodeV3, RetryDispositionV3 } from "./v3/security.js";

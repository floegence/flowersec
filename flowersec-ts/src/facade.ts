import type { Session as PublicSession } from "./public/contract.js";
export { V4OperationResultRead } from "./v4/operationResultRead.js";
export type { V4OperationResultReadOptions, V4OperationResultReadResult } from "./v4/operationResultRead.js";
import type {
  ConnectionControllerSnapshotV3 as CoreConnectionControllerSnapshotV3,
  ConnectionControllerV3 as CoreConnectionControllerV3,
} from "./v3/connectionController.js";

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
export { createStreamMetadata, createStreamMetadataEnvelope, StreamMetadataError } from "./public/streamMetadata.js";
export type { RawStreamMetadataContract, RawStreamMetadataField, StreamMetadata } from "./public/streamMetadata.js";
export { asWebStreams, V4WebStreamError } from "./v4/webStreams.js";
export type { V4LiveAuthorizationConfig, V4LiveAuthorizationProvider, V4LiveAuthorizationRequest } from "./v4/runtime/liveAuthorization.js";
export type { V4WebStreams, V4WebStreamsOptions, V4WebStreamFailure } from "./v4/webStreams.js";
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
export {
  ArtifactLeaseV3 as ArtifactLease,
  ArtifactLeaseV3Error as ArtifactLeaseError,
} from "./v3/artifactLease.js";
export type {
  ArtifactSourceResultV3 as ArtifactSourceResult,
  ArtifactSourceV3 as ArtifactSource,
  ConnectionDiagnosticV3 as ConnectionDiagnostic,
  ConnectionControllerFailureV3 as ConnectionControllerFailure,
  ConnectionControllerStateV3 as ConnectionState,
} from "./v3/connectionController.js";
export { connectionDiagnosticV3 as connectionDiagnostic } from "./v3/connectionController.js";
export type ConnectionController = CoreConnectionControllerV3<PublicSession>;
export type ConnectionSnapshot = CoreConnectionControllerSnapshotV3<PublicSession>;
export type ConnectionControllerOptions = Readonly<{ maximumAttempts?: number }>;
export {
  ConnectionControllerV3Error as ConnectionControllerError,
} from "./v3/connectionController.js";
export { ConnectErrorV3 as ConnectError } from "./v3/security.js";
export type {
  PublicConnectErrorCodeV3 as ConnectErrorCode,
  RetryDispositionV3 as RetryDisposition,
} from "./v3/security.js";

// The wire-v4 result registry is part of the package contract.  Keep the
// generated values on the ordinary facade so callers do not need an internal
// path (the runtime ledger still owns the durable TopUp transaction).
export * from "./generated/transportV4APIResults.js";

// v4 lifecycle helpers project original runtime owners. They preserve one read owner, one-use material and explicit cleanup
// facts without exposing carrier or key objects.
export {
  V4ConnectionMaterial,
  V4OperationHandle,
  V4ReaderCursor,
  V4Session,
  V4TransportEnvironment,
  V4WriteOperation,
} from "./v4/public.js";
export type {
  V4ConnectionMaterialSource,
  V4CleanupStatus,
  V4LifecycleObjectKind,
  V4LifecycleState,
  V4LifecycleReason,
  V4LifecycleResult,
  V4OperationStatus,
  V4ReadProgress,
  V4ReadResult,
  V4WriteProgress,
} from "./v4/public.js";

export { createV4TransportEnvironment } from "./v4/runtime/environment.js";
export type {
  V4EnvironmentConfig,
  V4EnvironmentClockConfig,
  V4NamespaceOptions,
  V4CredentialPolicy,
  V4CredentialBuffers,
  V4CredentialLengths,
  V4CredentialProvider,
} from "./v4/runtime/environment.js";
export { ResourceRoot as V4ResourceRoot, ResourceVector as V4ResourceVector } from "./v4/runtime/resources.js";
export type { ResourceRootConfig as V4ResourceRootConfig } from "./v4/runtime/resources.js";
export { ClockRate as V4ClockRate } from "./v4/runtime/timeArithmetic.js";

export { V4LivenessError } from "./v4/liveness.js";
export type { V4LivenessResult, V4LivenessFailure, V4AutomaticLivenessPolicy } from "./v4/liveness.js";
export { V4DrainOperation, V4DrainError } from "./v4/drain.js";
export type { V4DrainOptions, V4DrainOutcome, V4DrainResult } from "./v4/drain.js";
export { V4MethodDefinition, V4ServiceDefinition } from "./v4/serviceDefinition.js";
export { V4ServiceError } from "./v4/serviceHandlers.js";
export type { V4OutputInterest, V4OutputInterestProgress, V4OutputInterestReason, V4UnaryContext, V4UnaryHandler, V4UnaryAuthorizer, V4UnaryHandlerOptions } from "./v4/serviceHandlers.js";
export type { V4MethodDefinitionOptions, V4ServiceMethods, V4ServiceShape, V4ServiceSemantics, V4ApplicationErrorDefinition } from "./v4/serviceDefinition.js";
export { V4MessageStreamDefinition, v4BytesMessageCodec, v4UTF8MessageCodec, v4ApplicationMessageCodec } from "./v4/messageDefinition.js";
export type { V4MessageCodec, V4MessageDirection, V4ApplicationMessageCodec } from "./v4/messageDefinition.js";
export { asTypedMessages, V4TypedMessageStream, V4MessageStreamError } from "./v4/messageStream.js";
export type { V4MessageStreamOptions, V4MessageSendOptions, V4MessageReceiveOptions, V4MessageSendResult, V4MessageReceiveResult, V4MessageFailure } from "./v4/messageStream.js";
export { V4StreamRegistration } from "./v4/streamHandlers.js";
export type { V4AuthenticatedContext, V4ApplicationContext, V4ApplicationWaitOptions, V4StreamRegistrationOptions, V4StreamOpenAuthorizer, V4MessageStreamHandler, V4RawStreamHandler } from "./v4/streamHandlers.js";

export { V4ServiceClient } from "./v4/serviceClient.js";
export type { V4ServiceBindOptions, V4ServiceRefreshOptions, V4ServiceContract, V4ServiceRefreshResult, V4ServiceInfo } from "./v4/serviceClient.js";
export { V4UnaryOperation, V4ExecutionUnaryOperation } from "./v4/unaryOperation.js";
export type { V4UnaryOptions, V4UnaryResult, V4UnaryStatus, V4UnaryStartResult } from "./v4/unaryOperation.js";

export type { V4ClientServicesConfig } from "./v4/clientServices.js";

export { V4OperationReference } from "./v4/operationReference.js";
export type { V4ExecutionObservation, V4ExecutionManagementResult } from "./v4/operationReference.js";
export { V4OperationReferenceCodec, createV4OperationReferenceCodec } from "./v4/operationReferenceCodec.js";
export type { ServiceBindingTarget as V4ServiceBindingTarget } from "./v4/runtime/serviceBindingConfig.js";
export { V4OperationReferenceStore, createV4OperationReferenceStore } from "./v4/operationReferenceStore.js";
export type { V4ReferenceStorePolicy, V4ReferenceStoreSave, V4ReferenceStoreRecord, V4ReferenceSaveOutcome, V4ReferenceSaveStatus, V4ReferenceSaveFailure } from "./v4/operationReferenceStore.js";
export type { V4PrepareAndSaveResult, V4PrepareNotifyAndSaveResult, V4PrepareStreamAndSaveResult } from "./v4/serviceClient.js";
export type { RPCExecutionDelegation as V4ExecutionDelegation } from "./v4/runtime/rpcApplication.js";

export { V4StaticServiceContracts, createV4StaticServiceContracts } from "./v4/staticServiceContracts.js";
export type { V4StaticServiceContractInput, V4StaticServiceContractOptions } from "./v4/staticServiceContracts.js";

export { V4ObservationNotifyOperation, V4ExecutionNotifyOperation } from "./v4/notificationOperation.js";
export type { V4NotifyOptions, V4NotifyStatus, V4NotifyStartResult } from "./v4/notificationOperation.js";
export type { V4NotificationHandler, V4NotificationHandlerOptions } from "./v4/serviceHandlers.js";

export { V4NotificationSubscription } from "./v4/notificationSubscription.js";
export type { V4Notifications, V4NotificationSubscriptionOptions, V4ObservationStatus, V4NotificationGap, V4NotificationWaitOptions, V4NotificationClosedResult } from "./v4/notificationSubscription.js";

export { V4StreamingOperation, V4ExecutionStreamingOperation } from "./v4/streamingOperation.js";
export type { V4StreamingOptions, V4StreamingItem, V4StreamingStatus, V4StreamingAbandonResult } from "./v4/streamingOperation.js";
export type { V4StreamWriter, V4StreamingHandler, V4StreamingHandlerOptions, V4StreamingImplementation } from "./v4/serviceHandlers.js";

export { V4ByteEventSource, v4ByteEventSource } from "./v4/eventSource.js";
export type { V4ByteEventPublisher, V4ByteEventSourceOptions, V4EventPublishResult, V4EventSourceDisposer } from "./v4/eventSource.js";

export { issueV4Checkpoint } from "./v4/checkpoint.js";
export type { V4Checkpoint, V4CheckpointTarget, V4CheckpointIssuanceOptions, V4CheckpointResult } from "./v4/checkpoint.js";

export { v4RecoveryProgress, type V4ResumeResult, type V4ResumeProgress } from "./v4/resume.js";

export { saveV4StreamContent, readV4RetainedContent } from "./v4/streamContent.js";
export type { V4StreamContentDefinition, V4ContentObservation } from "./v4/streamContent.js";

export { V4MaintenanceOwner, createV4MaintenanceOwner } from "./v4/responsePublication.js";
export type { V4ResponsePublication, V4PublicationTransfer } from "./v4/responsePublication.js";

export { V4ConnectionController, createV4ConnectionController } from "./v4/controller.js";
export { createV4ServiceClient } from "./v4/serviceFactory.js";
export type { V4ServiceClientSource, V4ServiceClientGroups, V4ServiceSourceGroup } from "./v4/serviceFactory.js";
export type { V4ControllerConfig, V4ControllerReplaceOptions, V4ControllerReplaceResult, V4ControllerStatus, V4ControllerInitializationContext, V4ControllerStreamDeclaration } from "./v4/controller.js";

export { v4ServiceDependency } from "./v4/serviceDependencies.js";
export type { V4ServiceDependency, V4ServiceDependencies, V4DispatchRequirement, V4InvocationServices } from "./v4/serviceDependencies.js";

export type { InitializerWorkloadConfig as V4InitializerWorkloadConfig } from "./v4/runtime/initializerWorkload.js";

export { ServeHandle, ServeListener, ServeError } from "./v4/serve.js";
export type { ServeOptions, ServeCallbacks, ServeRequestContext, AuthenticatedRequestContext, AuthorizeApplicationResult, ApplicationAuthorizationLease, ServeReleaseContext, ServeFailure } from "./v4/serve.js";
export { createHandlerPlan, HandlerPlan } from "./v4/handlerPlan.js";
export type { HandlerPlanOptions, HandlerServices } from "./v4/handlerPlan.js";

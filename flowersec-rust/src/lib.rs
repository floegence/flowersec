#![recursion_limit = "256"]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![doc = include_str!("../README.md")]

//! Native Rust support for Flowersec secure direct and tunneled sessions over
//! the configured native transports.
//!
//! The client entry point is [`TransportEnvironment::connect`]
//! with a captured [`ConnectionMaterialSource`]; [`connect`] is the crate-root
//! convenience entry point, and [`ConnectionController`] adds
//! generation-safe replacement and managed service publication. Carrier
//! configuration, candidates, wire formats, and
//! cryptographic state are crate-private.
//!
//! ```compile_fail
//! use flowersec::framing;
//! ```
//!
//! ```compile_fail
//! use flowersec::client;
//! ```
//!
//! ```compile_fail
//! use flowersec::endpoint;
//! ```
//!
//! ```compile_fail
//! use flowersec::proxy;
//! ```
//!
//! ```compile_fail
//! use flowersec::origin;
//! ```
//!
//! ```compile_fail
//! use flowersec::rpc;
//! ```
//!
//! ```compile_fail
//! use flowersec::stream;
//! ```
//!
//! ```compile_fail
//! use flowersec::protocolio;
//! ```
//!
//! ```compile_fail
//! use flowersec::gen::flowersec::v1;
//! ```
//!
//! Carrier and wire implementation modules are intentionally inaccessible.
//!
mod api_v4;
mod application_lifetime_v4;
mod application_tails_v4;
mod codec_v4;
mod contract_acceptance_v4;
mod diagnostics_v4;
mod sqlite_application_format_v4;
pub use contract_acceptance_v4::{
    ContractAcceptance, ContractPolicyRejected, ContractRange, ContractRangeField,
};
pub use diagnostics_v4::{
    CancellableDiagnosticCallback, DiagnosticAttemptBucket, DiagnosticCallback,
    DiagnosticCleanupStatus, DiagnosticCode, DiagnosticCounts, DiagnosticDurationBucket,
    DiagnosticEvent, DiagnosticMetric, DiagnosticMetricCounts, DiagnosticObservation,
    DiagnosticPhase, DiagnosticRetryDisposition, DiagnosticSink, DiagnosticSinkConfiguration,
    DiagnosticSinkError, DiagnosticSinkOptions, DiagnosticState, TransportDiagnosticCounts,
};
mod connection_controller_v4;
pub use connection_controller_v4::{
    CandidateSessionInitializer, CapturedControllerService, ControllerMaterialSource,
    ControllerNotificationEvent, ControllerNotificationGap, ControllerNotificationGapReason,
    ControllerNotificationObservation, ControllerNotificationObserver,
    ControllerNotificationOptions, ControllerNotificationSnapshot,
    ControllerNotificationSourcePhase, ControllerNotificationSubscription, ControllerServiceClient,
    ControllerServiceError, ManagedServiceClient, ManagedServiceConfiguration,
    MaterialConnectionController, MaterialConnectionSnapshot, MaterialControllerError,
    MaterialControllerOptions, MaterialControllerProgress, MaterialControllerState,
    MaterialSessionReplaceOptions, MaterialSessionReplaceResult, MaterialSessionRetirement,
    MaterialSourceOwnership,
};
#[cfg(test)]
pub(crate) use connection_controller_v4::{
    NotificationLockOrderProbe, NotificationLockOrderStage, close_test_notification_root,
    exercise_test_notification_publication, exercise_test_old_input_rejection,
    install_notification_lock_order_probe, new_test_notification_root,
    start_test_notification_root, test_notification_root_attached,
};
#[cfg(test)]
pub(crate) use crypto_v4::{
    MaintenanceReceiveProbe, TerminalPublicationProbe, install_maintenance_receive_probe,
    install_terminal_publication_probe,
};
mod crypto_v4;
mod environment_v4;
mod idna_v4;
mod namespace_v4;
mod pool_v4;
mod proxy_credentials_v4;
mod proxy_network;
mod proxy_server;
pub use proxy_credentials_v4::{
    ProxyCookieSession, ProxyCredentialAuthorizer, ProxyCredentialClearResult,
    ProxyCredentialError, ProxyCredentialMode, ProxyCredentialPolicy, ProxyCredentialScope,
    ProxyServerInvalidation,
};
mod application_profile_v4;
mod proxy_wire;
pub use application_profile_v4::{
    ApplicationExecutorConfig, ApplicationExecutorSnapshot, ApplicationResourceProfile,
};
mod application_executor_v4;
pub use application_executor_v4::{ApplicationInvocationContext, ApplicationInvocationError};
mod checkpoint_v4;
pub use checkpoint_v4::{
    ApplicationCheckpoint, ApplicationCheckpointToken, ApplicationResumeProgress,
    ApplicationResumeResult, ApplicationResumeStatus, CheckpointTokenProtection,
    CheckpointVerificationKey, ExecutionRecoveryPolicy, ServiceCheckpointSigningKey,
};
mod execution_history;
mod sqlite_execution_store_v4;
pub use execution_history::{
    ExecutionAbsence, ExecutionCancelResult, ExecutionIdentity, ExecutionInvocation,
    ExecutionManagementResult, ExecutionObservation, ExecutionService, ExecutionServiceOptions,
    ExecutionState, ExecutionTarget,
};
pub use sqlite_execution_store_v4::{SQLiteExecutionStore, SQLiteExecutionStoreOptions};
mod rpc_channel_v4;
pub use rpc_channel_v4::RPCChannelClass;
mod preaccepted_streams_v4;
mod rpc_stream_messages_v4;
mod rpc_wire_v4;
pub use preaccepted_streams_v4::{StreamingPoolPolicy, StreamingPoolRequirement};
mod streaming_resume_v4;
pub use streaming_resume_v4::{StreamingResumeOperation, StreamingResumeState};
mod streaming_operation_v4;
mod streaming_service_v4;
pub use streaming_service_v4::{
    RegisteredStreamingService, ServiceStreamItem, StreamingItemSource, StreamingServiceConfig,
    StreamingServiceHandler, StreamingServiceRegistration, TypedStreamingItemSource,
    TypedStreamingService, TypedStreamingServiceAdapter,
};
mod resume_service_v4;
pub use resume_service_v4::{
    RegisteredResumeService, ResumeServiceConfig, ResumeServiceHandler, ResumeServiceRegistration,
    StreamingResumeServiceHandler, UnaryResumeServiceHandler,
};
pub use streaming_operation_v4::{
    EncodedStreamingItem, StreamingOperation, StreamingOperationProgress, StreamingPrepareOptions,
    StreamingTerminal, TypedStreamingItem,
};
mod control_https_v4;
pub use control_https_v4::{ControlHTTPSConfiguration, ControlHTTPSFailure};
mod live_material_source_v4;
pub use live_material_source_v4::{
    LiveAuthorityCarrier, LiveAuthoritySourceConfiguration, LiveTunnelAuthorityControl,
    LiveTunnelAuthorityControlConfiguration, LiveTunnelAuthorization,
    LiveTunnelSourceConfiguration, RegisteredLiveTunnelSourceConfiguration,
};
pub use pool_v4::relay::{SQLiteRelayBinding, SQLiteRelayLedger, SQLiteRelayOptions};
mod native_tcp_duplex_v4;
pub use native_tcp_duplex_v4::{
    NativeTcpDuplex, NativeTcpDuplexError, NativeTcpDuplexInfo, NativeTcpDuplexOptions,
};
mod duplex_bridge_v4;
pub use duplex_bridge_v4::{
    DUPLEX_BRIDGE_CHUNK_BYTES, DuplexBridge, DuplexBridgeError, DuplexBridgeErrorReason,
    DuplexBridgeOptions, DuplexDirectionTerminal, DuplexOutcome, DuplexProgress, DuplexResult,
    DuplexSendCompletion, TransferProgress,
};
mod top_up_v4;
pub use top_up_v4::{
    PoolTopUpConfiguration, PreauthorizedPoolSource, RedevenPoolControl, TopUpControlReplyDecoder,
    TopUpControlTransport, TopUpError, TopUpErrorCode, TopUpExchangeResult, TopUpFenceProvider,
    TopUpHandle, TopUpIntent, TopUpMaterialDecoder, TopUpOptions, TopUpOutcome,
    TopUpRecoveryResult, TopUpResult, TopUpState,
};
mod material_source_v4;
pub use crypto_v4::connect::{
    OriginalRelayDelivery, OriginalRelayPoolPublication, RelayLiveControlDeployment,
    RelayLiveForwardingProgress, RelayLivePreparationLimits, RelayOriginalDeliveryHandle,
    RelayOriginalDeliveryOptions, RelayOriginalIssuer, RelayParentRegistration,
    RelayPoolPublicationInput, RemoteRelayPublication, ReverseTunnelProviderOptions, WssRelayHost,
    WssRelayHostOptions, WssRelayLegOptions, WssRelayPublication,
};
pub use material_source_v4::{
    ApplicationProfile, ConnectionError, ConnectionMaterial, ConnectionMaterialSource,
    ConnectionRequest, LocalDirectMaterialSource, MaterialAcquisitionObservation,
    MaterialSourceError, PreauthorizedPoolSourceConfiguration,
    PreauthorizedReverseTunnelPoolSourceConfiguration, PreauthorizedTunnelPoolSourceConfiguration,
    connect,
};
mod message_codec_v4;
pub use message_codec_v4::{BytesMessageCodec, UTF8MessageCodec};
mod service_client_v4;
pub use service_client_v4::{
    ExecutionReferenceIdentity, ManagedOfferRenewal, ManagedOfferRenewalProgress,
    NotificationPrepareOptions, ResponseLimitPolicy, ServiceAdmission, ServiceBindingOptions,
    ServiceBindingSelection, ServiceClient, ServiceMethodRefreshResult, ServiceResumeBinding,
    ServiceStreamBinding, UnaryPrepareOptions,
};
mod reference_store_v4;
pub use reference_store_v4::{
    OperationReferenceStore, PrepareAndSaveError, ReferenceSaveFailure, ReferenceSaveOutcome,
    ReferenceSaveReceipt, ReferenceSaveSnapshot, SavedStreamingPreparation,
    SavedStreamingResumePreparation, SavedUnaryPreparation,
};
mod operation_reference_v4;
pub use operation_reference_v4::{OperationReference, OperationReferenceCodec};
pub type OperationHandle<T = Vec<u8>> = UnaryOperation<T>;
mod service_operation_v4;
pub use service_operation_v4::{
    EncodedUnaryResult, MessageCodecIdentity, ServicePublication, ServiceStartRefusal,
    ServiceStartResult, TypedUnaryResult, TypedUnaryValue, UnaryOperation, UnaryOperationProgress,
};
mod response_publication_v4;
pub use response_publication_v4::{
    MaintenanceOwner, MaintenanceOwnerOptions, ResponsePublication, ResponsePublicationCause,
    ResponsePublicationState, ResponsePublicationStatus, ResponseTransferResult,
};
mod service_peer_v4;
pub use service_peer_v4::{
    ContractAvailability, ContractQueryTarget, ContractSnapshot, FixedContractQuery, ServicePeer,
    UnaryRequestContext, UnaryResponse, UnaryServiceHandler, UnaryServiceRegistration,
};
mod service_contract;
pub use service_contract::{
    AdmissionOffer, ApplicationErrorDefinition, AsyncMessageCodec, MessageCodec, MessageDefinition,
    MethodDefinition, MethodDefinitionOptions, ServiceContract, ServiceDefinition, ServiceError,
    ServiceFailure, ServiceMethod, ServiceSemantics, ServiceShape, StreamContentDefinition,
    StreamingLimits,
};
mod transport;
mod unicode151_generated;

#[cfg(feature = "__flowersec_internal_fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// Exercise the current canonical Artifact schema within its byte bound.
    pub fn parse_artifact(data: &[u8]) {
        let _ = crate::codec_v4::decode(
            data,
            "Artifact",
            crate::codec_v4::Limits {
                bytes: 65_536,
                nodes: 16_384,
            },
            None,
        );
    }

    /// Exercise bounded current credential and handshake parsing without
    /// exposing carrier or wire implementation types.
    pub fn parse_protocol(data: &[u8]) {
        parse_artifact(data);
        let limits = crate::codec_v4::Limits {
            bytes: 65_536,
            nodes: 16_384,
        };
        for schema in [
            "ActivationAuthorization",
            "Grant",
            "ClientHello",
            "ServerHello",
            "Metadata",
        ] {
            let _ = crate::codec_v4::decode(data, schema, limits, None);
        }
    }
}

#[cfg(test)]
mod defaults_contract;
pub use api_v4::TransportEnvironment;
pub use connection_controller_v4::{
    MaterialConnectionController as ConnectionController,
    MaterialConnectionSnapshot as ConnectionSnapshot,
    MaterialControllerError as ConnectionControllerError,
    MaterialControllerOptions as ConnectionControllerOptions,
    MaterialControllerProgress as ConnectionProgress, MaterialControllerState as ConnectionState,
};
pub use crypto_v4::connect::serve::{
    AcceptedAuthorizationProfile, AcceptedMaterialSource, AcceptedServices,
    ApplicationAuthorization, ApplicationAuthorizationLease, ApplicationBinding, ApplicationLimits,
    AuthenticatedRequestContext, AuthorizeApplicationResult, HandlerPlan, HandlerPlanOptions,
    RawStreamHandler, RawStreamRegistration, RequestAuthorization, ReverseTunnelServeOptions,
    ServeCallbacks, ServeDrainOperation, ServeDrainResult, ServeError, ServeFailure, ServeHandle,
    ServeReleaseContext, ServeRequestContext, ServicePlan, SessionAcceptance, StreamAuthorization,
    StreamDispatch, TunnelServeHandle, TunnelServeOptions, WssServeOptions, WssServerIdentity,
};
pub use crypto_v4::connect::{
    ConnectionAdmissionState, ConnectionApplicationPublish, ConnectionAttemptFacts,
    ConnectionNetworkReady, ConnectionPhase, ConnectionQueryAvailability, ConnectionSourceProfile,
    ConnectionSpendState,
};
pub use crypto_v4::connect::{
    WssRelayHost as RelayHost, WssRelayHostOptions as RelayHostOptions,
    WssRelayLegOptions as RelayLegOptions, WssRelayPublication as RelayPublication,
};
pub use crypto_v4::{
    BindingMode, ConnectError as TransportConnectError, DrainOperation, DrainOutcome, DrainResult,
    IdentityKeys, Metadata, Namespace, NamespaceBootstrapRequest, OpenRequest,
    PoolConnectionMaterial, PoolCredentialBytes, PostAuthorizationFailure, PostSpendFailure,
    ProbeOutcome, ProbeResult, RawStreamMetadataContract, RawStreamMetadataField,
    RawStreamMetadataType, Session, Stream, TunnelPoolCredentialBytes,
    TunnelServerAllowConfiguration, UnreliableMessages, WssConnectOptions,
};
pub use environment_v4::{
    AutomaticLivenessPolicy, EnvironmentError, ResourceLimits, TransportEnvironmentOptions,
    TrustedTimeProfile, TrustedTimeSample, TrustedTimeSource,
};
pub use material_source_v4::ConnectionError as ConnectError;
pub use namespace_v4::verifier::NamespaceTrustRoot;
pub use notification_peer_v4::ServiceNotificationSubscription as NotificationSubscription;
pub use pool_v4::admission::{SQLiteAdmissionAuthority, SQLiteAdmissionBinding};
pub use pool_v4::{
    PoolSpendObservation, PoolSpendState, PoolStoreError, PoolStoreFailure, PoolWriteState,
    SQLitePoolBacking, SQLitePoolBinding, SQLitePoolContinuity, SQLitePoolIdentity,
    SQLitePoolLimits, SQLitePoolOptions, SQLitePoolStore, StorageFormatConversion,
    StorageFormatIncompatibility, StorageFormatMismatchReason, StorageFormatTransactionGroup,
    StorageWireFormat,
};

pub use api_v4::{
    CleanupStatus, ConnectionRequirements, OperationNotificationSubscription, OperationStatus,
    ReadCause, ReadDeliveryAuthorization, ReadError, ReadErrorCode, ReadErrorScope,
    ReadMethodFailure, ReadMethodFailureReason, ReadProgress, ReadResult, ReadRetryDisposition,
    ReadStreamStatus, ReadWaitStatus, ReaderCursor, ReaderCursorOptions, ReaderCursorSnapshot,
    ResultPayload, StreamExt, StreamReadOwner, StreamReadPermit, StreamWritePreparationPermit,
    WriteOperation, WriteProgress, WriteRequestAdmission, WriteStagingOwner,
};
pub use crypto_v4::connect::OriginalRelayPoolWinner;
pub use crypto_v4::connect::registered_pool::{
    RegisteredPoolServerConfiguration, RegisteredPoolTunnelServerMaterial,
};
pub use crypto_v4::connect::serve::{
    LiveReverseTunnelListener, LiveReverseTunnelServeOptions, LiveServerDeliveryHandle,
    LiveServerDeliveryOptions, OriginalLiveAcceptedSource, OriginalLiveServerDelivery,
    OriginalLiveServerPublication, OriginalLiveTunnelServerMaterial,
    OriginalLiveTunnelServerPublication, PoolServerAllowBinding, PoolServerAllowOptions,
    RegisteredLiveServerControlConfiguration, RegisteredLiveServerPreparation,
    RegisteredLiveTunnelServerPublication, RemoteLiveServerPublication,
    RemoteLiveTunnelServerPublication,
};
pub use proxy_server::{ProxyErrorReporter, ProxyServer, ProxyServerError, ProxyServerOptions};
pub use transport::{
    ByteStream, SessionError, SessionTermination, UnreliableMessageChannel, UnreliableMessageError,
    UnreliableMessageErrorCode, UnreliableMessagesInfo, UnreliableReceiveBlock,
    UnreliableSendOutcome,
};

mod execution_management_v4;
pub use execution_management_v4::{ExecutionHistoryGrant, ExecutionManagement};

mod typed_message_stream_v4;
pub use typed_message_stream_v4::{
    EncodedMessage, MessageReceiveTerminal, MessageStreamDefinition, MessageStreamHandler,
    MessageStreamOptions, TypedMessage, TypedMessageStream, register_message_stream,
};

mod sqlite_reference_store_v4;
pub use sqlite_reference_store_v4::{SQLiteOperationReferenceStore, SQLiteReferenceStoreOptions};

pub use service_peer_v4::FixedResultRead;

mod application_error_codec_v4;
pub use application_error_codec_v4::{ApplicationErrorCodec, DecodedApplicationError};

pub(crate) mod notification_peer_v4;
pub use notification_peer_v4::{
    ExecutionNotificationHandler, NotificationContext, NotificationDropPolicy,
    NotificationOperation, NotificationPeer, NotificationPublication,
    NotificationServiceRegistration, ServiceNotificationObserver, ServiceNotificationSubscription,
};

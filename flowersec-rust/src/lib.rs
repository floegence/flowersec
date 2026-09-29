#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![doc = include_str!("../README.md")]

//! Native Rust support for Flowersec secure direct and tunneled sessions over
//! the current wire v4 transport.
//!
//! Maintained callers use the opaque [`Artifact`], one-shot [`connect`],
//! optional long-lived [`ConnectionController`], and carrier-neutral
//! [`Session`], direct [`Acceptor`], and opaque [`TunnelRuntime`] contracts.
//! Carrier configuration, candidates, wire formats, and cryptographic state
//! are crate-private.
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
mod acceptor_v3;
mod api_v4;
mod application_lifetime_v4;
mod artifact_v3;
mod codec_v4;
mod contract_acceptance_v4;
pub use contract_acceptance_v4::{
    ContractAcceptance as V4ContractAcceptance, ContractPolicyRejected as V4ContractPolicyRejected,
    ContractRange as V4ContractRange, ContractRangeField as V4ContractRangeField,
};
mod connection_controller;
mod connector_v3;
mod crypto_v3;
mod crypto_v4;
mod pool_v4;
pub use pool_v4::{
    PoolStoreError as V4PoolStoreError, PoolStoreFailure as V4PoolStoreFailure,
    PoolWriteState as V4PoolWriteState, SQLitePoolBacking as V4SQLitePoolBacking,
    SQLitePoolBinding as V4SQLitePoolBinding, SQLitePoolContinuity as V4SQLitePoolContinuity,
    SQLitePoolIdentity as V4SQLitePoolIdentity, SQLitePoolLimits as V4SQLitePoolLimits,
    SQLitePoolOptions as V4SQLitePoolOptions, SQLitePoolStore as V4SQLitePoolStore,
};
mod environment_v4;
mod idna_v3;
mod namespace_v4;
mod protocol_v3;
mod proxy_network;
mod proxy_server;
mod proxy_wire;
mod raw_quic_v3;
mod session_handlers;
mod session_v3;
mod tls_v3;
mod transport;
mod transport_v3;
mod tunnel_runtime_v3;
mod unicode151_generated;
mod websocket_transport;
mod websocket_v3;

#[cfg(feature = "__flowersec_internal_fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// Exercise the handshake, control-record, encrypted-header, and
    /// unreliable-message parsers without exposing their wire types.
    pub fn parse_protocol(data: &[u8]) {
        crate::protocol_v3::fuzz_parse(data);
    }
}

#[cfg(test)]
mod defaults_contract;
pub use acceptor_v3::{
    AcceptError, AcceptErrorCode, Acceptor, AcceptorOptions, WebSocketAcceptorOptions,
};
pub use api_v4::{
    CleanupStatus, ConnectionRequirements, NotificationSubscription as V4NotificationSubscription,
    OperationHandle, OperationReference, OperationStatus, ReadCause, ReadDeliveryAuthorization,
    ReadError, ReadErrorCode, ReadErrorScope, ReadMethodFailure, ReadMethodFailureReason,
    ReadProgress, ReadResult, ReadRetryDisposition, ReadStreamStatus, ReadWaitStatus, ReaderCursor,
    ReaderCursorOptions, ReaderCursorSnapshot, ResultPayload, StreamReadOwner, StreamReadPermit,
    StreamV4Ext, TransportEnvironment as V4TransportEnvironment, WriteOperation, WriteProgress,
    WriteRequestAdmission, WriteStagingOwner,
};
pub use artifact_v3::{Artifact, ArtifactError, ArtifactLease, ArtifactSpendError};
pub use connection_controller::{
    ArtifactSource, ArtifactSourceError, ConnectionController,
    ConnectionControllerConfigurationError, ConnectionControllerError,
    ConnectionControllerErrorCode, ConnectionControllerOptions, ConnectionDiagnostic,
    ConnectionDiagnosticFailure, ConnectionFailure, ConnectionFailurePhase, ConnectionSnapshot,
    ConnectionState, RetryDisposition,
};
pub use connector_v3::{
    ConnectError, ConnectErrorCode, ConnectorOptions, connect_v3 as connect,
    connect_v3_with_cancellation as connect_with_cancellation,
};
pub use crypto_v4::connect::serve::{
    AcceptedMaterialSource as V4AcceptedMaterialSource,
    ApplicationAuthorization as V4ApplicationAuthorization,
    ApplicationAuthorizationLease as V4ApplicationAuthorizationLease,
    ApplicationBinding as V4ApplicationBinding, ApplicationLimits as V4ApplicationLimits,
    AuthenticatedRequestContext as V4AuthenticatedRequestContext,
    AuthorizeApplicationResult as V4AuthorizeApplicationResult, HandlerPlan as V4HandlerPlan,
    HandlerPlanOptions as V4HandlerPlanOptions, RawStreamHandler as V4RawStreamHandler,
    RawStreamRegistration as V4RawStreamRegistration,
    RequestAuthorization as V4RequestAuthorization, ServeCallbacks as V4ServeCallbacks,
    ServeDrainOperation as V4ServeDrainOperation, ServeDrainResult as V4ServeDrainResult,
    ServeError as V4ServeError, ServeFailure as V4ServeFailure, ServeHandle as V4ServeHandle,
    ServeReleaseContext as V4ServeReleaseContext, ServeRequestContext as V4ServeRequestContext,
    SessionAcceptance as V4SessionAcceptance, StreamAuthorization as V4StreamAuthorization,
    StreamDispatch as V4StreamDispatch, WssServeOptions as V4WssServeOptions,
    WssServerIdentity as V4WssServerIdentity,
};
pub use crypto_v4::{
    BindingMode as V4BindingMode, ConnectError as V4ConnectError, IdentityKeys as V4IdentityKeys,
    Namespace as V4Namespace, PoolConnectionMaterial as V4PoolConnectionMaterial,
    PoolCredentialBytes as V4PoolCredentialBytes, PostSpendFailure as V4PostSpendFailure,
    WssConnectOptions as V4WssConnectOptions,
};
pub use crypto_v4::{
    DrainOperation as V4DrainOperation, DrainOutcome as V4DrainOutcome,
    DrainResult as V4DrainResult, Metadata as V4Metadata, OpenRequest as V4OpenRequest,
    ProbeOutcome as V4ProbeOutcome, ProbeResult as V4ProbeResult,
    RawStreamMetadataContract as V4RawStreamMetadataContract,
    RawStreamMetadataField as V4RawStreamMetadataField,
    RawStreamMetadataType as V4RawStreamMetadataType, Session as V4Session, Stream as V4Stream,
};
pub use environment_v4::{
    AutomaticLivenessPolicy as V4AutomaticLivenessPolicy, EnvironmentError, ResourceLimits,
    TransportEnvironmentOptions, TrustedTimeProfile, TrustedTimeSample, TrustedTimeSource,
};
pub use namespace_v4::verifier::NamespaceTrustRoot as V4NamespaceTrustRoot;
pub use pool_v4::admission::{
    SQLiteAdmissionAuthority as V4SQLiteAdmissionAuthority,
    SQLiteAdmissionBinding as V4SQLiteAdmissionBinding,
};
pub use proxy_server::{ProxyErrorReporter, ProxyServer, ProxyServerError, ProxyServerOptions};
pub use session_handlers::{
    AcceptedSession, HandlerRegistrationError, NotificationHandler, RpcHandler, RpcHandlers,
    SessionHandlerOptions, SessionHandlers, StreamHandler, StreamHandlerOptions,
    StreamHandlerRegistrar, StreamHandlers,
};
pub use transport::{
    ByteStream, IncomingStream, JsonObject, NotificationSubscription, RpcCallError, RpcError,
    RpcPeer, RpcPeerExt, Session, SessionError, SessionTermination, StreamMetadata,
    StreamMetadataError, UnreliableMessageChannel, UnreliableMessageError,
    UnreliableMessageErrorCode, UnreliableSendOutcome,
};
pub use tunnel_runtime_v3::{
    RuntimeAuthorizationRequest, TunnelAdmissionOptions, TunnelAuthorizationError,
    TunnelAuthorizationResponse, TunnelAuthorizer, TunnelRuntime, TunnelRuntimeError,
    TunnelRuntimeOptions,
};
#[cfg(test)]
#[path = "idna_v3_integration_tests.rs"]
mod idna_v3_integration_tests;

#[cfg(test)]
#[path = "open_v3_integration_tests.rs"]
mod open_v3_integration_tests;

#[cfg(test)]
#[path = "raw_quic_v3_integration_tests.rs"]
mod raw_quic_v3_integration_tests;

#[cfg(test)]
#[path = "session_v3_integration_tests.rs"]
mod session_v3_integration_tests;

#[cfg(test)]
#[path = "transport_v3_crypto_integration_tests.rs"]
mod transport_v3_crypto_integration_tests;

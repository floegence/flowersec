#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![doc = include_str!("../README.md")]

//! Native Rust support for Flowersec v3 secure direct and tunneled sessions.
//!
//! Maintained callers use the opaque [`Artifact`], one-shot [`connect`],
//! optional long-lived [`ConnectionController`], and carrier-neutral
//! [`Session`], direct [`Acceptor`], and opaque [`TunnelRuntime`] contracts.
//! Legacy v2 and issuer surfaces live under [`v2`]. Carrier
//! configuration, candidates, wire formats, and cryptographic state are
//! crate-private.
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
//! ```compile_fail
//! use flowersec::raw_quic_v2::RawQuicListener;
//! ```
//!
//! ```compile_fail
//! use flowersec::protocol_v2::RecordMaterialV2;
//! ```
//!
//! ```compile_fail
//! use flowersec::session_v2::SessionConfigV2;
//! ```
//!
//! ```compile_fail
//! use flowersec::transport_v2::CarrierSessionV2;
//! ```
//!
//! ```compile_fail
//! use flowersec::artifact_v2::Artifact;
//! ```
//!
//! The legacy issuer API requires an explicit `v2` namespace.
//!
//! ```compile_fail
//! use flowersec::controlplane::Issuer;
//! ```
//!
mod acceptor_v2;
mod acceptor_v3;
mod admission_v2;
mod artifact_v2;
mod artifact_v3;
mod connection_controller;
mod connection_controller_v2;
mod connector_v2;
mod connector_v3;
mod controlplane;
mod crypto_v2;
mod crypto_v3;
mod idna_v2;
mod idna_v3;
mod native_runtime_v2;
mod protocol_v2;
mod protocol_v3;
mod proxy_server;
mod raw_quic_v2;
mod raw_quic_v3;
mod session_handlers;
mod session_v2;
mod session_v3;
mod tls_v3;
mod transport_v2;
mod transport_v3;
mod tunnel_runtime_v2;
mod tunnel_runtime_v3;
mod websocket_v2;

#[cfg(feature = "__flowersec_internal_fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// Exercise the final admission parser bounds without exposing wire types.
    pub fn parse_admission(data: &[u8]) {
        crate::admission_v2::fuzz_parse(data);
    }

    /// Exercise the final handshake, control-record, encrypted-header, and
    /// unreliable-message parsers without exposing their wire types.
    pub fn parse_protocol(data: &[u8]) {
        crate::protocol_v2::fuzz_parse(data);
    }
}

#[cfg(test)]
mod defaults_contract;
pub use acceptor_v3::{
    AcceptError, AcceptErrorCode, Acceptor, AcceptorOptions, WebSocketAcceptorOptions,
};
pub use artifact_v3::{
    ArtifactErrorV3 as ArtifactError, ArtifactErrorV3, ArtifactLeaseV3 as ArtifactLease,
    ArtifactLeaseV3, ArtifactSpendErrorV3 as ArtifactSpendError, ArtifactSpendErrorV3,
    ArtifactV3 as Artifact, ArtifactV3,
};
pub use connection_controller::{
    ArtifactSource, ArtifactSourceError, ConnectionController, ConnectionControllerOptions,
    ConnectionFailure, ConnectionSnapshot, ConnectionState, RetryDisposition,
};
pub use connector_v3::{
    ConnectError, ConnectErrorCode, ConnectorOptions, connect_v3 as connect,
    connect_v3_with_cancellation as connect_with_cancellation,
};
pub use connector_v3::{connect_v3, connect_v3_with_cancellation};
pub use proxy_server::{ProxyErrorReporter, ProxyServer, ProxyServerError, ProxyServerOptions};
pub use session_handlers::{
    AcceptedSession, HandlerRegistrationError, NotificationHandler, RpcHandler, RpcHandlers,
    SessionHandlerOptions, SessionHandlers, StreamHandler, StreamHandlerOptions,
    StreamHandlerRegistrar, StreamHandlers,
};
pub use transport_v2::{
    ByteStream, IncomingStream, JsonObject, NotificationSubscription, RpcCallError, RpcError,
    RpcPeer, RpcPeerExt, Session, SessionError, SessionTermination, StreamMetadata,
    StreamMetadataError, UnreliableMessageChannel, UnreliableMessageError, UnreliableSendOutcome,
};
pub use tunnel_runtime_v3::{
    RuntimeAuthorizationRequest, TunnelAdmissionOptions, TunnelAuthorizationError,
    TunnelAuthorizationResponse, TunnelAuthorizer, TunnelRuntime, TunnelRuntimeError,
    TunnelRuntimeOptions,
};
/// Explicit legacy v2 public surfaces. v2 is never selected implicitly by the
/// unversioned API.
pub mod v2 {
    pub use crate::acceptor_v2::{
        AcceptError, AcceptErrorCode, Acceptor, AcceptorOptions, WebSocketAcceptorOptions,
    };
    pub use crate::artifact_v2::{Artifact, ArtifactError, ArtifactLease, ArtifactSpendError};
    pub use crate::connection_controller_v2::{
        ArtifactSourceErrorV2 as ArtifactSourceError, ArtifactSourceV2 as ArtifactSource,
        ConnectionControllerOptionsV2 as ConnectionControllerOptions,
        ConnectionControllerV2 as ConnectionController, ConnectionFailureV2 as ConnectionFailure,
        ConnectionSnapshotV2 as ConnectionSnapshot, ConnectionStateV2 as ConnectionState,
        RetryDispositionV2 as RetryDisposition,
    };
    pub use crate::connector_v2::{ConnectError, ConnectErrorCode};
    pub use crate::controlplane::{
        AuthorizationRecord, ControlPlaneError, DirectIssueOptions, EndpointSet, IssuedArtifact,
        IssuedTunnelPair, Issuer, RuntimeAuthorizationRequest, RuntimeAuthorizationResponse,
        SessionOptions, TunnelAuthorizationResponse, TunnelIssueOptions, allow_tunnel_runtime,
        reject_runtime, reject_tunnel_runtime, retry_runtime, retry_tunnel_runtime,
    };
    pub use crate::native_runtime_v2::{ConnectorOptions, connect, connect_with_cancellation};
    pub use crate::transport_v2::Session;
    pub use crate::tunnel_runtime_v2::{
        TunnelAdmissionOptions, TunnelAuthorizer, TunnelRuntime, TunnelRuntimeError,
        TunnelRuntimeOptions,
    };
}

/// Strict Flowersec v3 artifact and connector surface.
pub mod v3 {
    pub use crate::{
        AcceptError, AcceptErrorCode, Acceptor, AcceptorOptions, Artifact, ArtifactError,
        ArtifactLease, ArtifactSource, ArtifactSourceError, ArtifactSpendError, ConnectError,
        ConnectErrorCode, ConnectionController, ConnectionControllerOptions, ConnectionFailure,
        ConnectionSnapshot, ConnectionState, ConnectorOptions, RetryDisposition,
        RuntimeAuthorizationRequest, Session, TunnelAdmissionOptions, TunnelAuthorizationError,
        TunnelAuthorizationResponse, TunnelAuthorizer, TunnelRuntime, TunnelRuntimeError,
        TunnelRuntimeOptions, WebSocketAcceptorOptions, connect, connect_with_cancellation,
    };
}

#[cfg(test)]
#[path = "idna_v2_integration_tests.rs"]
mod idna_v2_integration_tests;

#[cfg(test)]
#[path = "idna_v3_integration_tests.rs"]
mod idna_v3_integration_tests;

#[cfg(test)]
#[path = "open_v2_integration_tests.rs"]
mod open_v2_integration_tests;

#[cfg(test)]
#[path = "open_v3_integration_tests.rs"]
mod open_v3_integration_tests;

#[cfg(test)]
#[path = "raw_quic_v2_integration_tests.rs"]
mod raw_quic_v2_integration_tests;

#[cfg(test)]
#[path = "raw_quic_v3_integration_tests.rs"]
mod raw_quic_v3_integration_tests;

#[cfg(test)]
#[path = "session_v2_integration_tests.rs"]
mod session_v2_integration_tests;

#[cfg(test)]
#[path = "session_v3_integration_tests.rs"]
mod session_v3_integration_tests;

#[cfg(test)]
#[path = "transport_v2_crypto_integration_tests.rs"]
mod transport_v2_crypto_integration_tests;

#[cfg(test)]
#[path = "transport_v3_crypto_integration_tests.rs"]
mod transport_v3_crypto_integration_tests;

#[cfg(test)]
mod security_negative_vectors;

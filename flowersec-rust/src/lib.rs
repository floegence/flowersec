#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![doc = include_str!("../README.md")]

//! Native Rust support for Flowersec secure direct and tunneled sessions over Transport v3.
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
mod artifact_v3;
mod connection_controller;
mod connector_v3;
mod crypto_v3;
mod idna_v3;
mod protocol_v3;
mod proxy_server;
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
pub use artifact_v3::{
    ArtifactErrorV3 as ArtifactError, ArtifactLeaseV3 as ArtifactLease,
    ArtifactSpendErrorV3 as ArtifactSpendError, ArtifactV3 as Artifact,
};
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

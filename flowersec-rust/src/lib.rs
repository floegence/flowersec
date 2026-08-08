#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Native Rust support for Flowersec v2.2 secure direct and tunneled sessions.
//!
//! Maintained callers use the opaque [`Artifact`], one-shot [`connect`],
//! optional long-lived [`ConnectionController`], and carrier-neutral
//! [`Session`] contracts. Native runtimes accept direct sessions through
//! [`Acceptor`] without receiving carrier or wire objects. Carrier
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
mod acceptor_v2;
mod admission_v2;
mod artifact_v2;
mod connection_controller;
mod connector_v2;
mod crypto_v2;
mod idna_v2;
mod native_runtime_v2;
mod protocol_v2;
mod raw_quic_v2;
mod session_handlers;
mod session_v2;
mod transport_v2;

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
pub use acceptor_v2::{AcceptError, AcceptErrorCode, Acceptor, AcceptorOptions};
pub use artifact_v2::{Artifact, ArtifactError, ArtifactLease, ArtifactSpendError};
pub use connection_controller::{
    ArtifactSource, ArtifactSourceError, ConnectionController, ConnectionControllerOptions,
    ConnectionFailure, ConnectionSnapshot, ConnectionState, RetryDisposition,
};
pub use connector_v2::{ConnectError, ConnectErrorCode};
pub use native_runtime_v2::{ConnectorOptions, connect, connect_with_cancellation};
pub use session_handlers::{
    AcceptedSession, HandlerRegistrationError, RpcHandler, SessionHandlerOptions, SessionHandlers,
    StreamHandler,
};
pub use transport_v2::{
    ByteStream, IncomingStream, JsonObject, RpcCallError, RpcError, RpcPeer, RpcPeerExt, Session,
    SessionError, SessionTermination, StreamMetadata, StreamMetadataError,
    UnreliableMessageChannel, UnreliableMessageError, UnreliableSendOutcome,
};

#[cfg(test)]
#[path = "idna_v2_integration_tests.rs"]
mod idna_v2_integration_tests;

#[cfg(test)]
#[path = "open_v2_integration_tests.rs"]
mod open_v2_integration_tests;

#[cfg(test)]
#[path = "raw_quic_v2_integration_tests.rs"]
mod raw_quic_v2_integration_tests;

#[cfg(test)]
#[path = "session_v2_integration_tests.rs"]
mod session_v2_integration_tests;

#[cfg(test)]
#[path = "transport_v2_crypto_integration_tests.rs"]
mod transport_v2_crypto_integration_tests;

#[cfg(test)]
mod security_negative_vectors;

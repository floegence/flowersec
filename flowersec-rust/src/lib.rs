#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Native Rust support for Flowersec v2 secure direct and tunneled sessions.
//!
//! Maintained callers use the opaque [`Artifact`], [`Connector`], and
//! carrier-neutral [`Session`] contracts. Carrier configuration, candidates,
//! wire formats, and cryptographic state are crate-private.
//!
//! ```compile_fail
//! use flowersec::framing;
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

mod artifact_v2;
mod connector_v2;
mod crypto_v2;
mod idna_v2;
mod protocol_v2;
mod raw_quic_v2;
mod session_v2;
mod transport_v2;

#[cfg(test)]
mod defaults_contract;

pub use artifact_v2::{Artifact, ArtifactError, ArtifactLease, ArtifactSpendError};
pub use connector_v2::{ConnectError, ConnectErrorCode, Connector, ConnectorOptions};
pub use transport_v2::{
    ByteStreamV2 as ByteStream, IncomingStreamV2 as IncomingStream, JsonObjectV2 as JsonObject,
    RpcPeerV2 as RpcPeer, SessionError, SessionV2 as Session, StreamTerminalError,
    UnreliableMessageChannelV2 as UnreliableMessageChannel, UnreliableMessageError,
    UnreliableSendOutcome,
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

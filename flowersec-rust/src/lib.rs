#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Native Rust support for Flowersec v2 secure direct and tunneled sessions.
//!
//! Maintained callers use the opaque artifact, [`Connector`], and [`Session`]
//! contracts. The legacy framing module is not part of the v2 crate.
//!
//! ```compile_fail
//! use flowersec::framing;
//! ```

pub mod artifact_v2;
mod connector_v2;
mod crypto_v2;
pub mod idna_v2;
pub mod protocol_v2;
pub mod raw_quic_v2;
pub mod session_v2;
pub mod transport_v2;

#[cfg(test)]
mod defaults_contract;

pub use connector_v2::{ConnectError, ConnectErrorCode, Connector, ConnectorOptions};
pub use transport_v2::SessionV2 as Session;

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Native Rust support for Flowersec secure direct and tunneled sessions.

pub mod artifact;
pub mod artifact_v2;
pub mod client;
mod connector_v2;
pub mod controlplane;
pub mod defaults;
pub mod e2ee;
pub mod endpoint;
pub mod error;
pub mod framing;
#[path = "gen/mod.rs"]
pub mod generated;
pub mod idna_v2;
pub mod observability;
pub mod protocol_v2;
pub mod proxy;
pub mod raw_quic_v2;
pub mod reconnect;
pub mod rpc;
pub mod session_v2;
pub mod streamhello;
pub mod streamio;
pub mod transport;
pub mod transport_security;
pub mod transport_v2;
pub mod yamux;

pub use artifact::{ConnectArtifact, CorrelationContext, CorrelationKv, ScopeMetadataEntry};
pub use client::{Client, ConnectOptions, connect, connect_direct, connect_tunnel};
pub use connector_v2::{ConnectError, ConnectErrorCode, Connector, ConnectorOptions};
pub use error::{ErrorCode, FlowersecError, Path, Stage};
pub use transport_v2::SessionV2 as Session;

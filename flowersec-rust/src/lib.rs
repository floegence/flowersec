#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Native Rust support for Flowersec secure direct and tunneled sessions.

pub mod artifact;
pub mod client;
pub mod controlplane;
pub mod defaults;
pub mod e2ee;
pub mod endpoint;
pub mod error;
pub mod framing;
#[path = "gen/mod.rs"]
pub mod generated;
pub mod observability;
pub mod proxy;
pub mod reconnect;
pub mod rpc;
pub mod streamhello;
pub mod streamio;
pub mod transport;
pub mod transport_security;
pub mod yamux;

pub use artifact::{ConnectArtifact, CorrelationContext, CorrelationKv, ScopeMetadataEntry};
pub use client::{Client, ConnectOptions, connect, connect_direct, connect_tunnel};
pub use error::{ErrorCode, FlowersecError, Path, Stage};

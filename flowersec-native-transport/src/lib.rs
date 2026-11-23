#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Flowersec-owned native carrier primitives shared by Rust and Node runtimes.
//!
//! The public boundary intentionally exposes only Flowersec types. Transport
//! implementation types remain private to their carrier modules.

#[allow(dead_code, unused_imports, missing_debug_implementations)]
mod quic_proto;
#[allow(dead_code, unused_imports, missing_debug_implementations)]
mod quic_provider;
mod raw_quic;
pub mod webtransport;

pub use raw_quic::{
    ALPN_DIRECT, ALPN_TUNNEL, ApplicationClose, Cancellation, DatagramSendOutcome, PathProfile,
    RawQuicClientConfig, RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig,
    RawQuicSession, RawQuicStream,
};

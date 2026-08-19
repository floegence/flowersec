#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Flowersec-owned native carrier primitives shared by Rust and Node runtimes.
//!
//! The public boundary intentionally exposes only Flowersec types. Transport
//! implementation types remain private to their carrier modules.

mod raw_quic;

pub use raw_quic::{
    ALPN_DIRECT, ALPN_DIRECT_V3, ALPN_TUNNEL, ALPN_TUNNEL_V3, ApplicationClose, Cancellation,
    DatagramSendOutcome, PathProfile, ProtocolVersion, RawQuicClientConfig, RawQuicError,
    RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession, RawQuicStream,
};

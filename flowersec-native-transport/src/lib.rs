#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Flowersec-owned native carrier primitives shared by Rust and Node runtimes.
//!
//! The public boundary intentionally exposes only Flowersec types. Transport
//! implementation types remain private to their carrier modules.

#[allow(missing_debug_implementations)]
mod quic_proto;
#[allow(missing_debug_implementations)]
mod quic_provider;

mod raw_quic;

pub use raw_quic::{
    ALPN_DIRECT_V4, ALPN_TUNNEL_V4, ApplicationClose, Cancellation, DatagramSendOutcome,
    DatagramSubmission, NativeDirectionFailure, PathProfile, RawQuicClientConfig, RawQuicError,
    RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession, RawQuicStream,
};

mod web_transport;
pub use web_transport::{
    WebTransportConfig, WebTransportListener, WebTransportRequest, WebTransportSession,
};

mod preparation_budget;
pub use preparation_budget::PreparationLimits as PreparationCapacity;
pub use preparation_budget::{
    CandidatePreparationBudget, PreparationBudget, PreparationBudgetError, PreparationLimits,
    PreparationUsage,
};

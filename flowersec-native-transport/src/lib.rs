#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Flowersec-owned native carrier primitives shared by Rust and Node runtimes.
//!
//! The public boundary intentionally exposes only Flowersec types. Transport
//! implementation types remain private to their carrier modules.

mod raw_quic;
pub mod webtransport;

struct HandshakeQueue<T>(tokio::sync::Mutex<tokio::task::JoinSet<T>>);

impl<T: Send + 'static> HandshakeQueue<T> {
    fn new() -> Self {
        Self(tokio::sync::Mutex::new(tokio::task::JoinSet::new()))
    }

    async fn accept<F: std::future::Future<Output = T> + Send + 'static>(
        &self,
        endpoint: &quinn::Endpoint,
        handshake: impl Fn(quinn::Incoming) -> F,
    ) -> Option<T> {
        let mut pending = self.0.lock().await;
        loop {
            tokio::select! {
                biased;
                result = pending.join_next(), if !pending.is_empty() => {
                    if let Some(Ok(session)) = result { return Some(session); }
                }
                incoming = endpoint.accept(), if pending.len() < 64 => {
                    pending.spawn(handshake(incoming?));
                }
            }
        }
    }

    async fn shutdown(&self) {
        self.0.lock().await.shutdown().await;
    }
}

pub use raw_quic::{
    ALPN_DIRECT, ALPN_TUNNEL, ApplicationClose, Cancellation, DatagramSendOutcome, PathProfile,
    RawQuicClientConfig, RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig,
    RawQuicSession, RawQuicStream,
};

use crate::{
    connector_v3::CandidateFailureV3,
    tls_v3::NativeTlsPolicyV3,
    transport_v3::{
        CarrierKind, CarrierSessionV3, CarrierStreamV3, CarrierUnreliableMessageErrorV3,
        carrier_inbound_stream_limit_v3,
    },
};
use async_trait::async_trait;
use bytes::Bytes;
use flowersec_native_transport::webtransport as native;
use std::{
    fmt, io,
    net::{SocketAddr, UdpSocket},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;

pub use native::WebTransportListenerPolicy;
pub(crate) use native::{DIRECT, TUNNEL, valid_origin};

#[derive(Debug)]
pub(crate) struct Listener(native::Listener);
impl Listener {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        socket: UdpSocket,
        bind: SocketAddr,
        chain: Vec<Vec<u8>>,
        key: Vec<u8>,
        policy: WebTransportListenerPolicy,
        path: &'static str,
        streams: u16,
        timeout: Duration,
    ) -> io::Result<Self> {
        let capacity = carrier_inbound_stream_limit_v3(streams).map_err(io::Error::other)?;
        native::Listener::new(socket, bind, chain, key, policy, path, capacity, timeout).map(Self)
    }
    pub(crate) fn local_address(&self) -> io::Result<SocketAddr> {
        self.0.local_address()
    }
    pub(crate) fn ingress_url(&self) -> String {
        self.0.ingress_url()
    }
    pub(crate) async fn accept(&self) -> io::Result<(Arc<dyn CarrierSessionV3>, SocketAddr)> {
        let (inner, peer) = self.0.accept().await?;
        Ok((
            Arc::new(Carrier {
                inner,
                admission: Mutex::new(None),
            }),
            peer,
        ))
    }
    pub(crate) fn abort(&self) {
        self.0.abort()
    }
    pub(crate) async fn close(&self) {
        self.0.close().await
    }
}
pub(crate) async fn dial(
    url: &str,
    origin: &str,
    policy: NativeTlsPolicyV3,
    capacity: u32,
    deadline: tokio::time::Instant,
) -> Result<Arc<dyn CarrierSessionV3>, CandidateFailureV3> {
    let trust = match policy {
        NativeTlsPolicyV3::Ca { certificates } => native::ClientTrust::Ca(
            certificates
                .iter()
                .map(|item| item.as_ref().to_vec())
                .collect(),
        ),
        NativeTlsPolicyV3::Pin { active_leaf_hashes } => {
            native::ClientTrust::Pin(active_leaf_hashes)
        }
    };
    let inner = native::dial_until(url, origin, trust, capacity, deadline)
        .await
        .map_err(|_| CandidateFailureV3::Timeout)?
        .map_err(|error| match error {
            native::DialFailure::InvalidArtifact => CandidateFailureV3::InvalidArtifact,
            native::DialFailure::Security => CandidateFailureV3::Security,
            native::DialFailure::Connection => CandidateFailureV3::Connection,
        })?;
    let admission = inner
        .accept_stream()
        .await
        .map_err(|_| CandidateFailureV3::Connection)?;
    Ok(Arc::new(Carrier {
        inner,
        admission: Mutex::new(Some(admission)),
    }))
}
struct Carrier {
    inner: Arc<native::Carrier>,
    admission: Mutex<Option<Arc<native::Stream>>>,
}
#[cfg(test)]
pub(crate) fn session_test_carrier(inner: Arc<native::Carrier>) -> Arc<dyn CarrierSessionV3> {
    Arc::new(Carrier {
        inner,
        admission: Mutex::new(None),
    })
}
impl fmt::Debug for Carrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WebTransportCarrier { <opaque> }")
    }
}
#[async_trait]
impl CarrierSessionV3 for Carrier {
    fn kind(&self) -> CarrierKind {
        CarrierKind::WebTransport
    }
    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(self.inner.open_stream().await?)
    }
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(self.inner.accept_stream().await?)
    }
    async fn dialer_admission(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        Ok(self
            .admission
            .lock()
            .await
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?)
    }
    fn unreliable_message_max_size(&self) -> Option<usize> {
        self.inner.unreliable_message_max_size()
    }
    async fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV3> {
        self.inner
            .send_unreliable_message(payload)
            .await
            .map_err(message_error)
    }
    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
        self.inner
            .receive_unreliable_message()
            .await
            .map_err(message_error)
    }
    async fn close(&self) -> io::Result<()> {
        self.inner.close().await
    }
    fn abort(&self) {
        self.inner.abort()
    }
    async fn wait_termination(&self) {
        self.inner.wait_termination().await
    }
    async fn wait_tunnel_release(&self) -> io::Result<()> {
        self.inner.wait_termination().await;
        if self
            .inner
            .peer_application_close()
            .is_some_and(|close| close.code == 1 && close.reason == "session closed")
        {
            Ok(())
        } else {
            Err(io::ErrorKind::ConnectionReset.into())
        }
    }
    async fn close_tunnel(&self, normal: bool) -> io::Result<()> {
        let (code, reason) = if normal {
            (1, "session closed")
        } else {
            (6, "session close failed")
        };
        self.inner.close_with_reason(code, reason).await
    }
    async fn wait_shutdown(&self) {
        self.inner.wait_shutdown().await
    }
}
fn message_error(error: native::MessageError) -> CarrierUnreliableMessageErrorV3 {
    match error {
        native::MessageError::Unavailable => CarrierUnreliableMessageErrorV3::Unavailable,
        native::MessageError::TooLarge => CarrierUnreliableMessageErrorV3::TooLarge,
        native::MessageError::Dropped => CarrierUnreliableMessageErrorV3::Dropped,
        native::MessageError::Closed => CarrierUnreliableMessageErrorV3::Closed,
    }
}
#[async_trait]
impl CarrierStreamV3 for native::Stream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.read(payload).await
    }
    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.write(payload).await
    }
    async fn close_write(&self) -> io::Result<()> {
        self.close_write().await
    }
    async fn close_write_delivered(&self) -> io::Result<()> {
        self.close_write_delivered().await
    }
    async fn stop_sending(&self) -> io::Result<()> {
        self.stop_sending().await
    }
    async fn reset(&self) -> io::Result<()> {
        self.reset().await
    }
    async fn close(&self) -> io::Result<()> {
        self.reset().await
    }
}

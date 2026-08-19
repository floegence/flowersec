//! Rust SDK adapter for the shared Flowersec native raw QUIC driver.

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use flowersec_native_transport::{
    Cancellation, DatagramSendOutcome, PathProfile, RawQuicClientConfig as NativeClientConfig,
    RawQuicError as NativeError, RawQuicLimits as NativeLimits, RawQuicListener as NativeListener,
    RawQuicServerConfig as NativeServerConfig, RawQuicSession as NativeSession,
    RawQuicStream as NativeStream,
};

#[cfg(test)]
pub(crate) const RAW_QUIC_INITIAL_RTT: Duration = Duration::from_millis(250);

pub type RawQuicPathProfile = PathProfile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawQuicLimits {
    pub max_inbound_bidirectional_streams: u32,
    pub stream_receive_window: u64,
    pub connection_receive_window: u64,
    pub handshake_idle_timeout: Duration,
    pub max_idle_timeout: Duration,
    pub keep_alive_interval: Duration,
}

impl RawQuicLimits {
    pub(crate) fn for_session_v2(
        logical_max: u16,
        handshake_idle_timeout: Duration,
    ) -> Result<Self, RawQuicError> {
        Self {
            handshake_idle_timeout,
            ..Self::default()
        }
        .with_session_v2_logical_stream_limit(logical_max)
    }

    pub fn with_session_v2_logical_stream_limit(
        mut self,
        logical_max: u16,
    ) -> Result<Self, RawQuicError> {
        self.max_inbound_bidirectional_streams =
            crate::transport_v2::carrier_inbound_stream_limit_v2(logical_max).map_err(|_| {
                RawQuicError::InvalidLimits(
                    "logical max inbound streams must map to an exact carrier limit",
                )
            })?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(self) -> Result<(), RawQuicError> {
        self.native().map(|_| ())
    }

    fn native(self) -> Result<NativeLimits, RawQuicError> {
        let limits = NativeLimits {
            max_inbound_bidirectional_streams: self.max_inbound_bidirectional_streams,
            stream_receive_window: self.stream_receive_window,
            connection_receive_window: self.connection_receive_window,
            handshake_idle_timeout: self.handshake_idle_timeout,
            max_idle_timeout: self.max_idle_timeout,
            keep_alive_interval: self.keep_alive_interval,
        };
        limits
            .validate()
            .map_err(|_| RawQuicError::InvalidLimits("invalid shared raw QUIC resource policy"))?;
        Ok(limits)
    }
}

impl Default for RawQuicLimits {
    fn default() -> Self {
        let limits = NativeLimits::default();
        Self {
            max_inbound_bidirectional_streams: limits.max_inbound_bidirectional_streams,
            stream_receive_window: limits.stream_receive_window,
            connection_receive_window: limits.connection_receive_window,
            handshake_idle_timeout: limits.handshake_idle_timeout,
            max_idle_timeout: limits.max_idle_timeout,
            keep_alive_interval: limits.keep_alive_interval,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RawQuicError {
    #[error("invalid raw QUIC limits: {0}")]
    InvalidLimits(&'static str),
    #[error("invalid raw QUIC trust configuration: {0}")]
    InvalidTrust(String),
    #[error("invalid raw QUIC certificate chain: {0}")]
    InvalidCertificate(String),
    #[error("invalid raw QUIC TLS 1.3 configuration: {0}")]
    InvalidTls(String),
    #[error("raw QUIC endpoint failed: {0}")]
    Endpoint(#[source] io::Error),
    #[error("raw QUIC listener is closed")]
    ListenerClosed,
    #[error("raw QUIC connect failed: {0}")]
    Connect(String),
    #[error("raw QUIC handshake failed: {0}")]
    Handshake(String),
    #[error("invalid negotiated raw QUIC ALPN")]
    InvalidNegotiatedAlpn,
    #[error("raw QUIC stream operation failed: {0}")]
    Stream(String),
    #[error("raw QUIC active migration is unavailable for this session")]
    MigrationUnavailable,
    #[error("raw QUIC active migration failed: {0}")]
    Migration(#[source] io::Error),
    #[error("invalid raw QUIC application close error")]
    InvalidApplicationError,
}

#[derive(Clone)]
pub struct RawQuicClientConfig {
    profile: RawQuicPathProfile,
    limits: RawQuicLimits,
    inner: NativeClientConfig,
}

impl RawQuicClientConfig {
    pub fn new(
        profile: RawQuicPathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        let inner = NativeClientConfig::new(profile, trust_roots_der, limits.native()?)
            .map_err(map_native_error)?;
        Ok(Self {
            profile,
            limits,
            inner,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_datagram_send_buffer_for_test(
        mut self,
        bytes: usize,
    ) -> Result<Self, RawQuicError> {
        self.inner = self
            .inner
            .with_datagram_send_buffer_size_for_test(bytes)
            .map_err(map_native_error)?;
        Ok(self)
    }
}

impl fmt::Debug for RawQuicClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicClientConfig")
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

pub(crate) struct RawQuicServerConfig {
    profile: RawQuicPathProfile,
    limits: RawQuicLimits,
    inner: NativeServerConfig,
}

impl RawQuicServerConfig {
    pub(crate) fn new(
        profile: RawQuicPathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        let inner = NativeServerConfig::new(
            profile,
            certificate_chain_der,
            private_key_der,
            limits.native()?,
        )
        .map_err(map_native_error)?;
        Ok(Self {
            profile,
            limits,
            inner,
        })
    }
}

impl fmt::Debug for RawQuicServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicServerConfig")
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

pub(crate) struct RawQuicListener {
    inner: NativeListener,
    profile: RawQuicPathProfile,
}

impl RawQuicListener {
    pub(crate) fn bind(
        address: SocketAddr,
        config: RawQuicServerConfig,
    ) -> Result<Self, RawQuicError> {
        let profile = config.profile;
        let inner = NativeListener::bind(address, config.inner).map_err(map_native_error)?;
        Ok(Self { inner, profile })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_address().map_err(native_error_to_io)
    }

    pub(crate) async fn accept(&self) -> Result<RawQuicSession, RawQuicError> {
        self.inner
            .accept(&Cancellation::new())
            .await
            .map(RawQuicSession::new)
            .map_err(map_native_error)
    }
}

impl fmt::Debug for RawQuicListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicListener")
            .field("local_addr", &self.local_addr().ok())
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawQuicApplicationError {
    pub code: u64,
    pub reason: String,
}

#[derive(Clone)]
pub struct RawQuicSession {
    inner: NativeSession,
}

impl RawQuicSession {
    fn new(inner: NativeSession) -> Self {
        Self { inner }
    }

    pub async fn dial(
        local_address: SocketAddr,
        remote_address: SocketAddr,
        server_name: &str,
        config: RawQuicClientConfig,
    ) -> Result<Self, RawQuicError> {
        NativeSession::dial_from(
            local_address,
            remote_address,
            server_name.to_owned(),
            config.inner,
            &Cancellation::new(),
        )
        .await
        .map(Self::new)
        .map_err(map_native_error)
    }

    #[cfg(test)]
    pub const fn negotiated_profile(&self) -> RawQuicPathProfile {
        self.inner.profile()
    }

    #[cfg(test)]
    pub(crate) fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.inner.local_address().map_err(map_native_error)
    }

    #[cfg(test)]
    pub(crate) fn migrate_local_address(
        &self,
        address: SocketAddr,
    ) -> Result<SocketAddr, RawQuicError> {
        self.inner
            .migrate_local_address(address)
            .map_err(map_native_error)
    }

    pub(crate) fn peer_address(&self) -> SocketAddr {
        self.inner.peer_address()
    }

    #[cfg(test)]
    pub async fn open_stream(&self) -> Result<RawQuicStream, RawQuicError> {
        self.open_stream_inner()
            .await
            .map_err(|error| RawQuicError::Stream(error.to_string()))
    }

    async fn open_stream_inner(&self) -> io::Result<RawQuicStream> {
        self.inner
            .open_stream_io(&Cancellation::new())
            .await
            .map(RawQuicStream::new)
    }

    #[cfg(test)]
    pub async fn accept_stream(&self) -> Result<RawQuicStream, RawQuicError> {
        self.accept_stream_inner()
            .await
            .map_err(|error| RawQuicError::Stream(error.to_string()))
    }

    async fn accept_stream_inner(&self) -> io::Result<RawQuicStream> {
        self.inner
            .accept_stream_io(&Cancellation::new())
            .await
            .map(RawQuicStream::new)
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        use crate::transport_v2::CarrierUnreliableMessageErrorV2 as Error;

        match self.inner.send_datagram(payload.to_vec()) {
            DatagramSendOutcome::Accepted => Ok(()),
            DatagramSendOutcome::DroppedBudget => Err(Error::Dropped),
            DatagramSendOutcome::DroppedCarrier => Err(Error::Closed),
            DatagramSendOutcome::TooLarge => Err(Error::TooLarge),
            DatagramSendOutcome::Unavailable => Err(Error::Unavailable),
        }
    }

    async fn receive_unreliable_message(
        &self,
    ) -> Result<Bytes, crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        self.inner
            .receive_datagram(&Cancellation::new())
            .await
            .map(Bytes::from)
            .map_err(|_| crate::transport_v2::CarrierUnreliableMessageErrorV2::Closed)
    }

    #[cfg(test)]
    pub fn close_with_error(
        &self,
        application_error: RawQuicApplicationError,
    ) -> Result<(), RawQuicError> {
        self.inner
            .close(flowersec_native_transport::ApplicationClose {
                code: application_error.code,
                reason: application_error.reason,
            })
            .map_err(map_native_error)
    }

    pub fn close(&self) {
        self.inner.abort();
    }
}

impl fmt::Debug for RawQuicSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicSession")
            .field("profile", &self.inner.profile())
            .field("remote_address", &self.inner.peer_address())
            .field("local_address", &self.inner.local_address().ok())
            .finish_non_exhaustive()
    }
}

pub struct RawQuicStream {
    inner: NativeStream,
}

impl RawQuicStream {
    fn new(inner: NativeStream) -> Self {
        Self { inner }
    }

    pub async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner.read_into(payload, &Cancellation::new()).await
    }

    pub async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner.write_slice(payload, &Cancellation::new()).await
    }

    #[cfg(test)]
    pub async fn write_all(&self, mut payload: &[u8]) -> io::Result<()> {
        while !payload.is_empty() {
            let written = self.write(payload).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "raw QUIC stream accepted no bytes",
                ));
            }
            payload = &payload[written..];
        }
        Ok(())
    }

    pub async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write_io(&Cancellation::new()).await
    }

    async fn wait_write_delivered(&self) -> io::Result<()> {
        self.inner.wait_write_delivered().await
    }

    pub async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await.map_err(native_error_to_io)
    }

    pub async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await.map_err(native_error_to_io)
    }
}

impl fmt::Debug for RawQuicStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

#[async_trait::async_trait]
impl crate::transport_v2::CarrierStreamV2 for RawQuicStream {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        RawQuicStream::read(self, payload).await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        RawQuicStream::write(self, payload).await
    }

    async fn close_write(&self) -> io::Result<()> {
        RawQuicStream::close_write(self).await
    }

    async fn close_write_delivered(&self) -> io::Result<()> {
        RawQuicStream::close_write(self).await?;
        self.wait_write_delivered().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        RawQuicStream::stop_sending(self).await
    }

    async fn reset(&self) -> io::Result<()> {
        RawQuicStream::reset(self).await
    }

    async fn close(&self) -> io::Result<()> {
        self.close_write().await
    }
}

#[async_trait::async_trait]
impl crate::transport_v2::CarrierSessionV2 for RawQuicSession {
    fn kind(&self) -> crate::transport_v2::CarrierKind {
        crate::transport_v2::CarrierKind::RawQuic
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn crate::transport_v2::CarrierStreamV2>> {
        self.open_stream_inner()
            .await
            .map(|stream| Arc::new(stream) as Arc<dyn crate::transport_v2::CarrierStreamV2>)
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn crate::transport_v2::CarrierStreamV2>> {
        self.accept_stream_inner()
            .await
            .map(|stream| Arc::new(stream) as Arc<dyn crate::transport_v2::CarrierStreamV2>)
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        RawQuicSession::unreliable_message_max_size(self)
    }

    async fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        RawQuicSession::send_unreliable_message(self, payload)
    }

    async fn receive_unreliable_message(
        &self,
    ) -> Result<Bytes, crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        RawQuicSession::receive_unreliable_message(self).await
    }

    async fn close(&self) -> io::Result<()> {
        RawQuicSession::close(self);
        Ok(())
    }

    fn abort(&self) {
        RawQuicSession::close(self);
    }
}

fn map_native_error(error: NativeError) -> RawQuicError {
    match error {
        NativeError::InvalidLimits => RawQuicError::InvalidLimits("invalid shared driver limits"),
        NativeError::InvalidTrust => RawQuicError::InvalidTrust("invalid trust roots".into()),
        NativeError::InvalidServerIdentity => {
            RawQuicError::InvalidCertificate("invalid server identity".into())
        }
        NativeError::InvalidTls => RawQuicError::InvalidTls("invalid TLS policy".into()),
        NativeError::Endpoint(error) => RawQuicError::Endpoint(error),
        NativeError::ListenerClosed => RawQuicError::ListenerClosed,
        NativeError::Canceled => RawQuicError::Connect("operation canceled".into()),
        NativeError::NoUsableAddress => RawQuicError::Connect("no usable address".into()),
        NativeError::Connect => RawQuicError::Connect("connection could not start".into()),
        NativeError::Handshake => RawQuicError::Handshake("handshake failed".into()),
        NativeError::Timeout => RawQuicError::Handshake("handshake timed out".into()),
        NativeError::PinMismatch => RawQuicError::Handshake("handshake failed".into()),
        NativeError::PinCertificateInvalid => {
            RawQuicError::InvalidCertificate("invalid certificate".into())
        }
        NativeError::InvalidNegotiatedAlpn => RawQuicError::InvalidNegotiatedAlpn,
        NativeError::Stream => RawQuicError::Stream("stream failed".into()),
        NativeError::MigrationUnavailable => RawQuicError::MigrationUnavailable,
        NativeError::Migration(error) => RawQuicError::Migration(error),
        NativeError::InvalidApplicationClose => RawQuicError::InvalidApplicationError,
        NativeError::DatagramUnavailable | NativeError::Closed | NativeError::InvalidReadSize => {
            RawQuicError::Stream("native carrier operation failed".into())
        }
    }
}

fn native_error_to_io(error: NativeError) -> io::Error {
    match error {
        NativeError::Endpoint(error) | NativeError::Migration(error) => error,
        NativeError::Canceled => io::Error::new(io::ErrorKind::Interrupted, error),
        NativeError::ListenerClosed | NativeError::Closed => {
            io::Error::new(io::ErrorKind::ConnectionAborted, error)
        }
        NativeError::MigrationUnavailable => io::Error::new(io::ErrorKind::Unsupported, error),
        NativeError::InvalidLimits
        | NativeError::InvalidTrust
        | NativeError::InvalidServerIdentity
        | NativeError::PinCertificateInvalid
        | NativeError::InvalidTls
        | NativeError::InvalidApplicationClose
        | NativeError::InvalidReadSize => io::Error::new(io::ErrorKind::InvalidInput, error),
        NativeError::NoUsableAddress
        | NativeError::Connect
        | NativeError::Handshake
        | NativeError::PinMismatch
        | NativeError::InvalidNegotiatedAlpn
        | NativeError::Stream
        | NativeError::DatagramUnavailable => io::Error::other(error),
        NativeError::Timeout => io::Error::new(io::ErrorKind::TimedOut, error),
    }
}

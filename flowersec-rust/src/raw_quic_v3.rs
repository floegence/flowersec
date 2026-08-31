//! Native raw QUIC carrier for the Flowersec v3 ALPN contract.

use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use flowersec_native_transport::{
    Cancellation as NativeCancellation, DatagramSendOutcome, PathProfile as NativePathProfile,
    RawQuicError as NativeError, RawQuicLimits as NativeLimits, RawQuicListener as NativeListener,
    RawQuicServerConfig as NativeServerConfig, RawQuicSession as NativeSession,
    RawQuicStream as NativeStream,
};
use tokio_util::sync::CancellationToken;

use crate::{
    tls_v3::NativeTlsPolicyV3,
    transport_v3::{
        ALPN_DIRECT_V3, ALPN_TUNNEL_V3, CarrierKind, CarrierSessionV3, CarrierStreamV3,
        CarrierUnreliableMessageErrorV3, carrier_inbound_stream_limit_v3,
    },
};

pub(crate) struct RawQuicListenerV3 {
    inner: NativeListener,
}

impl RawQuicListenerV3 {
    pub(crate) fn bind(
        address: SocketAddr,
        profile: NativePathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        max_inbound_streams: u16,
        handshake_timeout: Duration,
    ) -> Result<Self, NativeError> {
        let limits = NativeLimits {
            max_inbound_bidirectional_streams: carrier_inbound_stream_limit_v3(max_inbound_streams)
                .map_err(|_| NativeError::InvalidLimits)?,
            handshake_idle_timeout: handshake_timeout,
            ..NativeLimits::default()
        };
        limits.validate()?;
        let config =
            NativeServerConfig::new(profile, certificate_chain_der, private_key_der, limits)?;
        Ok(Self {
            inner: NativeListener::bind(address, config)?,
        })
    }

    pub(crate) fn local_address(&self) -> Result<SocketAddr, NativeError> {
        self.inner.local_address()
    }

    pub(crate) async fn accept(
        &self,
    ) -> Result<(Arc<dyn CarrierSessionV3>, SocketAddr), NativeError> {
        let native = self.inner.accept(&NativeCancellation::new()).await?;
        let peer = native.peer_address();
        Ok((carrier_from_native_session(native), peer))
    }

    pub(crate) fn abort(&self) {
        self.inner.abort();
    }
}

impl fmt::Debug for RawQuicListenerV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicListenerV3")
            .field("local_address", &self.local_address().ok())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RawQuicDialFailureV3 {
    Invalid,
    Resolve,
    Security,
    Connection,
    Canceled,
    Timeout,
}

pub(crate) async fn dial(
    url: &str,
    tls: &NativeTlsPolicyV3,
    alpn: &[u8],
    inbound_capacity: u32,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
) -> Result<Arc<dyn CarrierSessionV3>, RawQuicDialFailureV3> {
    if !(3..=130).contains(&inbound_capacity) {
        return Err(RawQuicDialFailureV3::Invalid);
    }
    let profile = match alpn {
        ALPN_DIRECT_V3 => NativePathProfile::Direct,
        ALPN_TUNNEL_V3 => NativePathProfile::Tunnel,
        _ => return Err(RawQuicDialFailureV3::Invalid),
    };
    let parsed = url::Url::parse(url).map_err(|_| RawQuicDialFailureV3::Invalid)?;
    if parsed.scheme() != "quic"
        || !matches!(parsed.path(), "" | "/")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(RawQuicDialFailureV3::Invalid);
    }
    let host = parsed
        .host_str()
        .ok_or(RawQuicDialFailureV3::Invalid)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = parsed.port().unwrap_or(443);
    let addresses = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(RawQuicDialFailureV3::Canceled),
        result = tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port))) => {
            result
                .map_err(|_| RawQuicDialFailureV3::Timeout)?
                .map_err(|_| RawQuicDialFailureV3::Resolve)?
                .collect::<Vec<SocketAddr>>()
        }
    };
    if addresses.is_empty() {
        return Err(RawQuicDialFailureV3::Resolve);
    }
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        return Err(RawQuicDialFailureV3::Timeout);
    }
    let config = tls
        .raw_quic_config(profile, inbound_capacity, remaining)
        .map_err(|_| RawQuicDialFailureV3::Invalid)?;
    let native_cancellation = NativeCancellation::new();
    let session = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(RawQuicDialFailureV3::Canceled),
        result = tokio::time::timeout_at(
            deadline,
            NativeSession::dial(addresses, host, config, &native_cancellation),
        ) => result
            .map_err(|_| RawQuicDialFailureV3::Timeout)?
            .map_err(map_native_dial_error)?,
    };
    Ok(Arc::new(RawQuicCarrierV3 { inner: session }))
}

struct RawQuicCarrierV3 {
    inner: NativeSession,
}

pub(crate) fn carrier_from_native_session(inner: NativeSession) -> Arc<dyn CarrierSessionV3> {
    Arc::new(RawQuicCarrierV3 { inner })
}

impl fmt::Debug for RawQuicCarrierV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawQuicCarrierV3 { <opaque> }")
    }
}

#[async_trait]
impl CarrierSessionV3 for RawQuicCarrierV3 {
    fn kind(&self) -> CarrierKind {
        CarrierKind::RawQuic
    }

    fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inner.inbound_bidirectional_stream_capacity()
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner
            .open_stream_io(&NativeCancellation::new())
            .await
            .map(|stream| Arc::new(RawQuicStreamV3 { inner: stream }) as Arc<dyn CarrierStreamV3>)
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV3>> {
        self.inner
            .accept_stream_io(&NativeCancellation::new())
            .await
            .map(|stream| Arc::new(RawQuicStreamV3 { inner: stream }) as Arc<dyn CarrierStreamV3>)
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    async fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV3> {
        match self.inner.send_datagram(payload.to_vec()) {
            DatagramSendOutcome::Accepted => Ok(()),
            DatagramSendOutcome::DroppedBudget => Err(CarrierUnreliableMessageErrorV3::Dropped),
            DatagramSendOutcome::DroppedCarrier => Err(CarrierUnreliableMessageErrorV3::Closed),
            DatagramSendOutcome::TooLarge => Err(CarrierUnreliableMessageErrorV3::TooLarge),
            DatagramSendOutcome::Unavailable => Err(CarrierUnreliableMessageErrorV3::Unavailable),
        }
    }

    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV3> {
        self.inner
            .receive_datagram(&NativeCancellation::new())
            .await
            .map(Bytes::from)
            .map_err(|_| CarrierUnreliableMessageErrorV3::Closed)
    }

    async fn close(&self) -> io::Result<()> {
        self.inner.abort();
        self.inner.wait_termination().await;
        Ok(())
    }

    fn abort(&self) {
        self.inner.abort();
    }
}

struct RawQuicStreamV3 {
    inner: NativeStream,
}

impl fmt::Debug for RawQuicStreamV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawQuicStreamV3 { <opaque> }")
    }
}

#[async_trait]
impl CarrierStreamV3 for RawQuicStreamV3 {
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        self.inner
            .read_into(payload, &NativeCancellation::new())
            .await
    }

    async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        self.inner
            .write_slice(payload, &NativeCancellation::new())
            .await
    }

    async fn close_write(&self) -> io::Result<()> {
        self.inner.close_write_io(&NativeCancellation::new()).await
    }

    async fn close_write_delivered(&self) -> io::Result<()> {
        self.close_write().await?;
        self.inner.wait_write_delivered().await
    }

    async fn stop_sending(&self) -> io::Result<()> {
        self.inner.stop_sending().await.map_err(native_io_error)
    }

    async fn reset(&self) -> io::Result<()> {
        self.inner.reset().await.map_err(native_io_error)
    }

    async fn close(&self) -> io::Result<()> {
        self.reset().await
    }
}

fn map_native_dial_error(error: NativeError) -> RawQuicDialFailureV3 {
    match error {
        NativeError::InvalidLimits
        | NativeError::InvalidTrust
        | NativeError::InvalidServerIdentity
        | NativeError::InvalidTls
        | NativeError::InvalidApplicationClose
        | NativeError::InvalidReadSize => RawQuicDialFailureV3::Invalid,
        NativeError::NoUsableAddress => RawQuicDialFailureV3::Resolve,
        NativeError::Handshake
        | NativeError::PinMismatch
        | NativeError::PinCertificateInvalid
        | NativeError::InvalidNegotiatedAlpn => RawQuicDialFailureV3::Security,
        NativeError::Canceled => RawQuicDialFailureV3::Canceled,
        NativeError::Timeout => RawQuicDialFailureV3::Timeout,
        NativeError::Endpoint(_)
        | NativeError::ListenerClosed
        | NativeError::Connect
        | NativeError::Stream
        | NativeError::DatagramUnavailable
        | NativeError::Closed
        | NativeError::MigrationUnavailable
        | NativeError::Migration(_) => RawQuicDialFailureV3::Connection,
    }
}

fn native_io_error(error: NativeError) -> io::Error {
    match error {
        NativeError::Canceled => io::Error::new(io::ErrorKind::Interrupted, error),
        NativeError::Timeout => io::Error::new(io::ErrorKind::TimedOut, error),
        NativeError::ListenerClosed | NativeError::Closed => {
            io::Error::new(io::ErrorKind::ConnectionAborted, error)
        }
        NativeError::MigrationUnavailable => io::Error::new(io::ErrorKind::Unsupported, error),
        NativeError::InvalidLimits
        | NativeError::InvalidTrust
        | NativeError::InvalidServerIdentity
        | NativeError::InvalidTls
        | NativeError::PinCertificateInvalid
        | NativeError::InvalidApplicationClose
        | NativeError::InvalidReadSize => io::Error::new(io::ErrorKind::InvalidInput, error),
        NativeError::Endpoint(error) | NativeError::Migration(error) => error,
        NativeError::NoUsableAddress
        | NativeError::Connect
        | NativeError::Handshake
        | NativeError::PinMismatch
        | NativeError::InvalidNegotiatedAlpn
        | NativeError::Stream
        | NativeError::DatagramUnavailable => io::Error::other(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use cert_test_builder::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use flowersec_native_transport::{
        RawQuicLimits as NativeLimits, RawQuicListener as NativeListener,
        RawQuicServerConfig as NativeServerConfig,
    };
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest, Sha256};
    use time::{Duration as TimeDuration, OffsetDateTime};

    use super::*;

    struct TestIdentityV3 {
        chain: Vec<Vec<u8>>,
        leaf: Vec<u8>,
        key: Vec<u8>,
    }

    #[tokio::test]
    async fn production_quic_adapter_enforces_ca_and_pin_before_stream_use() {
        let (root, private_ca_identity) = private_ca_identity();
        let ca_policy =
            NativeTlsPolicyV3::ca_with_configured_roots([CertificateDer::from(root)]).unwrap();
        assert!(run_loopback_quic(private_ca_identity, ca_policy).await);

        let old_identity = self_signed_identity();
        let new_identity = self_signed_identity();
        let old_pin: [u8; 32] = Sha256::digest(&old_identity.leaf).into();
        let new_pin: [u8; 32] = Sha256::digest(&new_identity.leaf).into();
        assert_ne!(old_pin, new_pin);
        let overlap_policy = NativeTlsPolicyV3::pin([old_pin, new_pin]).unwrap();
        assert!(run_loopback_quic(old_identity, overlap_policy.clone()).await);
        assert!(run_loopback_quic(new_identity, overlap_policy).await);

        let mismatched_identity = self_signed_identity();
        let mismatch_policy = NativeTlsPolicyV3::pin([[0xA5; 32]]).unwrap();
        assert!(!run_loopback_quic(mismatched_identity, mismatch_policy).await);
    }

    async fn run_loopback_quic(identity: TestIdentityV3, policy: NativeTlsPolicyV3) -> bool {
        let limits = NativeLimits::for_session(3, Duration::from_secs(3)).unwrap();
        let server_config = NativeServerConfig::new(
            NativePathProfile::Direct,
            identity.chain,
            identity.key,
            limits,
        )
        .unwrap();
        let listener =
            Arc::new(NativeListener::bind((Ipv4Addr::LOCALHOST, 0).into(), server_config).unwrap());
        let address = listener.local_address().unwrap();
        let server_listener = listener.clone();
        let server = tokio::spawn(async move {
            let cancellation = NativeCancellation::new();
            let Ok(session) = server_listener.accept(&cancellation).await else {
                return false;
            };
            let Ok(stream) = session.accept_stream(&cancellation).await else {
                return false;
            };
            let Ok(Some(byte)) = stream.read(1, &cancellation).await else {
                return false;
            };
            if byte != [0x5A] {
                return false;
            }
            if !matches!(stream.write(vec![0xA5], &cancellation).await, Ok(1))
                || stream.close_write(&cancellation).await.is_err()
            {
                return false;
            }
            stream.wait_write_delivered().await.is_ok()
        });
        let url = format!("quic://127.0.0.1:{}", address.port());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let carrier = dial(
            &url,
            &policy,
            ALPN_DIRECT_V3,
            3,
            deadline,
            CancellationToken::new(),
        )
        .await;
        let client_ok = match carrier {
            Ok(carrier) => {
                let stream = carrier.open_stream().await.unwrap();
                let wrote = matches!(stream.write(&[0x5A]).await, Ok(1));
                let finished = stream.close_write().await.is_ok();
                let mut response = [0_u8; 1];
                let read = matches!(stream.read(&mut response).await, Ok(1)) && response == [0xA5];
                carrier.abort();
                wrote && finished && read
            }
            Err(_) => false,
        };
        let server_ok = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        listener.abort();
        client_ok && server_ok
    }

    fn validity() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - TimeDuration::minutes(1), now + TimeDuration::hours(1))
    }

    fn self_signed_identity() -> TestIdentityV3 {
        let (not_before, not_after) = validity();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let certificate = params.self_signed(&key).unwrap();
        let leaf = certificate.der().as_ref().to_vec();
        TestIdentityV3 {
            chain: vec![leaf.clone()],
            leaf,
            key: key.serialize_der(),
        }
    }

    fn private_ca_identity() -> (Vec<u8>, TestIdentityV3) {
        let (not_before, not_after) = validity();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.not_before = not_before;
        ca_params.not_after = not_after;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        leaf_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        leaf_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_certificate: Certificate = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let root = ca.der().as_ref().to_vec();
        let leaf = leaf_certificate.der().as_ref().to_vec();
        (
            root.clone(),
            TestIdentityV3 {
                chain: vec![leaf.clone(), root],
                leaf,
                key: leaf_key.serialize_der(),
            },
        )
    }
}

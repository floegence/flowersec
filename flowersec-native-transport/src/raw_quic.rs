use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use quinn::{Endpoint, VarInt};
use rustls::{
    CertificateError, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::{
        Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use x509_parser::{
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    prelude::{FromDer, X509Certificate, X509Version},
};

pub const ALPN_DIRECT: &str = "flowersec-direct/3";
pub const ALPN_TUNNEL: &str = "flowersec-tunnel/3";

const STREAM_RESET_CODE: u32 = 0x0000_f502;
const SESSION_CLOSE_CODE: u32 = 0x0000_f500;
const MAX_APPLICATION_ERROR_CODE: u64 = (1_u64 << 62) - 1;
const MAX_APPLICATION_ERROR_REASON_BYTES: usize = 128;
const MAX_STREAM_RECEIVE_WINDOW: u64 = 6 << 20;
const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 16 << 20;
const MAX_READ_BYTES: usize = 1 << 20;
const DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 256 * 1024;
const DATAGRAM_SEND_BUDGET: usize = 64;
const MAX_FLOWERSEC_DATAGRAM_BYTES: usize = 65_535;
const DATAGRAM_SEND_BUFFER_BYTES: usize = DATAGRAM_SEND_BUDGET * MAX_FLOWERSEC_DATAGRAM_BYTES;
const INITIAL_RTT: Duration = Duration::from_millis(250);
const PIN_FAILURE_NONE: u8 = 0;
const PIN_FAILURE_MISMATCH: u8 = 1;
const PIN_FAILURE_PROFILE: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum PinCertificateFailureV3 {
    #[error("pinned certificate profile is invalid")]
    InvalidProfile,
    #[error("pinned certificate hash does not match")]
    PinMismatch,
}

#[derive(Debug)]
struct PinnedServerVerifierV3 {
    active_leaf_der_sha256: Vec<[u8; 32]>,
    supported: WebPkiSupportedAlgorithms,
    failure: Arc<AtomicU8>,
}

impl ServerCertVerifier for PinnedServerVerifierV3 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match verify_pin_profile_v3(
            end_entity.as_ref(),
            &self.active_leaf_der_sha256,
            now.as_secs(),
        ) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(error) => {
                let code = match error {
                    PinCertificateFailureV3::PinMismatch => PIN_FAILURE_MISMATCH,
                    PinCertificateFailureV3::InvalidProfile => PIN_FAILURE_PROFILE,
                };
                self.failure.store(code, Ordering::Release);
                Err(RustlsError::InvalidCertificate(CertificateError::Other(
                    rustls::OtherError(Arc::new(error)),
                )))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn verify_pin_profile_v3(
    certificate_der: &[u8],
    active_leaf_der_sha256: &[[u8; 32]],
    now_unix_s: u64,
) -> Result<(), PinCertificateFailureV3> {
    let (remainder, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|_| PinCertificateFailureV3::InvalidProfile)?;
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = i64::try_from(now_unix_s).map_err(|_| PinCertificateFailureV3::InvalidProfile)?;
    let spki = certificate.public_key();
    let p256 = spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256);
    if !remainder.is_empty()
        || certificate.version() != X509Version::V3
        || now < not_before
        || now >= not_after
        || not_after
            .checked_sub(not_before)
            .is_none_or(|duration| duration > 1_209_600)
        || !p256
    {
        return Err(PinCertificateFailureV3::InvalidProfile);
    }
    let digest: [u8; 32] = Sha256::digest(certificate_der).into();
    let mut matched = 0u8;
    for pin in active_leaf_der_sha256 {
        matched |= digest.ct_eq(pin).unwrap_u8();
    }
    if matched == 0 {
        return Err(PinCertificateFailureV3::PinMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathProfile {
    Direct,
    Tunnel,
}

impl PathProfile {
    pub const fn alpn(self) -> &'static str {
        match self {
            Self::Direct => ALPN_DIRECT,
            Self::Tunnel => ALPN_TUNNEL,
        }
    }

    fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            value if value == ALPN_DIRECT.as_bytes() => Some(Self::Direct),
            value if value == ALPN_TUNNEL.as_bytes() => Some(Self::Tunnel),
            _ => None,
        }
    }
}

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
    pub fn for_session(
        inbound_bidirectional_stream_capacity: u32,
        handshake_idle_timeout: Duration,
    ) -> Result<Self, RawQuicError> {
        let limits = Self {
            max_inbound_bidirectional_streams: inbound_bidirectional_stream_capacity,
            handshake_idle_timeout,
            ..Self::default()
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(self) -> Result<(), RawQuicError> {
        if !(1..=130).contains(&self.max_inbound_bidirectional_streams) {
            return Err(RawQuicError::InvalidLimits);
        }
        if self.stream_receive_window == 0 || self.stream_receive_window > MAX_STREAM_RECEIVE_WINDOW
        {
            return Err(RawQuicError::InvalidLimits);
        }
        if self.connection_receive_window < self.stream_receive_window
            || self.connection_receive_window > MAX_CONNECTION_RECEIVE_WINDOW
        {
            return Err(RawQuicError::InvalidLimits);
        }
        if self.handshake_idle_timeout.is_zero()
            || self.max_idle_timeout.is_zero()
            || self.keep_alive_interval.is_zero()
            || self.keep_alive_interval >= self.max_idle_timeout
        {
            return Err(RawQuicError::InvalidLimits);
        }
        VarInt::from_u64(self.stream_receive_window).map_err(|_| RawQuicError::InvalidLimits)?;
        VarInt::from_u64(self.connection_receive_window)
            .map_err(|_| RawQuicError::InvalidLimits)?;
        let _: quinn::IdleTimeout = self
            .max_idle_timeout
            .try_into()
            .map_err(|_| RawQuicError::InvalidLimits)?;
        Ok(())
    }
}

impl Default for RawQuicLimits {
    fn default() -> Self {
        Self {
            max_inbound_bidirectional_streams: 130,
            stream_receive_window: 512 << 10,
            connection_receive_window: 1 << 20,
            handshake_idle_timeout: Duration::from_secs(10),
            max_idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(20),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RawQuicError {
    #[error("invalid raw QUIC limits")]
    InvalidLimits,
    #[error("invalid raw QUIC trust roots")]
    InvalidTrust,
    #[error("invalid raw QUIC server identity")]
    InvalidServerIdentity,
    #[error("invalid raw QUIC TLS policy")]
    InvalidTls,
    #[error("raw QUIC endpoint failed")]
    Endpoint(#[source] io::Error),
    #[error("raw QUIC listener is closed")]
    ListenerClosed,
    #[error("raw QUIC operation was canceled")]
    Canceled,
    #[error("raw QUIC name resolution returned no usable address")]
    NoUsableAddress,
    #[error("raw QUIC connection failed")]
    Connect,
    #[error("raw QUIC handshake failed")]
    Handshake,
    #[error("raw QUIC handshake timed out")]
    Timeout,
    #[error("raw QUIC pinned certificate does not match")]
    PinMismatch,
    #[error("raw QUIC pinned certificate profile is invalid")]
    PinCertificateInvalid,
    #[error("raw QUIC negotiated an invalid ALPN")]
    InvalidNegotiatedAlpn,
    #[error("raw QUIC stream failed")]
    Stream,
    #[error("raw QUIC datagrams are unavailable")]
    DatagramUnavailable,
    #[error("raw QUIC connection is closed")]
    Closed,
    #[error("raw QUIC active migration is unavailable for this session")]
    MigrationUnavailable,
    #[error("raw QUIC active migration failed")]
    Migration(#[source] io::Error),
    #[error("invalid raw QUIC application close")]
    InvalidApplicationClose,
    #[error("invalid raw QUIC read size")]
    InvalidReadSize,
}

#[derive(Clone, Debug)]
pub struct Cancellation {
    inner: CancellationToken,
}

impl Cancellation {
    pub fn new() -> Self {
        Self {
            inner: CancellationToken::new(),
        }
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    pub fn is_canceled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct RawQuicClientConfig {
    profile: PathProfile,
    limits: RawQuicLimits,
    inner: quinn::ClientConfig,
    pin_failure: Option<Arc<AtomicU8>>,
}

impl RawQuicClientConfig {
    pub fn new_ca(
        profile: PathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        Self::build_ca(profile, trust_roots_der, limits)
    }

    pub fn new_pin(
        profile: PathProfile,
        active_leaf_der_sha256: Vec<[u8; 32]>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        limits.validate()?;
        if active_leaf_der_sha256.is_empty()
            || active_leaf_der_sha256.len() > 4
            || active_leaf_der_sha256
                .iter()
                .enumerate()
                .any(|(index, pin)| active_leaf_der_sha256[..index].contains(pin))
        {
            return Err(RawQuicError::InvalidTls);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pin_failure = Arc::new(AtomicU8::new(PIN_FAILURE_NONE));
        let verifier = PinnedServerVerifierV3 {
            active_leaf_der_sha256,
            supported: provider.signature_verification_algorithms,
            failure: pin_failure.clone(),
        };
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RawQuicError::InvalidTls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        Self::from_tls(profile, limits, tls, Some(pin_failure))
    }

    fn build_ca(
        profile: PathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        limits.validate()?;
        if trust_roots_der.is_empty() {
            return Err(RawQuicError::InvalidTrust);
        }
        let mut roots = rustls::RootCertStore::empty();
        for root in trust_roots_der {
            roots
                .add(CertificateDer::from(root))
                .map_err(|_| RawQuicError::InvalidTrust)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RawQuicError::InvalidTls)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        Self::from_tls(profile, limits, tls, None)
    }

    fn from_tls(
        profile: PathProfile,
        limits: RawQuicLimits,
        tls: rustls::ClientConfig,
        pin_failure: Option<Arc<AtomicU8>>,
    ) -> Result<Self, RawQuicError> {
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|_| RawQuicError::InvalidTls)?;
        let mut inner = quinn::ClientConfig::new(Arc::new(crypto));
        inner.transport_config(Arc::new(transport_config(limits)?));
        Ok(Self {
            profile,
            limits,
            inner,
            pin_failure,
        })
    }

    fn reset_pin_failure(&self) {
        if let Some(failure) = &self.pin_failure {
            failure.store(PIN_FAILURE_NONE, Ordering::Release);
        }
    }

    fn pin_error(&self) -> Option<RawQuicError> {
        match self
            .pin_failure
            .as_ref()
            .map_or(PIN_FAILURE_NONE, |failure| failure.load(Ordering::Acquire))
        {
            PIN_FAILURE_MISMATCH => Some(RawQuicError::PinMismatch),
            PIN_FAILURE_PROFILE => Some(RawQuicError::PinCertificateInvalid),
            _ => None,
        }
    }

    fn connection_error(&self, error: &quinn::ConnectionError) -> RawQuicError {
        if let Some(pin_error) = self.pin_error() {
            return pin_error;
        }
        match error {
            quinn::ConnectionError::TransportError(error)
                if (0x100..0x200).contains(&u64::from(error.code)) =>
            {
                RawQuicError::Handshake
            }
            quinn::ConnectionError::ConnectionClosed(close)
                if (0x100..0x200).contains(&u64::from(close.error_code)) =>
            {
                RawQuicError::Handshake
            }
            quinn::ConnectionError::TimedOut => RawQuicError::Timeout,
            _ => RawQuicError::Connect,
        }
    }

    #[cfg(feature = "__flowersec_internal_test_support")]
    #[doc(hidden)]
    pub fn with_datagram_send_buffer_size_for_test(
        mut self,
        bytes: usize,
    ) -> Result<Self, RawQuicError> {
        let mut transport = transport_config(self.limits)?;
        transport.datagram_send_buffer_size(bytes);
        self.inner.transport_config(Arc::new(transport));
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

pub struct RawQuicServerConfig {
    profile: PathProfile,
    limits: RawQuicLimits,
    inner: quinn::ServerConfig,
}

impl RawQuicServerConfig {
    pub fn new(
        profile: PathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        limits.validate()?;
        if certificate_chain_der.is_empty() || private_key_der.is_empty() {
            return Err(RawQuicError::InvalidServerIdentity);
        }
        let certificate_chain = certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();
        let private_key = PrivateKeyDer::try_from(private_key_der)
            .map_err(|_| RawQuicError::InvalidServerIdentity)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RawQuicError::InvalidTls)?
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(|_| RawQuicError::InvalidServerIdentity)?;
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|_| RawQuicError::InvalidTls)?;
        let mut inner = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        inner.transport_config(Arc::new(transport_config(limits)?));
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

pub struct RawQuicListener {
    endpoint: Endpoint,
    profile: PathProfile,
    limits: RawQuicLimits,
    closed: AtomicBool,
}

impl RawQuicListener {
    pub fn bind(address: SocketAddr, config: RawQuicServerConfig) -> Result<Self, RawQuicError> {
        let endpoint = Endpoint::server(config.inner, address).map_err(RawQuicError::Endpoint)?;
        Ok(Self {
            endpoint,
            profile: config.profile,
            limits: config.limits,
            closed: AtomicBool::new(false),
        })
    }

    pub fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.endpoint.local_addr().map_err(RawQuicError::Endpoint)
    }

    pub async fn accept(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicSession, RawQuicError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(RawQuicError::ListenerClosed);
        }
        let incoming = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            incoming = self.endpoint.accept() => incoming.ok_or(RawQuicError::ListenerClosed)?,
        };
        let connection = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            result = tokio::time::timeout(self.limits.handshake_idle_timeout, incoming) => {
                result.map_err(|_| RawQuicError::Handshake)?
                    .map_err(|_| RawQuicError::Handshake)?
            }
        };
        RawQuicSession::from_connection(
            connection,
            self.endpoint.clone(),
            self.profile,
            self.limits.max_inbound_bidirectional_streams,
            false,
            None,
        )
    }

    pub fn abort(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.endpoint
                .close(VarInt::from_u32(SESSION_CLOSE_CODE), &[]);
        }
    }

    pub async fn close(&self) {
        self.abort();
        self.endpoint.wait_idle().await;
    }
}

impl fmt::Debug for RawQuicListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicListener")
            .field("local_address", &self.local_address().ok())
            .field("profile", &self.profile)
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationClose {
    pub code: u64,
    pub reason: String,
}

#[derive(Clone)]
pub struct RawQuicSession {
    connection: quinn::Connection,
    endpoint: Endpoint,
    profile: PathProfile,
    inbound_bidirectional_stream_capacity: u32,
    migration_allowed: bool,
    migration_lock: Arc<StdMutex<()>>,
    observed_route_local_address: Arc<StdMutex<Option<SocketAddr>>>,
}

impl RawQuicSession {
    pub async fn dial(
        remote_addresses: Vec<SocketAddr>,
        server_name: String,
        config: RawQuicClientConfig,
        cancellation: &Cancellation,
    ) -> Result<Self, RawQuicError> {
        if remote_addresses.is_empty() {
            return Err(RawQuicError::NoUsableAddress);
        }
        let deadline = tokio::time::Instant::now() + config.limits.handshake_idle_timeout;
        let mut last_error = RawQuicError::NoUsableAddress;
        let total = remote_addresses.len();
        for (index, remote) in remote_addresses.into_iter().enumerate() {
            if cancellation.is_canceled() {
                return Err(RawQuicError::Canceled);
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(preferred_dial_error(last_error, RawQuicError::Timeout));
            }
            let addresses_left = u32::try_from(total - index).unwrap_or(u32::MAX);
            let mut attempt_config = config.clone();
            attempt_config.limits.handshake_idle_timeout = remaining / addresses_left;
            match Self::dial_from(
                unspecified_for(remote),
                remote,
                server_name.clone(),
                attempt_config,
                cancellation,
            )
            .await
            {
                Ok(session) => return Ok(session),
                Err(RawQuicError::Canceled) => return Err(RawQuicError::Canceled),
                Err(error) => last_error = preferred_dial_error(last_error, error),
            }
        }
        Err(last_error)
    }

    pub async fn dial_from(
        local_address: SocketAddr,
        remote_address: SocketAddr,
        server_name: String,
        config: RawQuicClientConfig,
        cancellation: &Cancellation,
    ) -> Result<Self, RawQuicError> {
        config.reset_pin_failure();
        let endpoint = Endpoint::client(local_address).map_err(RawQuicError::Endpoint)?;
        let connecting = endpoint
            .connect_with(config.inner.clone(), remote_address, &server_name)
            .map_err(|_| RawQuicError::Connect)?;
        let connection = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            result = tokio::time::timeout(config.limits.handshake_idle_timeout, connecting) => {
                result.map_err(|_| config.pin_error().unwrap_or(RawQuicError::Timeout))?
                    .map_err(|error| config.connection_error(&error))?
            }
        };
        Self::from_connection(
            connection,
            endpoint,
            config.profile,
            config.limits.max_inbound_bidirectional_streams,
            true,
            preferred_route_local_address(remote_address).ok(),
        )
    }

    fn from_connection(
        connection: quinn::Connection,
        endpoint: Endpoint,
        expected_profile: PathProfile,
        inbound_bidirectional_stream_capacity: u32,
        migration_allowed: bool,
        observed_route_local_address: Option<SocketAddr>,
    ) -> Result<Self, RawQuicError> {
        let negotiated = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|handshake| {
                handshake
                    .protocol
                    .as_deref()
                    .and_then(PathProfile::from_alpn)
            })
            .ok_or(RawQuicError::InvalidNegotiatedAlpn)?;
        if negotiated != expected_profile {
            connection.close(
                VarInt::from_u32(SESSION_CLOSE_CODE),
                b"invalid negotiated ALPN",
            );
            return Err(RawQuicError::InvalidNegotiatedAlpn);
        }
        Ok(Self {
            connection,
            endpoint,
            profile: negotiated,
            inbound_bidirectional_stream_capacity,
            migration_allowed,
            migration_lock: Arc::new(StdMutex::new(())),
            observed_route_local_address: Arc::new(StdMutex::new(observed_route_local_address)),
        })
    }

    pub const fn profile(&self) -> PathProfile {
        self.profile
    }

    pub const fn inbound_bidirectional_stream_capacity(&self) -> u32 {
        self.inbound_bidirectional_stream_capacity
    }

    pub fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.endpoint.local_addr().map_err(RawQuicError::Endpoint)
    }

    pub fn peer_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn migrate_local_address(&self, address: SocketAddr) -> Result<SocketAddr, RawQuicError> {
        if !self.migration_allowed {
            return Err(RawQuicError::MigrationUnavailable);
        }
        let _migration = self
            .migration_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let socket = std::net::UdpSocket::bind(address).map_err(RawQuicError::Migration)?;
        socket
            .set_nonblocking(true)
            .map_err(RawQuicError::Migration)?;
        self.endpoint
            .rebind(socket)
            .map_err(RawQuicError::Migration)?;
        self.endpoint.local_addr().map_err(RawQuicError::Migration)
    }

    fn reconcile_active_path(&self) {
        if !self.migration_allowed {
            return;
        }
        let Ok(preferred) = preferred_route_local_address(self.connection.remote_address()) else {
            return;
        };
        let mut observed = self
            .observed_route_local_address
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(previous) = *observed else {
            *observed = Some(preferred);
            return;
        };
        if same_route_source(previous, preferred) {
            return;
        }
        let mut migration_address = preferred;
        migration_address.set_port(0);
        if self.migrate_local_address(migration_address).is_ok() {
            *observed = Some(preferred);
        }
    }

    pub async fn open_stream(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicStream, RawQuicError> {
        self.reconcile_active_path();
        let (send, receive) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            result = self.connection.open_bi() => result.map_err(|_| RawQuicError::Stream)?,
        };
        Ok(RawQuicStream::new(send, receive))
    }

    pub async fn open_stream_io(&self, cancellation: &Cancellation) -> io::Result<RawQuicStream> {
        self.reconcile_active_path();
        let (send, receive) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "raw QUIC operation was canceled"));
            }
            result = self.connection.open_bi() => result.map_err(connection_error_to_io)?,
        };
        Ok(RawQuicStream::new(send, receive))
    }

    pub async fn accept_stream(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicStream, RawQuicError> {
        self.reconcile_active_path();
        let (send, receive) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            result = self.connection.accept_bi() => result.map_err(|_| RawQuicError::Stream)?,
        };
        Ok(RawQuicStream::new(send, receive))
    }

    pub async fn accept_stream_io(&self, cancellation: &Cancellation) -> io::Result<RawQuicStream> {
        self.reconcile_active_path();
        let (send, receive) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "raw QUIC operation was canceled"));
            }
            result = self.connection.accept_bi() => result.map_err(connection_error_to_io)?,
        };
        Ok(RawQuicStream::new(send, receive))
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.reconcile_active_path();
        self.connection.max_datagram_size()
    }

    pub fn send_datagram(&self, payload: Vec<u8>) -> DatagramSendOutcome {
        self.reconcile_active_path();
        let Some(maximum) = self.connection.max_datagram_size() else {
            return DatagramSendOutcome::Unavailable;
        };
        if payload.len() > maximum {
            return DatagramSendOutcome::TooLarge;
        }
        if self.connection.datagram_send_buffer_space() < payload.len() {
            return DatagramSendOutcome::DroppedBudget;
        }
        match self.connection.send_datagram(Bytes::from(payload)) {
            Ok(()) => DatagramSendOutcome::Accepted,
            Err(quinn::SendDatagramError::TooLarge) => DatagramSendOutcome::TooLarge,
            Err(
                quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled,
            ) => DatagramSendOutcome::Unavailable,
            Err(quinn::SendDatagramError::ConnectionLost(_)) => DatagramSendOutcome::DroppedCarrier,
        }
    }

    pub async fn receive_datagram(
        &self,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, RawQuicError> {
        self.reconcile_active_path();
        tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(RawQuicError::Canceled),
            result = self.connection.read_datagram() => result
                .map(|payload| payload.to_vec())
                .map_err(|_| RawQuicError::Closed),
        }
    }

    pub fn close(&self, close: ApplicationClose) -> Result<(), RawQuicError> {
        if close.code > MAX_APPLICATION_ERROR_CODE
            || close.reason.len() > MAX_APPLICATION_ERROR_REASON_BYTES
        {
            return Err(RawQuicError::InvalidApplicationClose);
        }
        let code =
            VarInt::from_u64(close.code).map_err(|_| RawQuicError::InvalidApplicationClose)?;
        self.connection.close(code, close.reason.as_bytes());
        Ok(())
    }

    pub fn abort(&self) {
        self.connection
            .close(VarInt::from_u32(SESSION_CLOSE_CODE), &[]);
    }

    pub async fn wait_termination(&self) {
        let _ = self.connection.closed().await;
    }
}

impl fmt::Debug for RawQuicSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicSession")
            .field("profile", &self.profile)
            .field("local_address", &self.local_address().ok())
            .field("peer_address", &self.peer_address())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatagramSendOutcome {
    Accepted,
    DroppedBudget,
    DroppedCarrier,
    TooLarge,
    Unavailable,
}

#[derive(Clone)]
pub struct RawQuicStream {
    inner: Arc<RawQuicStreamInner>,
}

struct RawQuicStreamInner {
    id: u64,
    send: Mutex<quinn::SendStream>,
    receive: Mutex<quinn::RecvStream>,
    canceled: CancellationToken,
    send_finished: AtomicBool,
    receive_stopped: AtomicBool,
    reset: AtomicBool,
}

impl RawQuicStream {
    fn new(send: quinn::SendStream, receive: quinn::RecvStream) -> Self {
        let id = VarInt::from(send.id()).into_inner();
        debug_assert_eq!(id, VarInt::from(receive.id()).into_inner());
        Self {
            inner: Arc::new(RawQuicStreamInner {
                id,
                send: Mutex::new(send),
                receive: Mutex::new(receive),
                canceled: CancellationToken::new(),
                send_finished: AtomicBool::new(false),
                receive_stopped: AtomicBool::new(false),
                reset: AtomicBool::new(false),
            }),
        }
    }

    pub async fn read(
        &self,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Option<Vec<u8>>, RawQuicError> {
        if maximum_bytes == 0 || maximum_bytes > MAX_READ_BYTES {
            return Err(RawQuicError::InvalidReadSize);
        }
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(RawQuicError::Stream);
        }
        let mut payload = vec![0_u8; maximum_bytes];
        let mut receive = self.inner.receive.lock().await;
        let read = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            _ = self.inner.canceled.cancelled() => return Err(RawQuicError::Stream),
            result = receive.read(&mut payload) => result.map_err(|_| RawQuicError::Stream)?,
        };
        match read {
            None => Ok(None),
            Some(bytes) => {
                payload.truncate(bytes);
                Ok(Some(payload))
            }
        }
    }

    pub async fn read_into(
        &self,
        payload: &mut [u8],
        cancellation: &Cancellation,
    ) -> io::Result<usize> {
        if payload.is_empty() || payload.len() > MAX_READ_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid raw QUIC read size",
            ));
        }
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        let mut receive = self.inner.receive.lock().await;
        tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "raw QUIC operation was canceled",
            )),
            _ = self.inner.canceled.cancelled() => Err(if self.inner.reset.load(Ordering::Acquire) {
                local_reset_error()
            } else {
                local_canceled_error()
            }),
            result = receive.read(payload) => result
                .map(|read| read.unwrap_or(0))
                .map_err(io::Error::from),
        }
    }

    pub async fn write(
        &self,
        payload: Vec<u8>,
        cancellation: &Cancellation,
    ) -> Result<usize, RawQuicError> {
        if self.inner.reset.load(Ordering::Acquire)
            || self.inner.send_finished.load(Ordering::Acquire)
        {
            return Err(RawQuicError::Stream);
        }
        let mut send = self.inner.send.lock().await;
        tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(RawQuicError::Canceled),
            _ = self.inner.canceled.cancelled() => Err(RawQuicError::Stream),
            result = send.write(&payload) => result.map_err(|_| RawQuicError::Stream),
        }
    }

    pub async fn write_slice(
        &self,
        payload: &[u8],
        cancellation: &Cancellation,
    ) -> io::Result<usize> {
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.inner.send_finished.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "raw QUIC send direction is finished",
            ));
        }
        let mut send = self.inner.send.lock().await;
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.inner.send_finished.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "raw QUIC send direction is finished",
            ));
        }
        tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "raw QUIC operation was canceled",
            )),
            _ = self.inner.canceled.cancelled() => Err(if self.inner.reset.load(Ordering::Acquire) {
                local_reset_error()
            } else {
                local_canceled_error()
            }),
            result = send.write(payload) => result.map_err(io::Error::from),
        }
    }

    pub async fn close_write(&self, cancellation: &Cancellation) -> Result<(), RawQuicError> {
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(RawQuicError::Stream);
        }
        let mut send = self.inner.send.lock().await;
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(RawQuicError::Stream);
        }
        if self.inner.send_finished.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(RawQuicError::Canceled),
            _ = self.inner.canceled.cancelled() => Err(RawQuicError::Stream),
            result = async { send.finish() } => result.map_err(|_| RawQuicError::Stream),
        };
        if result.is_ok() {
            self.inner.send_finished.store(true, Ordering::Release);
        }
        result
    }

    pub async fn close_write_io(&self, cancellation: &Cancellation) -> io::Result<()> {
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        let mut send = self.inner.send.lock().await;
        if self.inner.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.inner.send_finished.load(Ordering::Acquire) {
            return Ok(());
        }
        let result = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "raw QUIC operation was canceled",
            )),
            _ = self.inner.canceled.cancelled() => Err(if self.inner.reset.load(Ordering::Acquire) {
                local_reset_error()
            } else {
                local_canceled_error()
            }),
            result = async { send.finish() } => result.map_err(|error| {
                io::Error::new(io::ErrorKind::BrokenPipe, error)
            }),
        };
        if result.is_ok() {
            self.inner.send_finished.store(true, Ordering::Release);
        }
        result
    }

    pub async fn wait_write_delivered(&self) -> io::Result<()> {
        let send = self.inner.send.lock().await;
        let stopped = send.stopped();
        drop(send);
        tokio::select! {
            biased;
            _ = self.inner.canceled.cancelled() => Err(local_reset_error()),
            result = stopped => match result {
                Ok(None) => Ok(()),
                Ok(Some(code)) => Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("raw QUIC send direction stopped with code {code}"),
                )),
                Err(quinn::StoppedError::ConnectionLost(
                    quinn::ConnectionError::ApplicationClosed(close),
                )) if close.error_code == VarInt::from_u32(SESSION_CLOSE_CODE)
                    && close.reason.is_empty() => Ok(()),
                Err(error) => Err(io::Error::new(io::ErrorKind::BrokenPipe, error)),
            },
        }
    }

    pub async fn stop_sending(&self) -> Result<(), RawQuicError> {
        if self.inner.reset.load(Ordering::Acquire)
            || self.inner.receive_stopped.swap(true, Ordering::AcqRel)
        {
            return Ok(());
        }
        let mut receive = self.inner.receive.lock().await;
        receive
            .stop(VarInt::from_u32(STREAM_RESET_CODE))
            .map_err(|_| RawQuicError::Stream)
    }

    pub async fn reset(&self) -> Result<(), RawQuicError> {
        if self.inner.reset.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.canceled.cancel();
        let code = VarInt::from_u32(STREAM_RESET_CODE);
        let mut send = self.inner.send.lock().await;
        let _ = send.reset(code);
        drop(send);
        let mut receive = self.inner.receive.lock().await;
        self.inner.receive_stopped.store(true, Ordering::Release);
        let _ = receive.stop(code);
        Ok(())
    }

    pub fn abort(&self) {
        self.inner.canceled.cancel();
    }
}

impl fmt::Debug for RawQuicStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicStream")
            .field("id", &self.inner.id)
            .field(
                "send_finished",
                &self.inner.send_finished.load(Ordering::Acquire),
            )
            .field("reset", &self.inner.reset.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

fn unspecified_for(remote: SocketAddr) -> SocketAddr {
    match remote.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn preferred_dial_error(current: RawQuicError, next: RawQuicError) -> RawQuicError {
    fn priority(error: &RawQuicError) -> u8 {
        match error {
            RawQuicError::PinMismatch
            | RawQuicError::PinCertificateInvalid
            | RawQuicError::Handshake
            | RawQuicError::InvalidNegotiatedAlpn => 3,
            RawQuicError::Timeout => 2,
            RawQuicError::Connect | RawQuicError::Endpoint(_) | RawQuicError::NoUsableAddress => 1,
            _ => 4,
        }
    }
    if priority(&next) >= priority(&current) {
        next
    } else {
        current
    }
}

fn preferred_route_local_address(remote: SocketAddr) -> io::Result<SocketAddr> {
    let socket = std::net::UdpSocket::bind(unspecified_for(remote))?;
    socket.connect(remote)?;
    socket.local_addr()
}

fn same_route_source(left: SocketAddr, right: SocketAddr) -> bool {
    left.ip() == right.ip()
        && match (left, right) {
            (SocketAddr::V6(left), SocketAddr::V6(right)) => left.scope_id() == right.scope_id(),
            _ => true,
        }
}

fn local_reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "raw QUIC stream was reset")
}

fn local_canceled_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "raw QUIC stream operation was canceled",
    )
}

fn connection_error_to_io(error: quinn::ConnectionError) -> io::Error {
    let kind = match &error {
        quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(SESSION_CLOSE_CODE)
                && close.reason.is_empty() =>
        {
            io::ErrorKind::ConnectionAborted
        }
        quinn::ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        quinn::ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

fn transport_config(limits: RawQuicLimits) -> Result<quinn::TransportConfig, RawQuicError> {
    limits.validate()?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .initial_rtt(INITIAL_RTT)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
        .max_concurrent_bidi_streams(VarInt::from_u32(limits.max_inbound_bidirectional_streams))
        .max_concurrent_uni_streams(0_u32.into())
        .stream_receive_window(
            VarInt::from_u64(limits.stream_receive_window)
                .map_err(|_| RawQuicError::InvalidLimits)?,
        )
        .receive_window(
            VarInt::from_u64(limits.connection_receive_window)
                .map_err(|_| RawQuicError::InvalidLimits)?,
        )
        .send_window(limits.connection_receive_window)
        .max_idle_timeout(Some(
            limits
                .max_idle_timeout
                .try_into()
                .map_err(|_| RawQuicError::InvalidLimits)?,
        ))
        .keep_alive_interval(Some(limits.keep_alive_interval))
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER_BYTES);
    Ok(transport)
}

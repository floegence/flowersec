use crate::preparation_budget::IncomingPreparationPool;
use crate::quic_provider as quinn;
use crate::{CandidatePreparationBudget, PreparationBudgetError, PreparationLimits};
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
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
use tokio::sync::{Mutex, Notify, oneshot};
use tokio_util::sync::CancellationToken;
use x509_parser::{
    oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY},
    prelude::{FromDer, X509Certificate, X509Version},
};

pub const ALPN_DIRECT_V4: &str = "flowersec-direct/4";
pub const ALPN_TUNNEL_V4: &str = "flowersec-tunnel/4";
const NORMAL_DRAINED_CODE: u32 = 62723;

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
enum PinCertificateFailure {
    #[error("pinned certificate profile is invalid")]
    InvalidProfile,
    #[error("pinned certificate hash does not match")]
    PinMismatch,
}

#[derive(Debug)]
struct PinnedServerVerifier {
    active_leaf_der_sha256: Vec<[u8; 32]>,
    supported: WebPkiSupportedAlgorithms,
    failure: Arc<AtomicU8>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let verification = verify_pin_profile(
            end_entity.as_ref(),
            &self.active_leaf_der_sha256,
            now.as_secs(),
        )
        .and_then(|()| verify_pin_extensions(end_entity.as_ref()));
        match verification {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(error) => {
                let code = match error {
                    PinCertificateFailure::PinMismatch => PIN_FAILURE_MISMATCH,
                    PinCertificateFailure::InvalidProfile => PIN_FAILURE_PROFILE,
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

fn verify_pin_profile(
    certificate_der: &[u8],
    active_leaf_der_sha256: &[[u8; 32]],
    now_unix_s: u64,
) -> Result<(), PinCertificateFailure> {
    let (remainder, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|_| PinCertificateFailure::InvalidProfile)?;
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now = i64::try_from(now_unix_s).map_err(|_| PinCertificateFailure::InvalidProfile)?;
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
        return Err(PinCertificateFailure::InvalidProfile);
    }
    let digest: [u8; 32] = Sha256::digest(certificate_der).into();
    let mut matched = 0u8;
    for pin in active_leaf_der_sha256 {
        matched |= digest.ct_eq(pin).unwrap_u8();
    }
    if matched == 0 {
        return Err(PinCertificateFailure::PinMismatch);
    }
    Ok(())
}

fn verify_pin_extensions(der: &[u8]) -> Result<(), PinCertificateFailure> {
    use x509_parser::extensions::ParsedExtension;
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| PinCertificateFailure::InvalidProfile)?;
    // Duplicate extensions and malformed understood constraints are refused.
    certificate
        .extensions_map()
        .map_err(|_| PinCertificateFailure::InvalidProfile)?;
    if certificate
        .key_usage()
        .map_err(|_| PinCertificateFailure::InvalidProfile)?
        .is_some_and(|usage| !usage.value.digital_signature())
    {
        return Err(PinCertificateFailure::InvalidProfile);
    }
    if certificate
        .extended_key_usage()
        .map_err(|_| PinCertificateFailure::InvalidProfile)?
        .is_some_and(|usage| !usage.value.server_auth && !usage.value.any)
    {
        return Err(PinCertificateFailure::InvalidProfile);
    }
    for extension in certificate.extensions() {
        if extension.critical
            && !matches!(
                extension.parsed_extension(),
                ParsedExtension::KeyUsage(_)
                    | ParsedExtension::ExtendedKeyUsage(_)
                    | ParsedExtension::BasicConstraints(_)
                    | ParsedExtension::SubjectAlternativeName(_)
            )
        {
            return Err(PinCertificateFailure::InvalidProfile);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathProfile {
    DirectV4,
    TunnelV4,
    WebTransportV4,
}

impl PathProfile {
    pub const fn alpn(self) -> &'static str {
        match self {
            Self::DirectV4 => ALPN_DIRECT_V4,
            Self::TunnelV4 => ALPN_TUNNEL_V4,
            Self::WebTransportV4 => "h3",
        }
    }

    fn from_alpn(alpn: &[u8]) -> Option<Self> {
        match alpn {
            value if value == ALPN_DIRECT_V4.as_bytes() => Some(Self::DirectV4),
            value if value == ALPN_TUNNEL_V4.as_bytes() => Some(Self::TunnelV4),
            b"h3" => Some(Self::WebTransportV4),
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
    pub datagram_queue_bytes: usize,
    pub datagram_send_queue_bytes: usize,
    pub pending_connections: u32,
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
        if !(1..=4097).contains(&self.max_inbound_bidirectional_streams) {
            return Err(RawQuicError::InvalidLimits);
        }
        if !(1..=DATAGRAM_RECEIVE_BUFFER_BYTES).contains(&self.datagram_queue_bytes)
            || !(1..=DATAGRAM_SEND_BUFFER_BYTES).contains(&self.datagram_send_queue_bytes)
            || !(1..=4096).contains(&self.pending_connections)
        {
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
            datagram_queue_bytes: DATAGRAM_RECEIVE_BUFFER_BYTES,
            datagram_send_queue_bytes: DATAGRAM_SEND_BUFFER_BYTES,
            pending_connections: 128,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RawQuicError {
    #[error("native preparation budget failed: {0}")]
    PreparationBudget(#[from] PreparationBudgetError),
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
    #[error("invalid WebTransport H3 connection")]
    WebTransportProtocol,
    #[error("native WebTransport tuple requires unsupported QUIC partial reset")]
    WebTransportPartialResetUnavailable,
    #[error("native receive direction drained")]
    NormalDrained,
    #[error("native direction reset")]
    DirectionReset,
}

pub(crate) fn incoming_preparation_failure(error: &RawQuicError) -> bool {
    matches!(
        error,
        RawQuicError::Handshake
            | RawQuicError::Timeout
            | RawQuicError::InvalidNegotiatedAlpn
            | RawQuicError::Closed
            | RawQuicError::Stream
            | RawQuicError::NormalDrained
            | RawQuicError::DirectionReset
            | RawQuicError::WebTransportProtocol
            | RawQuicError::WebTransportPartialResetUnavailable
            | RawQuicError::PreparationBudget(PreparationBudgetError::Exhausted)
    )
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
    preparation_budget: Option<CandidatePreparationBudget>,
}

impl RawQuicClientConfig {
    pub fn with_preparation_budget(
        mut self,
        budget: CandidatePreparationBudget,
    ) -> Result<Self, RawQuicError> {
        budget.check()?;
        self.preparation_budget = Some(budget);
        Ok(self)
    }
    pub fn preparation_budget(&self) -> Option<&CandidatePreparationBudget> {
        self.preparation_budget.as_ref()
    }

    pub fn new_ca(
        profile: PathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        Self::build_ca(profile, trust_roots_der, limits, None)
    }

    /// The current SDK supplies its original trusted clock before native TLS
    /// starts. A peer or reply cannot replace it during the connection.
    pub fn new_ca_with_time_provider(
        profile: PathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, RawQuicError> {
        Self::build_ca(profile, trust_roots_der, limits, Some(time_provider))
    }

    pub fn new_pin(
        profile: PathProfile,
        active_leaf_der_sha256: Vec<[u8; 32]>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        Self::build_pin(profile, active_leaf_der_sha256, limits, None)
    }
    pub fn new_pin_with_time_provider(
        profile: PathProfile,
        active_leaf_der_sha256: Vec<[u8; 32]>,
        limits: RawQuicLimits,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, RawQuicError> {
        Self::build_pin(profile, active_leaf_der_sha256, limits, Some(time_provider))
    }
    fn build_pin(
        profile: PathProfile,
        active_leaf_der_sha256: Vec<[u8; 32]>,
        limits: RawQuicLimits,
        time_provider: Option<Arc<dyn rustls::time_provider::TimeProvider>>,
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
        let verifier = PinnedServerVerifier {
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
        if let Some(time_provider) = time_provider {
            tls.time_provider = time_provider;
        }
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.enable_early_data = false;
        tls.resumption = Resumption::disabled();
        Self::from_tls(profile, limits, tls, Some(pin_failure))
    }

    pub(crate) fn cap_handshake_timeout(
        mut self,
        remaining: Duration,
    ) -> Result<Self, RawQuicError> {
        if remaining.is_zero() {
            return Err(RawQuicError::Timeout);
        }
        self.limits.handshake_idle_timeout = self.limits.handshake_idle_timeout.min(remaining);
        Ok(self)
    }

    fn build_ca(
        profile: PathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
        time_provider: Option<Arc<dyn rustls::time_provider::TimeProvider>>,
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
        if let Some(time_provider) = time_provider {
            tls.time_provider = time_provider;
        }
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
        inner.transport_config(Arc::new(transport_config(
            limits,
            profile == PathProfile::WebTransportV4,
        )?));
        Ok(Self {
            profile,
            limits,
            inner,
            pin_failure,
            preparation_budget: None,
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
        let mut transport =
            transport_config(self.limits, self.profile == PathProfile::WebTransportV4)?;
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
    preparation_budget: Option<CandidatePreparationBudget>,
    incoming_preparation: Option<IncomingPreparationPool>,
}

impl RawQuicServerConfig {
    /// A single original candidate socket; acceptance is sealed after its
    /// first incoming connection and completion never grants a second owner.
    pub fn with_preparation_budget(
        mut self,
        budget: CandidatePreparationBudget,
    ) -> Result<Self, RawQuicError> {
        if self.incoming_preparation.is_some() || self.preparation_budget.is_some() {
            return Err(PreparationBudgetError::Invalid.into());
        }
        budget.check()?;
        self.preparation_budget = Some(budget);
        Ok(self)
    }
    /// Long-lived shared listener policy. Each original incoming/CID gets its
    /// own finite budget before packet copy/QUIC/TLS, with pending ownership
    /// bounded by the already configured pending_connections capacity.
    pub fn with_incoming_preparation_capacity(
        mut self,
        capacity: PreparationLimits,
    ) -> Result<Self, RawQuicError> {
        if self.preparation_budget.is_some() || self.incoming_preparation.is_some() {
            return Err(PreparationBudgetError::Invalid.into());
        }
        self.incoming_preparation = Some(IncomingPreparationPool::new(
            capacity,
            self.limits.pending_connections as usize,
        )?);
        Ok(self)
    }

    pub fn new(
        profile: PathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        Self::build(
            profile,
            certificate_chain_der,
            private_key_der,
            limits,
            None,
        )
    }
    pub fn new_with_time_provider(
        profile: PathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
        time_provider: Arc<dyn rustls::time_provider::TimeProvider>,
    ) -> Result<Self, RawQuicError> {
        Self::build(
            profile,
            certificate_chain_der,
            private_key_der,
            limits,
            Some(time_provider),
        )
    }
    fn build(
        profile: PathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
        time_provider: Option<Arc<dyn rustls::time_provider::TimeProvider>>,
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
        if let Some(time_provider) = time_provider {
            tls.time_provider = time_provider;
        }
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|_| RawQuicError::InvalidTls)?;
        let mut inner = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        inner.transport_config(Arc::new(transport_config(
            limits,
            profile == PathProfile::WebTransportV4,
        )?));
        Ok(Self {
            profile,
            limits,
            inner,
            preparation_budget: None,
            incoming_preparation: None,
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
    preparation_budget: Option<CandidatePreparationBudget>,
    incoming_preparation: bool,
    endpoint: Endpoint,
    profile: PathProfile,
    limits: RawQuicLimits,
    closed: AtomicBool,
    closed_changed: Notify,
    active_accepts: AtomicUsize,
    accepts_changed: Notify,
}

struct ListenerAcceptGuard<'a>(&'a RawQuicListener);
impl Drop for ListenerAcceptGuard<'_> {
    fn drop(&mut self) {
        self.0.active_accepts.fetch_sub(1, Ordering::SeqCst);
        self.0.accepts_changed.notify_waiters();
    }
}

impl RawQuicListener {
    pub fn bind(address: SocketAddr, config: RawQuicServerConfig) -> Result<Self, RawQuicError> {
        if let Some(budget) = &config.preparation_budget {
            budget.debit_address()?;
        }
        let socket = std::net::UdpSocket::bind(address).map_err(RawQuicError::Endpoint)?;
        Self::from_socket_internal(socket, config)
    }

    /// Take ownership of a UDP socket bound by the deployment owner. This
    /// keeps route issuance and the eventual QUIC acceptor on one socket.
    pub fn from_socket(
        socket: std::net::UdpSocket,
        config: RawQuicServerConfig,
    ) -> Result<Self, RawQuicError> {
        if let Some(budget) = &config.preparation_budget {
            budget.debit_address()?;
        }
        Self::from_socket_internal(socket, config)
    }
    fn from_socket_internal(
        socket: std::net::UdpSocket,
        config: RawQuicServerConfig,
    ) -> Result<Self, RawQuicError> {
        let incoming_preparation = config.incoming_preparation.is_some();
        let endpoint_config = quinn::EndpointConfig::default();
        socket
            .set_nonblocking(true)
            .map_err(RawQuicError::Endpoint)?;
        let endpoint = if let Some(budget) = &config.preparation_budget {
            let runtime = Arc::new(quinn::TokioRuntime);
            let wrapped = quinn::Runtime::wrap_udp_socket(runtime.as_ref(), socket)
                .map_err(RawQuicError::Endpoint)?;
            Endpoint::new_with_abstract_socket(
                endpoint_config,
                Some(config.inner),
                budget.socket(wrapped),
                runtime,
            )
        } else {
            let runtime = Arc::new(quinn::TokioRuntime);
            let wrapped = quinn::Runtime::wrap_udp_socket(runtime.as_ref(), socket)
                .map_err(RawQuicError::Endpoint)?;
            Endpoint::new_with_abstract_socket_and_preparation(
                endpoint_config,
                Some(config.inner),
                wrapped,
                runtime,
                config.incoming_preparation,
            )
        }
        .map_err(RawQuicError::Endpoint)?;
        Ok(Self {
            endpoint,
            preparation_budget: config.preparation_budget,
            incoming_preparation,
            profile: config.profile,
            limits: config.limits,
            closed: AtomicBool::new(false),
            closed_changed: Notify::new(),
            active_accepts: AtomicUsize::new(0),
            accepts_changed: Notify::new(),
        })
    }

    pub fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.endpoint.local_addr().map_err(RawQuicError::Endpoint)
    }

    pub async fn accept(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicSession, RawQuicError> {
        loop {
            match self.accept_once(cancellation).await {
                Err(error)
                    if self.incoming_preparation
                        && incoming_preparation_failure(&error)
                        && !self.closed.load(Ordering::SeqCst)
                        && !cancellation.is_canceled() =>
                {
                    // The failed original connection has already finished
                    // cleanup. A shared accept job stays available without
                    // surfacing a peer failure as an endpoint-wide shutdown.
                    tokio::task::yield_now().await;
                }
                result => return result,
            }
        }
    }
    async fn accept_once(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicSession, RawQuicError> {
        // Admission and shutdown share one atomic order: shutdown cannot see
        // zero while an original accept still sees the listener as open.
        self.active_accepts.fetch_add(1, Ordering::SeqCst);
        let _original_accept = ListenerAcceptGuard(self);
        if self.closed.load(Ordering::SeqCst) {
            return Err(RawQuicError::ListenerClosed);
        }
        let (incoming, incoming_budget) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            _ = self.wait_closed() => return Err(RawQuicError::ListenerClosed),
            incoming = self.endpoint.accept_prepared() => incoming.ok_or(RawQuicError::ListenerClosed)?,
        };
        let preparation_budget = incoming_budget.or_else(|| self.preparation_budget.clone());
        if let Some(budget) = &preparation_budget {
            budget.check()?;
        }
        // An original candidate owner belongs to one physical connection.
        // Reusing it for another connection would bypass network Prepare limits.
        let connecting = if self.preparation_budget.is_some() {
            let connecting = incoming.accept_and_stop_current();
            self.stop_accepting_current();
            connecting
        } else {
            incoming.accept()
        };
        let connecting = match connecting {
            Ok(connecting) => connecting,
            Err(_) => {
                if let Some(budget) = &preparation_budget {
                    budget.check()?;
                }
                return Err(RawQuicError::Handshake);
            }
        };
        let preparation_budget = preparation_budget.or_else(|| connecting.preparation_budget());
        let cleanup = connecting.cleanup_current();
        let result = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => Err(RawQuicError::Canceled),
            result = tokio::time::timeout(self.limits.handshake_idle_timeout, connecting) => {
                result.map_err(|_| RawQuicError::Handshake)
                    .and_then(|connection| connection.map_err(|_| RawQuicError::Handshake))
            }
        };
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                cleanup.abort();
                cleanup.wait_termination().await;
                if let Some(budget) = &preparation_budget {
                    budget.check()?;
                }
                return Err(error);
            }
        };
        let result = RawQuicSession::from_connection(
            connection,
            self.endpoint.clone(),
            self.profile,
            self.limits.max_inbound_bidirectional_streams,
            false,
            None,
            false,
            preparation_budget.clone(),
            EndpointOwnership::Shared,
        );
        if result.is_err() {
            cleanup.abort();
            cleanup.wait_termination().await;
        }
        if let Some(budget) = &preparation_budget {
            budget.check()?;
        }
        result
    }

    /// Seal admission while preserving the existing original connections for
    /// their bounded Drain and physical cleanup. New handshakes are refused.
    pub fn stop_accepting_current(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.endpoint.set_server_config(None);
        self.closed_changed.notify_waiters();
    }

    pub fn abort(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.closed_changed.notify_waiters();
        self.endpoint
            .close(VarInt::from_u32(SESSION_CLOSE_CODE), &[]);
    }

    pub async fn close(&self) {
        self.abort();
        self.wait_termination().await;
    }

    async fn wait_closed(&self) {
        loop {
            let changed = self.closed_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.closed.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }

    pub async fn wait_termination(&self) {
        self.wait_closed().await;
        loop {
            let changed = self.accepts_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active_accepts.load(Ordering::SeqCst) == 0 {
                break;
            }
            changed.await;
        }
        // An accepted handshake finishes or cancels before endpoint idleness
        // can retire the physical socket. Stopping admission alone leaves
        // established sessions alive until their original work drains.
        self.endpoint.wait_idle_and_shutdown().await;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointOwnership {
    Shared,
    Dedicated,
}

#[derive(Clone)]
pub struct RawQuicSession {
    preparation_budget: Option<CandidatePreparationBudget>,
    connection: quinn::Connection,
    endpoint: Endpoint,
    profile: PathProfile,
    inbound_bidirectional_stream_capacity: u32,
    migration_allowed: bool,
    migration_lock: Arc<StdMutex<()>>,
    observed_route_local_address: Arc<StdMutex<Option<SocketAddr>>>,
    datagram_submission: Arc<StdMutex<()>>,
    certificate_verified: bool,
    lifetime: Arc<SessionLifetime>,
}

struct SessionLifetime {
    connection: quinn::Connection,
    ended: CancellationToken,
}
impl Drop for SessionLifetime {
    fn drop(&mut self) {
        self.connection
            .close(VarInt::from_u32(SESSION_CLOSE_CODE), &[]);
    }
}

impl RawQuicSession {
    pub fn preparation_budget(&self) -> Option<&CandidatePreparationBudget> {
        self.preparation_budget.as_ref()
    }
    pub fn complete_preparation(&self) -> Result<(), RawQuicError> {
        if let Some(budget) = &self.preparation_budget {
            budget.complete()?;
        }
        Ok(())
    }

    pub(crate) fn h3_connection(&self) -> &quinn::Connection {
        &self.connection
    }

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
                Err(error @ RawQuicError::PreparationBudget(_)) => return Err(error),
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
        let endpoint = if let Some(budget) = &config.preparation_budget {
            budget.debit_address()?;
            let socket =
                std::net::UdpSocket::bind(local_address).map_err(RawQuicError::Endpoint)?;
            socket
                .set_nonblocking(true)
                .map_err(RawQuicError::Endpoint)?;
            let runtime = Arc::new(quinn::TokioRuntime);
            let wrapped = quinn::Runtime::wrap_udp_socket(runtime.as_ref(), socket)
                .map_err(RawQuicError::Endpoint)?;
            Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                budget.socket(wrapped),
                runtime,
            )
        } else {
            Endpoint::client(local_address)
        }
        .map_err(RawQuicError::Endpoint)?;
        let connecting =
            match endpoint.connect_with(config.inner.clone(), remote_address, &server_name) {
                Ok(connecting) => connecting,
                Err(_) => {
                    endpoint.wait_idle_and_shutdown().await;
                    return Err(RawQuicError::Connect);
                }
            };
        let cleanup = connecting.cleanup_current();
        let result = tokio::select! {
            biased;
            _=cancellation.inner.cancelled()=>Err(RawQuicError::Canceled),
            result=tokio::time::timeout(config.limits.handshake_idle_timeout,connecting)=>match result {
                Ok(Ok(connection))=>Ok(connection),
                Ok(Err(error))=>Err(config.connection_error(&error)),
                Err(_)=>Err(config.pin_error().unwrap_or(RawQuicError::Timeout)),
            }
        };
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                cleanup.abort();
                cleanup.wait_termination().await;
                endpoint.wait_idle_and_shutdown().await;
                if let Some(budget) = &config.preparation_budget {
                    budget.check()?;
                }
                return Err(error);
            }
        };
        let original_endpoint = endpoint.clone();
        let result = Self::from_connection(
            connection,
            endpoint,
            config.profile,
            config.limits.max_inbound_bidirectional_streams,
            true,
            preferred_route_local_address(remote_address).ok(),
            true,
            config.preparation_budget.clone(),
            EndpointOwnership::Dedicated,
        );
        if result.is_err() {
            cleanup.abort();
            cleanup.wait_termination().await;
            original_endpoint.wait_idle_and_shutdown().await;
        }
        result
    }

    fn from_connection(
        connection: quinn::Connection,
        endpoint: Endpoint,
        expected_profile: PathProfile,
        inbound_bidirectional_stream_capacity: u32,
        migration_allowed: bool,
        observed_route_local_address: Option<SocketAddr>,
        certificate_verified: bool,
        preparation_budget: Option<CandidatePreparationBudget>,
        endpoint_ownership: EndpointOwnership,
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
        let ended = CancellationToken::new();
        let observed = ended.clone();
        let original = connection.clone();
        let dedicated_endpoint =
            (endpoint_ownership == EndpointOwnership::Dedicated).then(|| endpoint.clone());
        let lifetime_endpoint = dedicated_endpoint.clone();
        tokio::spawn(async move {
            let _ = original.closed().await;
            original.wait_driver_termination_current().await;
            drop(original);
            if let Some(endpoint) = lifetime_endpoint {
                endpoint.wait_idle_and_shutdown().await;
            }
            observed.cancel();
        });
        let lifetime = Arc::new(SessionLifetime {
            connection: connection.clone(),
            ended,
        });
        Ok(Self {
            connection,
            endpoint,
            profile: negotiated,
            inbound_bidirectional_stream_capacity,
            migration_allowed,
            migration_lock: Arc::new(StdMutex::new(())),
            observed_route_local_address: Arc::new(StdMutex::new(observed_route_local_address)),
            datagram_submission: Arc::new(StdMutex::new(())),
            certificate_verified,
            lifetime,
            preparation_budget,
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
            result = self.connection.open_bi() => result.map_err(stream_open_error)?,
        };
        Ok(RawQuicStream::new(
            send,
            receive,
            self.lifetime.ended.clone(),
            self.profile == PathProfile::WebTransportV4,
        ))
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
        Ok(RawQuicStream::new(
            send,
            receive,
            self.lifetime.ended.clone(),
            self.profile == PathProfile::WebTransportV4,
        ))
    }

    pub async fn accept_stream(
        &self,
        cancellation: &Cancellation,
    ) -> Result<RawQuicStream, RawQuicError> {
        self.reconcile_active_path();
        let (send, receive) = tokio::select! {
            biased;
            _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
            result = self.connection.accept_bi() => result.map_err(stream_open_error)?,
        };
        Ok(RawQuicStream::new(
            send,
            receive,
            self.lifetime.ended.clone(),
            self.profile == PathProfile::WebTransportV4,
        ))
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
        Ok(RawQuicStream::new(
            send,
            receive,
            self.lifetime.ended.clone(),
            self.profile == PathProfile::WebTransportV4,
        ))
    }

    pub fn max_datagram_size(&self) -> Option<usize> {
        self.reconcile_active_path();
        self.connection.max_datagram_size()
    }

    pub fn send_datagram(&self, payload: Vec<u8>) -> DatagramSendOutcome {
        let _admission = self
            .datagram_submission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    /// All-or-none admission retains the exact native Bytes owner until the
    /// actual Quinn queue/packetizer releases it. Observers cannot end custody.
    pub fn submit_datagram_current(&self, payload: Vec<u8>) -> Option<DatagramSubmission> {
        let _admission = self
            .datagram_submission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.reconcile_active_path();
        let maximum = self.connection.max_datagram_size()?;
        if payload.is_empty()
            || payload.len() > maximum
            || self.connection.datagram_send_buffer_space() < payload.len()
        {
            return None;
        }
        let (released, completion) = oneshot::channel();
        let bytes = Bytes::from_owner(DatagramBuffer {
            payload,
            released: Some(released),
        });
        self.connection.send_datagram(bytes).ok()?;
        Some(DatagramSubmission { completion })
    }

    /// Copy only a bounded accepted native packet. Oversized packets are
    /// dropped in this task before any output allocation crosses the bridge.
    pub async fn receive_datagram_bounded(
        &self,
        maximum: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, RawQuicError> {
        if maximum == 0 || maximum > MAX_FLOWERSEC_DATAGRAM_BYTES {
            return Err(RawQuicError::InvalidReadSize);
        }
        self.reconcile_active_path();
        loop {
            let packet = tokio::select! {
                biased;
                _ = cancellation.inner.cancelled() => return Err(RawQuicError::Canceled),
                result = self.connection.read_datagram() => result.map_err(|_| RawQuicError::Closed)?,
            };
            if packet.len() <= maximum {
                return Ok(packet.to_vec());
            }
            drop(packet);
            tokio::task::yield_now().await;
        }
    }

    pub fn certificate_verified(&self) -> bool {
        self.certificate_verified
    }

    pub fn peer_leaf_der(&self) -> Result<Vec<u8>, RawQuicError> {
        let identity = self
            .connection
            .peer_identity()
            .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok());
        let Some(chain) = identity else {
            return Ok(Vec::new());
        };
        let Some(leaf) = chain.first() else {
            return Ok(Vec::new());
        };
        if leaf.len() > 65536 {
            return Err(RawQuicError::InvalidTls);
        }
        if let Some(budget) = &self.preparation_budget {
            budget.debit_input(leaf.len() as u64, 1)?;
        }
        Ok(leaf.as_ref().to_vec())
    }

    pub fn export_keying_material(
        &self,
        length: usize,
        label: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, RawQuicError> {
        if length != 32 || label != b"EXPORTER-flowersec-v4" || context.len() != 32 {
            return Err(RawQuicError::InvalidTls);
        }
        // Exporter material is derived locally. It consumes crypto work, not
        // received input bytes or the peer certificate debit a second time.
        if let Some(budget) = &self.preparation_budget {
            budget.debit_work(1)?;
        }
        let mut output = vec![0; length];
        self.connection
            .export_keying_material(&mut output, label, context)
            .map_err(|_| RawQuicError::InvalidTls)?;
        Ok(output)
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
        self.connection.wait_driver_termination_current().await;
        // SessionLifetime cancels ended only after a dedicated dial endpoint
        // has joined its own idle/shutdown barrier. Shared listener endpoints
        // never enter that barrier.
        self.lifetime.ended.cancelled().await;
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

#[derive(Debug)]
pub struct DatagramSubmission {
    completion: oneshot::Receiver<()>,
}
impl DatagramSubmission {
    pub async fn completion(self) {
        let _ = self.completion.await;
    }
}
struct DatagramBuffer {
    payload: Vec<u8>,
    released: Option<oneshot::Sender<()>>,
}
impl AsRef<[u8]> for DatagramBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}
impl Drop for DatagramBuffer {
    fn drop(&mut self) {
        // Release bytes before signaling their actual original owner exit.
        let mut payload = std::mem::take(&mut self.payload);
        payload.fill(0);
        drop(payload);
        if let Some(released) = self.released.take() {
            let _ = released.send(());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDirectionFailure {
    NormalDrained,
    DirectionReset,
}

#[derive(Clone)]
pub struct RawQuicStream {
    inner: Arc<RawQuicStreamInner>,
}

struct RawQuicStreamInner {
    id: u64,
    normal_drained_code: VarInt,
    reset_code: VarInt,
    send: Mutex<quinn::SendStream>,
    receive: Mutex<quinn::RecvStream>,
    canceled: CancellationToken,
    send_finished: AtomicBool,
    receive_stopped: AtomicBool,
    reset: AtomicBool,
    send_cancelled: CancellationToken,
    receive_cancelled: CancellationToken,
    send_done: AtomicBool,
    send_observer_done: AtomicBool,
    connection_observer_done: AtomicBool,
    ended: CancellationToken,
    receive_done: AtomicBool,
    write_failure: StdMutex<Option<NativeDirectionFailure>>,
    changed: Notify,
}

impl RawQuicStreamInner {
    fn notify_changed(&self) {
        if self.send_done.load(Ordering::Acquire) && self.receive_done.load(Ordering::Acquire) {
            self.ended.cancel();
        }
        self.changed.notify_waiters();
    }
}

impl RawQuicStream {
    pub(crate) fn stream_id(&self) -> u64 {
        self.inner.id
    }
    fn new(
        send: quinn::SendStream,
        receive: quinn::RecvStream,
        connection_ended: CancellationToken,
        webtransport: bool,
    ) -> Self {
        let id = VarInt::from(send.id()).into_inner();
        debug_assert_eq!(id, VarInt::from(receive.id()).into_inner());
        let stopped = send.stopped();
        let terminated = send.terminated();
        let stream = Self {
            inner: Arc::new(RawQuicStreamInner {
                id,
                normal_drained_code: mapped_stream_code(NORMAL_DRAINED_CODE, webtransport),
                reset_code: mapped_stream_code(STREAM_RESET_CODE, webtransport),
                send: Mutex::new(send),
                receive: Mutex::new(receive),
                canceled: CancellationToken::new(),
                send_finished: AtomicBool::new(false),
                receive_stopped: AtomicBool::new(false),
                reset: AtomicBool::new(false),
                send_cancelled: CancellationToken::new(),
                receive_cancelled: CancellationToken::new(),
                send_done: AtomicBool::new(false),
                send_observer_done: AtomicBool::new(false),
                connection_observer_done: AtomicBool::new(false),
                ended: CancellationToken::new(),
                receive_done: AtomicBool::new(false),
                write_failure: StdMutex::new(None),
                changed: Notify::new(),
            }),
        };
        // A stop observation retains only its native stop future and a
        // weak registry link, never the whole send/receive buffer graph.
        let original = Arc::downgrade(&stream.inner);
        let cancelled = stream.inner.send_cancelled.clone();
        tokio::spawn(async move {
            let result = tokio::select! {
                result = stopped => Some(result),
                _ = cancelled.cancelled() => None,
            };
            if let Some(Ok(Some(code))) = result
                && let Some(owner) = original.upgrade()
            {
                let reason = if code == owner.normal_drained_code {
                    NativeDirectionFailure::NormalDrained
                } else {
                    NativeDirectionFailure::DirectionReset
                };
                *owner
                    .write_failure
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reason);
                owner.notify_changed();
                // Release a blocked writer before taking the send owner.
                // An already queued FIN remains its own physical tail.
                owner.send_cancelled.cancel();
                let mut send = owner.send.lock().await;
                if !owner.send_finished.load(Ordering::Acquire) {
                    let _ = send.reset(owner.reset_code);
                }
            }
            // STOP_SENDING and cancellation observe an action, not physical
            // completion. Prefix retransmission remains owned until retirement.
            terminated.await;
            if let Some(owner) = original.upgrade() {
                owner.send_done.store(true, Ordering::Release);
                owner.send_observer_done.store(true, Ordering::Release);
                owner.notify_changed();
            }
        });
        let original = Arc::downgrade(&stream.inner);
        let ended = stream.inner.ended.clone();
        tokio::spawn(async move {
            let connection_closed = tokio::select! {
                _ = connection_ended.cancelled() => true,
                _ = ended.cancelled() => false,
            };
            if let Some(original) = original.upgrade() {
                if connection_closed {
                    original.send_cancelled.cancel();
                    original.receive_cancelled.cancel();
                    // Both native owners return only after their actual
                    // readers/writers stop borrowing their original buffers.
                    let mut send = original.send.lock().await;
                    let _ = send.reset(original.reset_code);
                    drop(send);
                    let mut receive = original.receive.lock().await;
                    let _ = receive.stop(original.reset_code);
                    drop(receive);
                    original.send_done.store(true, Ordering::Release);
                    original.receive_done.store(true, Ordering::Release);
                }
                original
                    .connection_observer_done
                    .store(true, Ordering::Release);
                original.notify_changed();
            }
        });
        stream
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
            .stop(self.inner.reset_code)
            .map_err(|_| RawQuicError::Stream)
    }

    pub async fn reset(&self) -> Result<(), RawQuicError> {
        if self.inner.reset.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.inner.canceled.cancel();
        let code = self.inner.reset_code;
        let mut send = self.inner.send.lock().await;
        let _ = send.reset(code);
        drop(send);
        let mut receive = self.inner.receive.lock().await;
        self.inner.receive_stopped.store(true, Ordering::Release);
        let _ = receive.stop(code);
        Ok(())
    }

    pub async fn read_current(
        &self,
        maximum: usize,
        cancellation: &Cancellation,
    ) -> Result<Option<Vec<u8>>, RawQuicError> {
        if maximum == 0 || maximum > MAX_READ_BYTES {
            return Err(RawQuicError::InvalidReadSize);
        }
        let mut receive = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(RawQuicError::Canceled),
            _ = self.inner.receive_cancelled.cancelled() => return Err(RawQuicError::DirectionReset),
            owner = self.inner.receive.lock() => owner,
        };
        let mut payload = vec![0; maximum];
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(RawQuicError::Canceled),
            _ = self.inner.receive_cancelled.cancelled() => return Err(RawQuicError::DirectionReset),
            result = receive.read(&mut payload) => result,
        };
        match result {
            Ok(Some(length)) => {
                payload.truncate(length);
                Ok(Some(payload))
            }
            Ok(None) => {
                self.inner.receive_done.store(true, Ordering::Release);
                self.inner.notify_changed();
                Ok(None)
            }
            Err(quinn::ReadError::Reset(code)) => {
                self.inner.receive_done.store(true, Ordering::Release);
                self.inner.notify_changed();
                Err(if code == self.inner.normal_drained_code {
                    RawQuicError::NormalDrained
                } else {
                    RawQuicError::DirectionReset
                })
            }
            Err(_) => {
                self.inner.receive_done.store(true, Ordering::Release);
                self.inner.notify_changed();
                Err(RawQuicError::Closed)
            }
        }
    }

    /// A receipt admits this whole bounded candidate. Actual write exit, even
    /// after partial carrier progress, is the end of the original byte borrow.
    pub async fn write_all_current(&self, payload: &[u8]) -> Result<(), RawQuicError> {
        if self.inner.send_finished.load(Ordering::Acquire)
            || self.inner.send_done.load(Ordering::Acquire)
        {
            return Err(self.current_write_error());
        }
        let mut send = tokio::select! {
            owner = self.inner.send.lock() => owner,
            _ = self.inner.send_cancelled.cancelled() => return Err(RawQuicError::DirectionReset),
        };
        tokio::select! {
            biased;
            _ = self.inner.send_cancelled.cancelled() => Err(RawQuicError::DirectionReset),
            result = send.write_all(payload) => result.map_err(|error| match error {
                quinn::WriteError::Stopped(code) if code == self.inner.normal_drained_code => RawQuicError::NormalDrained,
                quinn::WriteError::Stopped(_) => RawQuicError::DirectionReset,
                _ => RawQuicError::Closed,
            }),
        }
    }

    fn current_write_error(&self) -> RawQuicError {
        match *self
            .inner
            .write_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            Some(NativeDirectionFailure::NormalDrained) => RawQuicError::NormalDrained,
            _ => RawQuicError::DirectionReset,
        }
    }

    pub async fn close_write_current(&self) -> Result<(), RawQuicError> {
        if self.inner.send_done.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut send = self.inner.send.lock().await;
        if self.inner.send_done.load(Ordering::Acquire)
            || self.inner.send_finished.load(Ordering::Acquire)
        {
            return Ok(());
        }
        if send.finish().is_err() {
            let stopped = send.stopped();
            drop(send);
            return match stopped.await {
                Ok(Some(code)) if code == self.inner.normal_drained_code => {
                    Err(RawQuicError::NormalDrained)
                }
                Ok(Some(_)) => Err(RawQuicError::DirectionReset),
                Ok(None) => Ok(()),
                Err(_) => Err(RawQuicError::Closed),
            };
        }
        self.inner.send_finished.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn stop_sending_current(&self, normal_drained: bool) -> Result<(), RawQuicError> {
        self.inner.receive_cancelled.cancel();
        let mut receive = self.inner.receive.lock().await;
        if !self.inner.receive_done.load(Ordering::Acquire) {
            let code = if normal_drained {
                self.inner.normal_drained_code
            } else {
                self.inner.reset_code
            };
            let _ = receive.stop(code);
        }
        drop(receive);
        self.inner.receive_done.store(true, Ordering::Release);
        self.inner.notify_changed();
        Ok(())
    }

    pub(crate) async fn write_webtransport_prefix(
        &self,
        prefix: &[u8],
    ) -> Result<(), RawQuicError> {
        let mut send = tokio::select! {
            owner = self.inner.send.lock() => owner,
            _ = self.inner.send_cancelled.cancelled() => return Err(RawQuicError::DirectionReset),
        };
        tokio::select! {
            biased;
            _ = self.inner.send_cancelled.cancelled() => Err(RawQuicError::DirectionReset),
            result = send.write_reliable_prefix(prefix) => result.map_err(|_| RawQuicError::Stream),
        }
    }

    pub async fn reset_write_current(&self) -> Result<(), RawQuicError> {
        self.reset_write_current_with_reason(false).await
    }

    /// Reset only the original write direction and retain the native owner
    /// until that direction terminates. NormalDrain remains distinguishable
    /// when an opaque relay carries a peer's directional shutdown.
    pub async fn reset_write_current_with_reason(
        &self,
        normal_drained: bool,
    ) -> Result<(), RawQuicError> {
        self.inner.send_cancelled.cancel();
        let mut send = self.inner.send.lock().await;
        if !self.inner.send_done.load(Ordering::Acquire)
            && !self.inner.send_finished.load(Ordering::Acquire)
        {
            let _ = send.reset(if normal_drained {
                self.inner.normal_drained_code
            } else {
                self.inner.reset_code
            });
        }
        let terminated = send.terminated();
        drop(send);
        terminated.await;
        self.inner.send_done.store(true, Ordering::Release);
        self.inner.notify_changed();
        Ok(())
    }

    pub async fn wait_write_failure(&self) -> Option<NativeDirectionFailure> {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let failure = *self
                .inner
                .write_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if failure.is_some() || self.inner.send_done.load(Ordering::Acquire) {
                return failure;
            }
            changed.await;
        }
    }

    pub async fn wait_termination_current(&self) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.inner.send_done.load(Ordering::Acquire)
                && self.inner.receive_done.load(Ordering::Acquire)
                && self.inner.send_observer_done.load(Ordering::Acquire)
                && self.inner.connection_observer_done.load(Ordering::Acquire)
            {
                return;
            }
            changed.await;
        }
    }

    pub fn cancel_current(&self) {
        self.inner.send_cancelled.cancel();
        self.inner.receive_cancelled.cancel();
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

fn stream_open_error(error: quinn::ConnectionError) -> RawQuicError {
    match error {
        quinn::ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(SESSION_CLOSE_CODE)
                && close.reason.is_empty() =>
        {
            RawQuicError::Closed
        }
        _ => RawQuicError::Stream,
    }
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

fn transport_config(
    limits: RawQuicLimits,
    webtransport: bool,
) -> Result<quinn::TransportConfig, RawQuicError> {
    limits.validate()?;
    let mut transport = quinn::TransportConfig::default();
    transport.reliable_stream_reset(webtransport);
    transport
        .initial_rtt(INITIAL_RTT)
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
        .max_concurrent_bidi_streams(VarInt::from_u32(limits.max_inbound_bidirectional_streams))
        .max_concurrent_uni_streams(if webtransport { 3_u32 } else { 0_u32 }.into())
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
        .datagram_receive_buffer_size(Some(limits.datagram_queue_bytes))
        .datagram_send_buffer_size(limits.datagram_send_queue_bytes);
    Ok(transport)
}

fn mapped_stream_code(code: u32, webtransport: bool) -> VarInt {
    let value = u64::from(code);
    VarInt::from_u64(if webtransport {
        0x52e4_a40f_a8db + value + value / 0x1e
    } else {
        value
    })
    .expect("fixed application code fits QUIC varint")
}

#[cfg(test)]
#[path = "../tests/support/raw_quic_tls.rs"]
mod tests;

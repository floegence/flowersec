//! Native raw QUIC carrier for the Flowersec v2 transport profile.

use std::{
    collections::HashSet,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use quinn::{Endpoint, VarInt};
use rustls::pki_types::CertificateDer;
#[cfg(test)]
use rustls::pki_types::PrivateKeyDer;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::protocol_v2::CipherSuiteV2;

/// The validated, signed session contract required by raw QUIC admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionContractV2 {
    pub channel_id: String,
    pub idle_timeout_seconds: u64,
    pub establish_timeout_seconds: u64,
    pub rekey_prepare_timeout_seconds: u64,
    pub rekey_completion_timeout_seconds: u64,
    pub max_inbound_streams: u16,
    pub psk: [u8; 32],
    pub allowed_suites: Vec<u16>,
    pub default_suite: u16,
    pub selected_features: u32,
    pub contract_hash: [u8; 32],
}

#[derive(Serialize)]
struct SessionContractHashWire<'a> {
    allowed_suites: &'a [u16],
    channel_id: &'a str,
    default_suite: u16,
    establish_timeout_seconds: u64,
    idle_timeout_seconds: u64,
    max_inbound_streams: u16,
    profile: &'static str,
    rekey_completion_timeout_seconds: u64,
    rekey_prepare_timeout_seconds: u64,
    selected_features: u32,
}

impl SessionContractV2 {
    pub fn canonical_hash(&self) -> [u8; 32] {
        let wire = SessionContractHashWire {
            allowed_suites: &self.allowed_suites,
            channel_id: &self.channel_id,
            default_suite: self.default_suite,
            establish_timeout_seconds: self.establish_timeout_seconds,
            idle_timeout_seconds: self.idle_timeout_seconds,
            max_inbound_streams: self.max_inbound_streams,
            profile: "flowersec/2",
            rekey_completion_timeout_seconds: self.rekey_completion_timeout_seconds,
            rekey_prepare_timeout_seconds: self.rekey_prepare_timeout_seconds,
            selected_features: self.selected_features,
        };
        let canonical = serde_json::to_vec(&wire).expect("session contract wire is serializable");
        let mut preimage = Vec::with_capacity(36 + canonical.len());
        preimage.extend_from_slice(b"flowersec-v2-session-contract\0");
        preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&canonical);
        sha2::Sha256::digest(preimage).into()
    }

    fn validate_against_config(
        &self,
        config: &crate::session_v2::SessionConfigV2,
    ) -> Result<(), io::Error> {
        if self.contract_hash != self.canonical_hash()
            || self.contract_hash != config.session_contract_hash
            || self.channel_id != config.channel_id
            || self.max_inbound_streams != config.max_inbound_streams
            || self.default_suite != suite_id(config.suite)
            || !self.allowed_suites.contains(&suite_id(config.suite))
            || self.selected_features & !crate::session_v2::UNRELIABLE_MESSAGES_FEATURE_V1 != 0
            || config.psk != self.psk
            || config.idle_timeout != Duration::from_secs(self.idle_timeout_seconds)
            || config.deadlines.establish != Duration::from_secs(self.establish_timeout_seconds)
            || config.deadlines.rekey_prepare
                != Duration::from_secs(self.rekey_prepare_timeout_seconds)
            || config.deadlines.rekey_completion
                != Duration::from_secs(self.rekey_completion_timeout_seconds)
        {
            return Err(invalid_fsb2(
                "SessionV2 config does not match the signed session contract",
            ));
        }
        Ok(())
    }
}

fn suite_id(suite: CipherSuiteV2) -> u16 {
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => 1,
        CipherSuiteV2::Aes256Gcm => 2,
    }
}

/// Exact ALPN for a direct Flowersec v2 raw QUIC connection.
pub const ALPN_DIRECT: &str = "flowersec-direct/2";
/// Exact ALPN for a tunnel Flowersec v2 raw QUIC connection.
pub const ALPN_TUNNEL: &str = "flowersec-tunnel/2";

const STREAM_RESET_CODE: u32 = 0x0000_f502;
const SESSION_CLOSE_CODE: u32 = 0x0000_f500;
#[cfg(test)]
const MAX_APPLICATION_ERROR_CODE: u64 = (1_u64 << 62) - 1;
#[cfg(test)]
const MAX_APPLICATION_ERROR_REASON_BYTES: usize = 128;
const MAX_STREAM_RECEIVE_WINDOW: u64 = 6 << 20;
const MAX_CONNECTION_RECEIVE_WINDOW: u64 = 16 << 20;
const FSB2_HEADER_BYTES: usize = 12;
const MAX_FSB2_PAYLOAD_BYTES: usize = 32_768;
const MAX_FSB2_CANDIDATES: usize = 4;
const MAX_FSB2_CREDENTIAL_BYTES: usize = 8_192;
const DATAGRAM_RECEIVE_BUFFER_BYTES: usize = 256 * 1024;
const DATAGRAM_SEND_BUDGET: usize = 64;
const DATAGRAM_SEND_BUFFER_BYTES: usize =
    DATAGRAM_SEND_BUDGET * crate::protocol_v2::MAX_UNRELIABLE_WIRE_V2_BYTES;

/// Identifies the only two registered raw QUIC wire profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawQuicPathProfile {
    /// A direct endpoint connection.
    Direct,
    /// A connection to or from a tunnel.
    Tunnel,
}

impl RawQuicPathProfile {
    /// Returns the exact ALPN value carried in TLS.
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

/// Bounded transport policy applied to both client and server endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawQuicLimits {
    /// Maximum concurrently open bidirectional streams initiated by the peer.
    pub max_inbound_bidirectional_streams: u32,
    /// Maximum receive credit held by one stream.
    pub stream_receive_window: u64,
    /// Maximum receive credit held by the entire connection.
    pub connection_receive_window: u64,
    /// Maximum wall-clock duration allowed for a TLS/QUIC handshake.
    pub handshake_idle_timeout: Duration,
    /// Maximum negotiated connection inactivity before timeout.
    pub max_idle_timeout: Duration,
    /// Period between transport keepalive packets.
    pub keep_alive_interval: Duration,
}

impl RawQuicLimits {
    /// Applies the exact SessionV2 carrier stream limit while preserving the
    /// remaining QUIC transport policy.
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

    /// Validates every resource relationship before any socket is opened.
    pub fn validate(self) -> Result<(), RawQuicError> {
        if self.max_inbound_bidirectional_streams == 0
            || self.max_inbound_bidirectional_streams > 130
        {
            return Err(RawQuicError::InvalidLimits(
                "max inbound bidirectional streams must be in 1..=130",
            ));
        }
        if self.stream_receive_window == 0 || self.stream_receive_window > MAX_STREAM_RECEIVE_WINDOW
        {
            return Err(RawQuicError::InvalidLimits(
                "stream receive window must be in 1..=6 MiB",
            ));
        }
        if self.connection_receive_window < self.stream_receive_window
            || self.connection_receive_window > MAX_CONNECTION_RECEIVE_WINDOW
        {
            return Err(RawQuicError::InvalidLimits(
                "connection receive window must cover one stream and not exceed 16 MiB",
            ));
        }
        if self.handshake_idle_timeout.is_zero() || self.max_idle_timeout.is_zero() {
            return Err(RawQuicError::InvalidLimits(
                "handshake and connection idle timeouts must be nonzero",
            ));
        }
        if self.keep_alive_interval.is_zero() || self.keep_alive_interval >= self.max_idle_timeout {
            return Err(RawQuicError::InvalidLimits(
                "keepalive must be nonzero and shorter than the connection idle timeout",
            ));
        }
        VarInt::from_u64(self.stream_receive_window).map_err(|_| {
            RawQuicError::InvalidLimits("stream receive window exceeds the QUIC varint range")
        })?;
        VarInt::from_u64(self.connection_receive_window).map_err(|_| {
            RawQuicError::InvalidLimits("connection receive window exceeds the QUIC varint range")
        })?;
        let _: quinn::IdleTimeout = self.max_idle_timeout.try_into().map_err(|_| {
            RawQuicError::InvalidLimits("connection idle timeout exceeds the QUIC varint range")
        })?;
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

/// Flowersec-owned error surface that does not expose a QUIC implementation type.
#[derive(Debug, thiserror::Error)]
pub enum RawQuicError {
    /// A resource limit is zero, out of range, or internally inconsistent.
    #[error("invalid raw QUIC limits: {0}")]
    InvalidLimits(&'static str),
    /// The supplied trust store is empty or contains an invalid certificate.
    #[error("invalid raw QUIC trust configuration: {0}")]
    InvalidTrust(String),
    /// The supplied server certificate chain is empty or invalid.
    #[cfg(test)]
    #[error("invalid raw QUIC certificate chain: {0}")]
    InvalidCertificate(String),
    /// The supplied private key is invalid or is not usable with the certificate.
    #[cfg(test)]
    #[error("invalid raw QUIC private key: {0}")]
    InvalidPrivateKey(String),
    /// The TLS 1.3 configuration could not be constructed.
    #[error("invalid raw QUIC TLS 1.3 configuration: {0}")]
    InvalidTls(String),
    /// The local UDP endpoint could not be created.
    #[error("raw QUIC endpoint failed: {0}")]
    Endpoint(#[source] io::Error),
    /// The local listener has stopped accepting connections.
    #[cfg(test)]
    #[error("raw QUIC listener is closed")]
    ListenerClosed,
    /// A connection could not be started.
    #[error("raw QUIC connect failed: {0}")]
    Connect(String),
    /// The handshake failed or exceeded its configured deadline.
    #[error("raw QUIC handshake failed: {0}")]
    Handshake(String),
    /// The peer negotiated a profile other than the exact configured profile.
    #[error("invalid negotiated raw QUIC ALPN")]
    InvalidNegotiatedAlpn,
    /// A native bidirectional stream could not be opened or accepted.
    #[error("raw QUIC stream operation failed: {0}")]
    Stream(String),
    /// Active migration is unavailable for a listener-owned server endpoint.
    #[error("raw QUIC active migration is unavailable for this session")]
    MigrationUnavailable,
    /// The client UDP socket could not be rebound for active path migration.
    #[error("raw QUIC active migration failed: {0}")]
    Migration(#[source] io::Error),
    /// An application close code or reason exceeded its stable bounds.
    #[cfg(test)]
    #[error("invalid raw QUIC application close error")]
    InvalidApplicationError,
}

/// Client policy built from caller-owned trust roots.
#[derive(Clone)]
pub struct RawQuicClientConfig {
    profile: RawQuicPathProfile,
    limits: RawQuicLimits,
    inner: quinn::ClientConfig,
}

impl RawQuicClientConfig {
    /// Builds a TLS 1.3-only client configuration from DER trust anchors.
    pub fn new(
        profile: RawQuicPathProfile,
        trust_roots_der: Vec<Vec<u8>>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        limits.validate()?;
        if trust_roots_der.is_empty() {
            return Err(RawQuicError::InvalidTrust(
                "at least one trust root is required".into(),
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for root in trust_roots_der {
            roots
                .add(CertificateDer::from(root))
                .map_err(|error| RawQuicError::InvalidTrust(error.to_string()))?;
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| RawQuicError::InvalidTls(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|error| RawQuicError::InvalidTls(error.to_string()))?;
        let mut inner = quinn::ClientConfig::new(Arc::new(crypto));
        inner.transport_config(Arc::new(transport_config(limits)?));
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

/// Server policy built from a caller-owned certificate chain and private key.
#[cfg(test)]
#[derive(Clone)]
pub struct RawQuicServerConfig {
    profile: RawQuicPathProfile,
    limits: RawQuicLimits,
    inner: quinn::ServerConfig,
}

#[cfg(test)]
impl RawQuicServerConfig {
    /// Builds a TLS 1.3-only server configuration from owned DER material.
    pub fn new(
        profile: RawQuicPathProfile,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        limits: RawQuicLimits,
    ) -> Result<Self, RawQuicError> {
        limits.validate()?;
        if certificate_chain_der.is_empty() {
            return Err(RawQuicError::InvalidCertificate(
                "at least one server certificate is required".into(),
            ));
        }
        let certificate_chain = certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect::<Vec<_>>();
        let private_key = PrivateKeyDer::try_from(private_key_der)
            .map_err(|error| RawQuicError::InvalidPrivateKey(error.into()))?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| RawQuicError::InvalidTls(error.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(|error| RawQuicError::InvalidCertificate(error.to_string()))?;
        tls.alpn_protocols = vec![profile.alpn().as_bytes().to_vec()];
        tls.max_early_data_size = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|error| RawQuicError::InvalidTls(error.to_string()))?;
        let mut inner = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        inner.transport_config(Arc::new(transport_config(limits)?));
        Ok(Self {
            profile,
            limits,
            inner,
        })
    }
}

#[cfg(test)]
impl fmt::Debug for RawQuicServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicServerConfig")
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// A bound raw QUIC server endpoint.
#[cfg(test)]
pub struct RawQuicListener {
    endpoint: Endpoint,
    profile: RawQuicPathProfile,
    handshake_idle_timeout: Duration,
    max_inbound_bidirectional_streams: u32,
}

#[cfg(test)]
impl RawQuicListener {
    /// Binds a UDP endpoint after all TLS and resource policy has been validated.
    pub fn bind(address: SocketAddr, config: RawQuicServerConfig) -> Result<Self, RawQuicError> {
        let endpoint = Endpoint::server(config.inner, address).map_err(RawQuicError::Endpoint)?;
        Ok(Self {
            endpoint,
            profile: config.profile,
            handshake_idle_timeout: config.limits.handshake_idle_timeout,
            max_inbound_bidirectional_streams: config.limits.max_inbound_bidirectional_streams,
        })
    }

    /// Returns the effective local UDP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accepts one fully established, non-early raw QUIC session.
    pub async fn accept(&self) -> Result<RawQuicSession, RawQuicError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(RawQuicError::ListenerClosed)?;
        let connection = tokio::time::timeout(self.handshake_idle_timeout, incoming)
            .await
            .map_err(|_| RawQuicError::Handshake("deadline exceeded".into()))?
            .map_err(|error| RawQuicError::Handshake(error.to_string()))?;
        RawQuicSession::from_connection(
            connection,
            self.endpoint.clone(),
            self.profile,
            self.max_inbound_bidirectional_streams,
            false,
            None,
        )
    }
}

#[cfg(test)]
impl fmt::Debug for RawQuicListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicListener")
            .field("local_addr", &self.local_addr().ok())
            .field("profile", &self.profile)
            .field("handshake_idle_timeout", &self.handshake_idle_timeout)
            .finish_non_exhaustive()
    }
}

/// A bounded application close diagnostic.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawQuicApplicationError {
    /// QUIC application error code in the RFC 9000 varint range.
    pub code: u64,
    /// UTF-8 diagnostic bounded to 128 bytes.
    pub reason: String,
}

/// One established raw QUIC connection with native bidirectional streams.
#[derive(Clone)]
pub struct RawQuicSession {
    connection: quinn::Connection,
    endpoint: Endpoint,
    profile: RawQuicPathProfile,
    max_inbound_bidirectional_streams: u32,
    migration_allowed: bool,
    migration_lock: Arc<StdMutex<()>>,
    observed_route_local_address: Arc<StdMutex<Option<SocketAddr>>>,
}

impl RawQuicSession {
    /// Establishes a non-early client connection using the supplied trust policy.
    pub async fn dial(
        local_address: SocketAddr,
        remote_address: SocketAddr,
        server_name: &str,
        config: RawQuicClientConfig,
    ) -> Result<Self, RawQuicError> {
        let endpoint = Endpoint::client(local_address).map_err(RawQuicError::Endpoint)?;
        let connecting = endpoint
            .connect_with(config.inner, remote_address, server_name)
            .map_err(|error| RawQuicError::Connect(error.to_string()))?;
        let connection = tokio::time::timeout(config.limits.handshake_idle_timeout, connecting)
            .await
            .map_err(|_| RawQuicError::Handshake("deadline exceeded".into()))?
            .map_err(|error| RawQuicError::Handshake(error.to_string()))?;
        let observed_route_local_address = preferred_route_local_address(remote_address).ok();
        Self::from_connection(
            connection,
            endpoint,
            config.profile,
            config.limits.max_inbound_bidirectional_streams,
            true,
            observed_route_local_address,
        )
    }

    fn from_connection(
        connection: quinn::Connection,
        endpoint: Endpoint,
        expected_profile: RawQuicPathProfile,
        max_inbound_bidirectional_streams: u32,
        migration_allowed: bool,
        observed_route_local_address: Option<SocketAddr>,
    ) -> Result<Self, RawQuicError> {
        let handshake = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .ok_or(RawQuicError::InvalidNegotiatedAlpn)?;
        let negotiated = handshake
            .protocol
            .as_deref()
            .and_then(RawQuicPathProfile::from_alpn)
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
            max_inbound_bidirectional_streams,
            migration_allowed,
            migration_lock: Arc::new(StdMutex::new(())),
            observed_route_local_address: Arc::new(StdMutex::new(observed_route_local_address)),
        })
    }

    /// Returns the exact ALPN profile negotiated by TLS.
    #[cfg(test)]
    pub const fn negotiated_profile(&self) -> RawQuicPathProfile {
        self.profile
    }

    /// Returns the effective local UDP address currently carrying this connection.
    pub(crate) fn local_address(&self) -> Result<SocketAddr, RawQuicError> {
        self.endpoint.local_addr().map_err(RawQuicError::Migration)
    }

    /// Starts migration by rebinding a client-owned UDP endpoint.
    ///
    /// Quinn retains the old receive socket until traffic arrives on the new socket and
    /// performs QUIC path validation internally. Quinn does not expose path-validation
    /// completion or a recoverable old socket, so callers must not treat this synchronous
    /// return as validation completion or promise rollback after a successful rebind.
    /// Bind and rebind failures leave the previous endpoint socket in place.
    /// Listener-owned server sessions reject this operation because rebinding their
    /// shared endpoint would move unrelated accepted connections.
    pub(crate) fn migrate_local_address(
        &self,
        address: SocketAddr,
    ) -> Result<SocketAddr, RawQuicError> {
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
        self.local_address()
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

    #[cfg(test)]
    pub(crate) fn replace_observed_route_for_test(&self, address: SocketAddr) {
        *self
            .observed_route_local_address
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(address);
    }

    #[cfg(test)]
    pub(crate) fn peer_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Opens one native bidirectional QUIC stream.
    pub async fn open_stream(&self) -> Result<RawQuicStream, RawQuicError> {
        self.reconcile_active_path();
        let (send, receive) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| RawQuicError::Stream(error.to_string()))?;
        Ok(RawQuicStream::new(send, receive))
    }

    /// Accepts one native bidirectional QUIC stream.
    pub async fn accept_stream(&self) -> Result<RawQuicStream, RawQuicError> {
        self.reconcile_active_path();
        let (send, receive) = self
            .connection
            .accept_bi()
            .await
            .map_err(|error| RawQuicError::Stream(error.to_string()))?;
        Ok(RawQuicStream::new(send, receive))
    }

    fn unreliable_message_max_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    fn send_unreliable_message(
        &self,
        payload: Bytes,
    ) -> Result<(), crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        use crate::transport_v2::CarrierUnreliableMessageErrorV2 as Error;

        self.reconcile_active_path();
        let Some(maximum) = self.connection.max_datagram_size() else {
            return Err(Error::Unavailable);
        };
        if payload.len() > maximum {
            return Err(Error::TooLarge);
        }
        if self.connection.datagram_send_buffer_space() < payload.len() {
            return Err(Error::Dropped);
        }
        self.connection
            .send_datagram(payload)
            .map_err(|error| match error {
                quinn::SendDatagramError::UnsupportedByPeer
                | quinn::SendDatagramError::Disabled => Error::Unavailable,
                quinn::SendDatagramError::TooLarge => Error::TooLarge,
                quinn::SendDatagramError::ConnectionLost(_) => Error::Closed,
            })
    }

    async fn receive_unreliable_message(
        &self,
    ) -> Result<Bytes, crate::transport_v2::CarrierUnreliableMessageErrorV2> {
        self.reconcile_active_path();
        self.connection
            .read_datagram()
            .await
            .map_err(|_| crate::transport_v2::CarrierUnreliableMessageErrorV2::Closed)
    }

    /// Commits one already-spent FSB2 credential, requires an exact successful
    /// FSA2 response and clean peer FIN, then establishes Flowersec SessionV2
    /// over this same native QUIC connection.
    pub async fn commit_admission_and_establish_v2(
        self,
        raw_fsb2: &[u8],
        mut session_config: crate::session_v2::SessionConfigV2,
        session_contract: SessionContractV2,
    ) -> io::Result<Arc<dyn crate::transport_v2::SessionV2>> {
        let establish_deadline = session_config.deadlines.establish;
        tokio::time::timeout(establish_deadline, async move {
            let expected_carrier_limit = crate::transport_v2::carrier_inbound_stream_limit_v2(
                session_config.max_inbound_streams,
            )
            .map_err(io::Error::other)?;
            if self.max_inbound_bidirectional_streams != expected_carrier_limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "raw QUIC carrier stream limit does not match SessionV2 logical limit",
                ));
            }
            let expected_path = match self.profile {
                RawQuicPathProfile::Direct => crate::transport_v2::PathKind::Direct,
                RawQuicPathProfile::Tunnel => crate::transport_v2::PathKind::Tunnel,
            };
            if session_config.path != expected_path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "raw QUIC ALPN path does not match SessionV2 path",
                ));
            }
            session_contract.validate_against_config(&session_config)?;
            let binding = validate_raw_fsb2(raw_fsb2, self.profile, &session_config)?;
            if session_config.path == crate::transport_v2::PathKind::Direct
                && session_config.peer_admission_binding != Some(binding)
            {
                return Err(invalid_fsb2("direct FSB2 peer admission binding mismatch"));
            }
            session_config.local_admission_binding = binding;
            let admission = self.open_stream().await.map_err(io::Error::other)?;
            admission.write_all(raw_fsb2).await?;
            admission.close_write().await?;
            let mut header = [0; 8];
            read_exact_raw_quic(&admission, &mut header).await?;
            if &header[..4] != b"FSA2" || header[4] != 2 || header[5] != 0 || header[6..8] != [0, 0]
            {
                let _ = admission.reset().await;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "raw QUIC admission rejected",
                ));
            }
            let mut trailing = [0; 1];
            if admission.read(&mut trailing).await? != 0 {
                let _ = admission.reset().await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trailing FSA2 bytes",
                ));
            }
            drop(admission);
            crate::session_v2::establish_session_v2(Arc::new(self), session_config).await
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "raw QUIC admission and session establish timeout",
            )
        })?
    }

    /// Closes the session with a bounded application diagnostic.
    #[cfg(test)]
    pub fn close_with_error(
        &self,
        application_error: RawQuicApplicationError,
    ) -> Result<(), RawQuicError> {
        if application_error.code > MAX_APPLICATION_ERROR_CODE
            || application_error.reason.len() > MAX_APPLICATION_ERROR_REASON_BYTES
        {
            return Err(RawQuicError::InvalidApplicationError);
        }
        let code = VarInt::from_u64(application_error.code)
            .map_err(|_| RawQuicError::InvalidApplicationError)?;
        self.connection
            .close(code, application_error.reason.as_bytes());
        Ok(())
    }

    /// Closes the session with Flowersec's generic carrier shutdown code.
    pub fn close(&self) {
        self.connection
            .close(VarInt::from_u32(SESSION_CLOSE_CODE), &[]);
    }
}

fn preferred_route_local_address(remote: SocketAddr) -> io::Result<SocketAddr> {
    let bind_address = match remote.ip() {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let socket = std::net::UdpSocket::bind(bind_address)?;
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

async fn read_exact_raw_quic(stream: &RawQuicStream, mut payload: &mut [u8]) -> io::Result<()> {
    while !payload.is_empty() {
        let read = stream.read(payload).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "raw QUIC stream truncated",
            ));
        }
        payload = &mut payload[read..];
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Fsb2Candidate {
    carrier: String,
    id: String,
    normalized_url: String,
    wire_profile: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectFsb2Payload {
    candidate_set_hash_b64u: String,
    candidates: Vec<Fsb2Candidate>,
    channel_id: String,
    chosen_candidate_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    routing_token: String,
    session_contract_hash_b64u: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TunnelFsb2Payload {
    attach_token: String,
    candidate_set_hash_b64u: String,
    candidates: Vec<Fsb2Candidate>,
    channel_id: String,
    chosen_candidate_id: String,
    endpoint_instance_id: String,
    listener_audience: String,
    profile: String,
    rendezvous_group_id: String,
    role: u8,
    session_contract_hash_b64u: String,
}

fn invalid_fsb2(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn decode_fsb2_hash(value: &str) -> Result<[u8; 32], io::Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid_fsb2("invalid FSB2 hash encoding"))?;
    bytes
        .try_into()
        .map_err(|_| invalid_fsb2("FSB2 hash must be exactly 32 bytes"))
}

fn valid_fsb2_registry_id(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn valid_fsb2_candidate_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_fsb2_ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.is_ascii()
}

fn validate_fsb2_candidate(candidate: &Fsb2Candidate, path: RawQuicPathProfile) -> bool {
    if !valid_fsb2_candidate_id(&candidate.id) || candidate.normalized_url.is_empty() {
        return false;
    }
    if candidate
        .normalized_url
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b'?' | b'#' | b'%'))
    {
        return false;
    }
    let expected_path = match path {
        RawQuicPathProfile::Direct => "direct",
        RawQuicPathProfile::Tunnel => "tunnel",
    };
    let expected_profile = format!("flowersec-{expected_path}/2");
    if candidate.wire_profile != expected_profile {
        return false;
    }
    if candidate.normalized_url.len() > 2_048 {
        return false;
    }
    canonicalize_fsb2_candidate_url(path, &candidate.carrier, &candidate.normalized_url)
        .is_some_and(|canonical| canonical == candidate.normalized_url)
}

fn canonicalize_fsb2_candidate_url(
    path: RawQuicPathProfile,
    carrier: &str,
    value: &str,
) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let expected_path = match path {
        RawQuicPathProfile::Direct => "direct",
        RawQuicPathProfile::Tunnel => "tunnel",
    };
    let (scheme, required_path) = match carrier {
        "raw_quic" => ("quic", "".to_owned()),
        "websocket" => ("wss", format!("/flowersec/v2/{expected_path}")),
        "webtransport" => (
            "https",
            format!("/flowersec/webtransport/v2/{expected_path}"),
        ),
        _ => return None,
    };
    if parsed.scheme() != scheme {
        return None;
    }
    if carrier == "raw_quic" {
        if !matches!(parsed.path(), "" | "/") {
            return None;
        }
    } else if parsed.path() != required_path {
        return None;
    }
    let host = match parsed.host()? {
        Host::Domain(value) if !value.is_empty() && !value.ends_with('.') => {
            if value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
            {
                let address = value.parse::<Ipv4Addr>().ok()?;
                if address.to_string() != value {
                    return None;
                }
                address.to_string()
            } else {
                crate::idna_v2::lookup_ascii(value).ok()?
            }
        }
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => format!("[{value}]"),
        Host::Domain(_) => return None,
    };
    let port = parsed.port();
    if port == Some(0) {
        return None;
    }
    let mut canonical = format!("{scheme}://{host}");
    if let Some(port) = port.filter(|port| *port != 443) {
        canonical.push(':');
        canonical.push_str(&port.to_string());
    }
    canonical.push_str(&required_path);
    Some(canonical)
}

fn hash_fsb2_candidates(candidates: &[Fsb2Candidate]) -> Result<[u8; 32], io::Error> {
    let canonical = serde_json::to_vec(candidates)
        .map_err(|_| invalid_fsb2("cannot encode FSB2 candidate set"))?;
    let mut preimage = Vec::with_capacity(4 + canonical.len() + 24);
    preimage.extend_from_slice(b"flowersec-v2-candidates\0");
    preimage.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&canonical);
    Ok(sha2::Sha256::digest(preimage).into())
}

fn validate_fsb2_candidates(
    candidates: &[Fsb2Candidate],
    chosen_candidate_id: &str,
    path: RawQuicPathProfile,
    candidate_set_hash_b64u: &str,
) -> Result<(), io::Error> {
    if candidates.is_empty() || candidates.len() > MAX_FSB2_CANDIDATES {
        return Err(invalid_fsb2("invalid FSB2 candidate count"));
    }
    let mut ids = HashSet::with_capacity(candidates.len());
    let mut tuples = HashSet::with_capacity(candidates.len());
    for candidate in candidates {
        if !ids.insert(candidate.id.clone())
            || !tuples.insert((
                candidate.carrier.clone(),
                candidate.normalized_url.clone(),
                candidate.wire_profile.clone(),
            ))
            || !validate_fsb2_candidate(candidate, path)
        {
            return Err(invalid_fsb2("invalid FSB2 candidate"));
        }
    }
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|left, right| left.id.cmp(&right.id));
    if sorted != candidates {
        return Err(invalid_fsb2("FSB2 candidates are not canonical"));
    }
    if !candidates
        .iter()
        .any(|candidate| candidate.id == chosen_candidate_id)
    {
        return Err(invalid_fsb2("FSB2 chosen candidate is absent"));
    }
    let chosen = candidates
        .iter()
        .find(|candidate| candidate.id == chosen_candidate_id)
        .expect("chosen candidate checked above");
    if chosen.carrier != "raw_quic" {
        return Err(invalid_fsb2("FSB2 chosen candidate is not raw QUIC"));
    }
    if decode_fsb2_hash(candidate_set_hash_b64u)? != hash_fsb2_candidates(candidates)? {
        return Err(invalid_fsb2("FSB2 candidate set hash mismatch"));
    }
    Ok(())
}

fn validate_fsb2_common(
    profile: &str,
    channel_id: &str,
    listener_audience: &str,
    rendezvous_group_id: &str,
    session_contract_hash_b64u: &str,
    expected_channel_id: &str,
    expected_session_contract_hash: [u8; 32],
) -> Result<(), io::Error> {
    if profile != "flowersec/2"
        || !valid_fsb2_registry_id(channel_id, 128)
        || !valid_fsb2_registry_id(listener_audience, 128)
        || !valid_fsb2_registry_id(rendezvous_group_id, 128)
    {
        return Err(invalid_fsb2("invalid FSB2 common fields"));
    }
    if channel_id != expected_channel_id
        || decode_fsb2_hash(session_contract_hash_b64u)? != expected_session_contract_hash
    {
        return Err(invalid_fsb2("FSB2 session contract binding mismatch"));
    }
    Ok(())
}

fn validate_raw_fsb2(
    raw_fsb2: &[u8],
    expected_profile: RawQuicPathProfile,
    session_config: &crate::session_v2::SessionConfigV2,
) -> Result<[u8; 32], io::Error> {
    if raw_fsb2.len() < FSB2_HEADER_BYTES || &raw_fsb2[..4] != b"FSB2" || raw_fsb2[4] != 2 {
        return Err(invalid_fsb2("invalid FSB2 header"));
    }
    let expected_path = match expected_profile {
        RawQuicPathProfile::Direct => 1,
        RawQuicPathProfile::Tunnel => 2,
    };
    if raw_fsb2[5] != expected_path || raw_fsb2[6..8] != [0, 0] {
        return Err(invalid_fsb2("FSB2 path or reserved bytes mismatch"));
    }
    let payload_length =
        u32::from_be_bytes(raw_fsb2[8..12].try_into().expect("header length")) as usize;
    if payload_length == 0 || payload_length > MAX_FSB2_PAYLOAD_BYTES {
        return Err(invalid_fsb2("invalid FSB2 payload length"));
    }
    if raw_fsb2.len() != FSB2_HEADER_BYTES + payload_length {
        return Err(invalid_fsb2("FSB2 truncation or trailing bytes"));
    }
    let payload = &raw_fsb2[FSB2_HEADER_BYTES..];
    match expected_profile {
        RawQuicPathProfile::Direct => {
            let request: DirectFsb2Payload = serde_json::from_slice(payload)
                .map_err(|_| invalid_fsb2("invalid direct FSB2 JSON"))?;
            let canonical = serde_json::to_vec(&request)
                .map_err(|_| invalid_fsb2("cannot encode direct FSB2 JSON"))?;
            if canonical != payload {
                return Err(invalid_fsb2("non-canonical direct FSB2 JSON"));
            }
            validate_fsb2_common(
                &request.profile,
                &request.channel_id,
                &request.listener_audience,
                &request.rendezvous_group_id,
                &request.session_contract_hash_b64u,
                &session_config.channel_id,
                session_config.session_contract_hash,
            )?;
            if session_config.path != crate::transport_v2::PathKind::Direct
                || session_config.role != crate::transport_v2::SessionRole::Client
                || session_config.local_endpoint_instance_id.is_some()
                || session_config.expected_peer_endpoint_instance_id.is_some()
            {
                return Err(invalid_fsb2("direct FSB2/session shape mismatch"));
            }
            if !valid_fsb2_ascii(&request.routing_token, MAX_FSB2_CREDENTIAL_BYTES) {
                return Err(invalid_fsb2("invalid direct FSB2 routing token"));
            }
            validate_fsb2_candidates(
                &request.candidates,
                &request.chosen_candidate_id,
                expected_profile,
                &request.candidate_set_hash_b64u,
            )?;
        }
        RawQuicPathProfile::Tunnel => {
            let request: TunnelFsb2Payload = serde_json::from_slice(payload)
                .map_err(|_| invalid_fsb2("invalid tunnel FSB2 JSON"))?;
            let canonical = serde_json::to_vec(&request)
                .map_err(|_| invalid_fsb2("cannot encode tunnel FSB2 JSON"))?;
            if canonical != payload {
                return Err(invalid_fsb2("non-canonical tunnel FSB2 JSON"));
            }
            validate_fsb2_common(
                &request.profile,
                &request.channel_id,
                &request.listener_audience,
                &request.rendezvous_group_id,
                &request.session_contract_hash_b64u,
                &session_config.channel_id,
                session_config.session_contract_hash,
            )?;
            let expected_role = match session_config.role {
                crate::transport_v2::SessionRole::Client => 1,
                crate::transport_v2::SessionRole::Server => 2,
            };
            if session_config.path != crate::transport_v2::PathKind::Tunnel
                || request.role != expected_role
                || session_config.local_endpoint_instance_id.as_deref()
                    != Some(request.endpoint_instance_id.as_str())
            {
                return Err(invalid_fsb2("tunnel FSB2/session shape mismatch"));
            }
            if !matches!(request.role, 1 | 2)
                || !valid_fsb2_registry_id(&request.endpoint_instance_id, 128)
                || !valid_fsb2_ascii(&request.attach_token, MAX_FSB2_CREDENTIAL_BYTES)
            {
                return Err(invalid_fsb2("invalid tunnel FSB2 endpoint fields"));
            }
            validate_fsb2_candidates(
                &request.candidates,
                &request.chosen_candidate_id,
                expected_profile,
                &request.candidate_set_hash_b64u,
            )?;
        }
    }
    let mut binding_preimage = b"flowersec-v2-admission\0".to_vec();
    binding_preimage.extend_from_slice(raw_fsb2);
    let binding: [u8; 32] = sha2::Sha256::digest(binding_preimage).into();
    if session_config.local_admission_binding != [0; 32]
        && session_config.local_admission_binding != binding
    {
        return Err(invalid_fsb2("FSB2 admission binding mismatch"));
    }
    Ok(binding)
}

impl fmt::Debug for RawQuicSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicSession")
            .field("profile", &self.profile)
            .field("remote_address", &self.connection.remote_address())
            .field("local_address", &self.endpoint.local_addr().ok())
            .finish_non_exhaustive()
    }
}

/// One reliable native QUIC bidirectional stream.
pub struct RawQuicStream {
    id: u64,
    send: Mutex<quinn::SendStream>,
    receive: Mutex<quinn::RecvStream>,
    canceled: CancellationToken,
    send_finished: AtomicBool,
    reset: AtomicBool,
}

impl RawQuicStream {
    fn new(send: quinn::SendStream, receive: quinn::RecvStream) -> Self {
        let id = VarInt::from(send.id()).into_inner();
        debug_assert_eq!(id, VarInt::from(receive.id()).into_inner());
        Self {
            id,
            send: Mutex::new(send),
            receive: Mutex::new(receive),
            canceled: CancellationToken::new(),
            send_finished: AtomicBool::new(false),
            reset: AtomicBool::new(false),
        }
    }

    /// Reads bytes, returning zero only after a clean peer FIN.
    pub async fn read(&self, payload: &mut [u8]) -> io::Result<usize> {
        if self.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        let canceled = self.canceled.cancelled();
        let mut receive = self.receive.lock().await;
        tokio::select! {
            biased;
            _ = canceled => Err(local_reset_error()),
            result = receive.read(payload) => result
                .map(|read| read.unwrap_or(0))
                .map_err(io::Error::from),
        }
    }

    /// Writes some bytes while preserving independent receive progress.
    pub async fn write(&self, payload: &[u8]) -> io::Result<usize> {
        if self.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.send_finished.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "raw QUIC send direction is finished",
            ));
        }
        let canceled = self.canceled.cancelled();
        let mut send = self.send.lock().await;
        if self.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.send_finished.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "raw QUIC send direction is finished",
            ));
        }
        tokio::select! {
            biased;
            _ = canceled => Err(local_reset_error()),
            result = send.write(payload) => result.map_err(io::Error::from),
        }
    }

    /// Writes the full payload or returns the first transport failure.
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

    /// Sends a native FIN while leaving the receive direction readable.
    pub async fn close_write(&self) -> io::Result<()> {
        if self.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        let canceled = self.canceled.cancelled();
        let mut send = self.send.lock().await;
        if self.reset.load(Ordering::Acquire) {
            return Err(local_reset_error());
        }
        if self.send_finished.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        tokio::select! {
            biased;
            _ = canceled => Err(local_reset_error()),
            result = async { send.finish() } => result.map_err(|error| {
                io::Error::new(io::ErrorKind::BrokenPipe, error)
            }),
        }
    }

    /// Sends both RESET_STREAM and STOP_SENDING using Flowersec's stable reset code.
    pub async fn reset(&self) -> io::Result<()> {
        if self.reset.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.canceled.cancel();
        let code = VarInt::from_u32(STREAM_RESET_CODE);
        let mut send = self.send.lock().await;
        let _ = send.reset(code);
        drop(send);
        let mut receive = self.receive.lock().await;
        let _ = receive.stop(code);
        Ok(())
    }
}

impl fmt::Debug for RawQuicStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawQuicStream")
            .field("id", &self.id)
            .field("send_finished", &self.send_finished.load(Ordering::Acquire))
            .field("reset", &self.reset.load(Ordering::Acquire))
            .finish_non_exhaustive()
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
        self.max_inbound_bidirectional_streams
    }

    async fn open_stream(&self) -> io::Result<Arc<dyn crate::transport_v2::CarrierStreamV2>> {
        RawQuicSession::open_stream(self)
            .await
            .map(|stream| Arc::new(stream) as Arc<dyn crate::transport_v2::CarrierStreamV2>)
            .map_err(io::Error::other)
    }

    async fn accept_stream(&self) -> io::Result<Arc<dyn crate::transport_v2::CarrierStreamV2>> {
        RawQuicSession::accept_stream(self)
            .await
            .map(|stream| Arc::new(stream) as Arc<dyn crate::transport_v2::CarrierStreamV2>)
            .map_err(io::Error::other)
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
}

fn transport_config(limits: RawQuicLimits) -> Result<quinn::TransportConfig, RawQuicError> {
    limits.validate()?;
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(limits.max_inbound_bidirectional_streams))
        .max_concurrent_uni_streams(0_u32.into())
        .stream_receive_window(
            VarInt::from_u64(limits.stream_receive_window)
                .map_err(|_| RawQuicError::InvalidLimits("invalid stream receive window"))?,
        )
        .receive_window(
            VarInt::from_u64(limits.connection_receive_window)
                .map_err(|_| RawQuicError::InvalidLimits("invalid connection receive window"))?,
        )
        .send_window(limits.connection_receive_window)
        .max_idle_timeout(Some(limits.max_idle_timeout.try_into().map_err(|_| {
            RawQuicError::InvalidLimits("invalid connection idle timeout")
        })?))
        .keep_alive_interval(Some(limits.keep_alive_interval))
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_SEND_BUFFER_BYTES);
    Ok(transport)
}

fn local_reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "raw QUIC stream was reset")
}

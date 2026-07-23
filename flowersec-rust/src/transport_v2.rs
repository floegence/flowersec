use std::{
    fmt, io,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical JSON metadata attached to a logical v2 stream.
pub type JsonObjectV2 = serde_json::Map<String, serde_json::Value>;

/// One reliable bidirectional carrier stream before Flowersec encryption.
///
/// Implementations expose native directional shutdown. In particular, the raw
/// QUIC implementation maps these operations to QUIC FIN, RESET_STREAM, and
/// STOP_SENDING rather than inserting a second multiplexing protocol.
#[async_trait]
pub trait CarrierStreamV2: fmt::Debug + Send + Sync + 'static {
    /// Reads carrier bytes, returning zero only after peer FIN.
    async fn read(&self, payload: &mut [u8]) -> io::Result<usize>;
    /// Writes some carrier bytes.
    async fn write(&self, payload: &[u8]) -> io::Result<usize>;
    /// Finishes the local send direction while preserving receive progress.
    async fn close_write(&self) -> io::Result<()>;
    /// Aborts both directions with the carrier's stable generic reset code.
    async fn reset(&self) -> io::Result<()>;
    /// Releases local resources after bounded shutdown.
    async fn close(&self) -> io::Result<()>;
}

/// Carrier-neutral source of reliable bidirectional streams.
#[async_trait]
pub trait CarrierSessionV2: fmt::Debug + Send + Sync + 'static {
    /// Returns the carrier represented by this session.
    #[cfg_attr(not(test), allow(dead_code))]
    fn kind(&self) -> CarrierKind;
    /// Returns the exact physical peer-initiated bidirectional stream capacity.
    /// Implementations must bind it before any FSC2/FSH2 bytes are written.
    fn inbound_bidirectional_stream_capacity(&self) -> u32;
    /// Opens one outbound carrier stream.
    async fn open_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>>;
    /// Accepts one peer-opened carrier stream.
    async fn accept_stream(&self) -> io::Result<Arc<dyn CarrierStreamV2>>;
    /// Returns the currently negotiated maximum carrier datagram size.
    /// `None` means this connection cannot carry unreliable messages.
    fn unreliable_message_max_size(&self) -> Option<usize> {
        None
    }
    /// Sends one unreliable carrier message without waiting for reliable
    /// delivery or falling back to a stream.
    async fn send_unreliable_message(
        &self,
        _payload: Bytes,
    ) -> Result<(), CarrierUnreliableMessageErrorV2> {
        Err(CarrierUnreliableMessageErrorV2::Unavailable)
    }
    /// Receives one unreliable carrier message.
    async fn receive_unreliable_message(&self) -> Result<Bytes, CarrierUnreliableMessageErrorV2> {
        Err(CarrierUnreliableMessageErrorV2::Unavailable)
    }
    /// Closes the complete carrier session.
    async fn close(&self) -> io::Result<()>;
}

/// Closed carrier-level failure set used by the encrypted unreliable-message
/// layer without exposing a concrete QUIC or WebTransport implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CarrierUnreliableMessageErrorV2 {
    #[error("unreliable messages are unavailable on this carrier")]
    Unavailable,
    #[error("unreliable message exceeds the negotiated maximum")]
    TooLarge,
    #[error("unreliable message was dropped by the bounded send budget")]
    Dropped,
    #[error("unreliable message carrier is closed")]
    Closed,
}

/// Maximum logical application streams accepted from one peer in SessionV2.
pub const MAX_LOGICAL_INBOUND_STREAMS_V2: u16 = 128;

/// Describes why a logical SessionV2 limit cannot be mapped to its carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CarrierStreamLimitErrorV2 {
    #[error("logical max inbound streams must be in 1..=128, got {0}")]
    InvalidLogicalLimit(u16),
    #[error("carrier inbound stream limit overflow")]
    Overflow,
}

/// Maps the logical application-stream limit to the exact carrier limit.
///
/// The two additional peer-initiated bidirectional streams are reserved for
/// the lifetime control stream and the persistent RPC stream. Admission has
/// completed and released its stream before SessionV2 establishes them.
pub fn carrier_inbound_stream_limit_v2(logical_max: u16) -> Result<u32, CarrierStreamLimitErrorV2> {
    if !(1..=MAX_LOGICAL_INBOUND_STREAMS_V2).contains(&logical_max) {
        return Err(CarrierStreamLimitErrorV2::InvalidLogicalLimit(logical_max));
    }
    u32::from(logical_max)
        .checked_add(2)
        .ok_or(CarrierStreamLimitErrorV2::Overflow)
}

/// Identifies a carrier without exposing its concrete implementation type.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CarrierKind {
    /// WebSocket over TLS.
    #[serde(rename = "websocket")]
    Wss,
    /// Native QUIC streams, without HTTP/3 or WebTransport framing.
    #[serde(rename = "raw_quic")]
    RawQuic,
    /// WebTransport over HTTP/3.
    #[serde(rename = "webtransport")]
    WebTransport,
}

/// Describes how the local transport obtains its network connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Dial,
    Listen,
}

/// Describes the Flowersec session role independently from [`NetworkMode`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionRole {
    Client,
    Server,
}

/// Identifies the Flowersec path independently from its carrier.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Direct,
    Tunnel,
}

/// One exact supported combination of carrier, network mode, role, and path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CapabilityTupleV2 {
    pub carrier: CarrierKind,
    pub network_mode: NetworkMode,
    pub session_role: SessionRole,
    pub path: PathKind,
}

/// One explicit unsupported carrier reason. Absence is never interpreted as
/// support because every registered carrier must appear on exactly one side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UnsupportedRuntimeCarrierV2 {
    pub carrier: CarrierKind,
    pub reason: String,
}

/// Flat runtime capability descriptor shared across all SDK languages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeCapabilityDescriptorV2 {
    pub language: String,
    pub runtime: String,
    pub schema_version: u8,
    pub tuples: Vec<CapabilityTupleV2>,
    pub unsupported: Vec<UnsupportedRuntimeCarrierV2>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl CapabilityTupleV2 {
    /// Creates a capability tuple without changing or inferring any dimension.
    pub const fn new(
        carrier: CarrierKind,
        network_mode: NetworkMode,
        session_role: SessionRole,
        path: PathKind,
    ) -> Self {
        Self {
            carrier,
            network_mode,
            session_role,
            path,
        }
    }

    /// Returns whether the tuple represents a legal Flowersec deployment role.
    pub const fn is_valid(self) -> bool {
        matches!(
            (self.network_mode, self.session_role, self.path),
            (NetworkMode::Dial, SessionRole::Client, PathKind::Direct)
                | (NetworkMode::Listen, SessionRole::Server, PathKind::Direct)
                | (NetworkMode::Dial, SessionRole::Client, PathKind::Tunnel)
                | (NetworkMode::Dial, SessionRole::Server, PathKind::Tunnel)
        )
    }
}

/// Exact end-to-end v2 tuples supported by the native Rust runtime.
///
/// The production connector proves direct client dialing and both tunnel
/// session roles. The runtime-owned listener proves the direct server role.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const NATIVE_RUST_CAPABILITIES_V2: &[CapabilityTupleV2] = &[
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Direct,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Tunnel,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Server,
        PathKind::Tunnel,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Listen,
        SessionRole::Server,
        PathKind::Direct,
    ),
];

/// Builds the canonical descriptor advertised by the native Rust runtime.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn native_rust_capability_descriptor_v2() -> RuntimeCapabilityDescriptorV2 {
    RuntimeCapabilityDescriptorV2 {
        language: "rust".into(),
        runtime: "native".into(),
        schema_version: 2,
        tuples: NATIVE_RUST_CAPABILITIES_V2.to_vec(),
        unsupported: vec![
            UnsupportedRuntimeCarrierV2 {
                carrier: CarrierKind::Wss,
                reason: "transport_v2_websocket_adapter_not_committed".into(),
            },
            UnsupportedRuntimeCarrierV2 {
                carrier: CarrierKind::WebTransport,
                reason: "rust_webtransport_not_committed".into(),
            },
        ],
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityTupleWireV2 {
    carrier: CarrierKind,
    #[serde(rename = "networkMode")]
    network_mode: NetworkMode,
    path: PathKind,
    #[serde(rename = "sessionRole")]
    session_role: SessionRole,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsupportedRuntimeCarrierWireV2 {
    carrier: CarrierKind,
    reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCapabilityWireV2 {
    language: String,
    runtime: String,
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    tuples: Vec<CapabilityTupleWireV2>,
    unsupported: Vec<UnsupportedRuntimeCarrierWireV2>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum RuntimeCapabilityCodecErrorV2 {
    #[error("invalid runtime capability descriptor")]
    Invalid,
    #[error("runtime capability descriptor is not canonical JSON")]
    NonCanonical,
    #[error("runtime capability descriptor codec failed")]
    Codec,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encode_runtime_capability_descriptor_v2(
    descriptor: &RuntimeCapabilityDescriptorV2,
) -> Result<Vec<u8>, RuntimeCapabilityCodecErrorV2> {
    validate_runtime_capability_descriptor_v2(descriptor)?;
    let wire = RuntimeCapabilityWireV2 {
        language: descriptor.language.clone(),
        runtime: descriptor.runtime.clone(),
        schema_version: descriptor.schema_version,
        tuples: descriptor
            .tuples
            .iter()
            .map(|tuple| CapabilityTupleWireV2 {
                carrier: tuple.carrier,
                network_mode: tuple.network_mode,
                path: tuple.path,
                session_role: tuple.session_role,
            })
            .collect(),
        unsupported: descriptor
            .unsupported
            .iter()
            .map(|value| UnsupportedRuntimeCarrierWireV2 {
                carrier: value.carrier,
                reason: value.reason.clone(),
            })
            .collect(),
    };
    serde_json::to_vec(&wire).map_err(|_| RuntimeCapabilityCodecErrorV2::Codec)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_runtime_capability_descriptor_v2(
    raw: &[u8],
) -> Result<RuntimeCapabilityDescriptorV2, RuntimeCapabilityCodecErrorV2> {
    let wire: RuntimeCapabilityWireV2 =
        serde_json::from_slice(raw).map_err(|_| RuntimeCapabilityCodecErrorV2::Codec)?;
    let descriptor = RuntimeCapabilityDescriptorV2 {
        language: wire.language,
        runtime: wire.runtime,
        schema_version: wire.schema_version,
        tuples: wire
            .tuples
            .into_iter()
            .map(|tuple| CapabilityTupleV2 {
                carrier: tuple.carrier,
                network_mode: tuple.network_mode,
                session_role: tuple.session_role,
                path: tuple.path,
            })
            .collect(),
        unsupported: wire
            .unsupported
            .into_iter()
            .map(|value| UnsupportedRuntimeCarrierV2 {
                carrier: value.carrier,
                reason: value.reason,
            })
            .collect(),
    };
    let canonical = encode_runtime_capability_descriptor_v2(&descriptor)?;
    if canonical != raw {
        return Err(RuntimeCapabilityCodecErrorV2::NonCanonical);
    }
    Ok(descriptor)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn runtime_capability_digest_v2(
    descriptor: &RuntimeCapabilityDescriptorV2,
) -> Result<[u8; 32], RuntimeCapabilityCodecErrorV2> {
    let canonical = encode_runtime_capability_descriptor_v2(descriptor)?;
    let mut hasher = Sha256::new();
    hasher.update(b"flowersec-v2-runtime-capability\0");
    hasher.update((canonical.len() as u32).to_be_bytes());
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn runtime_capability_digest_hex_v2(
    descriptor: &RuntimeCapabilityDescriptorV2,
) -> Result<String, RuntimeCapabilityCodecErrorV2> {
    use std::fmt::Write as _;

    let digest = runtime_capability_digest_v2(descriptor)?;
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing into String cannot fail");
    }
    Ok(encoded)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_runtime_capability_descriptor_v2(
    descriptor: &RuntimeCapabilityDescriptorV2,
) -> Result<(), RuntimeCapabilityCodecErrorV2> {
    if descriptor.schema_version != 2
        || !valid_registry_token(&descriptor.language)
        || !valid_registry_token(&descriptor.runtime)
        || descriptor.tuples.is_empty() && descriptor.unsupported.is_empty()
    {
        return Err(RuntimeCapabilityCodecErrorV2::Invalid);
    }
    let mut supported = std::collections::BTreeSet::new();
    for (index, tuple) in descriptor.tuples.iter().enumerate() {
        if !tuple.is_valid()
            || index > 0 && capability_tuple_cmp(&descriptor.tuples[index - 1], tuple).is_ge()
        {
            return Err(RuntimeCapabilityCodecErrorV2::Invalid);
        }
        supported.insert(tuple.carrier);
    }
    let mut unsupported = std::collections::BTreeSet::new();
    for (index, value) in descriptor.unsupported.iter().enumerate() {
        if !valid_registry_token(&value.reason)
            || supported.contains(&value.carrier)
            || index > 0
                && carrier_name(descriptor.unsupported[index - 1].carrier)
                    >= carrier_name(value.carrier)
        {
            return Err(RuntimeCapabilityCodecErrorV2::Invalid);
        }
        unsupported.insert(value.carrier);
    }
    for carrier in [
        CarrierKind::RawQuic,
        CarrierKind::Wss,
        CarrierKind::WebTransport,
    ] {
        if supported.contains(&carrier) == unsupported.contains(&carrier) {
            return Err(RuntimeCapabilityCodecErrorV2::Invalid);
        }
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]
fn valid_registry_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit() && index > 0
                || byte == b'_' && index > 0
        })
}

#[cfg_attr(not(test), allow(dead_code))]
fn capability_tuple_cmp(left: &CapabilityTupleV2, right: &CapabilityTupleV2) -> std::cmp::Ordering {
    (
        carrier_name(left.carrier),
        network_mode_name(left.network_mode),
        session_role_name(left.session_role),
        path_name(left.path),
    )
        .cmp(&(
            carrier_name(right.carrier),
            network_mode_name(right.network_mode),
            session_role_name(right.session_role),
            path_name(right.path),
        ))
}

#[cfg_attr(not(test), allow(dead_code))]
const fn carrier_name(value: CarrierKind) -> &'static str {
    match value {
        CarrierKind::RawQuic => "raw_quic",
        CarrierKind::Wss => "websocket",
        CarrierKind::WebTransport => "webtransport",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
const fn network_mode_name(value: NetworkMode) -> &'static str {
    match value {
        NetworkMode::Dial => "dial",
        NetworkMode::Listen => "listen",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
const fn session_role_name(value: SessionRole) -> &'static str {
    match value {
        SessionRole::Client => "client",
        SessionRole::Server => "server",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
const fn path_name(value: PathKind) -> &'static str {
    match value {
        PathKind::Direct => "direct",
        PathKind::Tunnel => "tunnel",
    }
}

/// Describes why a capability registry is not safe to advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum CapabilityValidationErrorV2 {
    #[error("duplicate capability tuple: {0:?}")]
    Duplicate(CapabilityTupleV2),
    #[error("invalid capability tuple: {0:?}")]
    Invalid(CapabilityTupleV2),
}

/// Rejects invalid and duplicate tuples without filling in inferred capabilities.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_capabilities_v2(
    capabilities: &[CapabilityTupleV2],
) -> Result<(), CapabilityValidationErrorV2> {
    for (index, capability) in capabilities.iter().copied().enumerate() {
        if !capability.is_valid() {
            return Err(CapabilityValidationErrorV2::Invalid(capability));
        }
        if capabilities[..index].contains(&capability) {
            return Err(CapabilityValidationErrorV2::Duplicate(capability));
        }
    }
    Ok(())
}

/// Stable, redacted terminal state for an encrypted logical byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StreamTerminalError {
    #[error("Flowersec stream closed")]
    Closed,
    #[error("Flowersec stream failed")]
    Failed,
    #[error("Flowersec stream reset")]
    Reset,
    #[error("Flowersec stream timed out")]
    TimedOut,
}

/// Closed, redacted failure set shared by public session, stream, and RPC operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("Flowersec operation was canceled")]
    Canceled,
    #[error("Flowersec session is closed")]
    Closed,
    #[error("invalid Flowersec operation")]
    InvalidInput,
    #[error("Flowersec operation was rejected")]
    Rejected,
    #[error("Flowersec resources are exhausted")]
    ResourceExhausted,
    #[error("Flowersec stream was reset")]
    Reset,
    #[error("Flowersec operation timed out")]
    TimedOut,
    #[error("Flowersec operation failed")]
    Failed,
}

/// Stable, redacted failure set for carrier-neutral unreliable messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnreliableMessageError {
    #[error("unreliable messages are unavailable for this session")]
    Unavailable,
    #[error("invalid unreliable message")]
    InvalidInput,
    #[error("unreliable message exceeds the negotiated maximum")]
    TooLarge,
    #[error("unreliable message expired before it was sent")]
    Expired,
    #[error("unreliable message was dropped by the bounded send budget")]
    DroppedBudget,
    #[error("unreliable message operation was canceled")]
    Canceled,
    #[error("unreliable message channel is closed")]
    Closed,
    #[error("unreliable message operation failed")]
    Failed,
}

/// Observable result of submitting one message to the native unreliable
/// carrier. It does not imply delivery or ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreliableSendOutcome {
    Accepted,
}

/// Opaque, carrier-neutral unreliable message access owned by a session.
#[async_trait]
pub trait UnreliableMessageChannelV2: fmt::Debug + Send + Sync + 'static {
    /// Maximum plaintext size accepted on this channel.
    fn max_message_size(&self) -> usize;
    /// Authenticates and submits one message with an absolute expiration time.
    async fn send(
        &self,
        payload: Bytes,
        expires_at: SystemTime,
    ) -> Result<UnreliableSendOutcome, UnreliableMessageError>;
    /// Receives the next authenticated, unexpired, non-replayed message.
    async fn receive(&self) -> Result<Bytes, UnreliableMessageError>;
}

impl SessionError {
    pub(crate) fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::Interrupted => Self::Canceled,
            io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof => Self::Closed,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Self::InvalidInput,
            io::ErrorKind::PermissionDenied => Self::Rejected,
            io::ErrorKind::OutOfMemory => Self::ResourceExhausted,
            io::ErrorKind::ConnectionReset => Self::Reset,
            io::ErrorKind::TimedOut => Self::TimedOut,
            _ => Self::Failed,
        }
    }
}

impl From<SessionError> for io::Error {
    fn from(error: SessionError) -> Self {
        let kind = match error {
            SessionError::Canceled => io::ErrorKind::Interrupted,
            SessionError::Closed => io::ErrorKind::ConnectionAborted,
            SessionError::InvalidInput => io::ErrorKind::InvalidInput,
            SessionError::Rejected => io::ErrorKind::PermissionDenied,
            SessionError::ResourceExhausted => io::ErrorKind::OutOfMemory,
            SessionError::Reset => io::ErrorKind::ConnectionReset,
            SessionError::TimedOut => io::ErrorKind::TimedOut,
            SessionError::Failed => io::ErrorKind::Other,
        };
        io::Error::new(kind, error)
    }
}

/// A reliable encrypted logical byte stream independent of the active carrier.
#[async_trait]
pub trait ByteStreamV2: fmt::Debug + Send + Sync + 'static {
    #[cfg(test)]
    fn internal_test_id(&self) -> u64;
    /// Application stream kind negotiated by the Flowersec v2 stream setup.
    fn kind(&self) -> &str;
    /// Stable terminal failure, if the stream has already terminated abnormally.
    /// The closed enum cannot retain carrier diagnostics, peer payloads, or secrets.
    fn terminal_error(&self) -> Option<StreamTerminalError>;
    /// Reads the next non-empty byte chunk, or `None` after peer FIN.
    async fn read(&self) -> Result<Option<Bytes>, SessionError>;
    /// Writes bytes and returns the accepted byte count.
    async fn write(&self, payload: Bytes) -> Result<usize, SessionError>;
    /// Sends logical FIN while keeping the receive direction available.
    async fn close_write(&self) -> Result<(), SessionError>;
    /// Aborts both logical directions using the stable generic reset state.
    async fn reset(&self) -> Result<(), SessionError>;
    /// Releases the stream and performs bounded local cleanup.
    async fn close(&self) -> Result<(), SessionError>;
}

/// One accepted logical stream and its authenticated setup metadata.
pub struct IncomingStreamV2 {
    kind: String,
    metadata: JsonObjectV2,
    stream: Box<dyn ByteStreamV2>,
}

impl IncomingStreamV2 {
    /// Wraps an accepted stream after its v2 setup metadata has been authenticated.
    pub fn new(
        kind: impl Into<String>,
        metadata: JsonObjectV2,
        stream: Box<dyn ByteStreamV2>,
    ) -> Self {
        Self {
            kind: kind.into(),
            metadata,
            stream,
        }
    }

    #[cfg(test)]
    pub(crate) fn internal_test_id(&self) -> u64 {
        self.stream.internal_test_id()
    }

    /// Returns the application stream kind.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the authenticated stream metadata.
    pub fn metadata(&self) -> &JsonObjectV2 {
        &self.metadata
    }

    /// Borrows the carrier-neutral byte stream.
    pub fn stream(&self) -> &dyn ByteStreamV2 {
        self.stream.as_ref()
    }

    /// Consumes the incoming record and returns its byte stream.
    pub fn into_stream(self) -> Box<dyn ByteStreamV2> {
        self.stream
    }
}

impl fmt::Debug for IncomingStreamV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncomingStreamV2")
            .field("kind", &self.kind)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Carrier-neutral RPC access owned by a v2 session.
#[async_trait]
pub trait RpcPeerV2: fmt::Debug + Send + Sync + 'static {
    /// Performs one request-response call using a canonical JSON payload.
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, SessionError>;
    /// Sends one notification without waiting for an application response.
    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), SessionError>;
}

/// Public Flowersec v2 session contract shared by WSS and raw QUIC.
#[async_trait]
pub trait SessionV2: fmt::Debug + Send + Sync + 'static {
    /// Borrows the session's carrier-neutral RPC peer.
    fn rpc(&self) -> &dyn RpcPeerV2;
    /// Borrows unreliable message access after FSH2 negotiation and READY.
    fn unreliable_messages(
        &self,
    ) -> Result<&dyn UnreliableMessageChannelV2, UnreliableMessageError> {
        Err(UnreliableMessageError::Unavailable)
    }
    /// Opens an encrypted logical stream with canonical setup metadata.
    async fn open_stream(
        &self,
        kind: &str,
        metadata: JsonObjectV2,
    ) -> Result<Box<dyn ByteStreamV2>, SessionError>;
    /// Accepts the next authenticated logical stream.
    async fn accept_stream(&self) -> Result<IncomingStreamV2, SessionError>;
    /// Advances the session key epoch.
    async fn rekey(&self) -> Result<(), SessionError>;
    /// Performs a carrier-neutral liveness probe and returns its round-trip time.
    async fn probe_liveness(&self) -> Result<Duration, SessionError>;
    /// Waits for authoritative session termination and returns its stable cause.
    /// Canceling this future never changes the session state.
    async fn wait_closed(&self) -> Result<(), SessionError>;
    /// Closes the session and performs bounded local cleanup.
    async fn close(&self) -> Result<(), SessionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_stream_limit_reserves_control_and_rpc_carrier_streams() {
        assert_eq!(carrier_inbound_stream_limit_v2(1).unwrap(), 3);
        assert_eq!(carrier_inbound_stream_limit_v2(128).unwrap(), 130);
        assert!(carrier_inbound_stream_limit_v2(0).is_err());
        assert!(carrier_inbound_stream_limit_v2(129).is_err());
    }

    #[test]
    fn native_capabilities_match_the_strict_shared_vector() {
        validate_capabilities_v2(NATIVE_RUST_CAPABILITIES_V2).unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/capability_vectors.json"
        ))
        .unwrap();
        let vector = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["name"] == "rust-native")
            .unwrap();
        let descriptor = native_rust_capability_descriptor_v2();
        let canonical = encode_runtime_capability_descriptor_v2(&descriptor).unwrap();
        assert_eq!(
            std::str::from_utf8(&canonical).unwrap(),
            vector["canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            runtime_capability_digest_hex_v2(&descriptor).unwrap(),
            vector["digest_hex"].as_str().unwrap()
        );
        assert_eq!(
            decode_runtime_capability_descriptor_v2(&canonical).unwrap(),
            descriptor
        );
    }

    #[test]
    fn capability_validation_rejects_duplicates_and_invalid_tuples() {
        let valid = NATIVE_RUST_CAPABILITIES_V2[0];
        assert!(validate_capabilities_v2(&[valid, valid]).is_err());
        assert!(
            validate_capabilities_v2(&[CapabilityTupleV2::new(
                CarrierKind::RawQuic,
                NetworkMode::Listen,
                SessionRole::Client,
                PathKind::Tunnel,
            )])
            .is_err()
        );
    }
}

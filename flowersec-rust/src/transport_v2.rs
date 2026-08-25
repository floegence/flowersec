use std::{
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical JSON metadata attached to a logical v2 stream.
pub type JsonObject = serde_json::Map<String, serde_json::Value>;

/// A validated immutable value accepted as application stream metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamMetadata {
    values: JsonObject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StreamMetadataError {
    #[error("invalid Flowersec stream metadata")]
    InvalidValue,
}

impl StreamMetadata {
    pub fn empty() -> Self {
        Self {
            values: JsonObject::new(),
        }
    }

    pub fn values(&self) -> &JsonObject {
        &self.values
    }

    pub(crate) fn from_validated(values: JsonObject) -> Self {
        Self { values }
    }
}

impl TryFrom<serde_json::Value> for StreamMetadata {
    type Error = StreamMetadataError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        crate::protocol_v2::canonical_open_metadata_value_v2(&value)
            .map_err(|_| StreamMetadataError::InvalidValue)?;
        let serde_json::Value::Object(values) = value else {
            return Err(StreamMetadataError::InvalidValue);
        };
        Ok(Self { values })
    }
}

impl TryFrom<JsonObject> for StreamMetadata {
    type Error = StreamMetadataError;

    fn try_from(values: JsonObject) -> Result<Self, Self::Error> {
        Self::try_from(serde_json::Value::Object(values))
    }
}

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
    /// Finishes an internal protocol stream after its bytes reach the peer transport.
    async fn close_write_delivered(&self) -> io::Result<()> {
        self.close_write().await
    }
    /// Stops the peer's send direction without resetting the local send direction.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn stop_sending(&self) -> io::Result<()>;
    /// Aborts both directions with the carrier's stable generic reset code.
    async fn reset(&self) -> io::Result<()>;
    /// Releases local resources after bounded shutdown.
    #[allow(dead_code)]
    async fn close(&self) -> io::Result<()>;
}

/// Carrier-neutral source of reliable bidirectional streams.
#[async_trait]
pub trait CarrierSessionV2: fmt::Debug + Send + Sync + 'static {
    /// Returns the carrier represented by this session.
    #[cfg_attr(not(test), allow(dead_code))]
    fn kind(&self) -> CarrierKind;
    /// Selects the local opener side before a multiplexed carrier is activated.
    fn set_multiplexer_client(&self, _client: bool) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "carrier has no configurable multiplexer role",
        ))
    }
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
    /// Gracefully closes the complete carrier session.
    async fn close(&self) -> io::Result<()>;
    /// Immediately aborts native resources without waiting for graceful delivery.
    fn abort(&self);
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

/// Maximum logical application streams accepted from one peer in Session.
pub const MAX_LOGICAL_INBOUND_STREAMS_V2: u16 = 128;

/// Describes why a logical Session limit cannot be mapped to its carrier.
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
/// completed and released its stream before Session establishes them.
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

/// One exact supported combination with independently declared data-plane capabilities.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CapabilityTupleV2 {
    pub carrier: CarrierKind,
    pub network_mode: NetworkMode,
    pub session_role: SessionRole,
    pub path: PathKind,
    pub reliable_streams: bool,
    pub datagrams: bool,
    pub migration: bool,
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
        reliable_streams: bool,
        datagrams: bool,
        migration: bool,
    ) -> Self {
        Self {
            carrier,
            network_mode,
            session_role,
            path,
            reliable_streams,
            datagrams,
            migration,
        }
    }

    /// Returns whether the tuple represents a legal Flowersec deployment role.
    pub const fn is_valid(self) -> bool {
        self.reliable_streams
            && matches!(
                (self.network_mode, self.session_role, self.path),
                (NetworkMode::Dial, SessionRole::Client, PathKind::Direct)
                    | (NetworkMode::Listen, SessionRole::Server, PathKind::Direct)
                    | (NetworkMode::Dial, SessionRole::Client, PathKind::Tunnel)
                    | (NetworkMode::Dial, SessionRole::Server, PathKind::Tunnel)
            )
            && (!self.migration || matches!(self.network_mode, NetworkMode::Dial))
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
        true,
        true,
        true,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Tunnel,
        true,
        true,
        true,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Dial,
        SessionRole::Server,
        PathKind::Tunnel,
        true,
        true,
        true,
    ),
    CapabilityTupleV2::new(
        CarrierKind::RawQuic,
        NetworkMode::Listen,
        SessionRole::Server,
        PathKind::Direct,
        true,
        true,
        false,
    ),
    CapabilityTupleV2::new(
        CarrierKind::Wss,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Direct,
        true,
        false,
        false,
    ),
    CapabilityTupleV2::new(
        CarrierKind::Wss,
        NetworkMode::Dial,
        SessionRole::Client,
        PathKind::Tunnel,
        true,
        false,
        false,
    ),
    CapabilityTupleV2::new(
        CarrierKind::Wss,
        NetworkMode::Dial,
        SessionRole::Server,
        PathKind::Tunnel,
        true,
        false,
        false,
    ),
    CapabilityTupleV2::new(
        CarrierKind::Wss,
        NetworkMode::Listen,
        SessionRole::Server,
        PathKind::Direct,
        true,
        false,
        false,
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
        unsupported: vec![UnsupportedRuntimeCarrierV2 {
            carrier: CarrierKind::WebTransport,
            reason: "driver_unavailable".into(),
        }],
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilityTupleWireV2 {
    carrier: CarrierKind,
    datagrams: bool,
    migration: bool,
    #[serde(rename = "networkMode")]
    network_mode: NetworkMode,
    path: PathKind,
    #[serde(rename = "reliableStreams")]
    reliable_streams: bool,
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
                datagrams: tuple.datagrams,
                migration: tuple.migration,
                network_mode: tuple.network_mode,
                path: tuple.path,
                reliable_streams: tuple.reliable_streams,
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
                datagrams: tuple.datagrams,
                migration: tuple.migration,
                network_mode: tuple.network_mode,
                session_role: tuple.session_role,
                path: tuple.path,
                reliable_streams: tuple.reliable_streams,
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

/// Closed, redacted failure set shared by public session, stream, and RPC operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("Flowersec operation was canceled")]
    Canceled,
    #[error("Flowersec session is closed")]
    Closed,
    #[error("Flowersec session is going away")]
    GoingAway,
    #[error("Flowersec stream was rejected")]
    StreamRejected,
    #[error("Flowersec resources are exhausted")]
    ResourceExhausted,
    #[error("Flowersec stream was reset")]
    StreamReset,
    #[error("Flowersec operation timed out")]
    Timeout,
    #[error("Flowersec rekey failed")]
    RekeyFailed,
    #[error("Flowersec liveness probe failed")]
    LivenessFailed,
    #[error("Flowersec operation failed")]
    OperationFailed,
}

/// Stable, redacted reason for authoritative session termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTermination {
    pub error: SessionError,
}

/// A bounded application failure returned by a remote RPC handler.
///
/// The display representation omits the message so generic error logging does
/// not disclose application data. Callers must explicitly request the already
/// sanitized message through [`RpcError::message`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec RPC application error (code={code})")]
pub struct RpcError {
    pub(crate) code: u32,
    pub(crate) message: Option<String>,
}

impl RpcError {
    pub(crate) const MAX_MESSAGE_BYTES: usize = 1_024;

    /// Creates a bounded application RPC failure suitable for returning from
    /// an accepted-session handler.
    pub fn new(code: u32, message: Option<String>) -> Result<Self, SessionError> {
        Self::from_wire(code, message)
    }

    pub(crate) fn from_wire(code: u32, message: Option<String>) -> Result<Self, SessionError> {
        if code == 0
            || message
                .as_ref()
                .is_some_and(|value| value.len() > Self::MAX_MESSAGE_BYTES)
        {
            return Err(SessionError::OperationFailed);
        }
        Ok(Self { code, message })
    }

    /// Returns the remote application's nonzero semantic error code.
    pub const fn code(&self) -> u32 {
        self.code
    }

    /// Returns the remote application's bounded, sanitized message when present.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// Separates a remote application outcome from a session operation failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RpcCallError {
    #[error(transparent)]
    Application(RpcError),
    #[error(transparent)]
    Session(SessionError),
}

/// A cancelable subscription for peer-originated RPC notifications.
pub struct NotificationSubscription {
    cancel: Arc<dyn Fn() + Send + Sync>,
    canceled: AtomicBool,
}

impl NotificationSubscription {
    pub(crate) fn new(cancel: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            cancel: Arc::new(cancel),
            canceled: AtomicBool::new(false),
        }
    }

    /// Removes this handler. Calling `cancel` more than once is harmless.
    pub fn cancel(&self) {
        if !self.canceled.swap(true, Ordering::AcqRel) {
            (self.cancel)();
        }
    }
}

impl fmt::Debug for NotificationSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NotificationSubscription { <opaque> }")
    }
}

impl Drop for NotificationSubscription {
    fn drop(&mut self) {
        self.cancel();
    }
}

impl From<SessionError> for RpcCallError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
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

/// Portable code set for unreliable-message failures. Dropped sends remain
/// observable outcomes rather than failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreliableMessageErrorCode {
    Unavailable,
    InvalidMessage,
    TooLarge,
    Canceled,
    Closed,
    OperationFailed,
}

impl UnreliableMessageErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::InvalidMessage => "invalid_message",
            Self::TooLarge => "too_large",
            Self::Canceled => "canceled",
            Self::Closed => "closed",
            Self::OperationFailed => "operation_failed",
        }
    }
}

impl UnreliableMessageError {
    pub const fn code(self) -> UnreliableMessageErrorCode {
        match self {
            Self::Unavailable => UnreliableMessageErrorCode::Unavailable,
            Self::InvalidInput | Self::Expired => UnreliableMessageErrorCode::InvalidMessage,
            Self::TooLarge => UnreliableMessageErrorCode::TooLarge,
            Self::Canceled => UnreliableMessageErrorCode::Canceled,
            Self::Closed => UnreliableMessageErrorCode::Closed,
            Self::DroppedBudget | Self::Failed => UnreliableMessageErrorCode::OperationFailed,
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.code().as_str()
    }
}

/// Observable result of submitting one message to the native unreliable
/// carrier. It does not imply delivery or ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreliableSendOutcome {
    Accepted,
    DroppedExpired,
    DroppedBudget,
    DroppedCarrier,
}

/// Opaque, carrier-neutral unreliable message access owned by a session.
#[async_trait]
pub trait UnreliableMessageChannel: fmt::Debug + Send + Sync + 'static {
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
    /// Returns the stable public code string for this redacted session failure.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Canceled => "canceled",
            Self::Closed => "closed",
            Self::GoingAway => "going_away",
            Self::StreamRejected => "stream_rejected",
            Self::ResourceExhausted => "resource_exhausted",
            Self::StreamReset => "stream_reset",
            Self::Timeout => "timeout",
            Self::RekeyFailed => "rekey_failed",
            Self::LivenessFailed => "liveness_failed",
            Self::OperationFailed => "operation_failed",
        }
    }

    pub(crate) fn from_io(error: &io::Error) -> Self {
        if error.kind() == io::ErrorKind::ConnectionAborted
            && error.to_string() == "peer is going away"
        {
            return Self::GoingAway;
        }
        match error.kind() {
            io::ErrorKind::Interrupted => Self::Canceled,
            io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof => Self::Closed,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Self::OperationFailed,
            io::ErrorKind::PermissionDenied => Self::StreamRejected,
            io::ErrorKind::OutOfMemory => Self::ResourceExhausted,
            io::ErrorKind::ConnectionReset => Self::StreamReset,
            io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::OperationFailed,
        }
    }
}

impl From<SessionError> for io::Error {
    fn from(error: SessionError) -> Self {
        let kind = match error {
            SessionError::Canceled => io::ErrorKind::Interrupted,
            SessionError::Closed | SessionError::GoingAway => io::ErrorKind::ConnectionAborted,
            SessionError::StreamRejected => io::ErrorKind::PermissionDenied,
            SessionError::ResourceExhausted => io::ErrorKind::OutOfMemory,
            SessionError::StreamReset => io::ErrorKind::ConnectionReset,
            SessionError::Timeout => io::ErrorKind::TimedOut,
            SessionError::RekeyFailed
            | SessionError::LivenessFailed
            | SessionError::OperationFailed => io::ErrorKind::Other,
        };
        io::Error::new(kind, error)
    }
}

/// A reliable encrypted logical byte stream independent of the active carrier.
#[async_trait]
pub trait ByteStream: fmt::Debug + Send + Sync + 'static {
    #[cfg(test)]
    fn internal_test_id(&self) -> u64;
    #[cfg(test)]
    fn internal_test_buffered_bytes(&self) -> usize {
        0
    }
    /// Application stream kind negotiated by the Flowersec v2 stream setup.
    fn kind(&self) -> &str;
    /// Stable terminal failure, if the stream has already terminated abnormally.
    /// The closed enum cannot retain carrier diagnostics, peer payloads, or secrets.
    fn terminal_error(&self) -> Option<SessionError>;
    /// Reads the next non-empty byte chunk, or `None` after peer FIN.
    async fn read(&self) -> Result<Option<Bytes>, SessionError>;
    /// Writes bytes and returns the accepted byte count.
    async fn write(&self, payload: Bytes) -> Result<usize, SessionError>;
    /// Sends logical FIN while keeping the receive direction available.
    async fn close_write(&self) -> Result<(), SessionError>;
    /// Aborts both logical directions using the stable generic reset state.
    async fn reset(&self) -> Result<(), SessionError>;
    /// Aborts both logical directions and releases local resources.
    ///
    /// This is the cleanup-oriented alias of [`ByteStream::reset`]. Use
    /// [`ByteStream::close_write`] when the peer must observe a clean FIN.
    async fn close(&self) -> Result<(), SessionError>;
}

/// One accepted logical stream and its authenticated setup metadata.
pub struct IncomingStream {
    kind: String,
    metadata: StreamMetadata,
    stream: Box<dyn ByteStream>,
}

impl IncomingStream {
    /// Wraps an accepted stream after its v2 setup metadata has been authenticated.
    pub fn new(
        kind: impl Into<String>,
        metadata: StreamMetadata,
        stream: Box<dyn ByteStream>,
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
    pub fn metadata(&self) -> &StreamMetadata {
        &self.metadata
    }

    /// Borrows the carrier-neutral byte stream.
    pub fn stream(&self) -> &dyn ByteStream {
        self.stream.as_ref()
    }

    /// Consumes the incoming record and returns its byte stream.
    pub fn into_stream(self) -> Box<dyn ByteStream> {
        self.stream
    }
}

impl fmt::Debug for IncomingStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncomingStream")
            .field("kind", &self.kind)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Carrier-neutral RPC access owned by a v2 session.
#[async_trait]
pub trait RpcPeer: fmt::Debug + Send + Sync + 'static {
    /// Performs one request-response call using a canonical JSON payload.
    async fn call(
        &self,
        type_id: u32,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, RpcCallError>;
    /// Sends one notification without waiting for an application response.
    async fn notify(&self, type_id: u32, request: serde_json::Value) -> Result<(), SessionError>;
    /// Subscribes one isolated handler for peer-originated notifications.
    fn subscribe_notification(
        &self,
        type_id: u32,
        handler: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
    ) -> Result<NotificationSubscription, SessionError>;
}

/// Type-safe JSON convenience methods layered over the object-safe RPC core.
#[async_trait]
pub trait RpcPeerExt {
    async fn call_typed<Request, Response>(
        &self,
        type_id: u32,
        request: &Request,
    ) -> Result<Response, RpcCallError>
    where
        Request: serde::Serialize + Sync,
        Response: serde::de::DeserializeOwned + Send;
}

#[async_trait]
impl<T> RpcPeerExt for T
where
    T: RpcPeer + ?Sized,
{
    async fn call_typed<Request, Response>(
        &self,
        type_id: u32,
        request: &Request,
    ) -> Result<Response, RpcCallError>
    where
        Request: serde::Serialize + Sync,
        Response: serde::de::DeserializeOwned + Send,
    {
        let request = serde_json::to_value(request)
            .map_err(|_| RpcCallError::Session(SessionError::OperationFailed))?;
        let response = self.call(type_id, request).await?;
        serde_json::from_value(response)
            .map_err(|_| RpcCallError::Session(SessionError::OperationFailed))
    }
}

/// Public Flowersec v2 session contract shared by WSS and raw QUIC.
#[async_trait]
pub trait Session: fmt::Debug + Send + Sync + 'static {
    #[cfg(test)]
    fn internal_test_inbound_available_permits(&self) -> usize {
        0
    }
    #[cfg(test)]
    async fn internal_test_send_goaway(&self, _reason: u16) -> Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    /// Borrows the session's carrier-neutral RPC peer.
    fn rpc(&self) -> &dyn RpcPeer;
    /// Borrows unreliable message access after FSH2 negotiation and READY.
    fn unreliable_messages(&self) -> Result<&dyn UnreliableMessageChannel, UnreliableMessageError> {
        Err(UnreliableMessageError::Unavailable)
    }
    /// Opens an encrypted logical stream with canonical setup metadata.
    async fn open_stream(
        &self,
        kind: &str,
        metadata: StreamMetadata,
    ) -> Result<Box<dyn ByteStream>, SessionError>;
    /// Accepts the next authenticated logical stream.
    async fn accept_stream(&self) -> Result<IncomingStream, SessionError>;
    /// Advances the session key epoch.
    async fn rekey(&self) -> Result<(), SessionError>;
    /// Performs a carrier-neutral liveness probe and returns its round-trip time.
    async fn probe_liveness(&self) -> Result<Duration, SessionError>;
    /// Waits for authoritative session termination and returns its stable cause.
    /// Canceling this future never changes the session state.
    async fn wait_termination(&self) -> SessionTermination;
    /// Closes the session and performs bounded local cleanup.
    async fn close(&self) -> Result<(), SessionError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn unreliable_error_codes_collapse_legacy_variants() {
        let cases = [
            (UnreliableMessageError::Unavailable, "unavailable"),
            (UnreliableMessageError::InvalidInput, "invalid_message"),
            (UnreliableMessageError::Expired, "invalid_message"),
            (UnreliableMessageError::TooLarge, "too_large"),
            (UnreliableMessageError::Canceled, "canceled"),
            (UnreliableMessageError::Closed, "closed"),
            (UnreliableMessageError::DroppedBudget, "operation_failed"),
            (UnreliableMessageError::Failed, "operation_failed"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.as_str(), expected);
        }
    }

    #[derive(Debug)]
    struct TypedRpcPeer {
        calls: Mutex<Vec<(u32, serde_json::Value)>>,
        result: Result<serde_json::Value, RpcCallError>,
    }

    #[async_trait]
    impl RpcPeer for TypedRpcPeer {
        async fn call(
            &self,
            type_id: u32,
            request: serde_json::Value,
        ) -> Result<serde_json::Value, RpcCallError> {
            self.calls.lock().unwrap().push((type_id, request));
            self.result.clone()
        }

        async fn notify(
            &self,
            _type_id: u32,
            _request: serde_json::Value,
        ) -> Result<(), SessionError> {
            Ok(())
        }

        fn subscribe_notification(
            &self,
            _type_id: u32,
            _handler: Arc<dyn Fn(serde_json::Value) + Send + Sync>,
        ) -> Result<NotificationSubscription, SessionError> {
            Ok(NotificationSubscription::new(|| {}))
        }
    }

    #[derive(Serialize)]
    struct TypedRequest {
        value: String,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct TypedResponse {
        accepted: bool,
    }

    #[tokio::test]
    async fn typed_rpc_encodes_decodes_and_preserves_application_errors() {
        let peer = TypedRpcPeer {
            calls: Mutex::new(Vec::new()),
            result: Ok(serde_json::json!({"accepted": true})),
        };
        let response = peer
            .call_typed::<TypedRequest, TypedResponse>(
                7,
                &TypedRequest {
                    value: "request".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(response, TypedResponse { accepted: true });
        assert_eq!(
            *peer.calls.lock().unwrap(),
            vec![(7, serde_json::json!({"value": "request"}))]
        );

        let application = RpcError::from_wire(409, Some("conflict".into())).unwrap();
        let peer = TypedRpcPeer {
            calls: Mutex::new(Vec::new()),
            result: Err(RpcCallError::Application(application.clone())),
        };
        assert_eq!(
            peer.call_typed::<TypedRequest, TypedResponse>(
                8,
                &TypedRequest {
                    value: "request".into(),
                },
            )
            .await,
            Err(RpcCallError::Application(application))
        );
    }

    #[test]
    fn rpc_application_error_is_bounded_and_safe_to_log() {
        let error = RpcError::from_wire(429, Some("retry later".into())).expect("valid RPC error");
        assert_eq!(error.code(), 429);
        assert_eq!(error.message(), Some("retry later"));
        assert_eq!(
            error.to_string(),
            "Flowersec RPC application error (code=429)"
        );
        assert!(!error.to_string().contains("retry later"));

        assert_eq!(
            RpcError::from_wire(0, None),
            Err(SessionError::OperationFailed)
        );
        assert_eq!(
            RpcError::from_wire(500, Some("x".repeat(RpcError::MAX_MESSAGE_BYTES + 1))),
            Err(SessionError::OperationFailed)
        );
        assert!(RpcError::new(7, None).is_ok());
        assert!(RpcError::new(7, Some("a".repeat(1_024))).is_ok());
        assert!(RpcError::new(7, Some("é".repeat(512))).is_ok());
        assert_eq!(
            RpcError::new(7, Some("a".repeat(1_025))),
            Err(SessionError::OperationFailed)
        );
        assert_eq!(
            RpcError::new(7, Some(format!("{}a", "é".repeat(512)))),
            Err(SessionError::OperationFailed)
        );
    }

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
                true,
                true,
                false,
            )])
            .is_err()
        );
    }
}

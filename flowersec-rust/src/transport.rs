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
#[cfg(test)]
use serde::{Deserialize, Serialize};

/// Canonical JSON metadata attached to a logical stream.
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
        crate::protocol_v3::canonical_open_metadata_value_v3(&value)
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
    /// Application stream kind negotiated by the Flowersec stream setup.
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
    /// Wraps an accepted stream after its setup metadata has been authenticated.
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

/// Carrier-neutral RPC access owned by a session.
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

/// Public Flowersec session contract shared by WSS and raw QUIC.
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
    /// Borrows unreliable message access after FSH3 negotiation and READY.
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
}

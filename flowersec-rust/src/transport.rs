use std::{fmt, io, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;

/// Closed, redacted failure set shared by public session, stream, and RPC operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionError {
    #[error("Flowersec stream read is already in progress")]
    ReadInProgress,
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
    #[error("Flowersec authenticated liveness path is unresponsive")]
    LivenessPathUnresponsive,
    #[error("Flowersec operation failed")]
    OperationFailed,
}

/// Stable, redacted reason for authoritative session termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionTermination {
    pub error: SessionError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreliableReceiveBlock {
    InvalidInputBudget,
    KeyOpenBudget,
}

/// Stable, redacted failure set for carrier-neutral unreliable messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnreliableMessageError {
    #[error("unreliable messages are unavailable for this session")]
    Unavailable,
    #[error("invalid unreliable message")]
    InvalidMessage,
    #[error("unreliable message exceeds the negotiated maximum")]
    TooLarge,
    #[error("unreliable message operation was canceled")]
    Canceled,
    #[error("unreliable message channel is closed")]
    Closed,
    #[error("unreliable receive is temporarily blocked")]
    TemporarilyBlocked {
        reason: UnreliableReceiveBlock,
        retry_after_ms: Option<u64>,
    },
    #[error("unreliable receive is disabled by the invalid input budget")]
    ReceiveDisabled,
    #[error("unreliable message operation failed")]
    OperationFailed,
}

/// Local facts from the original datagram owner. The maximum concerns local
/// submission; a receive guard failure does not describe reliable Session I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnreliableMessagesInfo {
    pub epoch: u32,
    pub max_message_bytes: usize,
    pub receive_failure: Option<UnreliableMessageError>,
}

/// Portable code set for unreliable-message failures. Dropped sends remain
/// observable outcomes rather than failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnreliableMessageErrorCode {
    TemporarilyBlocked,
    ReceiveDisabled,
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
            Self::TemporarilyBlocked => "temporarily_blocked",
            Self::ReceiveDisabled => "receive_disabled",
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
            Self::TemporarilyBlocked { .. } => UnreliableMessageErrorCode::TemporarilyBlocked,
            Self::ReceiveDisabled => UnreliableMessageErrorCode::ReceiveDisabled,
            Self::Unavailable => UnreliableMessageErrorCode::Unavailable,
            Self::InvalidMessage => UnreliableMessageErrorCode::InvalidMessage,
            Self::TooLarge => UnreliableMessageErrorCode::TooLarge,
            Self::Canceled => UnreliableMessageErrorCode::Canceled,
            Self::Closed => UnreliableMessageErrorCode::Closed,
            Self::OperationFailed => UnreliableMessageErrorCode::OperationFailed,
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

/// Carrier-neutral unreliable-message operations exposed by an authenticated Session.
#[async_trait]
pub trait UnreliableMessageChannel: Send + Sync {
    fn max_message_size(&self) -> usize;
    async fn send(
        &self,
        payload: Bytes,
        expires_at: std::time::SystemTime,
    ) -> Result<UnreliableSendOutcome, UnreliableMessageError>;
    async fn receive(&self) -> Result<Bytes, UnreliableMessageError>;
}

impl SessionError {
    /// Returns the stable public code string for this redacted session failure.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadInProgress => "read_in_progress",
            Self::Canceled => "canceled",
            Self::Closed => "closed",
            Self::GoingAway => "going_away",
            Self::StreamRejected => "stream_rejected",
            Self::ResourceExhausted => "resource_exhausted",
            Self::StreamReset => "stream_reset",
            Self::Timeout => "timeout",
            Self::RekeyFailed => "rekey_failed",
            Self::LivenessFailed => "liveness_failed",
            Self::LivenessPathUnresponsive => "liveness_path_unresponsive",
            Self::OperationFailed => "operation_failed",
        }
    }
}

impl From<SessionError> for io::Error {
    fn from(error: SessionError) -> Self {
        let kind = match error {
            SessionError::Canceled => io::ErrorKind::Interrupted,
            SessionError::ReadInProgress => io::ErrorKind::WouldBlock,
            SessionError::Closed | SessionError::GoingAway => io::ErrorKind::ConnectionAborted,
            SessionError::StreamRejected => io::ErrorKind::PermissionDenied,
            SessionError::ResourceExhausted => io::ErrorKind::OutOfMemory,
            SessionError::StreamReset => io::ErrorKind::ConnectionReset,
            SessionError::Timeout => io::ErrorKind::TimedOut,
            SessionError::RekeyFailed
            | SessionError::LivenessFailed
            | SessionError::LivenessPathUnresponsive
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
    /// Current committed receive terminal without consuming input.
    fn read_state(
        &self,
    ) -> (
        crate::api_v4::ReadStreamStatus,
        Option<crate::api_v4::ReadError>,
    ) {
        (
            if self.terminal_error().is_some() {
                crate::api_v4::ReadStreamStatus::Aborted
            } else {
                crate::api_v4::ReadStreamStatus::Open
            },
            None,
        )
    }
    /// Shared receive owner, including ordinary reads. Providers without a
    /// bounded cursor-transfer implementation must leave this unavailable.
    fn read_owner(&self) -> Option<Arc<crate::api_v4::StreamReadOwner>> {
        None
    }
    /// Original private result-delivery owner. Providers that cannot retain
    /// an independent trusted handoff gate must leave this unavailable;
    /// ReaderCursor then fails closed before exposing any bytes.
    fn read_delivery_owner(&self) -> Option<Arc<crate::api_v4::ReadDeliveryAuthorization>> {
        None
    }
    /// Transfer one authenticated prefix from the original bounded receive queue.
    /// A canceled wait must leave both the source record and untransferred suffix
    /// owned by that stream. This method must not use ordinary `read` plus an
    /// adapter suffix queue, and must validate the cursor's owner identity.
    async fn read_cursor_piece(
        &self,
        _cursor: &crate::api_v4::ReaderCursor,
    ) -> Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    /// Reads the next non-empty byte chunk, or `None` after peer FIN.
    async fn read(&self) -> Result<Option<Bytes>, SessionError>;
    /// Writes bytes and returns the accepted byte count.
    async fn write(&self, payload: Bytes) -> Result<usize, SessionError>;
    /// Original Stream ownership qualification retained through the real
    /// prepared/native write lifetime.  A caller cannot release another
    /// operation's qualification by mutating an adapter label or counter.
    fn write_preparation_permit(
        &self,
    ) -> Result<Option<crate::api_v4::StreamWritePreparationPermit>, SessionError> {
        Ok(None)
    }
    /// Original session staging owner shared by every stream of that session.
    /// Missing capability rejects preparation before retaining input or work.
    fn write_staging_owner(&self) -> Option<Arc<crate::api_v4::WriteStagingOwner>> {
        None
    }
    /// Runs a prepared request using the stream's actual ordered admission gate.
    /// The default refuses: wrapping ordinary `write` would invent acceptance.
    async fn write_prepared(
        &self,
        _payload: Bytes,
        _admission: &crate::api_v4::WriteRequestAdmission,
    ) -> Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    /// Sends logical FIN while keeping the receive direction available.
    async fn close_write(&self) -> Result<(), SessionError>;
    /// Waits until the authenticated send direction is drained.  Providers
    /// that cannot expose a separate drain report the same stable operation
    /// error instead of silently treating close as a successful Finish.
    async fn finish(&self) -> Result<(), SessionError> {
        Err(SessionError::OperationFailed)
    }
    /// Aborts both logical directions using the stable generic reset state.
    async fn reset(&self) -> Result<(), SessionError>;
    /// Aborts both logical directions and releases local resources.
    ///
    /// This is the cleanup-oriented alias of [`ByteStream::reset`]. Use
    /// [`ByteStream::close_write`] when the peer must observe a clean FIN.
    async fn close(&self) -> Result<(), SessionError>;
}

/// The v6 name for the carrier-neutral encrypted byte stream.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreliable_error_codes_are_exact() {
        for (error, expected) in [
            (UnreliableMessageError::Unavailable, "unavailable"),
            (UnreliableMessageError::InvalidMessage, "invalid_message"),
            (UnreliableMessageError::TooLarge, "too_large"),
            (UnreliableMessageError::Canceled, "canceled"),
            (UnreliableMessageError::Closed, "closed"),
            (UnreliableMessageError::OperationFailed, "operation_failed"),
        ] {
            assert_eq!(error.as_str(), expected);
        }
    }
}

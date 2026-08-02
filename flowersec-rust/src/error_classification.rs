use crate::{ConnectError, ConnectErrorCode, SessionError};

/// Carrier-neutral next step for a redacted public failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorRetryAction {
    Retry,
    RefreshArtifact,
    Stop,
}

impl ErrorRetryAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::RefreshArtifact => "refresh_artifact",
            Self::Stop => "stop",
        }
    }
}

/// Bounded application recovery policy that contains no transport diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorRetryClassification {
    pub action: ErrorRetryAction,
    pub caller_canceled: bool,
    pub session_closed: bool,
}

pub const fn classify_connect_error(error: ConnectError) -> ErrorRetryClassification {
    match error.code() {
        ConnectErrorCode::InvalidInput => classification(ErrorRetryAction::Stop, false, false),
        ConnectErrorCode::Canceled => classification(ErrorRetryAction::Stop, true, false),
        ConnectErrorCode::Expired
        | ConnectErrorCode::ResolveFailed
        | ConnectErrorCode::SpendFailed
        | ConnectErrorCode::DialFailed
        | ConnectErrorCode::Timeout
        | ConnectErrorCode::HandshakeFailed => {
            classification(ErrorRetryAction::RefreshArtifact, false, false)
        }
    }
}

pub const fn classify_session_error(error: SessionError) -> ErrorRetryClassification {
    match error {
        SessionError::Canceled => classification(ErrorRetryAction::Stop, true, false),
        SessionError::Closed | SessionError::GoingAway => {
            classification(ErrorRetryAction::RefreshArtifact, false, true)
        }
        SessionError::ResourceExhausted
        | SessionError::StreamReset
        | SessionError::Timeout
        | SessionError::RekeyFailed
        | SessionError::LivenessFailed => classification(ErrorRetryAction::Retry, false, false),
        SessionError::StreamRejected | SessionError::OperationFailed => {
            classification(ErrorRetryAction::Stop, false, false)
        }
    }
}

const fn classification(
    action: ErrorRetryAction,
    caller_canceled: bool,
    session_closed: bool,
) -> ErrorRetryClassification {
    ErrorRetryClassification {
        action,
        caller_canceled,
        session_closed,
    }
}

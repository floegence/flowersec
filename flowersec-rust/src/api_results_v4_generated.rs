// Generated draft native API types; DO NOT EDIT. Not a qualified SDK runtime.
pub(crate) const API_RESULTS_SCHEMA_SHA256: &str = "3a7a448d49a46f86700e56dc0d30e62d8915bdc67e12d1b697c9d92083f4cc1c";

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ApplicationProfile {
    Transport,
    Services,
    Execution,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ReliableProgress {
    SharedOrdered,
    IndependentWithinProfile,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4BoundStreamInputIsolation {
    SharedFailureScope,
    BoundStreamWithinProfile,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ConsumerTLS13Verification {
    NotApplicable,
    ControlledTerminator,
    ConsumerEnforced,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ConnectionGuaranteeScope {
    CompleteDirectPath,
    CompleteRelayPath,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ConnectionGuaranteeAssumptions {
    AuthenticatedPeerWithinTransportProfile,
    TrustedRelayAndPeersWithinTransportProfile,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ConnectionRequirements {
    pub(crate) independent_reliable_read_progress: bool,
    pub(crate) bound_stream_input_isolation: bool,
    pub(crate) datagram: bool,
    pub(crate) local_consumer_tls13_verification: bool,
    pub(crate) application_profile: Option<V4ApplicationProfile>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ConnectionGuarantees {
    pub(crate) reliable_progress: V4ReliableProgress,
    pub(crate) bound_stream_input_isolation: V4BoundStreamInputIsolation,
    pub(crate) datagram: bool,
    pub(crate) local_consumer_tls13_verification: V4ConsumerTLS13Verification,
    pub(crate) scope: V4ConnectionGuaranteeScope,
    pub(crate) assumptions: V4ConnectionGuaranteeAssumptions,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4SessionInfo {
    pub(crate) application_profile: V4ApplicationProfile,
    pub(crate) selected_features: u64,
    pub(crate) guarantees: V4ConnectionGuarantees,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4Direction {
    C2s,
    S2c,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ReadTerminal {
    Eof,
    Abandoned,
    Open,
    Unknown,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4WaitStatus {
    Ready,
    Blocked,
    WaitCanceled,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4StreamStatus {
    Open,
    Eof,
    Aborted,
    Error,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ReadCause {
    DelimiterNotFound,
    UnexpectedEof,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4CleanupState {
    Pending,
    Complete,
    CleanupIncomplete,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4CoreCleanup {
    Pending,
    Complete,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4WritePhase {
    Prepared,
    Running,
    Terminal,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4WriteTerminalReason {
    None,
    Complete,
    Canceled,
    DeadlineExceeded,
    QueueFull,
    StreamTerminated,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4DuplexEndpointKind {
    FlowersecStream,
    NativeDuplex,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4DuplexOutcome {
    Normal,
    Failed,
    Aborted,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ResponsePublicationState {
    NotApplicable,
    Pending,
    Flushed,
    Unknown,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ResponsePublicationCause {
    ResponseSuperseded,
    ResponseAborted,
    OwnerUnavailable,
    Deadline,
    PublishFailed,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4PublicationTransferResult {
    Success,
    AlreadyTransferred,
    OwnerUnavailable,
    Expired,
    Invalid,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ErrorCode {
    ProtocolViolation,
    FramingError,
    AuthenticationFailed,
    SequenceError,
    ReplayDetected,
    CryptoFailure,
    RekeyFailed,
    ResourceExhausted,
    StreamSequenceError,
    StreamDataInvalid,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ErrorScope {
    Session,
    Stream,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4RetryDisposition {
    PreserveFacts,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4TypedError {
    pub(crate) code: V4ErrorCode,
    pub(crate) scope: V4ErrorScope,
    pub(crate) retry_disposition: V4RetryDisposition,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ReadProgress {
    pub(crate) offset: u64,
    pub(crate) filled: u64,
    pub(crate) target: Option<u64>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ReadResult {
    pub(crate) data: Vec<u8>,
    pub(crate) progress: V4ReadProgress,
    pub(crate) wait_status: V4WaitStatus,
    pub(crate) stream_status: V4StreamStatus,
    pub(crate) cause: Option<V4ReadCause>,
    pub(crate) error: Option<V4TypedError>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4ReadMethodFailureReason {
    InvalidArgument,
    TargetMismatch,
    ReadInProgress,
    PrefixFrozen,
    AlreadyDelivered,
    Closed,
    TimePending,
    TimeUnavailable,
    AuthorizationDenied,
    OwnerUnavailable,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ReaderCursorSnapshot {
    pub(crate) offset: u64,
    pub(crate) transferred_bytes: u64,
    pub(crate) target: u64,
    pub(crate) stream_status: V4StreamStatus,
    pub(crate) target_cause: Option<V4ReadCause>,
    pub(crate) stream_error: Option<V4TypedError>,
    pub(crate) complete: bool,
    pub(crate) frozen: bool,
    pub(crate) delivered: bool,
    pub(crate) closed: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ReadMethodFailure {
    pub(crate) reason: V4ReadMethodFailureReason,
    pub(crate) cursor: Option<V4ReaderCursorSnapshot>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4CleanupStatus {
    pub(crate) status: V4CleanupState,
    pub(crate) core_cleanup: V4CoreCleanup,
    pub(crate) pending_callbacks: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4CloseResult {
    pub(crate) direction: V4Direction,
    pub(crate) send_drained: bool,
    pub(crate) read_terminal: V4ReadTerminal,
    pub(crate) cleanup_status: V4CleanupStatus,
    pub(crate) first_error: Option<V4TypedError>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4WriteProgress {
    pub(crate) requested_bytes: u64,
    pub(crate) accepted_bytes: u64,
    pub(crate) phase: V4WritePhase,
    pub(crate) terminal_reason: V4WriteTerminalReason,
    pub(crate) cleanup_status: V4CleanupStatus,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4TransferProgress {
    pub(crate) source_read_bytes: u64,
    pub(crate) destination_accepted_bytes: u64,
    pub(crate) unaccepted_tail: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4DuplexSendResult {
    pub(crate) endpoint_kind: V4DuplexEndpointKind,
    pub(crate) send_drained: Option<bool>,
    pub(crate) native_send_finished: Option<bool>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4DuplexDirectionResult {
    pub(crate) progress: V4TransferProgress,
    pub(crate) source_status: V4StreamStatus,
    pub(crate) send_result: V4DuplexSendResult,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4DuplexResult {
    pub(crate) a_to_b: V4DuplexDirectionResult,
    pub(crate) b_to_a: V4DuplexDirectionResult,
    pub(crate) outcome: V4DuplexOutcome,
    pub(crate) cleanup_status: V4CleanupStatus,
    pub(crate) first_error: Option<V4TypedError>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4ResponsePublicationStatus {
    pub(crate) state: V4ResponsePublicationState,
    pub(crate) cause: Option<V4ResponsePublicationCause>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4TopUpWireResult {
    Success,
    Replay,
    SourceExhausted,
    SourceUnavailable,
    SourceContractInvalid,
    SourceStateUnknown,
    OperationConflict,
    StaleGeneration,
    FutureGeneration,
    StaleOperation,
    FutureOperation,
    SequenceGap,
    ConfigurationCapacity,
    CapacityExhausted,
    RelinkRequired,
    SpentUnknown,
    TopUpRequestExpired,
    SourceResetRequired,
    PermissionDenied,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4TopUpErrorCode {
    SourceExhausted,
    SourceUnavailable,
    SourceContractInvalid,
    SourceStateUnknown,
    OperationConflict,
    StaleGeneration,
    FutureGeneration,
    StaleOperation,
    FutureOperation,
    SequenceGap,
    ConfigurationCapacity,
    CapacityExhausted,
    RelinkRequired,
    SpentUnknown,
    TopUpRequestExpired,
    SourceResetRequired,
    PermissionDenied,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4TopUpErrorScope {
    Source,
    Operation,
    Request,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4TopUpWriteAction {
    None,
    Terminal,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4TopUpError {
    pub(crate) code: V4TopUpErrorCode,
    pub(crate) scope: V4TopUpErrorScope,
    pub(crate) write_action: V4TopUpWriteAction,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4LifecycleObjectKind {
    Session,
    Environment,
    Operation,
    Subscription,
    Bridge,
    Adapter,
    Stream,
    Material,
    Source,
    Registration,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4LifecycleState {
    Active,
    Closing,
    Closed,
    SessionAborted,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum V4LifecycleReason {
    None,
    Canceled,
    DeadlineExceeded,
    DependencyUnavailable,
    CoreCleanupFailed,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V4LifecycleResult {
    pub(crate) object_kind: V4LifecycleObjectKind,
    pub(crate) lifecycle_state: V4LifecycleState,
    pub(crate) cleanup_status: V4CleanupStatus,
    pub(crate) reason: V4LifecycleReason,
}

pub(crate) fn top_up_error_projection(code: V4TopUpErrorCode, action: V4TopUpWriteAction) -> Option<V4TopUpError> {
    match code {
        V4TopUpErrorCode::SourceExhausted => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::SourceUnavailable => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::SourceContractInvalid => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::SourceStateUnknown => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::OperationConflict => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::StaleGeneration => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Request, write_action: action }) } else { None } },
        V4TopUpErrorCode::FutureGeneration => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Request, write_action: action }) } else { None } },
        V4TopUpErrorCode::StaleOperation => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::FutureOperation => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::SequenceGap => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::ConfigurationCapacity => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Request, write_action: action }) } else { None } },
        V4TopUpErrorCode::CapacityExhausted => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::RelinkRequired => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::SpentUnknown => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::TopUpRequestExpired => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Operation, write_action: action }) } else { None } },
        V4TopUpErrorCode::SourceResetRequired => { if action == V4TopUpWriteAction::None || action == V4TopUpWriteAction::Terminal { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
        V4TopUpErrorCode::PermissionDenied => { if action == V4TopUpWriteAction::None { Some(V4TopUpError { code, scope: V4TopUpErrorScope::Source, write_action: action }) } else { None } },
    }
}

pub(crate) fn valid_lifecycle_result(value: &V4LifecycleResult) -> bool {
    let cleanup = &value.cleanup_status;
    (cleanup.status == V4CleanupState::Complete) == (cleanup.core_cleanup == V4CoreCleanup::Complete && cleanup.pending_callbacks == 0)
        && (value.lifecycle_state != V4LifecycleState::SessionAborted || value.object_kind == V4LifecycleObjectKind::Session)
        && (cleanup.status != V4CleanupState::Complete || matches!(value.lifecycle_state, V4LifecycleState::Closed | V4LifecycleState::SessionAborted))
}

pub(crate) fn connection_assurance(class: &str) -> Option<V4ConnectionGuarantees> {
    match class {
        "native_websocket_tls13" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ConsumerEnforced, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "native_websocket_loopback" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "accepted_websocket" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "browser_websocket_terminator" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ControlledTerminator, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "native_quic_tls13" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ConsumerEnforced, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "accepted_quic" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "native_webtransport_tls13" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ConsumerEnforced, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "accepted_webtransport" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteDirectPath, assumptions: V4ConnectionGuaranteeAssumptions::AuthenticatedPeerWithinTransportProfile }),
        "go_relay_native_consumer" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ConsumerEnforced, scope: V4ConnectionGuaranteeScope::CompleteRelayPath, assumptions: V4ConnectionGuaranteeAssumptions::TrustedRelayAndPeersWithinTransportProfile }),
        "go_relay_native_observer" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::IndependentWithinProfile, bound_stream_input_isolation: V4BoundStreamInputIsolation::BoundStreamWithinProfile, datagram: true, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteRelayPath, assumptions: V4ConnectionGuaranteeAssumptions::TrustedRelayAndPeersWithinTransportProfile }),
        "go_relay_shared_consumer" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::ConsumerEnforced, scope: V4ConnectionGuaranteeScope::CompleteRelayPath, assumptions: V4ConnectionGuaranteeAssumptions::TrustedRelayAndPeersWithinTransportProfile }),
        "go_relay_shared_observer" => Some(V4ConnectionGuarantees { reliable_progress: V4ReliableProgress::SharedOrdered, bound_stream_input_isolation: V4BoundStreamInputIsolation::SharedFailureScope, datagram: false, local_consumer_tls13_verification: V4ConsumerTLS13Verification::NotApplicable, scope: V4ConnectionGuaranteeScope::CompleteRelayPath, assumptions: V4ConnectionGuaranteeAssumptions::TrustedRelayAndPeersWithinTransportProfile }),
        _ => None,
    }
}

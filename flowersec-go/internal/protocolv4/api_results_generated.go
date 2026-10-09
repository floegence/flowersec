// Generated draft native API types; DO NOT EDIT. Not a qualified SDK runtime.
package protocolv4

const APIResultsSchemaSHA256 = "3a7a448d49a46f86700e56dc0d30e62d8915bdc67e12d1b697c9d92083f4cc1c"

type V4ApplicationProfile string

const V4ApplicationProfileTransport V4ApplicationProfile = "transport"
const V4ApplicationProfileServices V4ApplicationProfile = "services"
const V4ApplicationProfileExecution V4ApplicationProfile = "execution"

type V4ReliableProgress string

const V4ReliableProgressSharedOrdered V4ReliableProgress = "shared_ordered"
const V4ReliableProgressIndependentWithinProfile V4ReliableProgress = "independent_within_profile"

type V4BoundStreamInputIsolation string

const V4BoundStreamInputIsolationSharedFailureScope V4BoundStreamInputIsolation = "shared_failure_scope"
const V4BoundStreamInputIsolationBoundStreamWithinProfile V4BoundStreamInputIsolation = "bound_stream_within_profile"

type V4ConsumerTLS13Verification string

const V4ConsumerTLS13VerificationNotApplicable V4ConsumerTLS13Verification = "not_applicable"
const V4ConsumerTLS13VerificationControlledTerminator V4ConsumerTLS13Verification = "controlled_terminator"
const V4ConsumerTLS13VerificationConsumerEnforced V4ConsumerTLS13Verification = "consumer_enforced"

type V4ConnectionGuaranteeScope string

const V4ConnectionGuaranteeScopeCompleteDirectPath V4ConnectionGuaranteeScope = "complete_direct_path"
const V4ConnectionGuaranteeScopeCompleteRelayPath V4ConnectionGuaranteeScope = "complete_relay_path"

type V4ConnectionGuaranteeAssumptions string

const V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile V4ConnectionGuaranteeAssumptions = "authenticated_peer_within_transport_profile"
const V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile V4ConnectionGuaranteeAssumptions = "trusted_relay_and_peers_within_transport_profile"

type V4ConnectionRequirements struct {
	IndependentReliableReadProgress bool
	BoundStreamInputIsolation       bool
	Datagram                        bool
	LocalConsumerTls13Verification  bool
	ApplicationProfile              *V4ApplicationProfile
}

type V4ConnectionGuarantees struct {
	ReliableProgress               V4ReliableProgress
	BoundStreamInputIsolation      V4BoundStreamInputIsolation
	Datagram                       bool
	LocalConsumerTls13Verification V4ConsumerTLS13Verification
	Scope                          V4ConnectionGuaranteeScope
	Assumptions                    V4ConnectionGuaranteeAssumptions
}

type V4SessionInfo struct {
	ApplicationProfile V4ApplicationProfile
	SelectedFeatures   uint64
	Guarantees         V4ConnectionGuarantees
}

type V4Direction string

const V4DirectionC2s V4Direction = "c2s"
const V4DirectionS2c V4Direction = "s2c"

type V4ReadTerminal string

const V4ReadTerminalEof V4ReadTerminal = "eof"
const V4ReadTerminalAbandoned V4ReadTerminal = "abandoned"
const V4ReadTerminalOpen V4ReadTerminal = "open"
const V4ReadTerminalUnknown V4ReadTerminal = "unknown"

type V4WaitStatus string

const V4WaitStatusReady V4WaitStatus = "ready"
const V4WaitStatusBlocked V4WaitStatus = "blocked"
const V4WaitStatusWaitCanceled V4WaitStatus = "wait_canceled"

type V4StreamStatus string

const V4StreamStatusOpen V4StreamStatus = "open"
const V4StreamStatusEof V4StreamStatus = "eof"
const V4StreamStatusAborted V4StreamStatus = "aborted"
const V4StreamStatusError V4StreamStatus = "error"

type V4ReadCause string

const V4ReadCauseDelimiterNotFound V4ReadCause = "delimiter_not_found"
const V4ReadCauseUnexpectedEof V4ReadCause = "unexpected_eof"

type V4CleanupState string

const V4CleanupStatePending V4CleanupState = "pending"
const V4CleanupStateComplete V4CleanupState = "complete"
const V4CleanupStateCleanupIncomplete V4CleanupState = "cleanup_incomplete"

type V4CoreCleanup string

const V4CoreCleanupPending V4CoreCleanup = "pending"
const V4CoreCleanupComplete V4CoreCleanup = "complete"

type V4WritePhase string

const V4WritePhasePrepared V4WritePhase = "prepared"
const V4WritePhaseRunning V4WritePhase = "running"
const V4WritePhaseTerminal V4WritePhase = "terminal"

type V4WriteTerminalReason string

const V4WriteTerminalReasonNone V4WriteTerminalReason = "none"
const V4WriteTerminalReasonComplete V4WriteTerminalReason = "complete"
const V4WriteTerminalReasonCanceled V4WriteTerminalReason = "canceled"
const V4WriteTerminalReasonDeadlineExceeded V4WriteTerminalReason = "deadline_exceeded"
const V4WriteTerminalReasonQueueFull V4WriteTerminalReason = "queue_full"
const V4WriteTerminalReasonStreamTerminated V4WriteTerminalReason = "stream_terminated"
const V4WriteTerminalReasonFailed V4WriteTerminalReason = "failed"

type V4DuplexEndpointKind string

const V4DuplexEndpointKindFlowersecStream V4DuplexEndpointKind = "flowersec_stream"
const V4DuplexEndpointKindNativeDuplex V4DuplexEndpointKind = "native_duplex"

type V4DuplexOutcome string

const V4DuplexOutcomeNormal V4DuplexOutcome = "normal"
const V4DuplexOutcomeFailed V4DuplexOutcome = "failed"
const V4DuplexOutcomeAborted V4DuplexOutcome = "aborted"

type V4ResponsePublicationState string

const V4ResponsePublicationStateNotApplicable V4ResponsePublicationState = "not_applicable"
const V4ResponsePublicationStatePending V4ResponsePublicationState = "pending"
const V4ResponsePublicationStateFlushed V4ResponsePublicationState = "flushed"
const V4ResponsePublicationStateUnknown V4ResponsePublicationState = "unknown"

type V4ResponsePublicationCause string

const V4ResponsePublicationCauseResponseSuperseded V4ResponsePublicationCause = "response_superseded"
const V4ResponsePublicationCauseResponseAborted V4ResponsePublicationCause = "response_aborted"
const V4ResponsePublicationCauseOwnerUnavailable V4ResponsePublicationCause = "owner_unavailable"
const V4ResponsePublicationCauseDeadline V4ResponsePublicationCause = "deadline"
const V4ResponsePublicationCausePublishFailed V4ResponsePublicationCause = "publish_failed"

type V4PublicationTransferResult string

const V4PublicationTransferResultSuccess V4PublicationTransferResult = "success"
const V4PublicationTransferResultAlreadyTransferred V4PublicationTransferResult = "already_transferred"
const V4PublicationTransferResultOwnerUnavailable V4PublicationTransferResult = "owner_unavailable"
const V4PublicationTransferResultExpired V4PublicationTransferResult = "expired"
const V4PublicationTransferResultInvalid V4PublicationTransferResult = "invalid"

type V4ErrorCode string

const V4ErrorCodeProtocolViolation V4ErrorCode = "protocol_violation"
const V4ErrorCodeFramingError V4ErrorCode = "framing_error"
const V4ErrorCodeAuthenticationFailed V4ErrorCode = "authentication_failed"
const V4ErrorCodeSequenceError V4ErrorCode = "sequence_error"
const V4ErrorCodeReplayDetected V4ErrorCode = "replay_detected"
const V4ErrorCodeCryptoFailure V4ErrorCode = "crypto_failure"
const V4ErrorCodeRekeyFailed V4ErrorCode = "rekey_failed"
const V4ErrorCodeResourceExhausted V4ErrorCode = "resource_exhausted"
const V4ErrorCodeStreamSequenceError V4ErrorCode = "stream_sequence_error"
const V4ErrorCodeStreamDataInvalid V4ErrorCode = "stream_data_invalid"

type V4ErrorScope string

const V4ErrorScopeSession V4ErrorScope = "session"
const V4ErrorScopeStream V4ErrorScope = "stream"

type V4RetryDisposition string

const V4RetryDispositionPreserveFacts V4RetryDisposition = "preserve_facts"

type V4TypedError struct {
	Code             V4ErrorCode
	Scope            V4ErrorScope
	RetryDisposition V4RetryDisposition
}

type V4ReadProgress struct {
	Offset uint64
	Filled uint64
	Target *uint64
}

type V4ReadResult struct {
	Data         []byte
	Progress     V4ReadProgress
	WaitStatus   V4WaitStatus
	StreamStatus V4StreamStatus
	Cause        *V4ReadCause
	Error        *V4TypedError
}

type V4ReadMethodFailureReason string

const V4ReadMethodFailureReasonInvalidArgument V4ReadMethodFailureReason = "invalid_argument"
const V4ReadMethodFailureReasonTargetMismatch V4ReadMethodFailureReason = "target_mismatch"
const V4ReadMethodFailureReasonReadInProgress V4ReadMethodFailureReason = "read_in_progress"
const V4ReadMethodFailureReasonPrefixFrozen V4ReadMethodFailureReason = "prefix_frozen"
const V4ReadMethodFailureReasonAlreadyDelivered V4ReadMethodFailureReason = "already_delivered"
const V4ReadMethodFailureReasonClosed V4ReadMethodFailureReason = "closed"
const V4ReadMethodFailureReasonTimePending V4ReadMethodFailureReason = "time_pending"
const V4ReadMethodFailureReasonTimeUnavailable V4ReadMethodFailureReason = "time_unavailable"
const V4ReadMethodFailureReasonAuthorizationDenied V4ReadMethodFailureReason = "authorization_denied"
const V4ReadMethodFailureReasonOwnerUnavailable V4ReadMethodFailureReason = "owner_unavailable"

type V4ReaderCursorSnapshot struct {
	Offset           uint64
	TransferredBytes uint64
	Target           uint64
	StreamStatus     V4StreamStatus
	TargetCause      *V4ReadCause
	StreamError      *V4TypedError
	Complete         bool
	Frozen           bool
	Delivered        bool
	Closed           bool
}

type V4ReadMethodFailure struct {
	Reason V4ReadMethodFailureReason
	Cursor *V4ReaderCursorSnapshot
}

type V4CleanupStatus struct {
	Status           V4CleanupState
	CoreCleanup      V4CoreCleanup
	PendingCallbacks uint64
}

type V4CloseResult struct {
	Direction     V4Direction
	SendDrained   bool
	ReadTerminal  V4ReadTerminal
	CleanupStatus V4CleanupStatus
	FirstError    *V4TypedError
}

type V4WriteProgress struct {
	RequestedBytes uint64
	AcceptedBytes  uint64
	Phase          V4WritePhase
	TerminalReason V4WriteTerminalReason
	CleanupStatus  V4CleanupStatus
}

type V4TransferProgress struct {
	SourceReadBytes          uint64
	DestinationAcceptedBytes uint64
	UnacceptedTail           []byte
}

type V4DuplexSendResult struct {
	EndpointKind       V4DuplexEndpointKind
	SendDrained        *bool
	NativeSendFinished *bool
}

type V4DuplexDirectionResult struct {
	Progress     V4TransferProgress
	SourceStatus V4StreamStatus
	SendResult   V4DuplexSendResult
}

type V4DuplexResult struct {
	AToB          V4DuplexDirectionResult
	BToA          V4DuplexDirectionResult
	Outcome       V4DuplexOutcome
	CleanupStatus V4CleanupStatus
	FirstError    *V4TypedError
}

type V4ResponsePublicationStatus struct {
	State V4ResponsePublicationState
	Cause *V4ResponsePublicationCause
}

type V4TopUpWireResult string

const V4TopUpWireResultSuccess V4TopUpWireResult = "success"
const V4TopUpWireResultReplay V4TopUpWireResult = "replay"
const V4TopUpWireResultSourceExhausted V4TopUpWireResult = "source_exhausted"
const V4TopUpWireResultSourceUnavailable V4TopUpWireResult = "source_unavailable"
const V4TopUpWireResultSourceContractInvalid V4TopUpWireResult = "source_contract_invalid"
const V4TopUpWireResultSourceStateUnknown V4TopUpWireResult = "source_state_unknown"
const V4TopUpWireResultOperationConflict V4TopUpWireResult = "operation_conflict"
const V4TopUpWireResultStaleGeneration V4TopUpWireResult = "stale_generation"
const V4TopUpWireResultFutureGeneration V4TopUpWireResult = "future_generation"
const V4TopUpWireResultStaleOperation V4TopUpWireResult = "stale_operation"
const V4TopUpWireResultFutureOperation V4TopUpWireResult = "future_operation"
const V4TopUpWireResultSequenceGap V4TopUpWireResult = "sequence_gap"
const V4TopUpWireResultConfigurationCapacity V4TopUpWireResult = "configuration_capacity"
const V4TopUpWireResultCapacityExhausted V4TopUpWireResult = "capacity_exhausted"
const V4TopUpWireResultRelinkRequired V4TopUpWireResult = "relink_required"
const V4TopUpWireResultSpentUnknown V4TopUpWireResult = "spent_unknown"
const V4TopUpWireResultTopUpRequestExpired V4TopUpWireResult = "top_up_request_expired"
const V4TopUpWireResultSourceResetRequired V4TopUpWireResult = "source_reset_required"
const V4TopUpWireResultPermissionDenied V4TopUpWireResult = "permission_denied"

type V4TopUpErrorCode string

const V4TopUpErrorCodeSourceExhausted V4TopUpErrorCode = "source_exhausted"
const V4TopUpErrorCodeSourceUnavailable V4TopUpErrorCode = "source_unavailable"
const V4TopUpErrorCodeSourceContractInvalid V4TopUpErrorCode = "source_contract_invalid"
const V4TopUpErrorCodeSourceStateUnknown V4TopUpErrorCode = "source_state_unknown"
const V4TopUpErrorCodeOperationConflict V4TopUpErrorCode = "operation_conflict"
const V4TopUpErrorCodeStaleGeneration V4TopUpErrorCode = "stale_generation"
const V4TopUpErrorCodeFutureGeneration V4TopUpErrorCode = "future_generation"
const V4TopUpErrorCodeStaleOperation V4TopUpErrorCode = "stale_operation"
const V4TopUpErrorCodeFutureOperation V4TopUpErrorCode = "future_operation"
const V4TopUpErrorCodeSequenceGap V4TopUpErrorCode = "sequence_gap"
const V4TopUpErrorCodeConfigurationCapacity V4TopUpErrorCode = "configuration_capacity"
const V4TopUpErrorCodeCapacityExhausted V4TopUpErrorCode = "capacity_exhausted"
const V4TopUpErrorCodeRelinkRequired V4TopUpErrorCode = "relink_required"
const V4TopUpErrorCodeSpentUnknown V4TopUpErrorCode = "spent_unknown"
const V4TopUpErrorCodeTopUpRequestExpired V4TopUpErrorCode = "top_up_request_expired"
const V4TopUpErrorCodeSourceResetRequired V4TopUpErrorCode = "source_reset_required"
const V4TopUpErrorCodePermissionDenied V4TopUpErrorCode = "permission_denied"

type V4TopUpErrorScope string

const V4TopUpErrorScopeSource V4TopUpErrorScope = "source"
const V4TopUpErrorScopeOperation V4TopUpErrorScope = "operation"
const V4TopUpErrorScopeRequest V4TopUpErrorScope = "request"

type V4TopUpWriteAction string

const V4TopUpWriteActionNone V4TopUpWriteAction = "none"
const V4TopUpWriteActionTerminal V4TopUpWriteAction = "terminal"

type V4TopUpError struct {
	Code        V4TopUpErrorCode
	Scope       V4TopUpErrorScope
	WriteAction V4TopUpWriteAction
}

type V4LifecycleObjectKind string

const V4LifecycleObjectKindSession V4LifecycleObjectKind = "session"
const V4LifecycleObjectKindEnvironment V4LifecycleObjectKind = "environment"
const V4LifecycleObjectKindOperation V4LifecycleObjectKind = "operation"
const V4LifecycleObjectKindSubscription V4LifecycleObjectKind = "subscription"
const V4LifecycleObjectKindBridge V4LifecycleObjectKind = "bridge"
const V4LifecycleObjectKindAdapter V4LifecycleObjectKind = "adapter"
const V4LifecycleObjectKindStream V4LifecycleObjectKind = "stream"
const V4LifecycleObjectKindMaterial V4LifecycleObjectKind = "material"
const V4LifecycleObjectKindSource V4LifecycleObjectKind = "source"
const V4LifecycleObjectKindRegistration V4LifecycleObjectKind = "registration"

type V4LifecycleState string

const V4LifecycleStateActive V4LifecycleState = "active"
const V4LifecycleStateClosing V4LifecycleState = "closing"
const V4LifecycleStateClosed V4LifecycleState = "closed"
const V4LifecycleStateSessionAborted V4LifecycleState = "session_aborted"

type V4LifecycleReason string

const V4LifecycleReasonNone V4LifecycleReason = "none"
const V4LifecycleReasonCanceled V4LifecycleReason = "canceled"
const V4LifecycleReasonDeadlineExceeded V4LifecycleReason = "deadline_exceeded"
const V4LifecycleReasonDependencyUnavailable V4LifecycleReason = "dependency_unavailable"
const V4LifecycleReasonCoreCleanupFailed V4LifecycleReason = "core_cleanup_failed"

type V4LifecycleResult struct {
	ObjectKind     V4LifecycleObjectKind
	LifecycleState V4LifecycleState
	CleanupStatus  V4CleanupStatus
	Reason         V4LifecycleReason
}

func TopUpErrorProjection(code V4TopUpErrorCode, action V4TopUpWriteAction) (V4TopUpError, bool) {
	switch code {
	case V4TopUpErrorCodeSourceExhausted:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSourceUnavailable:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSourceContractInvalid:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSourceStateUnknown:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeOperationConflict:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeStaleGeneration:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeRequest, WriteAction: action}, true
		}
	case V4TopUpErrorCodeFutureGeneration:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeRequest, WriteAction: action}, true
		}
	case V4TopUpErrorCodeStaleOperation:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeFutureOperation:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSequenceGap:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeConfigurationCapacity:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeRequest, WriteAction: action}, true
		}
	case V4TopUpErrorCodeCapacityExhausted:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeRelinkRequired:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSpentUnknown:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodeTopUpRequestExpired:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeOperation, WriteAction: action}, true
		}
	case V4TopUpErrorCodeSourceResetRequired:
		if action == V4TopUpWriteActionNone || action == V4TopUpWriteActionTerminal {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	case V4TopUpErrorCodePermissionDenied:
		if action == V4TopUpWriteActionNone {
			return V4TopUpError{Code: code, Scope: V4TopUpErrorScopeSource, WriteAction: action}, true
		}
	}
	return V4TopUpError{}, false
}

func ValidLifecycleResult(value V4LifecycleResult) bool {
	cleanup := value.CleanupStatus
	return (value.ObjectKind == V4LifecycleObjectKindSession || value.ObjectKind == V4LifecycleObjectKindEnvironment || value.ObjectKind == V4LifecycleObjectKindOperation || value.ObjectKind == V4LifecycleObjectKindSubscription || value.ObjectKind == V4LifecycleObjectKindBridge || value.ObjectKind == V4LifecycleObjectKindAdapter || value.ObjectKind == V4LifecycleObjectKindStream || value.ObjectKind == V4LifecycleObjectKindMaterial || value.ObjectKind == V4LifecycleObjectKindSource || value.ObjectKind == V4LifecycleObjectKindRegistration) &&
		(value.LifecycleState == V4LifecycleStateActive || value.LifecycleState == V4LifecycleStateClosing || value.LifecycleState == V4LifecycleStateClosed || value.LifecycleState == V4LifecycleStateSessionAborted) &&
		(value.Reason == V4LifecycleReasonNone || value.Reason == V4LifecycleReasonCanceled || value.Reason == V4LifecycleReasonDeadlineExceeded || value.Reason == V4LifecycleReasonDependencyUnavailable || value.Reason == V4LifecycleReasonCoreCleanupFailed) &&
		(cleanup.Status == V4CleanupStatePending || cleanup.Status == V4CleanupStateComplete || cleanup.Status == V4CleanupStateCleanupIncomplete) &&
		(cleanup.CoreCleanup == V4CoreCleanupPending || cleanup.CoreCleanup == V4CoreCleanupComplete) &&
		(cleanup.Status == V4CleanupStateComplete) == (cleanup.CoreCleanup == V4CoreCleanupComplete && cleanup.PendingCallbacks == 0) &&
		(value.LifecycleState != V4LifecycleStateSessionAborted || value.ObjectKind == V4LifecycleObjectKindSession) &&
		(cleanup.Status != V4CleanupStateComplete || value.LifecycleState == V4LifecycleStateClosed || value.LifecycleState == V4LifecycleStateSessionAborted)
}

func ConnectionAssurance(class string) (V4ConnectionGuarantees, bool) {
	switch class {
	case "native_websocket_tls13":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationConsumerEnforced, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "native_websocket_loopback":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "accepted_websocket":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "browser_websocket_terminator":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationControlledTerminator, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "native_quic_tls13":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationConsumerEnforced, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "accepted_quic":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "native_webtransport_tls13":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationConsumerEnforced, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "accepted_webtransport":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteDirectPath, Assumptions: V4ConnectionGuaranteeAssumptionsAuthenticatedPeerWithinTransportProfile}, true
	case "go_relay_native_consumer":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationConsumerEnforced, Scope: V4ConnectionGuaranteeScopeCompleteRelayPath, Assumptions: V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile}, true
	case "go_relay_native_observer":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressIndependentWithinProfile, BoundStreamInputIsolation: V4BoundStreamInputIsolationBoundStreamWithinProfile, Datagram: true, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteRelayPath, Assumptions: V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile}, true
	case "go_relay_shared_consumer":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationConsumerEnforced, Scope: V4ConnectionGuaranteeScopeCompleteRelayPath, Assumptions: V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile}, true
	case "go_relay_shared_observer":
		return V4ConnectionGuarantees{ReliableProgress: V4ReliableProgressSharedOrdered, BoundStreamInputIsolation: V4BoundStreamInputIsolationSharedFailureScope, Datagram: false, LocalConsumerTls13Verification: V4ConsumerTLS13VerificationNotApplicable, Scope: V4ConnectionGuaranteeScopeCompleteRelayPath, Assumptions: V4ConnectionGuaranteeAssumptionsTrustedRelayAndPeersWithinTransportProfile}, true
	default:
		return V4ConnectionGuarantees{}, false
	}
}

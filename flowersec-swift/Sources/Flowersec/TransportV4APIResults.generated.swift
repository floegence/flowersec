// Generated draft native API types; DO NOT EDIT. Not a qualified SDK runtime.
enum TransportV4APIResults { static let schemaSHA256 = "9d2322a4755f74a1744e9ff5688b2ef95c3e22bf511d12c4083c96f2fe16813f" }

enum V4ApplicationProfile: String {
    case transport = "transport"
    case services = "services"
    case execution = "execution"
}

enum V4ReliableProgress: String {
    case sharedOrdered = "shared_ordered"
    case independentWithinProfile = "independent_within_profile"
}

enum V4BoundStreamInputIsolation: String {
    case sharedFailureScope = "shared_failure_scope"
    case boundStreamWithinProfile = "bound_stream_within_profile"
}

enum V4ConsumerTLS13Verification: String {
    case notApplicable = "not_applicable"
    case controlledTerminator = "controlled_terminator"
    case consumerEnforced = "consumer_enforced"
}

enum V4ConnectionGuaranteeScope: String {
    case completeDirectPath = "complete_direct_path"
    case completeRelayPath = "complete_relay_path"
}

enum V4ConnectionGuaranteeAssumptions: String {
    case authenticatedPeerWithinTransportProfile = "authenticated_peer_within_transport_profile"
    case trustedRelayAndPeersWithinTransportProfile = "trusted_relay_and_peers_within_transport_profile"
}

struct V4ConnectionRequirements {
    let independentReliableReadProgress: Bool
    let boundStreamInputIsolation: Bool
    let datagram: Bool
    let localConsumerTls13Verification: Bool
    let applicationProfile: V4ApplicationProfile?
}

struct V4ConnectionGuarantees {
    let reliableProgress: V4ReliableProgress
    let boundStreamInputIsolation: V4BoundStreamInputIsolation
    let datagram: Bool
    let localConsumerTls13Verification: V4ConsumerTLS13Verification
    let scope: V4ConnectionGuaranteeScope
    let assumptions: V4ConnectionGuaranteeAssumptions
}

struct V4SessionInfo {
    let applicationProfile: V4ApplicationProfile
    let selectedFeatures: UInt64
    let guarantees: V4ConnectionGuarantees
}

enum V4Direction: String {
    case c2s = "c2s"
    case s2c = "s2c"
}

enum V4ReadTerminal: String {
    case eof = "eof"
    case abandoned = "abandoned"
    case open = "open"
    case unknown = "unknown"
}

enum V4WaitStatus: String {
    case ready = "ready"
    case blocked = "blocked"
    case waitCanceled = "wait_canceled"
}

enum V4StreamStatus: String {
    case open = "open"
    case eof = "eof"
    case aborted = "aborted"
    case error = "error"
}

enum V4ReadCause: String {
    case delimiterNotFound = "delimiter_not_found"
    case unexpectedEof = "unexpected_eof"
}

enum V4CleanupState: String {
    case pending = "pending"
    case complete = "complete"
    case cleanupIncomplete = "cleanup_incomplete"
}

enum V4CoreCleanup: String {
    case pending = "pending"
    case complete = "complete"
}

enum V4WritePhase: String {
    case prepared = "prepared"
    case running = "running"
    case terminal = "terminal"
}

enum V4WriteTerminalReason: String {
    case none = "none"
    case complete = "complete"
    case canceled = "canceled"
    case deadlineExceeded = "deadline_exceeded"
    case queueFull = "queue_full"
    case streamTerminated = "stream_terminated"
    case failed = "failed"
}

enum V4DuplexEndpointKind: String {
    case flowersecStream = "flowersec_stream"
    case nativeDuplex = "native_duplex"
}

enum V4DuplexOutcome: String {
    case normal = "normal"
    case failed = "failed"
    case aborted = "aborted"
}

enum V4ResponsePublicationState: String {
    case notApplicable = "not_applicable"
    case pending = "pending"
    case flushed = "flushed"
    case unknown = "unknown"
}

enum V4ResponsePublicationCause: String {
    case responseSuperseded = "response_superseded"
    case responseAborted = "response_aborted"
    case ownerUnavailable = "owner_unavailable"
    case deadline = "deadline"
    case publishFailed = "publish_failed"
}

enum V4PublicationTransferResult: String {
    case success = "success"
    case alreadyTransferred = "already_transferred"
    case ownerUnavailable = "owner_unavailable"
    case expired = "expired"
    case invalid = "invalid"
}

enum V4ErrorCode: String {
    case protocolViolation = "protocol_violation"
    case framingError = "framing_error"
    case authenticationFailed = "authentication_failed"
    case sequenceError = "sequence_error"
    case replayDetected = "replay_detected"
    case cryptoFailure = "crypto_failure"
    case rekeyFailed = "rekey_failed"
    case resourceExhausted = "resource_exhausted"
    case streamSequenceError = "stream_sequence_error"
    case streamDataInvalid = "stream_data_invalid"
}

enum V4ErrorScope: String {
    case session = "session"
    case stream = "stream"
}

enum V4RetryDisposition: String {
    case preserveFacts = "preserve_facts"
}

struct V4TypedError {
    let code: V4ErrorCode
    let scope: V4ErrorScope
    let retryDisposition: V4RetryDisposition
}

struct V4ReadProgress {
    let offset: UInt64
    let filled: UInt64
    let target: UInt64?
}

struct V4ReadResult {
    let data: [UInt8]
    let progress: V4ReadProgress
    let waitStatus: V4WaitStatus
    let streamStatus: V4StreamStatus
    let cause: V4ReadCause?
    let error: V4TypedError?
}

enum V4ReadMethodFailureReason: String {
    case invalidArgument = "invalid_argument"
    case targetMismatch = "target_mismatch"
    case readInProgress = "read_in_progress"
    case prefixFrozen = "prefix_frozen"
    case alreadyDelivered = "already_delivered"
    case closed = "closed"
    case timePending = "time_pending"
    case timeUnavailable = "time_unavailable"
    case authorizationDenied = "authorization_denied"
    case ownerUnavailable = "owner_unavailable"
}

struct V4ReaderCursorSnapshot {
    let offset: UInt64
    let transferredBytes: UInt64
    let target: UInt64
    let streamStatus: V4StreamStatus
    let targetCause: V4ReadCause?
    let streamError: V4TypedError?
    let complete: Bool
    let frozen: Bool
    let delivered: Bool
    let closed: Bool
}

struct V4ReadMethodFailure {
    let reason: V4ReadMethodFailureReason
    let cursor: V4ReaderCursorSnapshot?
}

struct V4CleanupStatus {
    let status: V4CleanupState
    let coreCleanup: V4CoreCleanup
    let pendingCallbacks: UInt64
}

struct V4CloseResult {
    let direction: V4Direction
    let sendDrained: Bool
    let readTerminal: V4ReadTerminal
    let cleanupStatus: V4CleanupStatus
    let firstError: V4TypedError?
}

struct V4WriteProgress {
    let requestedBytes: UInt64
    let acceptedBytes: UInt64
    let phase: V4WritePhase
    let terminalReason: V4WriteTerminalReason
    let cleanupStatus: V4CleanupStatus
}

struct V4TransferProgress {
    let sourceReadBytes: UInt64
    let destinationAcceptedBytes: UInt64
    let unacceptedTail: [UInt8]
}

struct V4DuplexSendResult {
    let endpointKind: V4DuplexEndpointKind
    let sendDrained: Bool?
    let nativeSendFinished: Bool?
}

struct V4DuplexDirectionResult {
    let progress: V4TransferProgress
    let sourceStatus: V4StreamStatus
    let sendResult: V4DuplexSendResult
}

struct V4DuplexResult {
    let aToB: V4DuplexDirectionResult
    let bToA: V4DuplexDirectionResult
    let outcome: V4DuplexOutcome
    let cleanupStatus: V4CleanupStatus
    let firstError: V4TypedError?
}

struct V4ResponsePublicationStatus {
    let state: V4ResponsePublicationState
    let cause: V4ResponsePublicationCause?
}

enum V4TopUpWireResult: String {
    case success = "success"
    case replay = "replay"
    case sourceExhausted = "source_exhausted"
    case sourceUnavailable = "source_unavailable"
    case sourceContractInvalid = "source_contract_invalid"
    case sourceStateUnknown = "source_state_unknown"
    case operationConflict = "operation_conflict"
    case staleGeneration = "stale_generation"
    case futureGeneration = "future_generation"
    case staleOperation = "stale_operation"
    case futureOperation = "future_operation"
    case sequenceGap = "sequence_gap"
    case configurationCapacity = "configuration_capacity"
    case capacityExhausted = "capacity_exhausted"
    case relinkRequired = "relink_required"
    case spentUnknown = "spent_unknown"
    case topUpRequestExpired = "top_up_request_expired"
    case sourceResetRequired = "source_reset_required"
    case permissionDenied = "permission_denied"
}

enum V4TopUpErrorCode: String {
    case sourceExhausted = "source_exhausted"
    case sourceUnavailable = "source_unavailable"
    case sourceContractInvalid = "source_contract_invalid"
    case sourceStateUnknown = "source_state_unknown"
    case operationConflict = "operation_conflict"
    case staleGeneration = "stale_generation"
    case futureGeneration = "future_generation"
    case staleOperation = "stale_operation"
    case futureOperation = "future_operation"
    case sequenceGap = "sequence_gap"
    case configurationCapacity = "configuration_capacity"
    case capacityExhausted = "capacity_exhausted"
    case relinkRequired = "relink_required"
    case spentUnknown = "spent_unknown"
    case topUpRequestExpired = "top_up_request_expired"
    case sourceResetRequired = "source_reset_required"
    case permissionDenied = "permission_denied"
}

enum V4TopUpErrorScope: String {
    case source = "source"
    case operation = "operation"
    case request = "request"
}

enum V4TopUpWriteAction: String {
    case none = "none"
    case terminal = "terminal"
}

struct V4TopUpError {
    let code: V4TopUpErrorCode
    let scope: V4TopUpErrorScope
    let writeAction: V4TopUpWriteAction
}

enum V4LifecycleObjectKind: String {
    case session = "session"
    case environment = "environment"
    case operation = "operation"
    case subscription = "subscription"
    case bridge = "bridge"
    case adapter = "adapter"
    case stream = "stream"
    case material = "material"
    case source = "source"
    case registration = "registration"
}

enum V4LifecycleState: String {
    case active = "active"
    case closing = "closing"
    case closed = "closed"
    case sessionAborted = "session_aborted"
}

enum V4LifecycleReason: String {
    case none = "none"
    case canceled = "canceled"
    case deadlineExceeded = "deadline_exceeded"
    case dependencyUnavailable = "dependency_unavailable"
    case coreCleanupFailed = "core_cleanup_failed"
}

struct V4LifecycleResult {
    let objectKind: V4LifecycleObjectKind
    let lifecycleState: V4LifecycleState
    let cleanupStatus: V4CleanupStatus
    let reason: V4LifecycleReason
}

func topUpErrorProjection(_ code: V4TopUpErrorCode, _ action: V4TopUpWriteAction) -> V4TopUpError? {
    switch code {
    case .sourceExhausted: return (action == .none) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .sourceUnavailable: return (action == .none) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .sourceContractInvalid: return (action == .none) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .sourceStateUnknown: return (action == .none) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .operationConflict: return (action == .none) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .staleGeneration: return (action == .none) ? V4TopUpError(code: code, scope: .request, writeAction: action) : nil
    case .futureGeneration: return (action == .none) ? V4TopUpError(code: code, scope: .request, writeAction: action) : nil
    case .staleOperation: return (action == .none) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .futureOperation: return (action == .none) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .sequenceGap: return (action == .none) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .configurationCapacity: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .request, writeAction: action) : nil
    case .capacityExhausted: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .relinkRequired: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .spentUnknown: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .topUpRequestExpired: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .operation, writeAction: action) : nil
    case .sourceResetRequired: return (action == .none || action == .terminal) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    case .permissionDenied: return (action == .none) ? V4TopUpError(code: code, scope: .source, writeAction: action) : nil
    }
}

func validLifecycleResult(_ value: V4LifecycleResult) -> Bool {
    let cleanup = value.cleanupStatus
    return (cleanup.status == .complete) == (cleanup.coreCleanup == .complete && cleanup.pendingCallbacks == 0)
        && (value.lifecycleState != .sessionAborted || value.objectKind == .session)
        && (cleanup.status != .complete || value.lifecycleState == .closed || value.lifecycleState == .sessionAborted)
}

func connectionAssurance(_ value: String) -> V4ConnectionGuarantees? {
    switch value {
    case "native_websocket_tls13": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .consumerEnforced, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "native_websocket_loopback": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .notApplicable, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "accepted_websocket": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .notApplicable, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "browser_websocket_terminator": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .controlledTerminator, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "native_quic_tls13": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .consumerEnforced, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "accepted_quic": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .notApplicable, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "native_webtransport_tls13": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .consumerEnforced, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "accepted_webtransport": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .notApplicable, scope: .completeDirectPath, assumptions: .authenticatedPeerWithinTransportProfile)
    case "go_relay_native_consumer": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .consumerEnforced, scope: .completeRelayPath, assumptions: .trustedRelayAndPeersWithinTransportProfile)
    case "go_relay_native_observer": return V4ConnectionGuarantees(reliableProgress: .independentWithinProfile, boundStreamInputIsolation: .boundStreamWithinProfile, datagram: true, localConsumerTls13Verification: .notApplicable, scope: .completeRelayPath, assumptions: .trustedRelayAndPeersWithinTransportProfile)
    case "go_relay_shared_consumer": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .consumerEnforced, scope: .completeRelayPath, assumptions: .trustedRelayAndPeersWithinTransportProfile)
    case "go_relay_shared_observer": return V4ConnectionGuarantees(reliableProgress: .sharedOrdered, boundStreamInputIsolation: .sharedFailureScope, datagram: false, localConsumerTls13Verification: .notApplicable, scope: .completeRelayPath, assumptions: .trustedRelayAndPeersWithinTransportProfile)
    default: return nil
    }
}

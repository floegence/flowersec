// Generated draft native API types; DO NOT EDIT. Not a qualified SDK runtime.
export const transportV4APIResultsSchemaSHA256 = "9d2322a4755f74a1744e9ff5688b2ef95c3e22bf511d12c4083c96f2fe16813f" as const;

export type V4ApplicationProfile = "transport" | "services" | "execution";

export type V4ReliableProgress = "shared_ordered" | "independent_within_profile";

export type V4BoundStreamInputIsolation = "shared_failure_scope" | "bound_stream_within_profile";

export type V4ConsumerTLS13Verification = "not_applicable" | "controlled_terminator" | "consumer_enforced";

export type V4ConnectionGuaranteeScope = "complete_direct_path" | "complete_relay_path";

export type V4ConnectionGuaranteeAssumptions = "authenticated_peer_within_transport_profile" | "trusted_relay_and_peers_within_transport_profile";

export interface V4ConnectionRequirements {
  readonly independent_reliable_read_progress: boolean;
  readonly bound_stream_input_isolation: boolean;
  readonly datagram: boolean;
  readonly local_consumer_tls13_verification: boolean;
  readonly application_profile?: V4ApplicationProfile;
}

export interface V4ConnectionGuarantees {
  readonly reliable_progress: V4ReliableProgress;
  readonly bound_stream_input_isolation: V4BoundStreamInputIsolation;
  readonly datagram: boolean;
  readonly local_consumer_tls13_verification: V4ConsumerTLS13Verification;
  readonly scope: V4ConnectionGuaranteeScope;
  readonly assumptions: V4ConnectionGuaranteeAssumptions;
}

export interface V4SessionInfo {
  readonly application_profile: V4ApplicationProfile;
  readonly selected_features: bigint;
  readonly guarantees: V4ConnectionGuarantees;
}

export type V4Direction = "c2s" | "s2c";

export type V4ReadTerminal = "eof" | "abandoned" | "open" | "unknown";

export type V4WaitStatus = "ready" | "blocked" | "wait_canceled";

export type V4StreamStatus = "open" | "eof" | "aborted" | "error";

export type V4ReadCause = "delimiter_not_found" | "unexpected_eof";

export type V4CleanupState = "pending" | "complete" | "cleanup_incomplete";

export type V4CoreCleanup = "pending" | "complete";

export type V4WritePhase = "prepared" | "running" | "terminal";

export type V4WriteTerminalReason = "none" | "complete" | "canceled" | "deadline_exceeded" | "queue_full" | "stream_terminated" | "failed";

export type V4DuplexEndpointKind = "flowersec_stream" | "native_duplex";

export type V4DuplexOutcome = "normal" | "failed" | "aborted";

export type V4ResponsePublicationState = "not_applicable" | "pending" | "flushed" | "unknown";

export type V4ResponsePublicationCause = "response_superseded" | "response_aborted" | "owner_unavailable" | "deadline" | "publish_failed";

export type V4PublicationTransferResult = "success" | "already_transferred" | "owner_unavailable" | "expired" | "invalid";

export type V4ErrorCode = "protocol_violation" | "framing_error" | "authentication_failed" | "sequence_error" | "replay_detected" | "crypto_failure" | "rekey_failed" | "resource_exhausted" | "stream_sequence_error" | "stream_data_invalid";

export type V4ErrorScope = "session" | "stream";

export type V4RetryDisposition = "preserve_facts";

export interface V4TypedError {
  readonly code: V4ErrorCode;
  readonly scope: V4ErrorScope;
  readonly retry_disposition: V4RetryDisposition;
}

export interface V4ReadProgress {
  readonly offset: bigint;
  readonly filled: bigint;
  readonly target?: bigint;
}

export interface V4ReadResult {
  readonly data: Uint8Array;
  readonly progress: V4ReadProgress;
  readonly wait_status: V4WaitStatus;
  readonly stream_status: V4StreamStatus;
  readonly cause?: V4ReadCause;
  readonly error?: V4TypedError;
}

export type V4ReadMethodFailureReason = "invalid_argument" | "target_mismatch" | "read_in_progress" | "prefix_frozen" | "already_delivered" | "closed" | "time_pending" | "time_unavailable" | "authorization_denied" | "owner_unavailable";

export interface V4ReaderCursorSnapshot {
  readonly offset: bigint;
  readonly transferred_bytes: bigint;
  readonly target: bigint;
  readonly stream_status: V4StreamStatus;
  readonly target_cause?: V4ReadCause;
  readonly stream_error?: V4TypedError;
  readonly complete: boolean;
  readonly frozen: boolean;
  readonly delivered: boolean;
  readonly closed: boolean;
}

export interface V4ReadMethodFailure {
  readonly reason: V4ReadMethodFailureReason;
  readonly cursor?: V4ReaderCursorSnapshot;
}

export interface V4CleanupStatus {
  readonly status: V4CleanupState;
  readonly core_cleanup: V4CoreCleanup;
  readonly pending_callbacks: bigint;
}

export interface V4CloseResult {
  readonly direction: V4Direction;
  readonly send_drained: boolean;
  readonly read_terminal: V4ReadTerminal;
  readonly cleanup_status: V4CleanupStatus;
  readonly first_error?: V4TypedError;
}

export interface V4WriteProgress {
  readonly requested_bytes: bigint;
  readonly accepted_bytes: bigint;
  readonly phase: V4WritePhase;
  readonly terminal_reason: V4WriteTerminalReason;
  readonly cleanup_status: V4CleanupStatus;
}

export interface V4TransferProgress {
  readonly source_read_bytes: bigint;
  readonly destination_accepted_bytes: bigint;
  readonly unaccepted_tail: Uint8Array;
}

export interface V4DuplexSendResult {
  readonly endpoint_kind: V4DuplexEndpointKind;
  readonly send_drained?: boolean;
  readonly native_send_finished?: boolean;
}

export interface V4DuplexDirectionResult {
  readonly progress: V4TransferProgress;
  readonly source_status: V4StreamStatus;
  readonly send_result: V4DuplexSendResult;
}

export interface V4DuplexResult {
  readonly a_to_b: V4DuplexDirectionResult;
  readonly b_to_a: V4DuplexDirectionResult;
  readonly outcome: V4DuplexOutcome;
  readonly cleanup_status: V4CleanupStatus;
  readonly first_error?: V4TypedError;
}

export interface V4ResponsePublicationStatus {
  readonly state: V4ResponsePublicationState;
  readonly cause?: V4ResponsePublicationCause;
}

export type V4TopUpWireResult = "success" | "replay" | "source_exhausted" | "source_unavailable" | "source_contract_invalid" | "source_state_unknown" | "operation_conflict" | "stale_generation" | "future_generation" | "stale_operation" | "future_operation" | "sequence_gap" | "configuration_capacity" | "capacity_exhausted" | "relink_required" | "spent_unknown" | "top_up_request_expired" | "source_reset_required" | "permission_denied";

export type V4TopUpErrorCode = "source_exhausted" | "source_unavailable" | "source_contract_invalid" | "source_state_unknown" | "operation_conflict" | "stale_generation" | "future_generation" | "stale_operation" | "future_operation" | "sequence_gap" | "configuration_capacity" | "capacity_exhausted" | "relink_required" | "spent_unknown" | "top_up_request_expired" | "source_reset_required" | "permission_denied";

export type V4TopUpErrorScope = "source" | "operation" | "request";

export type V4TopUpWriteAction = "none" | "terminal";

export interface V4TopUpError {
  readonly code: V4TopUpErrorCode;
  readonly scope: V4TopUpErrorScope;
  readonly write_action: V4TopUpWriteAction;
}

export type V4LifecycleObjectKind = "session" | "environment" | "operation" | "subscription" | "bridge" | "adapter" | "stream" | "material" | "source" | "registration";

export type V4LifecycleState = "active" | "closing" | "closed" | "session_aborted";

export type V4LifecycleReason = "none" | "canceled" | "deadline_exceeded" | "dependency_unavailable" | "core_cleanup_failed";

export interface V4LifecycleResult {
  readonly object_kind: V4LifecycleObjectKind;
  readonly lifecycle_state: V4LifecycleState;
  readonly cleanup_status: V4CleanupStatus;
  readonly reason: V4LifecycleReason;
}

export function topUpErrorProjection(code: V4TopUpErrorCode, action: V4TopUpWriteAction): V4TopUpError | undefined {
  switch (code) {
    case "source_exhausted": return (action === "none") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "source_unavailable": return (action === "none") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "source_contract_invalid": return (action === "none") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "source_state_unknown": return (action === "none") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "operation_conflict": return (action === "none") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "stale_generation": return (action === "none") ? Object.freeze({code, scope: "request", write_action: action}) : undefined;
    case "future_generation": return (action === "none") ? Object.freeze({code, scope: "request", write_action: action}) : undefined;
    case "stale_operation": return (action === "none") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "future_operation": return (action === "none") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "sequence_gap": return (action === "none") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "configuration_capacity": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "request", write_action: action}) : undefined;
    case "capacity_exhausted": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "relink_required": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "spent_unknown": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "top_up_request_expired": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "operation", write_action: action}) : undefined;
    case "source_reset_required": return (action === "none" || action === "terminal") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
    case "permission_denied": return (action === "none") ? Object.freeze({code, scope: "source", write_action: action}) : undefined;
  }
}

export function validLifecycleResult(value: V4LifecycleResult): boolean {
  const cleanup = value.cleanup_status;
  return (value.object_kind === "session" || value.object_kind === "environment" || value.object_kind === "operation" || value.object_kind === "subscription" || value.object_kind === "bridge" || value.object_kind === "adapter" || value.object_kind === "stream" || value.object_kind === "material" || value.object_kind === "source" || value.object_kind === "registration") &&
    (value.lifecycle_state === "active" || value.lifecycle_state === "closing" || value.lifecycle_state === "closed" || value.lifecycle_state === "session_aborted") &&
    (value.reason === "none" || value.reason === "canceled" || value.reason === "deadline_exceeded" || value.reason === "dependency_unavailable" || value.reason === "core_cleanup_failed") &&
    (cleanup.status === "pending" || cleanup.status === "complete" || cleanup.status === "cleanup_incomplete") &&
    (cleanup.core_cleanup === "pending" || cleanup.core_cleanup === "complete") &&
    typeof cleanup.pending_callbacks === "bigint" && cleanup.pending_callbacks >= 0n && cleanup.pending_callbacks <= 0xffffffffffffffffn &&
    (cleanup.status === "complete") === (cleanup.core_cleanup === "complete" && cleanup.pending_callbacks === 0n) &&
    (value.lifecycle_state !== "session_aborted" || value.object_kind === "session") &&
    (cleanup.status !== "complete" || value.lifecycle_state === "closed" || value.lifecycle_state === "session_aborted");
}

export function connectionAssurance(value: string): V4ConnectionGuarantees | undefined {
  switch (value) {
    case "native_websocket_tls13": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"consumer_enforced","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "native_websocket_loopback": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"not_applicable","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "accepted_websocket": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"not_applicable","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "browser_websocket_terminator": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"controlled_terminator","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "native_quic_tls13": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"consumer_enforced","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "accepted_quic": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"not_applicable","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "native_webtransport_tls13": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"consumer_enforced","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "accepted_webtransport": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"not_applicable","scope":"complete_direct_path","assumptions":"authenticated_peer_within_transport_profile"});
    case "go_relay_native_consumer": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"consumer_enforced","scope":"complete_relay_path","assumptions":"trusted_relay_and_peers_within_transport_profile"});
    case "go_relay_native_observer": return Object.freeze({"reliable_progress":"independent_within_profile","bound_stream_input_isolation":"bound_stream_within_profile","datagram":true,"local_consumer_tls13_verification":"not_applicable","scope":"complete_relay_path","assumptions":"trusted_relay_and_peers_within_transport_profile"});
    case "go_relay_shared_consumer": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"consumer_enforced","scope":"complete_relay_path","assumptions":"trusted_relay_and_peers_within_transport_profile"});
    case "go_relay_shared_observer": return Object.freeze({"reliable_progress":"shared_ordered","bound_stream_input_isolation":"shared_failure_scope","datagram":false,"local_consumer_tls13_verification":"not_applicable","scope":"complete_relay_path","assumptions":"trusted_relay_and_peers_within_transport_profile"});
    default: return undefined;
  }
}

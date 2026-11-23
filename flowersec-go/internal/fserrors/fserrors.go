package fserrors

import (
	"fmt"
)

// RuntimeError owns failures produced before a carrier contract exists, such
// as socket, TLS, HTTP/3, or native runtime startup.
type RuntimeError struct {
	Operation string
	Err       error
}

func (e *RuntimeError) Error() string { return fmt.Sprintf("runtime %s: %v", e.Operation, e.Err) }
func (e *RuntimeError) Unwrap() error { return e.Err }

// CarrierError owns reliable-stream, datagram, admission transport, and native
// carrier termination failures after the runtime adapter is ready.
type CarrierError struct {
	Operation string
	Err       error
}

func (e *CarrierError) Error() string { return fmt.Sprintf("carrier %s: %v", e.Operation, e.Err) }
func (e *CarrierError) Unwrap() error { return e.Err }

// SessionError owns Flowersec handshake, RPC, rekey, liveness, and logical
// stream protocol failures above an admitted carrier.
type SessionError struct {
	Operation string
	Err       error
}

func (e *SessionError) Error() string { return fmt.Sprintf("session %s: %v", e.Operation, e.Err) }
func (e *SessionError) Unwrap() error { return e.Err }

func Runtime(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &RuntimeError{Operation: operation, Err: err}
}

func Carrier(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &CarrierError{Operation: operation, Err: err}
}

func Session(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &SessionError{Operation: operation, Err: err}
}

// Path identifies the top-level connect path.
type Path string

const (
	PathTunnel Path = "tunnel"
	PathDirect Path = "direct"
)

// Stage identifies which step of the protocol stack failed.
type Stage string

const (
	StageValidate  Stage = "validate"
	StageConnect   Stage = "connect"
	StageAttach    Stage = "attach"
	StageHandshake Stage = "handshake"
	StageSecure    Stage = "secure"
	StageRPC       Stage = "rpc"
	StageClose     Stage = "close"
)

// Code is a stable, programmatic error identifier for user-facing operations.
type Code string

const (
	CodeTimeout                   Code = "timeout"
	CodeCanceled                  Code = "canceled"
	CodeInvalidInput              Code = "invalid_input"
	CodeMissingGrant              Code = "missing_grant"
	CodeMissingConnectInfo        Code = "missing_connect_info"
	CodeRoleMismatch              Code = "role_mismatch"
	CodeMissingTunnelURL          Code = "missing_tunnel_url"
	CodeMissingWSURL              Code = "missing_ws_url"
	CodeMissingOrigin             Code = "missing_origin"
	CodeMissingConn               Code = "missing_conn"
	CodeMissingChannelID          Code = "missing_channel_id"
	CodeMissingToken              Code = "missing_token"
	CodeMissingInitExp            Code = "missing_init_exp"
	CodeTimestampAfterInitExp     Code = "timestamp_after_init_exp"
	CodeTimestampOutOfSkew        Code = "timestamp_out_of_skew"
	CodeAuthTagMismatch           Code = "auth_tag_mismatch"
	CodeInvalidVersion            Code = "invalid_version"
	CodeInvalidSuite              Code = "invalid_suite"
	CodeInvalidPSK                Code = "invalid_psk"
	CodeInvalidEndpointInstanceID Code = "invalid_endpoint_instance_id"
	CodeInvalidOption             Code = "invalid_option"
	CodeResolveFailed             Code = "resolve_failed"
	CodeUnsupportedCapability     Code = "unsupported_capability"
	CodeTLSUnsupported            Code = "tls_unsupported"
	CodeTLSPolicyExpired          Code = "tls_policy_expired"
	CodeTLSFailed                 Code = "tls_failed"
	CodeCredentialCommitFailed    Code = "credential_commit_failed"
	CodeRandomFailed              Code = "random_failed"
	CodeUpgradeFailed             Code = "upgrade_failed"
	CodeNotConnected              Code = "not_connected"
	CodeMissingHandler            Code = "missing_handler"
	CodeMissingStreamKind         Code = "missing_stream_kind"
	CodeDialFailed                Code = "dial_failed"
	CodeAttachFailed              Code = "attach_failed"
	CodeTooManyConnections        Code = "too_many_connections"
	CodeExpectedAttach            Code = "expected_attach"
	CodeInvalidAttach             Code = "invalid_attach"
	CodeInvalidToken              Code = "invalid_token"
	CodeChannelMismatch           Code = "channel_mismatch"
	CodeInitExpMismatch           Code = "init_exp_mismatch"
	CodeIdleTimeoutMismatch       Code = "idle_timeout_mismatch"
	CodeTokenReplay               Code = "token_replay"
	CodeTenantMismatch            Code = "tenant_mismatch"
	CodePolicyDenied              Code = "policy_denied"
	CodePolicyError               Code = "policy_error"
	CodeReplaceRateLimited        Code = "replace_rate_limited"
	CodeHandshakeFailed           Code = "handshake_failed"
	CodePingFailed                Code = "ping_failed"
	CodeRekeyFailed               Code = "rekey_failed"
	CodeAcceptStreamFailed        Code = "accept_stream_failed"
	CodeOpenStreamFailed          Code = "open_stream_failed"
	CodeStreamHelloFailed         Code = "stream_hello_failed"
	CodeRPCFailed                 Code = "rpc_failed"
	CodeResourceExhausted         Code = "resource_exhausted"
)

// CandidateDiagnostic records one transport candidate failure without losing
// the stable connect error taxonomy exposed to callers.
type CandidateDiagnostic struct {
	CandidateID string
	Carrier     string
	Stage       Stage
	Code        Code
	Err         error
	// Detail is restricted internal telemetry. Public SDK errors must never
	// expose it or the underlying provider error.
	Detail string
}

// Error is a structured, programmatically identifiable error for user-facing operations.
type Error struct {
	Path        Path
	Stage       Stage
	Code        Code
	Err         error
	Diagnostics []CandidateDiagnostic
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err != nil {
		return fmt.Sprintf("%s %s (%s): %v", e.Path, e.Stage, e.Code, e.Err)
	}
	return fmt.Sprintf("%s %s (%s)", e.Path, e.Stage, e.Code)
}

func (e *Error) Unwrap() error { return e.Err }

func Wrap(path Path, stage Stage, code Code, err error) error {
	return &Error{Path: path, Stage: stage, Code: code, Err: err}
}

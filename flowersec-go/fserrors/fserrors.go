package fserrors

import "fmt"

// Path identifies the top-level connect path.
type Path string

const (
	PathAuto   Path = "auto"
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
	StageYamux     Stage = "yamux"
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
	CodeRandomFailed              Code = "random_failed"
	CodeUpgradeFailed             Code = "upgrade_failed"
	CodeNotConnected              Code = "not_connected"
	CodeMissingHandler            Code = "missing_handler"
	CodeMissingStreamKind         Code = "missing_stream_kind"
	CodeDialFailed                Code = "dial_failed"
	CodeAttachFailed              Code = "attach_failed"
	CodeHandshakeFailed           Code = "handshake_failed"
	CodePingFailed                Code = "ping_failed"
	CodeMuxFailed                 Code = "mux_failed"
	CodeAcceptStreamFailed        Code = "accept_stream_failed"
	CodeOpenStreamFailed          Code = "open_stream_failed"
	CodeStreamHelloFailed         Code = "stream_hello_failed"
)

// Error is a structured, programmatically identifiable error for user-facing operations.
type Error struct {
	Path  Path
	Stage Stage
	Code  Code
	Err   error
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

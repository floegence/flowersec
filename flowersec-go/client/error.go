package client

import "fmt"

type Stage string

const (
	StageValidate  Stage = "validate"
	StageConnect   Stage = "connect"
	StageAttach    Stage = "attach"
	StageHandshake Stage = "handshake"
	StageYamux     Stage = "yamux"
	StageRPC       Stage = "rpc"
	StageClose     Stage = "close"
)

type Code string

const (
	CodeMissingGrant              Code = "missing_grant"
	CodeMissingConnectInfo        Code = "missing_connect_info"
	CodeRoleMismatch              Code = "role_mismatch"
	CodeMissingTunnelURL          Code = "missing_tunnel_url"
	CodeMissingWSURL              Code = "missing_ws_url"
	CodeMissingOrigin             Code = "missing_origin"
	CodeMissingChannelID          Code = "missing_channel_id"
	CodeInvalidSuite              Code = "invalid_suite"
	CodeInvalidPSK                Code = "invalid_psk"
	CodeInvalidEndpointInstanceID Code = "invalid_endpoint_instance_id"
	CodeRandomFailed              Code = "random_failed"
	CodeNotConnected              Code = "not_connected"
	CodeMissingStreamKind         Code = "missing_stream_kind"
	CodeDialFailed                Code = "dial_failed"
	CodeAttachFailed              Code = "attach_failed"
	CodeHandshakeFailed           Code = "handshake_failed"
	CodeMuxFailed                 Code = "mux_failed"
	CodeOpenStreamFailed          Code = "open_stream_failed"
	CodeStreamHelloFailed         Code = "stream_hello_failed"
)

// Error is a structured, programmatically identifiable error for high-level client operations.
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

func wrapErr(path Path, stage Stage, code Code, err error) error {
	return &Error{Path: path, Stage: stage, Code: code, Err: err}
}

package endpoint

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
	CodeRoleMismatch              Code = "role_mismatch"
	CodeMissingTunnelURL          Code = "missing_tunnel_url"
	CodeMissingOrigin             Code = "missing_origin"
	CodeMissingConn               Code = "missing_conn"
	CodeMissingChannelID          Code = "missing_channel_id"
	CodeMissingInitExp            Code = "missing_init_exp"
	CodeInvalidPSK                Code = "invalid_psk"
	CodeInvalidEndpointInstanceID Code = "invalid_endpoint_instance_id"
	CodeInvalidSuite              Code = "invalid_suite"
	CodeRandomFailed              Code = "random_failed"
	CodeUpgradeFailed             Code = "upgrade_failed"
	CodeDialFailed                Code = "dial_failed"
	CodeAttachFailed              Code = "attach_failed"
	CodeHandshakeFailed           Code = "handshake_failed"
	CodeMuxFailed                 Code = "mux_failed"
	CodeNotConnected              Code = "not_connected"
	CodeMissingHandler            Code = "missing_handler"
	CodeAcceptStreamFailed        Code = "accept_stream_failed"
	CodeStreamHelloFailed         Code = "stream_hello_failed"
)

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

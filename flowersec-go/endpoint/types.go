package endpoint

import "github.com/floegence/flowersec/flowersec-go/fserrors"

type Error = fserrors.Error

type Path = fserrors.Path

const (
	PathTunnel = fserrors.PathTunnel
	PathDirect = fserrors.PathDirect
)

type Stage = fserrors.Stage

const (
	StageValidate  = fserrors.StageValidate
	StageConnect   = fserrors.StageConnect
	StageAttach    = fserrors.StageAttach
	StageHandshake = fserrors.StageHandshake
	StageYamux     = fserrors.StageYamux
	StageRPC       = fserrors.StageRPC
	StageClose     = fserrors.StageClose
)

type Code = fserrors.Code

const (
	CodeMissingGrant              = fserrors.CodeMissingGrant
	CodeRoleMismatch              = fserrors.CodeRoleMismatch
	CodeMissingTunnelURL          = fserrors.CodeMissingTunnelURL
	CodeMissingOrigin             = fserrors.CodeMissingOrigin
	CodeMissingConn               = fserrors.CodeMissingConn
	CodeMissingChannelID          = fserrors.CodeMissingChannelID
	CodeMissingInitExp            = fserrors.CodeMissingInitExp
	CodeInvalidPSK                = fserrors.CodeInvalidPSK
	CodeInvalidEndpointInstanceID = fserrors.CodeInvalidEndpointInstanceID
	CodeInvalidSuite              = fserrors.CodeInvalidSuite
	CodeInvalidOption             = fserrors.CodeInvalidOption
	CodeRandomFailed              = fserrors.CodeRandomFailed
	CodeUpgradeFailed             = fserrors.CodeUpgradeFailed
	CodeDialFailed                = fserrors.CodeDialFailed
	CodeAttachFailed              = fserrors.CodeAttachFailed
	CodeHandshakeFailed           = fserrors.CodeHandshakeFailed
	CodeMuxFailed                 = fserrors.CodeMuxFailed
	CodeNotConnected              = fserrors.CodeNotConnected
	CodeMissingHandler            = fserrors.CodeMissingHandler
	CodeAcceptStreamFailed        = fserrors.CodeAcceptStreamFailed
	CodeOpenStreamFailed          = fserrors.CodeOpenStreamFailed
	CodeMissingStreamKind         = fserrors.CodeMissingStreamKind
	CodeStreamHelloFailed         = fserrors.CodeStreamHelloFailed
)

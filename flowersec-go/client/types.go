package client

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
	CodeMissingConnectInfo        = fserrors.CodeMissingConnectInfo
	CodeRoleMismatch              = fserrors.CodeRoleMismatch
	CodeMissingTunnelURL          = fserrors.CodeMissingTunnelURL
	CodeMissingWSURL              = fserrors.CodeMissingWSURL
	CodeMissingOrigin             = fserrors.CodeMissingOrigin
	CodeMissingChannelID          = fserrors.CodeMissingChannelID
	CodeMissingInitExp            = fserrors.CodeMissingInitExp
	CodeInvalidSuite              = fserrors.CodeInvalidSuite
	CodeInvalidPSK                = fserrors.CodeInvalidPSK
	CodeInvalidEndpointInstanceID = fserrors.CodeInvalidEndpointInstanceID
	CodeInvalidOption             = fserrors.CodeInvalidOption
	CodeRandomFailed              = fserrors.CodeRandomFailed
	CodeNotConnected              = fserrors.CodeNotConnected
	CodeMissingStreamKind         = fserrors.CodeMissingStreamKind
	CodeDialFailed                = fserrors.CodeDialFailed
	CodeAttachFailed              = fserrors.CodeAttachFailed
	CodeHandshakeFailed           = fserrors.CodeHandshakeFailed
	CodeMuxFailed                 = fserrors.CodeMuxFailed
	CodeOpenStreamFailed          = fserrors.CodeOpenStreamFailed
	CodeStreamHelloFailed         = fserrors.CodeStreamHelloFailed
)

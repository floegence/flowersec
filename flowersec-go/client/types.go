package client

import "github.com/floegence/flowersec/flowersec-go/fserrors"

type Error = fserrors.Error

type Path = fserrors.Path

const (
	PathAuto   = fserrors.PathAuto
	PathTunnel = fserrors.PathTunnel
	PathDirect = fserrors.PathDirect
)

type Stage = fserrors.Stage

const (
	StageValidate  = fserrors.StageValidate
	StageConnect   = fserrors.StageConnect
	StageAttach    = fserrors.StageAttach
	StageHandshake = fserrors.StageHandshake
	StageSecure    = fserrors.StageSecure
	StageYamux     = fserrors.StageYamux
	StageRPC       = fserrors.StageRPC
	StageClose     = fserrors.StageClose
)

type Code = fserrors.Code

const (
	CodeTimeout                   = fserrors.CodeTimeout
	CodeCanceled                  = fserrors.CodeCanceled
	CodeInvalidInput              = fserrors.CodeInvalidInput
	CodeMissingGrant              = fserrors.CodeMissingGrant
	CodeMissingConnectInfo        = fserrors.CodeMissingConnectInfo
	CodeRoleMismatch              = fserrors.CodeRoleMismatch
	CodeMissingTunnelURL          = fserrors.CodeMissingTunnelURL
	CodeMissingWSURL              = fserrors.CodeMissingWSURL
	CodeMissingOrigin             = fserrors.CodeMissingOrigin
	CodeMissingChannelID          = fserrors.CodeMissingChannelID
	CodeMissingToken              = fserrors.CodeMissingToken
	CodeMissingInitExp            = fserrors.CodeMissingInitExp
	CodeTimestampAfterInitExp     = fserrors.CodeTimestampAfterInitExp
	CodeTimestampOutOfSkew        = fserrors.CodeTimestampOutOfSkew
	CodeAuthTagMismatch           = fserrors.CodeAuthTagMismatch
	CodeInvalidVersion            = fserrors.CodeInvalidVersion
	CodeInvalidSuite              = fserrors.CodeInvalidSuite
	CodeInvalidPSK                = fserrors.CodeInvalidPSK
	CodeInvalidEndpointInstanceID = fserrors.CodeInvalidEndpointInstanceID
	CodeInvalidOption             = fserrors.CodeInvalidOption
	CodeRandomFailed              = fserrors.CodeRandomFailed
	CodeNotConnected              = fserrors.CodeNotConnected
	CodeMissingStreamKind         = fserrors.CodeMissingStreamKind
	CodeDialFailed                = fserrors.CodeDialFailed
	CodeAttachFailed              = fserrors.CodeAttachFailed
	CodeTooManyConnections        = fserrors.CodeTooManyConnections
	CodeExpectedAttach            = fserrors.CodeExpectedAttach
	CodeInvalidAttach             = fserrors.CodeInvalidAttach
	CodeInvalidToken              = fserrors.CodeInvalidToken
	CodeChannelMismatch           = fserrors.CodeChannelMismatch
	CodeTokenReplay               = fserrors.CodeTokenReplay
	CodeReplaceRateLimited        = fserrors.CodeReplaceRateLimited
	CodeHandshakeFailed           = fserrors.CodeHandshakeFailed
	CodePingFailed                = fserrors.CodePingFailed
	CodeMuxFailed                 = fserrors.CodeMuxFailed
	CodeOpenStreamFailed          = fserrors.CodeOpenStreamFailed
	CodeStreamHelloFailed         = fserrors.CodeStreamHelloFailed
)

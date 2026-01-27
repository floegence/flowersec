package endpoint

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
	CodeMissingConn               = fserrors.CodeMissingConn
	CodeMissingChannelID          = fserrors.CodeMissingChannelID
	CodeMissingToken              = fserrors.CodeMissingToken
	CodeMissingInitExp            = fserrors.CodeMissingInitExp
	CodeTimestampAfterInitExp     = fserrors.CodeTimestampAfterInitExp
	CodeTimestampOutOfSkew        = fserrors.CodeTimestampOutOfSkew
	CodeAuthTagMismatch           = fserrors.CodeAuthTagMismatch
	CodeInvalidVersion            = fserrors.CodeInvalidVersion
	CodeInvalidPSK                = fserrors.CodeInvalidPSK
	CodeInvalidEndpointInstanceID = fserrors.CodeInvalidEndpointInstanceID
	CodeInvalidSuite              = fserrors.CodeInvalidSuite
	CodeInvalidOption             = fserrors.CodeInvalidOption
	CodeResolveFailed             = fserrors.CodeResolveFailed
	CodeRandomFailed              = fserrors.CodeRandomFailed
	CodeUpgradeFailed             = fserrors.CodeUpgradeFailed
	CodeDialFailed                = fserrors.CodeDialFailed
	CodeAttachFailed              = fserrors.CodeAttachFailed
	CodeTooManyConnections        = fserrors.CodeTooManyConnections
	CodeExpectedAttach            = fserrors.CodeExpectedAttach
	CodeInvalidAttach             = fserrors.CodeInvalidAttach
	CodeInvalidToken              = fserrors.CodeInvalidToken
	CodeChannelMismatch           = fserrors.CodeChannelMismatch
	CodeInitExpMismatch           = fserrors.CodeInitExpMismatch
	CodeIdleTimeoutMismatch       = fserrors.CodeIdleTimeoutMismatch
	CodeTokenReplay               = fserrors.CodeTokenReplay
	CodeReplaceRateLimited        = fserrors.CodeReplaceRateLimited
	CodeHandshakeFailed           = fserrors.CodeHandshakeFailed
	CodePingFailed                = fserrors.CodePingFailed
	CodeMuxFailed                 = fserrors.CodeMuxFailed
	CodeNotConnected              = fserrors.CodeNotConnected
	CodeMissingHandler            = fserrors.CodeMissingHandler
	CodeAcceptStreamFailed        = fserrors.CodeAcceptStreamFailed
	CodeOpenStreamFailed          = fserrors.CodeOpenStreamFailed
	CodeMissingStreamKind         = fserrors.CodeMissingStreamKind
	CodeStreamHelloFailed         = fserrors.CodeStreamHelloFailed
	CodeRPCFailed                 = fserrors.CodeRPCFailed
)

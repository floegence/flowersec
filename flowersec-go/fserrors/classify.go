package fserrors

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
	"github.com/gorilla/websocket"
)

// ClassifyConnectCode maps a connect-layer error to a stable Code.
func ClassifyConnectCode(err error) Code {
	return classifyContextCode(err, CodeDialFailed)
}

// ClassifyAttachCode maps an attach-layer error to a stable Code.
func ClassifyAttachCode(err error) Code {
	return classifyContextCode(err, CodeAttachFailed)
}

// ClassifyHandshakeCode maps an E2EE handshake error to a stable Code.
func ClassifyHandshakeCode(err error) Code {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return CodeTimeout
	case errors.Is(err, context.Canceled):
		return CodeCanceled
	case errors.Is(err, e2ee.ErrUnsupportedSuite):
		return CodeInvalidSuite
	case errors.Is(err, e2ee.ErrTimestampOutOfSkew):
		return CodeTimestampOutOfSkew
	case errors.Is(err, e2ee.ErrTimestampAfterInitExp):
		return CodeTimestampAfterInitExp
	case errors.Is(err, e2ee.ErrAuthTagMismatch):
		return CodeAuthTagMismatch
	case errors.Is(err, e2ee.ErrInvalidVersion):
		return CodeInvalidVersion
	default:
		return CodeHandshakeFailed
	}
}

func classifyContextCode(err error, fallback Code) Code {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return CodeTimeout
	case errors.Is(err, context.Canceled):
		return CodeCanceled
	default:
		return fallback
	}
}

// ClassifyTunnelAttachCloseCode maps a tunnel websocket close error to a stable Code.
//
// The tunnel uses close status + reason tokens (for example "invalid_token", "token_replay")
// to signal attach rejections before the E2EE handshake begins.
func ClassifyTunnelAttachCloseCode(err error) (Code, bool) {
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		return "", false
	}
	switch ce.Text {
	case "too_many_connections":
		return CodeTooManyConnections, true
	case "expected_attach":
		return CodeExpectedAttach, true
	case "invalid_attach":
		return CodeInvalidAttach, true
	case "invalid_token":
		return CodeInvalidToken, true
	case "channel_mismatch":
		return CodeChannelMismatch, true
	case "init_exp_mismatch":
		return CodeInitExpMismatch, true
	case "idle_timeout_mismatch":
		return CodeIdleTimeoutMismatch, true
	case "role_mismatch":
		return CodeRoleMismatch, true
	case "token_replay":
		return CodeTokenReplay, true
	case "replace_rate_limited":
		return CodeReplaceRateLimited, true
	case "attach_failed":
		return CodeAttachFailed, true
	case "timeout":
		return CodeTimeout, true
	case "canceled":
		return CodeCanceled, true
	default:
		return "", false
	}
}

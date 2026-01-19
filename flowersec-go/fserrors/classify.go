package fserrors

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
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

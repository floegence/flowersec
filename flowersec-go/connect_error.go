package flowersec

import (
	"context"
	"errors"
)

var (
	ErrInvalidConnectorOptions = errors.New("invalid Flowersec connector options")
	ErrConnectionFailed        = errors.New("Flowersec connection failed")
)

// ConnectErrorCode is the closed, carrier-neutral connection outcome set.
type ConnectErrorCode string

const (
	ConnectArtifactInvalid              ConnectErrorCode = "artifact_invalid"
	ConnectExpired                      ConnectErrorCode = "expired_artifact"
	ConnectTransportSecurityUnsupported ConnectErrorCode = "transport_security_unsupported"
	ConnectTransportSecurityFailed      ConnectErrorCode = "transport_security_failed"
	ConnectConnectionFailed             ConnectErrorCode = "connection_failed"
)

func (code ConnectErrorCode) String() string { return string(code) }

// ConnectError is the redacted, stable public connection failure.
type ConnectError struct {
	code        ConnectErrorCode
	disposition RetryDisposition
	detail      connectErrorDetail
}

type connectErrorDetail uint8

const (
	connectErrorDetailNone connectErrorDetail = iota
	connectErrorDetailInvalidOptions
	connectErrorDetailCanceled
	connectErrorDetailTimeout
)

func (err *ConnectError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec connection failed (code=" + string(err.Code()) + ")"
}

func (err *ConnectError) Unwrap() error {
	if err != nil && err.detail == connectErrorDetailInvalidOptions {
		return ErrInvalidConnectorOptions
	}
	return ErrConnectionFailed
}

// Is preserves cancellation and deadline matching without exposing the
// internal connection failure that produced this public projection.
func (err *ConnectError) Is(target error) bool {
	if target == ErrConnectionFailed {
		return true
	}
	if err == nil {
		return false
	}
	switch err.detail {
	case connectErrorDetailCanceled:
		return target == context.Canceled
	case connectErrorDetailTimeout:
		return target == context.DeadlineExceeded
	default:
		return false
	}
}

// Code returns the closed, carrier-neutral connection outcome.
func (err *ConnectError) Code() ConnectErrorCode {
	if err == nil {
		return ConnectConnectionFailed
	}
	switch err.code {
	case ConnectArtifactInvalid, ConnectExpired, ConnectTransportSecurityUnsupported,
		ConnectTransportSecurityFailed, ConnectConnectionFailed:
		return err.code
	default:
		return ConnectConnectionFailed
	}
}

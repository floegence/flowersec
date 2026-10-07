package flowersec

import "context"

// SessionErrorCode is the closed failure set shared by sessions, RPC, and streams.
type SessionErrorCode string

const (
	SessionCanceled          SessionErrorCode = "canceled"
	SessionTimeout           SessionErrorCode = "timeout"
	SessionClosed            SessionErrorCode = "closed"
	SessionGoingAway         SessionErrorCode = "going_away"
	SessionResourceExhausted SessionErrorCode = "resource_exhausted"
	SessionStreamRejected    SessionErrorCode = "stream_rejected"
	SessionStreamReset       SessionErrorCode = "stream_reset"
	SessionRekeyFailed       SessionErrorCode = "rekey_failed"
	SessionLivenessFailed    SessionErrorCode = "liveness_failed"
	SessionOperationFailed   SessionErrorCode = "operation_failed"
)

// SessionError contains no carrier, wire, key, credential, or peer detail.
type SessionError struct {
	code SessionErrorCode
}

func (err *SessionError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec session failed (code=" + string(err.code) + ")"
}

// Unwrap preserves stable cancellation and deadline matching. Other session
// failures deliberately retain no public cause.
func (err *SessionError) Unwrap() error {
	if err == nil {
		return nil
	}
	switch err.Code() {
	case SessionCanceled:
		return context.Canceled
	case SessionTimeout:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Code returns the closed carrier-neutral session outcome.
func (err *SessionError) Code() SessionErrorCode {
	if err == nil || err.code == "" {
		return SessionOperationFailed
	}
	return err.code
}

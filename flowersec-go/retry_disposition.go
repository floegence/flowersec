package flowersec

const maximumRetryAfterUnixMilliseconds int64 = 253_402_300_799_999

// RetryDispositionKind is the complete set of controller retry decisions.
// Retry decisions are never inferred from error text or carrier identity.
type RetryDispositionKind string

const (
	RetryDispositionTerminal   RetryDispositionKind = "terminal"
	RetryDispositionRetryable  RetryDispositionKind = "retryable"
	RetryDispositionRetryAfter RetryDispositionKind = "retry_after"
)

// RetryDisposition is the structured retry decision consumed by a
// ConnectionController. RetryAtUnixMilliseconds is required only for
// RetryAfter and is an exact Unix wall-clock not-before deadline.
type RetryDisposition struct {
	Kind                    RetryDispositionKind
	RetryAtUnixMilliseconds int64
}

func terminalDisposition() RetryDisposition {
	return RetryDisposition{Kind: RetryDispositionTerminal}
}

func retryableDisposition() RetryDisposition {
	return RetryDisposition{Kind: RetryDispositionRetryable}
}

func retryAfterDisposition(retryAtUnixMilliseconds int64) RetryDisposition {
	return RetryDisposition{Kind: RetryDispositionRetryAfter, RetryAtUnixMilliseconds: retryAtUnixMilliseconds}
}

func (disposition RetryDisposition) valid() bool {
	switch disposition.Kind {
	case RetryDispositionTerminal, RetryDispositionRetryable:
		return disposition.RetryAtUnixMilliseconds == 0
	case RetryDispositionRetryAfter:
		return validRetryAfterUnixMilliseconds(disposition.RetryAtUnixMilliseconds)
	default:
		return false
	}
}

func validRetryAfterUnixMilliseconds(value int64) bool {
	return value >= 0 && value <= maximumRetryAfterUnixMilliseconds
}

// RetryDisposition reports the structured recovery decision for a one-shot
// connection failure.
func (err *ConnectError) RetryDisposition() RetryDisposition {
	if err == nil {
		return terminalDisposition()
	}
	if err.disposition.valid() {
		return err.disposition
	}
	switch err.Code() {
	case ConnectExpired, ConnectConnectionFailed:
		return retryableDisposition()
	default:
		return terminalDisposition()
	}
}

// RetryDisposition reports the structured recovery decision for a terminated
// one-shot session. It never implies replay or migration of session work.
func (err *SessionError) RetryDisposition() RetryDisposition {
	if err == nil {
		return terminalDisposition()
	}
	switch err.Code() {
	case SessionClosed, SessionGoingAway, SessionTimeout, SessionResourceExhausted,
		SessionStreamReset, SessionRekeyFailed, SessionLivenessFailed:
		return retryableDisposition()
	default:
		return terminalDisposition()
	}
}

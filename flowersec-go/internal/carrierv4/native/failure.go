package native

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// ErrConnectionLost is a carrier-owned fact from an actual connection I/O
// call. It conveys no permission to replay a credential or application action.
var ErrConnectionLost = errors.New("native: connection interrupted")

// ErrAddressesExhausted means a factory's immutable numeric address list has
// no entry at this ordinal. It does not replace an earlier attempt's outcome.
// Policy refusal must use its own error, never this inventory-only fact.
var ErrAddressesExhausted = errors.New("native: numeric address list exhausted")

// NetworkFailure is called only at native socket boundaries, never on policy,
// authentication, framing, application or cleanup errors. Do not unwrap an
// arbitrary error: its methods may execute application code.
func NetworkFailure(err error) error {
	// Preserve EOF: on application streams it is an ordinary peer half-close.
	if e, ok := err.(*net.OpError); ok && e != nil && (e.Op == "dial" || e.Op == "read" || e.Op == "write") {
		if e.Err == context.Canceled || e.Err == context.DeadlineExceeded || e.Err == net.ErrClosed {
			return err
		}
		cause := e.Err
		if syscallError, ok := cause.(*os.SyscallError); ok && syscallError != nil {
			cause = syscallError.Err
		}
		if networkCause(cause) {
			return ErrConnectionLost
		}
	}
	// The bounded numeric TCP connector returns syscall errors directly.
	// Local descriptor/memory exhaustion is not a network retry decision.
	if e, ok := err.(*os.SyscallError); ok && e != nil && e.Syscall == "connect" {
		switch e.Err {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ETIMEDOUT:
			return ErrConnectionLost
		}
	}
	return err
}

func networkCause(err error) bool {
	if err == os.ErrDeadlineExceeded {
		return true
	}
	switch err {
	case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.ENETUNREACH, syscall.ENETDOWN, syscall.EHOSTUNREACH, syscall.ETIMEDOUT, syscall.EPIPE:
		return true
	}
	return false
}

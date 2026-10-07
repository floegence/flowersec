package flowersec

import (
	"context"
	"time"
)

type UnreliableSendStatus string

const (
	UnreliableAccepted       UnreliableSendStatus = "accepted"
	UnreliableDroppedExpired UnreliableSendStatus = "dropped_expired"
	UnreliableDroppedBudget  UnreliableSendStatus = "dropped_budget"
	UnreliableDroppedCarrier UnreliableSendStatus = "dropped_carrier"
)

type UnreliableSendOptions struct {
	ExpiresAt time.Time
}

// UnreliableMessageErrorCode is the complete carrier-neutral unreliable-message
// failure set. Dropped sends are reported as UnreliableSendStatus values.
type UnreliableMessageErrorCode string

const (
	UnreliableMessageUnavailable     UnreliableMessageErrorCode = "unavailable"
	UnreliableMessageInvalid         UnreliableMessageErrorCode = "invalid_message"
	UnreliableMessageTooLarge        UnreliableMessageErrorCode = "too_large"
	UnreliableMessageCanceled        UnreliableMessageErrorCode = "canceled"
	UnreliableMessageClosed          UnreliableMessageErrorCode = "closed"
	UnreliableMessageOperationFailed UnreliableMessageErrorCode = "operation_failed"
)

func (code UnreliableMessageErrorCode) String() string { return string(code) }

// UnreliableMessageError is a stable, redacted unreliable-message failure.
type UnreliableMessageError struct {
	code UnreliableMessageErrorCode
}

func (err *UnreliableMessageError) Error() string {
	if err == nil {
		return "<nil>"
	}
	return "Flowersec unreliable message failed (code=" + string(err.Code()) + ")"
}

func (err *UnreliableMessageError) Code() UnreliableMessageErrorCode {
	if err == nil {
		return UnreliableMessageOperationFailed
	}
	switch err.code {
	case UnreliableMessageUnavailable, UnreliableMessageInvalid, UnreliableMessageTooLarge,
		UnreliableMessageCanceled, UnreliableMessageClosed, UnreliableMessageOperationFailed,
		UnreliableMessageTemporarilyBlocked, UnreliableMessageReceiveDisabled:
		return err.code
	default:
		return UnreliableMessageOperationFailed
	}
}

// UnreliableMessageChannel sends opaque end-to-end encrypted messages without
// retransmission. An accepted send is queued locally and may still be lost.
type UnreliableMessageChannel interface {
	MaxMessageBytes() int
	Send(context.Context, []byte, UnreliableSendOptions) (UnreliableSendStatus, error)
	Receive(context.Context) ([]byte, error)
}

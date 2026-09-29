package flowersec

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// UnreliableMessages is available only after the original READY selected the
// signed feature on a complete native datagram route. Accepted means local
// provider submission, and never delivery or remote application consumption.
func (s *V4Session) UnreliableMessages() (UnreliableMessageChannel, error) {
	if s == nil || s.unreliable == nil {
		return nil, &UnreliableMessageError{code: UnreliableMessageUnavailable}
	}
	channel, err := s.unreliable()
	if err != nil {
		return nil, redactV4UnreliableError(err)
	}
	return &v4UnreliableChannel{inner: channel}, nil
}

type v4UnreliableChannel struct{ inner *sessionv4.UnreliableMessages }

func (c *v4UnreliableChannel) MaxMessageBytes() int { return c.inner.MaxMessageBytes() }
func (c *v4UnreliableChannel) Send(ctx context.Context, payload []byte, options UnreliableSendOptions) (UnreliableSendStatus, error) {
	status, err := c.inner.Send(ctx, payload, options.ExpiresAt)
	if err != nil {
		return UnreliableSendStatus(status), redactV4UnreliableError(err)
	}
	return UnreliableSendStatus(status), nil
}
func (c *v4UnreliableChannel) Receive(ctx context.Context) ([]byte, error) {
	payload, err := c.inner.Receive(ctx)
	if err != nil {
		return nil, redactV4UnreliableError(err)
	}
	return payload, nil
}

const (
	UnreliableMessageTemporarilyBlocked UnreliableMessageErrorCode = "temporarily_blocked"
	UnreliableMessageReceiveDisabled    UnreliableMessageErrorCode = "receive_disabled"
)

func redactV4UnreliableError(err error) *UnreliableMessageError {
	code := UnreliableMessageOperationFailed
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code = UnreliableMessageCanceled
	case errors.Is(err, cryptov4.ErrClosed):
		code = UnreliableMessageClosed
	case errors.Is(err, sessionv4.ErrUnreliableUnavailable):
		code = UnreliableMessageUnavailable
	case errors.Is(err, sessionv4.ErrUnreliableExpiry):
		code = UnreliableMessageInvalid
	case errors.Is(err, sessionv4.ErrUnreliableTooLarge):
		code = UnreliableMessageTooLarge
	case errors.Is(err, cryptov4.ErrReceiveBlocked):
		code = UnreliableMessageTemporarilyBlocked
	case errors.Is(err, cryptov4.ErrReceiveDisabled):
		code = UnreliableMessageReceiveDisabled
	}
	return &UnreliableMessageError{code: code}
}

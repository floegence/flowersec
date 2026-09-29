package quicfailure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	quic "github.com/quic-go/quic-go"
)

func TestConnectionInterruptionsExcludeProtocolAndStreamFailures(t *testing.T) {
	for _, err := range []error{&quic.IdleTimeoutError{}, &quic.HandshakeTimeoutError{}, &quic.StatelessResetError{},
		&quic.TransportError{ErrorCode: quic.ConnectionRefused}, &quic.TransportError{ErrorCode: quic.NoViablePathError}} {
		if got := Connection(err); got != native.ErrConnectionLost {
			t.Fatalf("native interruption lost: %T", err)
		}
	}
	for _, err := range []error{nil, io.EOF, io.ErrClosedPipe, context.Canceled, context.DeadlineExceeded,
		&quic.ApplicationError{}, &quic.StreamError{}, &quic.VersionNegotiationError{},
		&quic.TransportError{ErrorCode: quic.ProtocolViolation}, &quic.TransportError{ErrorCode: quic.FlowControlError},
		&quic.TransportError{ErrorCode: quic.TransportErrorCode(0x100)},
		fmt.Errorf("policy: %w", &quic.IdleTimeoutError{}), errors.New("timeout")} {
		if got := Connection(err); got != err {
			t.Fatalf("non-connection failure reclassified: %T", err)
		}
	}
}

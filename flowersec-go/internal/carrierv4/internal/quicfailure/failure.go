// Package quicfailure projects native connection interruptions without exposing
// a concrete QUIC implementation to Session or Controller state.
package quicfailure

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	quic "github.com/quic-go/quic-go"
)

func Connection(err error) error {
	switch e := err.(type) {
	case *quic.IdleTimeoutError:
		if e != nil {
			return native.ErrConnectionLost
		}
	case *quic.HandshakeTimeoutError:
		if e != nil {
			return native.ErrConnectionLost
		}
	case *quic.StatelessResetError:
		if e != nil {
			return native.ErrConnectionLost
		}
	case *quic.TransportError:
		if e != nil && (e.ErrorCode == quic.ConnectionRefused || e.ErrorCode == quic.NoViablePathError) {
			return native.ErrConnectionLost
		}
	}
	// Stream resets, application closes, crypto alerts and protocol violations
	// are deliberately not connection-interruption facts.
	return native.NetworkFailure(err)
}

// Stream projects only actual QUIC stream errors. The code is supplied by the
// concrete raw-QUIC or WebTransport adapter, never by an incoming envelope.
func Stream(err error, normalDrained quic.StreamErrorCode) error {
	if e, ok := err.(*quic.StreamError); ok && e != nil {
		if e.ErrorCode == normalDrained {
			return native.ErrNormalDrained
		}
		return native.ErrDirectionReset
	}
	return Connection(err)
}

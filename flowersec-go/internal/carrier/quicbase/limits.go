// Package quicbase defines the resource policy shared by native QUIC runtime
// adapters without coupling raw QUIC and WebTransport implementations.
package quicbase

import (
	"errors"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrier"
)

const MinimumInitialPacketSize uint16 = 1200

const (
	maxStreamReceiveWindow     = 6 << 20
	maxConnectionReceiveWindow = 16 << 20
)

var ErrInvalidLimits = errors.New("invalid QUIC carrier limits")

type Limits struct {
	MaxInboundStreams              int64
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	HandshakeIdleTimeout           time.Duration
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxInboundStreams:              carrier.MaxLogicalIncomingStreams + carrier.ReservedSessionStreams,
		InitialStreamReceiveWindow:     512 << 10,
		MaxStreamReceiveWindow:         maxStreamReceiveWindow,
		InitialConnectionReceiveWindow: 1 << 20,
		MaxConnectionReceiveWindow:     maxConnectionReceiveWindow,
		HandshakeIdleTimeout:           30 * time.Second,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                20 * time.Second,
	}
}

func BindSessionLimits(limits Limits, maxLogical uint16) (Limits, error) {
	physical, err := carrier.RequiredIncomingStreams(maxLogical)
	if err != nil {
		return Limits{}, err
	}
	limits.MaxInboundStreams = int64(physical)
	if err := limits.Validate(); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

func (limits Limits) Validate() error {
	if limits.MaxInboundStreams < 1 || limits.MaxInboundStreams > 130 ||
		limits.InitialStreamReceiveWindow == 0 ||
		limits.InitialStreamReceiveWindow > maxStreamReceiveWindow ||
		limits.MaxStreamReceiveWindow > maxStreamReceiveWindow ||
		limits.InitialStreamReceiveWindow > limits.MaxStreamReceiveWindow ||
		limits.InitialConnectionReceiveWindow == 0 ||
		limits.InitialConnectionReceiveWindow > maxConnectionReceiveWindow ||
		limits.MaxConnectionReceiveWindow > maxConnectionReceiveWindow ||
		limits.InitialConnectionReceiveWindow > limits.MaxConnectionReceiveWindow ||
		limits.HandshakeIdleTimeout <= 0 || limits.MaxIdleTimeout <= 0 ||
		limits.KeepAlivePeriod < 0 || limits.KeepAlivePeriod >= limits.MaxIdleTimeout {
		return ErrInvalidLimits
	}
	return nil
}

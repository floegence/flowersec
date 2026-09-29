// Package native defines the private I/O shape shared by SDK-owned QUIC and
// WebTransport connections. Session assembly separately checks concrete owners;
// implementing these interfaces does not confer admission authority.
package native

import (
	"context"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
	StopSending() error
	ResetWrite() error
	Reset() error
	Context() context.Context
	WaitCleanup(context.Context) error
	Retire() error
}

type Connection interface {
	ExportBinding([32]byte) ([32]byte, error)
	CheckEnvironment(resourcev4.Reference) error
	CheckStreamCapacity(uint32) error
	ClaimSession(resourcev4.Reference) error
	ProtectNativeStreams([]StreamProtection) error
	OpenNativeStream(context.Context) (Stream, error)
	AcceptNativeStream(context.Context) (Stream, error)
	MaxDatagramBytes() int
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context, []byte) (int, error)
	Close() error
	WaitCleanup(context.Context) error
	Retire() error
}

// StreamProtection owns one future native handle in the original provider
// table. It performs no network I/O until Open, and grants no peer stream
// credit. The real stream and every provider method must retire before reuse.
type StreamProtection interface {
	Open(context.Context) (Stream, error)
	CheckAvailable() error
	Close()
}

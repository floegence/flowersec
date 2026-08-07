// Package session defines Flowersec v2's carrier-neutral public session API.
package session

import (
	"context"
	"io"
	"time"
)

type PathKind string

const (
	PathDirect PathKind = "direct"
	PathTunnel PathKind = "tunnel"
)

type SessionRole string

const (
	RoleClient SessionRole = "client"
	RoleServer SessionRole = "server"
)

// Metadata is the bounded canonical JSON object supplied when a logical stream
// is opened. Wire codecs enforce the v2 size, depth, key, and value limits.
type Metadata map[string]any

// ByteStream is an end-to-end encrypted logical stream. CloseWrite sends FIN;
// Reset aborts both directions and exposes only the stable generic reset state.
type ByteStream interface {
	io.Reader
	io.Writer
	io.Closer
	ID() uint64
	Kind() string
	TerminalError() error
	CloseWrite() error
	Reset() error
}

type IncomingStream struct {
	ID       uint64
	Kind     string
	Metadata Metadata
	Stream   ByteStream
}

type RPCPeer interface {
	Call(ctx context.Context, typeID uint32, request, response any) error
	Notify(ctx context.Context, typeID uint32, request any) error
}

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

// UnreliableMessageChannel sends independent encrypted messages over a native
// unreliable carrier. Accepted means queued locally, never delivered.
type UnreliableMessageChannel interface {
	MaxMessageBytes() int
	Send(context.Context, []byte, UnreliableSendOptions) (UnreliableSendStatus, error)
	Receive(context.Context) ([]byte, error)
}

// SessionV2 is shared by WSS, raw QUIC, and WebTransport. Implementations must
// not expose Yamux or a concrete QUIC stack through this interface.
type SessionV2 interface {
	Path() PathKind
	EndpointInstanceID() (string, bool)
	RPC() RPCPeer
	UnreliableMessages() (UnreliableMessageChannel, error)
	OpenStream(ctx context.Context, kind string, metadata Metadata) (ByteStream, error)
	AcceptStream(ctx context.Context) (IncomingStream, error)
	Rekey(ctx context.Context) error
	ProbeLiveness(ctx context.Context) (time.Duration, error)
	Termination() <-chan struct{}
	WaitClosed(ctx context.Context) error
	Close() error
}

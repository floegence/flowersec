// Package session defines Flowersec v2's carrier-neutral public session API.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/floegence/flowersec/flowersec-go/carrier"
)

type PathKind string

const (
	PathDirect PathKind = "direct"
	PathTunnel PathKind = "tunnel"
)

type NetworkMode string

const (
	NetworkDial   NetworkMode = "dial"
	NetworkListen NetworkMode = "listen"
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

// SessionV2 is shared by WSS, raw QUIC, and WebTransport. Implementations must
// not expose Yamux or a concrete QUIC stack through this interface.
type SessionV2 interface {
	Path() PathKind
	ChosenCarrier() carrier.Kind
	EndpointInstanceID() (string, bool)
	RPC() RPCPeer
	OpenStream(ctx context.Context, kind string, metadata Metadata) (ByteStream, error)
	AcceptStream(ctx context.Context) (IncomingStream, error)
	Rekey(ctx context.Context) error
	ProbeLiveness(ctx context.Context) (time.Duration, error)
	Termination() <-chan struct{}
	WaitClosed(ctx context.Context) error
	Close() error
}

type CapabilityTuple struct {
	Carrier     carrier.Kind `json:"carrier"`
	NetworkMode NetworkMode  `json:"networkMode"`
	Path        PathKind     `json:"path"`
	SessionRole SessionRole  `json:"sessionRole"`
}

type UnsupportedCapability struct {
	Carrier carrier.Kind `json:"carrier"`
	Reason  string       `json:"reason"`
}

type CapabilityDescriptor struct {
	Language      string                  `json:"language"`
	Runtime       string                  `json:"runtime"`
	SchemaVersion uint8                   `json:"schemaVersion"`
	Tuples        []CapabilityTuple       `json:"tuples"`
	Unsupported   []UnsupportedCapability `json:"unsupported"`
}

var (
	ErrInvalidCapability   = errors.New("invalid capability")
	ErrDuplicateCapability = errors.New("duplicate capability")
)

func (d CapabilityDescriptor) Validate() error {
	if err := validateCapabilityDescriptorShape(d); err != nil {
		return ErrInvalidCapability
	}
	seen := make(map[CapabilityTuple]struct{}, len(d.Tuples))
	for index, tuple := range d.Tuples {
		if err := tuple.validate(); err != nil {
			return err
		}
		if _, ok := seen[tuple]; ok {
			return fmt.Errorf("%w: %+v", ErrDuplicateCapability, tuple)
		}
		if index > 0 && !capabilityTupleLess(d.Tuples[index-1], tuple) {
			return ErrInvalidCapability
		}
		seen[tuple] = struct{}{}
	}
	return validateUnsupportedCapabilities(d, seen)
}

func (d CapabilityDescriptor) Supports(want CapabilityTuple) bool {
	for _, tuple := range d.Tuples {
		if tuple == want {
			return true
		}
	}
	return false
}

func (t CapabilityTuple) validate() error {
	if err := t.Carrier.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCapability, err)
	}
	if t.NetworkMode != NetworkDial && t.NetworkMode != NetworkListen {
		return ErrInvalidCapability
	}
	if t.SessionRole != RoleClient && t.SessionRole != RoleServer {
		return ErrInvalidCapability
	}
	if t.Path != PathDirect && t.Path != PathTunnel {
		return ErrInvalidCapability
	}
	switch t.Path {
	case PathDirect:
		if (t.NetworkMode != NetworkDial || t.SessionRole != RoleClient) &&
			(t.NetworkMode != NetworkListen || t.SessionRole != RoleServer) {
			return ErrInvalidCapability
		}
	case PathTunnel:
		if t.NetworkMode != NetworkDial {
			return ErrInvalidCapability
		}
	}
	return nil
}

// GoCapabilities explicitly lists supported tuples. It intentionally avoids a
// carrier x mode x role x path cross-product because several combinations are
// not valid Flowersec deployment roles.
func GoCapabilities() CapabilityDescriptor {
	return CapabilityDescriptor{Language: "go", Runtime: "native", SchemaVersion: 2, Tuples: []CapabilityTuple{
		{Carrier: carrier.KindQUIC, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathDirect},
		{Carrier: carrier.KindQUIC, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathTunnel},
		{Carrier: carrier.KindQUIC, NetworkMode: NetworkDial, SessionRole: RoleServer, Path: PathTunnel},
		{Carrier: carrier.KindQUIC, NetworkMode: NetworkListen, SessionRole: RoleServer, Path: PathDirect},
		{Carrier: carrier.KindWebSocket, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathDirect},
		{Carrier: carrier.KindWebSocket, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathTunnel},
		{Carrier: carrier.KindWebSocket, NetworkMode: NetworkDial, SessionRole: RoleServer, Path: PathTunnel},
		{Carrier: carrier.KindWebSocket, NetworkMode: NetworkListen, SessionRole: RoleServer, Path: PathDirect},
		{Carrier: carrier.KindWebTransport, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathDirect},
		{Carrier: carrier.KindWebTransport, NetworkMode: NetworkDial, SessionRole: RoleClient, Path: PathTunnel},
		{Carrier: carrier.KindWebTransport, NetworkMode: NetworkDial, SessionRole: RoleServer, Path: PathTunnel},
		{Carrier: carrier.KindWebTransport, NetworkMode: NetworkListen, SessionRole: RoleServer, Path: PathDirect},
	}}
}

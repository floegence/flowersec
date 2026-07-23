// Package carrier defines the transport-neutral substrate used by Flowersec v2.
package carrier

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Kind identifies a v2 carrier without exposing its implementation type.
type Kind string

const (
	KindWebSocket    Kind = "websocket"
	KindQUIC         Kind = "raw_quic"
	KindWebTransport Kind = "webtransport"
)

// Path identifies the negotiated Flowersec v2 routing profile.
type Path string

const (
	PathDirect Path = "direct"
	PathTunnel Path = "tunnel"
)

var (
	ErrInvalidKind           = errors.New("invalid carrier kind")
	ErrInvalidPath           = errors.New("invalid carrier path")
	ErrInvalidStreamCapacity = errors.New("invalid carrier stream capacity")
	ErrStreamReset           = errors.New("carrier stream reset")
)

const (
	MaxLogicalIncomingStreams = 128
	ReservedSessionStreams    = 2
)

// RequiredIncomingStreams returns the physical bidirectional stream budget for
// one lifetime control stream, one persistent reserved RPC stream, and the
// negotiated logical data-stream limit.
func RequiredIncomingStreams(maxLogical uint16) (uint16, error) {
	if maxLogical < 1 || maxLogical > MaxLogicalIncomingStreams {
		return 0, ErrInvalidStreamCapacity
	}
	return maxLogical + ReservedSessionStreams, nil
}

// Validate rejects unregistered carrier strings.
func (k Kind) Validate() error {
	switch k {
	case KindWebSocket, KindQUIC, KindWebTransport:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidKind, k)
	}
}

// Validate rejects unregistered routing paths.
func (p Path) Validate() error {
	switch p {
	case PathDirect, PathTunnel:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidPath, p)
	}
}

const MaxApplicationErrorReasonBytes = 128

// ApplicationError is a bounded hop-level close diagnostic. It never carries
// endpoint E2EE state or application stream metadata.
type ApplicationError struct {
	Code   uint64
	Reason string
}

// Stream is one reliable bidirectional carrier stream.
type Stream interface {
	io.Reader
	io.Writer
	io.Closer
	CloseWrite() error
	Reset() error
	Context() context.Context
}

// Session opens and accepts independent reliable bidirectional streams.
type Session interface {
	Kind() Kind
	// Path returns the immutable routing profile negotiated by the carrier
	// subprotocol, ALPN, or exact WebTransport CONNECT path.
	Path() Path
	MaxIncomingStreams() uint16
	OpenStream(context.Context) (Stream, error)
	AcceptStream(context.Context) (Stream, error)
	// CloseWithErrorContext performs bounded carrier-owned teardown. It must
	// make the session locally unable to open or write before returning, even
	// when ctx expires while graceful shutdown is in progress. A nil ctx is
	// treated as context.Background().
	CloseWithErrorContext(context.Context, ApplicationError) error
	CloseWithError(ApplicationError) error
	Close() error
}

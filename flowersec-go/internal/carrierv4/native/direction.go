package native

import (
	"context"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// NormalDrainedCode is the application stream code in the carrier registry.
// WebTransport carries it through the RFC 9297 application-code mapping.
// It is a direction hint, never an authenticated application result.
const NormalDrainedCode uint32 = protocolv4.NativeNormalDrainedCode

var (
	ErrNormalDrained  = errors.New("native: receive direction drained")
	ErrDirectionReset = errors.New("native: stream direction reset")
)

// DirectionalStream exposes the real send half's completion even when no
// Write is pending. Context is still the lifecycle of the complete stream.
// StopSendingDrained is reserved for authenticated endpoint termination or
// propagation of the same actual downstream signal by an opaque relay.
type DirectionalStream interface {
	Stream
	StopSendingDrained() error
	// CloseDirections seals a physically ended pair of halves without resetting
	// an already queued FIN or discarding its previously submitted bytes.
	CloseDirections() error
	WriteContext() context.Context
	WriteStopReason() error
}

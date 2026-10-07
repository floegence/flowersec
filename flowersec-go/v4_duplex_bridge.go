package flowersec

import (
	"context"
	"net/netip"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// DuplexBridgeOptions fixes bounded chunk and complete operation lifetimes.
// Zero values select the ordinary SDK profile. Timeout includes prepared time.
type DuplexBridgeOptions struct {
	ChunkBytes       uint64
	TimeoutMS        uint64
	CleanupTimeoutMS uint64
}

type DuplexOutcome = protocolv4.V4DuplexOutcome
type DuplexResult = protocolv4.V4DuplexResult
type DuplexDirectionResult = protocolv4.V4DuplexDirectionResult
type DuplexSendResult = protocolv4.V4DuplexSendResult
type DuplexDirectionProgress = sessionv4.CopyProgress
type DuplexProgress = sessionv4.DuplexProgress
type DuplexObservation = sessionv4.DuplexObservation

const (
	DuplexNormal  = protocolv4.V4DuplexOutcomeNormal
	DuplexFailed  = protocolv4.V4DuplexOutcomeFailed
	DuplexAborted = protocolv4.V4DuplexOutcomeAborted
)

var ErrDuplexAborted = sessionv4.ErrDuplexAborted
var ErrDuplexCleanupIncomplete = sessionv4.ErrDuplexCleanupIncomplete

// DuplexBridge owns both original endpoints. EOF half-closes the destination;
// both directions complete before either endpoint is finished. Repeated Wait
// observes the same final result and tail backing. Wait cancellation is passive.
type DuplexBridge struct{ inner *sessionv4.DuplexBridge }

func duplexOptions(options DuplexBridgeOptions) sessionv4.DuplexOptions {
	if options.ChunkBytes == 0 {
		options.ChunkBytes = 32 << 10
	}
	if options.TimeoutMS == 0 {
		options.TimeoutMS = 90000
	}
	if options.CleanupTimeoutMS == 0 {
		options.CleanupTimeoutMS = 5000
	}
	return sessionv4.DuplexOptions{ChunkBytes: options.ChunkBytes, TimeoutMS: options.TimeoutMS, CleanupTimeoutMS: options.CleanupTimeoutMS}
}

// NewDuplexBridge atomically takes two unused original raw Streams in the same
// Environment. Arbitrary implementations of Stream cannot substitute owners.
func NewDuplexBridge(ctx context.Context, a, b Stream, options DuplexBridgeOptions) (*DuplexBridge, error) {
	left, leftOK := a.(*v4Stream)
	right, rightOK := b.(*v4Stream)
	if ctx == nil || !leftOK || !rightOK || left == nil || right == nil || left.owner == nil || right.owner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	bridge, err := sessionv4.NewOwnedDuplexBridge(ctx, left.owner, right.owner, duplexOptions(options))
	if err != nil {
		return nil, err
	}
	return &DuplexBridge{inner: bridge}, nil
}

// NewNativeDuplexBridge owns one original Stream and one sealed TCP endpoint
// from StartNativeTCPDial. Native send completion is
// reported separately from authenticated Flowersec send drain.
func NewNativeDuplexBridge(ctx context.Context, stream Stream, native *NativeTCP, options DuplexBridgeOptions) (*DuplexBridge, error) {
	raw, ok := stream.(*v4Stream)
	if ctx == nil || !ok || raw == nil || raw.owner == nil || native == nil || native.inner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	bridge, err := sessionv4.NewOwnedNativeDuplexBridge(ctx, raw.owner, native.inner, duplexOptions(options))
	if err != nil {
		return nil, err
	}
	return &DuplexBridge{inner: bridge}, nil
}

func (d *DuplexBridge) Start() error {
	if d == nil || d.inner == nil {
		return ErrOperationClosed
	}
	return d.inner.Start()
}
func (d *DuplexBridge) Abort() {
	if d != nil && d.inner != nil {
		d.inner.Abort()
	}
}
func (d *DuplexBridge) Wait(ctx context.Context) (DuplexObservation, error) {
	if d == nil || d.inner == nil {
		return DuplexObservation{}, ErrOperationClosed
	}
	return d.inner.Wait(ctx)
}
func (d *DuplexBridge) Progress() DuplexProgress {
	if d == nil || d.inner == nil {
		return DuplexProgress{}
	}
	return d.inner.Progress()
}
func (d *DuplexBridge) CleanupStatus() CleanupStatus {
	if d == nil || d.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(d.inner.CleanupStatus())
}

// NativeTCP is an opaque binary endpoint with full-duplex TCP half-close.
// It exposes no socket adoption or raw connection accessor. Value-copy aliases
// share the canonical private owner, which rejects Close while a bridge owns it.
type NativeTCP struct{ inner *sessionv4.NativeTCP }
type NativeTCPOptions = sessionv4.NativeTCPOptions
type NativeTCPDialOptions = sessionv4.NativeTCPDialOptions

func NativeTCPCharge(options NativeTCPOptions) (ResourceVector, error) {
	return sessionv4.NativeTCPCharge(options)
}
func NativeTCPDialCharge(options NativeTCPDialOptions) (ResourceVector, error) {
	return sessionv4.NativeTCPDialCharge(options)
}

type NativeTCPDial struct{ inner *sessionv4.NativeTCPDial }

// StartNativeTCPDial admits a fixed numeric target through the original
// qualified clock and two distinct budget references. Use the same Environment
// resource ancestry and clock as the Stream to be paired. The caller owns this
// prepared endpoint until a bridge takes it; cancellation retains late provider
// and socket custody until real exit. No arbitrary socket can be substituted.
func StartNativeTCPDial(ctx context.Context, clock *Clock, address netip.AddrPort, options NativeTCPDialOptions, reservation, socket ResourceReference) (*NativeTCPDial, error) {
	dial, err := sessionv4.StartNativeTCPDial(ctx, clock, address, options, reservation, socket)
	if err != nil {
		return nil, err
	}
	return &NativeTCPDial{inner: dial}, nil
}
func (d *NativeTCPDial) Wait(ctx context.Context) (*NativeTCP, error) {
	if d == nil || d.inner == nil {
		return nil, ErrOperationClosed
	}
	native, err := d.inner.Wait(ctx)
	if native == nil {
		return nil, err
	}
	return &NativeTCP{inner: native}, err
}
func (d *NativeTCPDial) Cancel() {
	if d != nil && d.inner != nil {
		d.inner.Cancel()
	}
}
func (d *NativeTCPDial) CleanupStatus() CleanupStatus {
	if d == nil || d.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(d.inner.CleanupStatus())
}
func (n *NativeTCP) Close() error {
	if n == nil || n.inner == nil {
		return ErrOperationClosed
	}
	return n.inner.Close()
}
func (n *NativeTCP) CleanupStatus() CleanupStatus {
	if n == nil || n.inner == nil {
		return CleanupStatus{}
	}
	return publicCleanupStatus(n.inner.CleanupStatus())
}

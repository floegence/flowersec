package flowersec

import (
	"context"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// HTTPStreamOptions fixes the native parsing, handler and upgrade envelope
// before claiming the original Stream. The external runtime is explicitly
// qualified by the deployment; it is not an RSS promise for arbitrary handlers.
type HTTPStreamOptions = sessionv4.HTTPStreamOptions
type HTTPStream = sessionv4.HTTPStream
type StreamConnOptions = sessionv4.StreamConnOptions
type StreamConn = sessionv4.StreamConn
type DelegatedHTTPService = sessionv4.DelegatedHTTPService
type ControlledHTTPService = sessionv4.ControlledHTTPService
type ControlledHTTPUpgradeConfig = sessionv4.ControlledHTTPUpgradeConfig
type HTTPUpgradePeer = sessionv4.HTTPUpgradePeer
type HTTPStreamUpgrader = sessionv4.HTTPStreamUpgrader

func HTTPStreamCharge(options HTTPStreamOptions) (ResourceVector, error) {
	return sessionv4.HTTPStreamCharge(options)
}

func StreamConnCharge(options StreamConnOptions) (ResourceVector, error) {
	return sessionv4.StreamConnCharge(options)
}

// StartHTTPStream transfers both original I/O directions to the native HTTP/1
// owner. It opens no port. Keep-alive and upgraded connections keep the original
// cancellation and cleanup owner; Close preserves accepted bytes through Finish.
func StartHTTPStream(ctx context.Context, stream Stream, handler http.Handler, options HTTPStreamOptions, reservation, connection, dependencies ResourceReference) (*HTTPStream, error) {
	original, ok := stream.(*v4Stream)
	if !ok || original == nil || original.owner == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return sessionv4.StartHTTPStream(ctx, original.owner, handler, options, reservation, connection, dependencies)
}

// ServeHTTPStream waits for authenticated Finish and actual compound cleanup.
// A caller that needs to observe cleanup after cancellation retains the handle
// returned by StartHTTPStream instead.
func ServeHTTPStream(ctx context.Context, stream Stream, handler http.Handler, options HTTPStreamOptions, reservation, connection, dependencies ResourceReference) (CloseResult, error) {
	handle, err := StartHTTPStream(ctx, stream, handler, options, reservation, connection, dependencies)
	if err != nil {
		return CloseResult{}, err
	}
	return handle.WaitCleanup(ctx)
}

// StartAcceptedHTTPStream hosts the original accepted owner delivered to a raw
// handler. It uses exactly the same admission and native lifecycle as the public
// Stream entry and does not build another ByteStream or framing layer.
func StartAcceptedHTTPStream(ctx context.Context, owner *StreamOwnership, handler http.Handler, options HTTPStreamOptions, reservation, connection, dependencies ResourceReference) (*HTTPStream, error) {
	return sessionv4.StartHTTPStream(ctx, owner, handler, options, reservation, connection, dependencies)
}

package flowersec

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

// ConnectorOptions binds one current connection attempt to its reusable
// environment and its complete, finite connect request.
type ConnectorOptions struct {
	Environment *TransportEnvironment
	ConnectOptions
}

// Connect acquires current material through the caller's original environment.
// Pool and live authority inputs retain their explicit, distinct spend paths.
func Connect(ctx context.Context, source ConnectionMaterialSource, options ConnectorOptions) (*Session, error) {
	if ctx == nil || options.Environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return options.Environment.Connect(ctx, source, options.ConnectOptions)
}

// ConnectMaterial consumes already acquired current material without invoking
// a source again. Cleanup remains attached to the original environment.
func ConnectMaterial(ctx context.Context, material *ConnectionMaterial, options ConnectorOptions) (*Session, error) {
	if ctx == nil || options.Environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return options.Environment.ConnectMaterial(ctx, material, options.ConnectOptions)
}

// ConnectPool uses an installed, unspent local pool and never replenishes it.
func ConnectPool(ctx context.Context, source *PreauthorizedPoolSource, options ConnectorOptions) (*Session, error) {
	if ctx == nil || options.Environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return options.Environment.ConnectPool(ctx, source, options.ConnectOptions)
}

// ConnectionControllerOptions groups controller admission with its original
// environment so every replacement remains owned by the same lifecycle.
type ConnectionControllerOptions struct {
	Environment *TransportEnvironment
	ControllerOptions
}

// NewConnectionController admits the controller in the original environment.
func NewConnectionController(ctx context.Context, options ConnectionControllerOptions) (*ConnectionController, error) {
	if ctx == nil || options.Environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return options.Environment.NewConnectionController(ctx, options.ControllerOptions)
}

// AcceptorOptions binds ingress registration to its original environment.
type AcceptorOptions struct {
	Environment *TransportEnvironment
	ServeOptions
}

// NewAcceptor registers one current ingress aggregate. Its accept methods run
// verification, durable admission, Noise and READY before returning a session.
func NewAcceptor(ctx context.Context, options AcceptorOptions) (*ServeHandle, error) {
	if ctx == nil || options.Environment == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return options.Environment.Serve(ctx, options.ServeOptions)
}

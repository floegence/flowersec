package serve

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/endpoint"
)

// DirectHandlerOptions configures an HTTP handler for direct (no-tunnel) server endpoints.
//
// The returned handler upgrades to WebSocket, performs the server-side E2EE handshake, and then
// dispatches yamux streams to Server.HandleStream(ctx, kind, stream).
type DirectHandlerOptions struct {
	// Server is required and is used to dispatch streams (including the built-in RPC stream handler).
	Server *Server

	AllowedOrigins []string
	AllowNoOrigin  bool

	Handshake endpoint.AcceptDirectOptions

	// OnError is called on upgrade/handshake/serve failures. It must not panic.
	// If nil, Server's OnError callback (if configured) is used.
	OnError func(err error)
}

// NewDirectHandler is a convenience wrapper over endpoint.NewDirectHandler that dispatches streams
// using srv.HandleStream.
func NewDirectHandler(opts DirectHandlerOptions) (http.HandlerFunc, error) {
	if opts.Server == nil {
		return nil, errors.New("missing server")
	}
	onErr := opts.OnError
	if onErr == nil {
		onErr = opts.Server.reportError
	}
	return endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
		AllowedOrigins:      opts.AllowedOrigins,
		AllowNoOrigin:       opts.AllowNoOrigin,
		Handshake:           opts.Handshake,
		MaxStreamHelloBytes: opts.Server.maxHelloBytes,
		OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {
			opts.Server.HandleStream(ctx, kind, stream)
		},
		OnError: onErr,
	})
}

// DirectHandlerResolvedOptions is like DirectHandlerOptions, but resolves per-channel handshake secrets at runtime.
type DirectHandlerResolvedOptions struct {
	Server *Server

	AllowedOrigins []string
	AllowNoOrigin  bool

	Handshake endpoint.AcceptDirectResolverOptions

	OnError func(err error)
}

// NewDirectHandlerResolved is a convenience wrapper over endpoint.NewDirectHandlerResolved that dispatches streams
// using srv.HandleStream.
func NewDirectHandlerResolved(opts DirectHandlerResolvedOptions) (http.HandlerFunc, error) {
	if opts.Server == nil {
		return nil, errors.New("missing server")
	}
	onErr := opts.OnError
	if onErr == nil {
		onErr = opts.Server.reportError
	}
	return endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
		AllowedOrigins:      opts.AllowedOrigins,
		AllowNoOrigin:       opts.AllowNoOrigin,
		Handshake:           opts.Handshake,
		MaxStreamHelloBytes: opts.Server.maxHelloBytes,
		OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {
			opts.Server.HandleStream(ctx, kind, stream)
		},
		OnError: onErr,
	})
}

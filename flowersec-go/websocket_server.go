package flowersec

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// ErrInvalidWebSocketServer reports a missing or unsafe WebSocket server
// configuration. WebSocket v3 endpoints must be served through
// WebSocketHTTPServer so TLS policy is fixed before the first handshake.
var ErrInvalidWebSocketServer = errors.New("invalid Flowersec WebSocket server")

const defaultWebSocketReadHeaderTimeout = 10 * time.Second

// WebSocketHTTPServerOptions configures the TLS-owned HTTP server used by
// Flowersec direct and tunnel WebSocket handlers. Handler must be returned by
// Acceptor.Handler or TunnelRuntime.Handler. The server owns a private clone
// of TLSConfig and never exposes it for post-construction mutation.
type WebSocketHTTPServerOptions struct {
	Handler           http.Handler
	TLSConfig         *tls.Config
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
}

// WebSocketHTTPServer owns the HTTP and TLS boundary for a v3 WebSocket
// endpoint. Its TLS configuration is immutable from the caller's perspective.
type WebSocketHTTPServer struct {
	httpServer *http.Server
	tlsConfig  *tls.Config
	mu         sync.Mutex
	listener   net.Listener
}

// NewWebSocketHTTPServer constructs a server for a Flowersec direct or tunnel
// WebSocket handler. The resulting server enforces TLS 1.3 only and disables
// session tickets before any connection is accepted. Dynamic GetConfigForClient
// callbacks are rejected because they could replace that policy at handshake
// time.
func NewWebSocketHTTPServer(options WebSocketHTTPServerOptions) (*WebSocketHTTPServer, error) {
	if options.Handler == nil || options.TLSConfig == nil || options.ReadHeaderTimeout < 0 ||
		options.ReadTimeout < 0 || options.WriteTimeout < 0 || options.IdleTimeout < 0 {
		return nil, ErrInvalidWebSocketServer
	}
	boundary, ok := options.Handler.(webSocketHandlerBoundary)
	if !ok || boundary == nil || boundary.secureHandler() == nil {
		return nil, ErrInvalidWebSocketServer
	}
	tlsConfig, err := prepareWebSocketServerTLS(options.TLSConfig)
	if err != nil {
		return nil, ErrInvalidWebSocketServer
	}
	readHeaderTimeout := options.ReadHeaderTimeout
	if readHeaderTimeout == 0 {
		readHeaderTimeout = defaultWebSocketReadHeaderTimeout
	}
	return &WebSocketHTTPServer{
		httpServer: &http.Server{
			Handler:           boundary.secureHandler(),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       options.ReadTimeout,
			WriteTimeout:      options.WriteTimeout,
			IdleTimeout:       options.IdleTimeout,
		},
		tlsConfig: tlsConfig,
	}, nil
}

// Serve serves one TCP listener with the server-owned TLS policy. Callers pass
// a plain listener; wrapping it again with TLS would fail the first handshake
// rather than bypassing the server-owned policy.
func (server *WebSocketHTTPServer) Serve(listener net.Listener) error {
	if server == nil || server.httpServer == nil || server.tlsConfig == nil || listener == nil {
		return ErrInvalidWebSocketServer
	}
	server.mu.Lock()
	if server.listener != nil {
		server.mu.Unlock()
		return ErrInvalidWebSocketServer
	}
	server.listener = listener
	server.mu.Unlock()
	tlsListener := tls.NewListener(listener, server.tlsConfig.Clone())
	return server.httpServer.Serve(tlsListener)
}

// ListenAndServe binds address and serves it with the server-owned TLS policy.
func (server *WebSocketHTTPServer) ListenAndServe(address string) error {
	if server == nil || server.httpServer == nil || server.tlsConfig == nil || address == "" {
		return ErrInvalidWebSocketServer
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return server.Serve(listener)
}

// Shutdown gracefully closes the HTTP server and active connections.
func (server *WebSocketHTTPServer) Shutdown(ctx context.Context) error {
	if server == nil || server.httpServer == nil {
		return ErrInvalidWebSocketServer
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return server.httpServer.Shutdown(ctx)
}

// Close immediately closes the HTTP server and active connections.
func (server *WebSocketHTTPServer) Close() error {
	if server == nil || server.httpServer == nil {
		return ErrInvalidWebSocketServer
	}
	return server.httpServer.Close()
}

func prepareWebSocketServerTLS(input *tls.Config) (*tls.Config, error) {
	if input == nil || input.GetConfigForClient != nil || input.WrapSession != nil || input.UnwrapSession != nil {
		return nil, ErrInvalidWebSocketServer
	}
	if len(input.Certificates) == 0 && input.GetCertificate == nil {
		return nil, ErrInvalidWebSocketServer
	}
	config := input.Clone()
	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	config.NextProtos = []string{"http/1.1"}
	config.SessionTicketsDisabled = true
	return config, nil
}

type webSocketHandlerBoundary interface {
	http.Handler
	secureHandler() http.Handler
}

// webSocketBoundary rejects direct use as an http.Server.Handler. The
// WebSocketHTTPServer constructor unwraps it only after it has fixed TLS.
type webSocketBoundary struct {
	handler http.Handler
	enabled bool
}

func (boundary *webSocketBoundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if boundary == nil || boundary.handler == nil {
		http.Error(writer, "Flowersec WebSocket server is not configured", http.StatusForbidden)
		return
	}
	http.Error(writer, "Flowersec WebSocket server requires WebSocketHTTPServer", http.StatusForbidden)
}

func (boundary *webSocketBoundary) secureHandler() http.Handler {
	if boundary == nil || !boundary.enabled {
		return nil
	}
	return boundary.handler
}

package flowersec

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	gorillaws "github.com/gorilla/websocket"
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
	httpServer      *http.Server
	tlsConfig       *tls.Config
	mu              sync.Mutex
	listener        net.Listener
	closing         bool
	connections     map[net.Conn]struct{}
	upgrades        map[*webSocketServerUpgrade]struct{}
	upgradesChanged chan struct{}
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
	server := &WebSocketHTTPServer{
		tlsConfig:       tlsConfig,
		connections:     make(map[net.Conn]struct{}),
		upgrades:        make(map[*webSocketServerUpgrade]struct{}),
		upgradesChanged: make(chan struct{}),
	}
	server.httpServer = &http.Server{
		Handler:           http.HandlerFunc(server.serveHTTP(boundary.secureHandler())),
		ConnState:         server.trackConnection,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       options.ReadTimeout,
		WriteTimeout:      options.WriteTimeout,
		IdleTimeout:       options.IdleTimeout,
	}
	return server, nil
}

// Serve serves one TCP listener with the server-owned TLS policy. Callers pass
// a plain listener; wrapping it again with TLS would fail the first handshake
// rather than bypassing the server-owned policy.
func (server *WebSocketHTTPServer) Serve(listener net.Listener) error {
	if server == nil || server.httpServer == nil || server.tlsConfig == nil || listener == nil {
		return ErrInvalidWebSocketServer
	}
	server.mu.Lock()
	if server.listener != nil || server.closing {
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
	defer listener.Close()
	return server.Serve(listener)
}

// Shutdown gracefully closes ordinary HTTP connections, terminates upgraded
// WebSocket connections, and waits for their handlers to release resources.
func (server *WebSocketHTTPServer) Shutdown(ctx context.Context) error {
	if server == nil || server.httpServer == nil {
		return ErrInvalidWebSocketServer
	}
	if ctx == nil {
		ctx = context.Background()
	}
	server.stopWebSocketUpgrades(false, false)
	shutdownErr := server.httpServer.Shutdown(ctx)
	waitErr := server.waitForWebSocketUpgrades(ctx)
	if shutdownErr != nil || waitErr != nil {
		server.forceCloseOwnedConnections()
	}
	return errors.Join(shutdownErr, waitErr)
}

// Close immediately closes the HTTP server and upgraded WebSocket connections,
// detaches server ownership, and returns without waiting for application
// callbacks that ignore cancellation.
func (server *WebSocketHTTPServer) Close() error {
	if server == nil || server.httpServer == nil {
		return ErrInvalidWebSocketServer
	}
	server.forceCloseOwnedConnections()
	closeErr := server.httpServer.Close()
	return closeErr
}

func (server *WebSocketHTTPServer) serveHTTP(next http.Handler) func(http.ResponseWriter, *http.Request) {
	return func(writer http.ResponseWriter, request *http.Request) {
		if !gorillaws.IsWebSocketUpgrade(request) {
			next.ServeHTTP(writer, request)
			return
		}
		ctx, cancel := context.WithCancel(request.Context())
		upgrade := &webSocketServerUpgrade{server: server, cancel: cancel}
		server.mu.Lock()
		if server.closing {
			server.mu.Unlock()
			cancel()
			http.Error(writer, "Flowersec WebSocket server is closed", http.StatusServiceUnavailable)
			return
		}
		server.upgrades[upgrade] = struct{}{}
		server.mu.Unlock()

		trackedWriter := &webSocketServerResponseWriter{ResponseWriter: writer, upgrade: upgrade}
		defer upgrade.finish()
		next.ServeHTTP(trackedWriter, request.WithContext(ctx))
	}
}

func (server *WebSocketHTTPServer) stopWebSocketUpgrades(force, detach bool) {
	server.mu.Lock()
	server.closing = true
	upgrades := make([]*webSocketServerUpgrade, 0, len(server.upgrades))
	for upgrade := range server.upgrades {
		upgrades = append(upgrades, upgrade)
	}
	if detach && len(server.upgrades) != 0 {
		clear(server.upgrades)
		close(server.upgradesChanged)
		server.upgradesChanged = make(chan struct{})
	}
	server.mu.Unlock()
	for _, upgrade := range upgrades {
		upgrade.cancel()
	}
	if force {
		for _, upgrade := range upgrades {
			upgrade.closeConnection()
		}
	}
}

func (server *WebSocketHTTPServer) forceCloseOwnedConnections() {
	server.mu.Lock()
	server.closing = true
	connections := make([]net.Conn, 0, len(server.connections))
	for connection := range server.connections {
		connections = append(connections, connection)
	}
	clear(server.connections)
	server.mu.Unlock()
	server.stopWebSocketUpgrades(true, true)
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (server *WebSocketHTTPServer) trackConnection(connection net.Conn, state http.ConnState) {
	if connection == nil {
		return
	}
	server.mu.Lock()
	switch state {
	case http.StateNew:
		if !server.closing {
			server.connections[connection] = struct{}{}
			server.mu.Unlock()
			return
		}
	case http.StateHijacked, http.StateClosed:
		delete(server.connections, connection)
	}
	closing := server.closing
	server.mu.Unlock()
	if closing && state == http.StateNew {
		_ = connection.Close()
	}
}

func (server *WebSocketHTTPServer) waitForWebSocketUpgrades(ctx context.Context) error {
	for {
		server.mu.Lock()
		if len(server.upgrades) == 0 {
			server.mu.Unlock()
			return nil
		}
		changed := server.upgradesChanged
		server.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

type webSocketServerUpgrade struct {
	server     *WebSocketHTTPServer
	cancel     context.CancelFunc
	connection net.Conn
}

func (upgrade *webSocketServerUpgrade) attach(connection net.Conn) bool {
	server := upgrade.server
	server.mu.Lock()
	if server.closing {
		server.mu.Unlock()
		_ = connection.Close()
		return false
	}
	upgrade.connection = connection
	server.mu.Unlock()
	return true
}

func (upgrade *webSocketServerUpgrade) closeConnection() {
	server := upgrade.server
	server.mu.Lock()
	connection := upgrade.connection
	server.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
}

func (upgrade *webSocketServerUpgrade) finish() {
	upgrade.cancel()
	upgrade.closeConnection()
	server := upgrade.server
	server.mu.Lock()
	if _, exists := server.upgrades[upgrade]; exists {
		delete(server.upgrades, upgrade)
		close(server.upgradesChanged)
		server.upgradesChanged = make(chan struct{})
	}
	server.mu.Unlock()
}

type webSocketServerResponseWriter struct {
	http.ResponseWriter
	upgrade *webSocketServerUpgrade
}

func (writer *webSocketServerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := writer.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("Flowersec WebSocket response does not support hijacking")
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if !writer.upgrade.attach(connection) {
		return nil, nil, net.ErrClosed
	}
	return connection, buffered, nil
}

func (writer *webSocketServerResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
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

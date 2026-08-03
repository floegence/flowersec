package connectv2

import (
	"crypto/tls"
	"net"
	"sync"
)

// WebSocketHandshakeListener enables the Linux handshake recovery policy for
// each accepted TCP connection until the HTTP server reaches a terminal
// handshake boundary and calls Restore.
type WebSocketHandshakeListener struct {
	net.Listener

	mu         sync.Mutex
	restoreFor map[net.Conn]func()
	prepare    func(net.Conn) func()
}

// NewWebSocketHandshakeListener wraps a TLS listener used by an HTTP/WebSocket
// server. Call Restore from the server's ConnState callback for Active,
// Hijacked, or Closed connections.
func NewWebSocketHandshakeListener(listener net.Listener) *WebSocketHandshakeListener {
	return newWebSocketHandshakeListener(listener, prepareWebSocketHandshakeConnection)
}

func newWebSocketHandshakeListener(listener net.Listener, prepare func(net.Conn) func()) *WebSocketHandshakeListener {
	if prepare == nil {
		prepare = func(net.Conn) func() { return func() {} }
	}
	return &WebSocketHandshakeListener{
		Listener: listener, restoreFor: make(map[net.Conn]func()), prepare: prepare,
	}
}

func (listener *WebSocketHandshakeListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	networkConnection := connection
	if tlsConnection, ok := connection.(*tls.Conn); ok {
		networkConnection = tlsConnection.NetConn()
	}
	restore := listener.prepare(networkConnection)
	if restore == nil {
		restore = func() {}
	}
	listener.mu.Lock()
	listener.restoreFor[connection] = restore
	listener.mu.Unlock()
	return connection, nil
}

// Restore disables handshake-only recovery for one accepted connection. It is
// safe to call repeatedly and after the connection has already been removed.
func (listener *WebSocketHandshakeListener) Restore(connection net.Conn) {
	if listener == nil || connection == nil {
		return
	}
	listener.mu.Lock()
	restore := listener.restoreFor[connection]
	delete(listener.restoreFor, connection)
	listener.mu.Unlock()
	if restore != nil {
		restore()
	}
}

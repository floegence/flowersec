package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
)

type webSocketHandshakeListener struct {
	net.Listener

	mu         sync.Mutex
	restoreFor map[net.Conn]func()
}

func newWebSocketHandshakeListener(listener net.Listener) *webSocketHandshakeListener {
	return &webSocketHandshakeListener{
		Listener:   listener,
		restoreFor: make(map[net.Conn]func()),
	}
}

func (listener *webSocketHandshakeListener) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	networkConnection := connection
	if tlsConnection, ok := connection.(*tls.Conn); ok {
		networkConnection = tlsConnection.NetConn()
	}
	restore := connectv2.PrepareWebSocketHandshakeConnection(networkConnection)
	listener.mu.Lock()
	listener.restoreFor[connection] = restore
	listener.mu.Unlock()
	return connection, nil
}

func (listener *webSocketHandshakeListener) connState(connection net.Conn, state http.ConnState) {
	switch state {
	case http.StateActive, http.StateHijacked, http.StateClosed:
		listener.restore(connection)
	}
}

func (listener *webSocketHandshakeListener) restore(connection net.Conn) {
	listener.mu.Lock()
	restore := listener.restoreFor[connection]
	delete(listener.restoreFor, connection)
	listener.mu.Unlock()
	if restore != nil {
		restore()
	}
}

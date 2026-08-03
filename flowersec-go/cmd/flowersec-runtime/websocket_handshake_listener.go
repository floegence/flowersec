package main

import (
	"net"
	"net/http"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/connectv2"
)

type webSocketHandshakeListener struct {
	*connectv2.WebSocketHandshakeListener
}

func newWebSocketHandshakeListener(listener net.Listener) *webSocketHandshakeListener {
	return &webSocketHandshakeListener{
		WebSocketHandshakeListener: connectv2.NewWebSocketHandshakeListener(listener),
	}
}

func (listener *webSocketHandshakeListener) connState(connection net.Conn, state http.ConnState) {
	switch state {
	case http.StateActive, http.StateHijacked, http.StateClosed:
		listener.restore(connection)
	}
}

func (listener *webSocketHandshakeListener) restore(connection net.Conn) {
	listener.Restore(connection)
}

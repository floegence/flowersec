//go:build !linux

package connectv2

import "net"

func prepareWebSocketHandshakeConnection(net.Conn) func() {
	return func() {}
}

// PrepareWebSocketHandshakeConnection preserves the platform TCP policy and
// returns a no-op restore function outside Linux.
func PrepareWebSocketHandshakeConnection(conn net.Conn) func() {
	return prepareWebSocketHandshakeConnection(conn)
}

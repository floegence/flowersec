//go:build !linux

package connectv2

import "net"

func prepareWebSocketHandshakeConnection(net.Conn) func() {
	return func() {}
}

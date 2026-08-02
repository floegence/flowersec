//go:build linux

package connectv2

import (
	"net"
	"sync"
	"syscall"
)

const tcpThinLinearTimeouts = 16

// Keep a fragmented TLS ClientHello recoverable inside the fixed artifact
// establishment timeout without changing TCP policy after the upgrade.
func prepareWebSocketHandshakeConnection(conn net.Conn) func() {
	tcpConnection, ok := conn.(*net.TCPConn)
	if !ok {
		return func() {}
	}
	rawConnection, err := tcpConnection.SyscallConn()
	if err != nil {
		return func() {}
	}
	enabled := false
	if err := rawConnection.Control(func(descriptor uintptr) {
		enabled = syscall.SetsockoptInt(
			int(descriptor), syscall.IPPROTO_TCP, tcpThinLinearTimeouts, 1,
		) == nil
	}); err != nil || !enabled {
		return func() {}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = rawConnection.Control(func(descriptor uintptr) {
				_ = syscall.SetsockoptInt(
					int(descriptor), syscall.IPPROTO_TCP, tcpThinLinearTimeouts, 0,
				)
			})
		})
	}
}

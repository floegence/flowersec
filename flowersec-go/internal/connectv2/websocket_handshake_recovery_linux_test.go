//go:build linux

package connectv2

import (
	"net"
	"syscall"
	"testing"
)

func TestPrepareWebSocketHandshakeConnectionRestoresTCPBackoff(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case server := <-accepted:
		t.Cleanup(func() { _ = server.Close() })
	case err := <-acceptErrors:
		t.Fatal(err)
	}

	restore := prepareWebSocketHandshakeConnection(client)
	if got := tcpThinLinearTimeoutValue(t, client); got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS during handshake = %d, want 1", got)
	}
	restore()
	if got := tcpThinLinearTimeoutValue(t, client); got != 0 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS after handshake = %d, want 0", got)
	}
	restore()
}

func tcpThinLinearTimeoutValue(t *testing.T, connection *net.TCPConn) int {
	t.Helper()
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	value := -1
	var socketErr error
	if err := rawConnection.Control(func(descriptor uintptr) {
		value, socketErr = syscall.GetsockoptInt(
			int(descriptor), syscall.IPPROTO_TCP, tcpThinLinearTimeouts,
		)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return value
}

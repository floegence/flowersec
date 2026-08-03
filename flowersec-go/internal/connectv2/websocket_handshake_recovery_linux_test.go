//go:build linux

package connectv2

import (
	"crypto/tls"
	"net"
	"syscall"
	"testing"
)

func TestWebSocketHandshakeListenerPreparesAcceptedSocketUntilRestore(t *testing.T) {
	rawListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listener := NewWebSocketHandshakeListener(tls.NewListener(rawListener, &tls.Config{}))
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	client, err := net.DialTCP("tcp4", nil, rawListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var connection net.Conn
	select {
	case connection = <-accepted:
		t.Cleanup(func() { _ = connection.Close() })
	case err := <-acceptErrors:
		t.Fatal(err)
	}
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		t.Fatalf("accepted connection type = %T, want *tls.Conn", connection)
	}
	server, ok := tlsConnection.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("TLS network connection type = %T, want *net.TCPConn", tlsConnection.NetConn())
	}
	if got := tcpThinLinearTimeoutValue(t, server); got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS before restore = %d, want 1", got)
	}
	listener.Restore(connection)
	if got := tcpThinLinearTimeoutValue(t, server); got != 0 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS after restore = %d, want 0", got)
	}
	listener.Restore(connection)
}

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

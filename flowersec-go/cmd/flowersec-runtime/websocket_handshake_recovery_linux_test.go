//go:build linux

package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"syscall"
	"testing"
)

const testTCPThinLinearTimeouts = 16

func TestWebSocketHandshakeListenerRestoresTCPBackoffWhenHTTPBecomesActive(t *testing.T) {
	rawListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	handshakeListener := newWebSocketHandshakeListener(
		tls.NewListener(rawListener, &tls.Config{}),
	)
	t.Cleanup(func() { _ = handshakeListener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := handshakeListener.Accept()
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

	var server net.Conn
	select {
	case server = <-accepted:
		firstServer := server
		t.Cleanup(func() { _ = firstServer.Close() })
	case err := <-acceptErrors:
		t.Fatal(err)
	}

	if got := serverTCPThinLinearTimeoutValue(t, server); got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS during server handshake = %d, want 1", got)
	}
	handshakeListener.connState(server, http.StateNew)
	if got := serverTCPThinLinearTimeoutValue(t, server); got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS before HTTP active = %d, want 1", got)
	}
	handshakeListener.connState(server, http.StateActive)
	if got := serverTCPThinLinearTimeoutValue(t, server); got != 0 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS after HTTP active = %d, want 0", got)
	}
	handshakeListener.connState(server, http.StateClosed)

	accepted = make(chan net.Conn, 1)
	acceptErrors = make(chan error, 1)
	go func() {
		connection, acceptErr := handshakeListener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	secondClient, err := net.DialTCP("tcp4", nil, rawListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secondClient.Close() })
	select {
	case server = <-accepted:
		secondServer := server
		t.Cleanup(func() { _ = secondServer.Close() })
	case err := <-acceptErrors:
		t.Fatal(err)
	}
	if got := serverTCPThinLinearTimeoutValue(t, server); got != 1 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS during second server handshake = %d, want 1", got)
	}
	handshakeListener.connState(server, http.StateClosed)
	if got := serverTCPThinLinearTimeoutValue(t, server); got != 0 {
		t.Fatalf("TCP_THIN_LINEAR_TIMEOUTS after failed handshake close = %d, want 0", got)
	}
}

func serverTCPThinLinearTimeoutValue(t *testing.T, connection net.Conn) int {
	t.Helper()
	tlsConnection, ok := connection.(*tls.Conn)
	if !ok {
		t.Fatalf("accepted connection type = %T, want *tls.Conn", connection)
	}
	tcpConnection, ok := tlsConnection.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("TLS network connection type = %T, want *net.TCPConn", tlsConnection.NetConn())
	}
	rawConnection, err := tcpConnection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	value := -1
	var socketErr error
	if err := rawConnection.Control(func(descriptor uintptr) {
		value, socketErr = syscall.GetsockoptInt(
			int(descriptor), syscall.IPPROTO_TCP, testTCPThinLinearTimeouts,
		)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	return value
}

package connectv2

import (
	"net"
	"sync/atomic"
	"testing"
)

func TestWebSocketHandshakeListenerRestoresEachAcceptedConnectionOnce(t *testing.T) {
	firstServer, firstClient := net.Pipe()
	secondServer, secondClient := net.Pipe()
	t.Cleanup(func() {
		_ = firstClient.Close()
		_ = secondClient.Close()
	})
	base := &scriptedListener{connections: make(chan net.Conn, 2)}
	base.connections <- firstServer
	base.connections <- secondServer
	close(base.connections)
	var prepared atomic.Int32
	var restored atomic.Int32
	listener := newWebSocketHandshakeListener(base, func(net.Conn) func() {
		prepared.Add(1)
		return func() { restored.Add(1) }
	})
	first, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := prepared.Load(); got != 2 {
		t.Fatalf("prepared connections = %d, want 2", got)
	}
	listener.Restore(first)
	listener.Restore(first)
	if got := restored.Load(); got != 1 {
		t.Fatalf("restored connections after first = %d, want 1", got)
	}
	listener.Restore(second)
	if got := restored.Load(); got != 2 {
		t.Fatalf("restored connections = %d, want 2", got)
	}
}

type scriptedListener struct {
	connections chan net.Conn
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	connection, ok := <-listener.connections
	if !ok {
		return nil, net.ErrClosed
	}
	return connection, nil
}

func (*scriptedListener) Close() error   { return nil }
func (*scriptedListener) Addr() net.Addr { return stubAddr("scripted") }

type stubAddr string

func (addr stubAddr) Network() string { return string(addr) }
func (addr stubAddr) String() string  { return string(addr) }

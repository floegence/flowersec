package flowersec

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestByteStreamConnReadDeadlineCanBeClearedWithoutDroppingData(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn, err := NewByteStreamConn(context.Background(), httpTestByteStream{left})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 4)); done <- err }()
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt read")
	}
	_ = conn.SetReadDeadline(time.Time{})
	go func() { _, _ = right.Write([]byte("data")) }()
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "data" {
		t.Fatalf("read after deadline: %q %v", buffer, err)
	}
}

func TestByteStreamConnWriteDeadlineCancelsBlockedWriteAndOwnsCallerBuffer(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn, _ := NewByteStreamConn(context.Background(), httpTestByteStream{left})
	defer conn.Close()
	done := make(chan error, 1)
	payload := make([]byte, byteStreamBufferBytes*3)
	go func() { _, err := conn.Write(payload); done <- err }()
	_ = conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("write timeout did not return")
	}
	// Run under race: an in-flight carrier write must not retain caller memory.
	for i := range payload {
		payload[i] = 1
	}
	if _, err := conn.Write([]byte("again")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stream revived: %v", err)
	}
}

func TestByteStreamConnIdleWriteDeadlineIsReversible(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	conn, _ := NewByteStreamConn(context.Background(), httpTestByteStream{left})
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := conn.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	go func() { _, _ = io.Copy(io.Discard, right) }()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
}

type countingStream struct {
	httpTestByteStream
	reads atomic.Int32
}

func (s *countingStream) Read(p []byte) (int, error) {
	s.reads.Add(1)
	return s.httpTestByteStream.Read(p)
}

func TestByteStreamConnBoundsUnreadDataAndCancellationClosesListener(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	stream := &countingStream{httpTestByteStream: httpTestByteStream{left}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, _ := NewByteStreamListener(ctx, stream)
	defer listener.Close()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	writes := make(chan struct{})
	go func() { _, _ = right.Write(make([]byte, byteStreamBufferBytes*8)); close(writes) }()
	time.Sleep(20 * time.Millisecond)
	if got := stream.reads.Load(); got != 1 {
		t.Fatalf("unconsumed reads: %d", got)
	}
	accepted := make(chan error, 1)
	go func() { _, err := listener.Accept(); accepted <- err }()
	cancel()
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept survived cancellation")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-writes:
	case <-time.After(time.Second):
		t.Fatal("peer writer survived cancellation")
	}
}

type tcpByteStream struct{ *net.TCPConn }

func (s tcpByteStream) Kind() string                 { return "test/tcp" }
func (s tcpByteStream) TerminalError() *SessionError { return nil }
func (s tcpByteStream) Reset() error                 { return s.Close() }

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.AcceptTCP()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	return a, b
}

func TestRelayStreamsPreservesResponseAfterRequestHalfClose(t *testing.T) {
	client, left := tcpPair(t)
	right, server := tcpPair(t)
	a, _ := NewByteStreamConn(context.Background(), tcpByteStream{left})
	b, _ := NewByteStreamConn(context.Background(), tcpByteStream{right})
	done := make(chan error, 1)
	go func() { done <- RelayStreams(context.Background(), a, b) }()
	_, _ = client.Write([]byte("request"))
	_ = client.CloseWrite()
	request, err := io.ReadAll(server)
	if err != nil || string(request) != "request" {
		t.Fatalf("request %q %v", request, err)
	}
	_, _ = server.Write([]byte("response"))
	_ = server.CloseWrite()
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response" {
		t.Fatalf("response %q %v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelayStreamsCancellationInterruptsBothDirections(t *testing.T) {
	_, left := tcpPair(t)
	right, _ := tcpPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RelayStreams(ctx, left, right) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not join workers")
	}
}

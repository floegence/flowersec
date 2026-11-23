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

func TestRelayStreamsCancellationAbortsNetworkAdapters(t *testing.T) {
	left, peerLeft := net.Pipe()
	right, peerRight := net.Pipe()
	defer peerLeft.Close()
	defer peerRight.Close()
	a, _ := NewByteStreamConn(context.Background(), httpTestByteStream{left})
	b, _ := NewByteStreamConn(context.Background(), httpTestByteStream{right})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RelayStreams(ctx, a, b) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay cancellation waited for graceful-close drain")
	}
}

func TestByteStreamConnCancellationInterruptsGracefulDrain(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := NewByteStreamConn(ctx, httpTestByteStream{left})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	<-conn.done
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for the graceful-close timeout")
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

type delayedWriteStream struct {
	tcpByteStream
	started chan struct{}
	release chan struct{}
}

func (s *delayedWriteStream) Write(p []byte) (int, error) {
	close(s.started)
	<-s.release
	return s.tcpByteStream.Write(p)
}

func TestByteStreamConnCloseDeliversAcceptedWriteBeforeFIN(t *testing.T) {
	left, right := tcpPair(t)
	stream := &delayedWriteStream{tcpByteStream{left}, make(chan struct{}), make(chan struct{})}
	conn, err := NewByteStreamConn(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("accepted response")); written <- err }()
	<-stream.started
	closed := make(chan struct{})
	go func() { _ = conn.Close(); close(closed) }()
	<-conn.done
	select {
	case err := <-written:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("interrupted application write: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt application I/O")
	}
	close(stream.release)
	body, err := io.ReadAll(right)
	if err != nil || string(body) != "accepted response" {
		t.Fatalf("peer response: %q %v", body, err)
	}
	_ = right.CloseWrite()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("clean FIN exchange did not finish Close")
	}
}

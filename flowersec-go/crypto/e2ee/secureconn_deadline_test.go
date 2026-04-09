package e2ee

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingWriteTransport struct {
	writeStarted sync.Once
	writeCh      chan struct{}
	releaseCh    chan struct{}
	closed       chan struct{}
	sent         atomic.Bool
}

func newBlockingWriteTransport() *blockingWriteTransport {
	return &blockingWriteTransport{
		writeCh:   make(chan struct{}),
		releaseCh: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (t *blockingWriteTransport) ReadBinary(_ context.Context) ([]byte, error) {
	<-t.closed
	return nil, io.EOF
}

func (t *blockingWriteTransport) WriteBinary(_ context.Context, _ []byte) error {
	t.writeStarted.Do(func() { close(t.writeCh) })
	select {
	case <-t.releaseCh:
		t.sent.Store(true)
		return nil
	case <-t.closed:
		return io.EOF
	}
}

func (t *blockingWriteTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
		return nil
	}
}

type cancelAwareWriteTransport struct {
	writeStarted sync.Once
	writeCh      chan struct{}
	releaseCh    chan struct{}
	closed       chan struct{}
	sent         atomic.Bool
}

func newCancelAwareWriteTransport() *cancelAwareWriteTransport {
	return &cancelAwareWriteTransport{
		writeCh:   make(chan struct{}),
		releaseCh: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (t *cancelAwareWriteTransport) ReadBinary(_ context.Context) ([]byte, error) {
	<-t.closed
	return nil, io.EOF
}

func (t *cancelAwareWriteTransport) WriteBinary(ctx context.Context, _ []byte) error {
	t.writeStarted.Do(func() { close(t.writeCh) })
	select {
	case <-t.releaseCh:
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		t.sent.Store(true)
		return nil
	case <-ctx.Done():
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		return ctx.Err()
	case <-t.closed:
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return io.EOF
	}
}

func (t *cancelAwareWriteTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
		return nil
	}
}

func TestSecureChannelReadDeadlineTimesOut(t *testing.T) {
	tr := &testBinaryTransport{readCh: make(chan []byte)}
	conn := NewSecureChannel(tr, RecordKeyState{}, 1<<20, 0)
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("expected net.Error timeout, got %T: %v", err, err)
	}
}

func TestSecureChannelReadDeadlineUpdateAffectsInFlightRead(t *testing.T) {
	tr := &testBinaryTransport{readCh: make(chan []byte)}
	conn := NewSecureChannel(tr, RecordKeyState{}, 1<<20, 0)
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		errCh <- err
	}()

	time.Sleep(30 * time.Millisecond)
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected timeout error")
		}
		ne, ok := err.(net.Error)
		if !ok || !ne.Timeout() {
			t.Fatalf("expected net.Error timeout, got %T: %v", err, err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for Read to return")
	}
}

func TestSecureChannelWriteDeadlineUpdateAffectsInFlightWrite(t *testing.T) {
	tr := newBlockingWriteTransport()
	keys := RecordKeyState{
		SendDir: DirC2S,
		SendSeq: 1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	type result struct {
		n   int
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		n, err := conn.Write([]byte("hi"))
		resCh <- result{n: n, err: err}
	}()

	// Ensure the writer goroutine is blocked in the underlying transport write.
	select {
	case <-tr.writeCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for WriteBinary to start")
	}

	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))

	select {
	case res := <-resCh:
		if res.err == nil {
			t.Fatalf("expected timeout error")
		}
		ne, ok := res.err.(net.Error)
		if !ok || !ne.Timeout() {
			t.Fatalf("expected net.Error timeout, got %T: %v", res.err, res.err)
		}
		if res.n != 0 {
			t.Fatalf("expected n=0 on timeout, got %d", res.n)
		}
		if tr.sent.Load() {
			t.Fatalf("timed-out write must not be reported as sent")
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for Write to return")
	}
}

func TestSecureChannelWriteDeadlinePreventsLateSend(t *testing.T) {
	tr := newCancelAwareWriteTransport()
	keys := RecordKeyState{
		SendDir: DirC2S,
		SendSeq: 1,
	}
	conn := NewSecureChannel(tr, keys, 1<<20, 0)
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("hi"))
		errCh <- err
	}()

	select {
	case <-tr.writeCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for WriteBinary to start")
	}

	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("expected timeout error")
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline exceeded, got %T: %v", err, err)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for Write to return")
	}

	close(tr.releaseCh)
	time.Sleep(50 * time.Millisecond)
	if tr.sent.Load() {
		t.Fatalf("timed-out write must not be delivered after Write returns")
	}
}

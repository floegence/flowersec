package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type controlLifecycleStream struct {
	eof       bool
	reset     chan struct{}
	resetOnce sync.Once
	resets    atomic.Int32
}

func newControlLifecycleStream(eof bool) *controlLifecycleStream {
	return &controlLifecycleStream{eof: eof, reset: make(chan struct{})}
}

func (stream *controlLifecycleStream) Read([]byte) (int, error) {
	if stream.eof {
		return 0, io.EOF
	}
	<-stream.reset
	return 0, io.ErrClosedPipe
}

func (*controlLifecycleStream) Write(payload []byte) (int, error) { return len(payload), nil }

func (stream *controlLifecycleStream) CloseWrite() error {
	<-stream.reset
	return io.ErrClosedPipe
}

func (*controlLifecycleStream) StopSending() error { return nil }

func (stream *controlLifecycleStream) Reset() error {
	stream.resets.Add(1)
	stream.resetOnce.Do(func() { close(stream.reset) })
	return nil
}

func (*controlLifecycleStream) Close() error { return nil }

func (*controlLifecycleStream) Context() context.Context { return context.Background() }

func TestControlHalfCloseGraceStartsBeforeCloseWriteCompletes(t *testing.T) {
	left := newControlLifecycleStream(true)
	right := newControlLifecycleStream(false)
	completed := make(chan error, 1)
	go func() {
		completed <- spliceStreamPair(context.Background(), left, right, 1024, 10*time.Millisecond)
	}()

	select {
	case err := <-completed:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("splice error = %v, want deadline exceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("control splice retained a stuck FIN past the half-close grace")
	}
	if left.resets.Load() == 0 || right.resets.Load() == 0 {
		t.Fatalf("reset counts = (%d, %d), want both non-zero", left.resets.Load(), right.resets.Load())
	}
}

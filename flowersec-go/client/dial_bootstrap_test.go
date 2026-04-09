package client

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/fserrors"
)

type deadlineWakeConn struct {
	mu        sync.Mutex
	deadlines []time.Time
	immediate chan struct{}
	once      sync.Once
}

func newDeadlineWakeConn() *deadlineWakeConn {
	return &deadlineWakeConn{immediate: make(chan struct{})}
}

func (c *deadlineWakeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	if !t.IsZero() && !time.Now().Before(t) {
		c.once.Do(func() { close(c.immediate) })
	}
	return nil
}

type blockingBootstrapStream struct {
	closed chan struct{}
}

func newBlockingBootstrapStream() *blockingBootstrapStream {
	return &blockingBootstrapStream{closed: make(chan struct{})}
}

func (s *blockingBootstrapStream) Read(_ []byte) (int, error) { return 0, io.EOF }

func (s *blockingBootstrapStream) Write(_ []byte) (int, error) {
	<-s.closed
	return 0, io.ErrClosedPipe
}

func (s *blockingBootstrapStream) Close() error {
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
		return nil
	}
}

func (s *blockingBootstrapStream) SetWriteDeadline(_ time.Time) error { return nil }

func TestOpenBootstrapStreamHonorsContextDuringOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	secure := newDeadlineWakeConn()
	_, err := openBootstrapStream(ctx, fserrors.PathDirect, secure, func() (io.ReadWriteCloser, error) {
		<-secure.immediate
		return nil, os.ErrDeadlineExceeded
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathDirect || fe.Stage != StageYamux || fe.Code != CodeTimeout {
		t.Fatalf("unexpected error: %+v", fe)
	}
}

func TestOpenBootstrapStreamHonorsContextDuringStreamHello(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	stream := newBlockingBootstrapStream()
	secure := newDeadlineWakeConn()
	_, err := openBootstrapStream(ctx, fserrors.PathTunnel, secure, func() (io.ReadWriteCloser, error) {
		return stream, nil
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var fe *Error
	if !errors.As(err, &fe) {
		t.Fatalf("expected *client.Error, got %T", err)
	}
	if fe.Path != PathTunnel || fe.Stage != StageYamux || fe.Code != CodeTimeout {
		t.Fatalf("unexpected error: %+v", fe)
	}
	select {
	case <-stream.closed:
	default:
		t.Fatalf("expected timed-out bootstrap stream to be closed")
	}
}

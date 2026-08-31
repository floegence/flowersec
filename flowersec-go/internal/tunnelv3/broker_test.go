package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
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

func TestBridgeRegistersBaseTasksBeforeLaunchingWorkers(t *testing.T) {
	controlStarted := make(chan struct{})
	var controlStartedOnce sync.Once
	var availabilityReturned atomic.Bool
	var workerStartedEarly atomic.Bool
	newControl := func() *immediateBridgeControlStream {
		return &immediateBridgeControlStream{onRead: func() {
			if !availabilityReturned.Load() {
				workerStartedEarly.Store(true)
			}
			controlStartedOnce.Do(func() { close(controlStarted) })
		}}
	}
	client := newBridgeLifecycleSession()
	server := newBridgeLifecycleSession()
	client.acceptControl = newControl()
	server.openControl = newControl()
	client.unreliableAvailable = func() bool {
		select {
		case <-controlStarted:
		case <-time.After(25 * time.Millisecond):
		}
		availabilityReturned.Store(true)
		return false
	}

	completed := make(chan error, 1)
	go func() {
		completed <- Bridge(
			context.Background(),
			client,
			server,
			Limits{MaxConcurrentStreams: 1, CopyBufferBytes: 1024, CleanupTimeout: 20 * time.Millisecond},
			100*time.Millisecond,
		)
	}()

	select {
	case err := <-completed:
		if !errors.Is(err, ErrControlClosed) {
			t.Fatalf("Bridge error = %v, want control closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Bridge did not complete after the control stream closed")
	}
	if workerStartedEarly.Load() {
		t.Fatal("control worker started before Bridge registered its complete base task count")
	}
}

type immediateBridgeControlStream struct {
	onRead func()
}

func (stream *immediateBridgeControlStream) Read([]byte) (int, error) {
	stream.onRead()
	return 0, io.EOF
}

func (*immediateBridgeControlStream) Write(payload []byte) (int, error) { return len(payload), nil }
func (*immediateBridgeControlStream) CloseWrite() error                 { return nil }
func (*immediateBridgeControlStream) StopSending() error                { return nil }
func (*immediateBridgeControlStream) Reset() error                      { return nil }
func (*immediateBridgeControlStream) Close() error                      { return nil }
func (*immediateBridgeControlStream) Context() context.Context          { return context.Background() }

type bridgeLifecycleSession struct {
	mu                  sync.Mutex
	acceptControl       carrier.Stream
	openControl         carrier.Stream
	terminated          chan struct{}
	closeOnce           sync.Once
	unreliableAvailable func() bool
}

func newBridgeLifecycleSession() *bridgeLifecycleSession {
	return &bridgeLifecycleSession{
		terminated:          make(chan struct{}),
		unreliableAvailable: func() bool { return false },
	}
}

func (*bridgeLifecycleSession) Kind() carrier.Kind         { return carrier.KindRawQUIC }
func (*bridgeLifecycleSession) Path() carrier.Path         { return carrier.PathTunnel }
func (*bridgeLifecycleSession) MaxIncomingStreams() uint16 { return 130 }

func (session *bridgeLifecycleSession) OpenStream(ctx context.Context) (carrier.Stream, error) {
	session.mu.Lock()
	control := session.openControl
	session.openControl = nil
	session.mu.Unlock()
	if control != nil {
		return control, nil
	}
	return nil, waitForBridgeLifecycleEnd(ctx, session.terminated)
}

func (session *bridgeLifecycleSession) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	session.mu.Lock()
	control := session.acceptControl
	session.acceptControl = nil
	session.mu.Unlock()
	if control != nil {
		return control, nil
	}
	return nil, waitForBridgeLifecycleEnd(ctx, session.terminated)
}

func (session *bridgeLifecycleSession) Termination() <-chan struct{} { return session.terminated }
func (session *bridgeLifecycleSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return session.Close()
}
func (session *bridgeLifecycleSession) CloseWithError(carrier.ApplicationError) error {
	return session.Close()
}
func (session *bridgeLifecycleSession) Abort(carrier.ApplicationError) error { return session.Close() }
func (session *bridgeLifecycleSession) Close() error {
	session.closeOnce.Do(func() { close(session.terminated) })
	return nil
}

func (session *bridgeLifecycleSession) UnreliableAvailable() bool {
	return session.unreliableAvailable()
}

func (*bridgeLifecycleSession) SendUnreliable([]byte) error { return io.ErrClosedPipe }
func (session *bridgeLifecycleSession) ReceiveUnreliable(ctx context.Context) ([]byte, error) {
	return nil, waitForBridgeLifecycleEnd(ctx, session.terminated)
}

func waitForBridgeLifecycleEnd(ctx context.Context, terminated <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-terminated:
		return io.ErrClosedPipe
	}
}

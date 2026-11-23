package tunnelv3

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
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
	newControl := func(retire func() error) *immediateBridgeControlStream {
		return &immediateBridgeControlStream{onRead: func() {
			if !availabilityReturned.Load() {
				workerStartedEarly.Store(true)
			}
			controlStartedOnce.Do(func() { close(controlStarted) })
			_ = retire()
		}}
	}
	client := newBridgeLifecycleSession()
	server := newBridgeLifecycleSession()
	client.acceptControl = newControl(client.Close)
	server.openControl = newControl(server.Close)
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

type reportingBridgeLeg struct {
	*bridgeLifecycleSession
	kind       carrier.Kind
	closedWith carrier.ApplicationError
}

func (leg *reportingBridgeLeg) Kind() carrier.Kind { return leg.kind }

func (leg *reportingBridgeLeg) CloseWithErrorContext(ctx context.Context, reason carrier.ApplicationError) error {
	leg.closedWith = reason
	return leg.bridgeLifecycleSession.CloseWithErrorContext(ctx, reason)
}

func TestMixedBridgeReportsControlOutcomeToBothLegs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		readErr error
		code    uint64
	}{{"both FINs", io.EOF, 1}, {"interrupted reply", io.ErrUnexpectedEOF, 6}} {
		t.Run(tc.name, func(t *testing.T) {
			client := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: carrier.KindWebTransport}
			server := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: carrier.KindRawQUIC}
			forwarded := make(chan struct{})
			client.acceptControl = &immediateBridgeControlStream{onRead: func() {}}
			server.openControl = &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false),
				read: func([]byte) (int, error) { <-forwarded; return 0, tc.readErr }, closeWrite: func() error { close(forwarded); return nil }}
			err := Bridge(t.Context(), client, server, DefaultLimits(), time.Second)
			if errors.Is(err, ErrControlClosed) != (tc.readErr == io.EOF) || (tc.readErr != io.EOF && !errors.Is(err, tc.readErr)) {
				t.Errorf("bridge outcome: %v", err)
			}
			for _, got := range []carrier.ApplicationError{client.closedWith, server.closedWith, closeApplicationError(err)} {
				if got.Code != tc.code {
					t.Errorf("application close = %+v; want code %d", got, tc.code)
				}
			}
		})
	}
}

type observedDrainLeg struct {
	*bridgeLifecycleSession
	wait chan struct{}
	once sync.Once
}

func TestBridgeCallerCancellationKeepsCarrierCloseReason(t *testing.T) {
	for _, kind := range []carrier.Kind{carrier.KindRawQUIC, carrier.KindWebTransport} {
		client := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: kind}
		server := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: kind}
		ctx, cancel := context.WithCancelCause(t.Context())
		stop := errors.New("listener stopped during control forwarding")
		clientStream := newControlLifecycleStream(false)
		client.acceptControl = &halfCloseRelayStream{controlLifecycleStream: clientStream, read: func(p []byte) (int, error) {
			cancel(stop)
			return clientStream.Read(p)
		}}
		server.openControl = newControlLifecycleStream(false)
		err := Bridge(ctx, client, server, DefaultLimits(), time.Second)
		want := carrier.ApplicationError{Reason: "tunnel bridge closed"}
		if kind == carrier.KindWebTransport {
			want = carrier.ApplicationError{Code: 6, Reason: "tunnel control forwarding failed"}
		}
		if !errors.Is(err, stop) || errors.Is(err, ErrControlClosed) || client.closedWith != want || server.closedWith != want {
			t.Errorf("%v: cancellation = %v; close reasons = %+v, %+v; want %+v", kind, err, client.closedWith, server.closedWith, want)
		}
	}
}

func (leg *observedDrainLeg) Termination() <-chan struct{} {
	leg.once.Do(func() { close(leg.wait) })
	return leg.terminated
}

type h3DrainLeg struct{ *observedDrainLeg }

func (*h3DrainLeg) Kind() carrier.Kind { return carrier.KindWebTransport }

func TestH3BridgeKeepsReplyUntilFirstHalfCloserRetires(t *testing.T) {
	for _, first := range []int{0, 1} {
		legs := [2]*h3DrainLeg{}
		controls := [2]*halfCloseRelayStream{}
		forwarded := make(chan struct{})
		for direction := range legs {
			legs[direction] = &h3DrainLeg{&observedDrainLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), wait: make(chan struct{})}}
			controls[direction] = &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false), read: func([]byte) (int, error) {
				if direction != first {
					select {
					case <-forwarded:
					case <-t.Context().Done():
						return 0, t.Context().Err()
					}
				}
				return 0, io.EOF
			}, closeWrite: func() error {
				if direction != first {
					close(forwarded)
				}
				return nil
			}}
		}
		legs[0].acceptControl, legs[1].openControl = controls[0], controls[1]
		done := make(chan error, 1)
		go func() { done <- Bridge(t.Context(), legs[0], legs[1], DefaultLimits(), time.Second) }()
		select {
		case <-legs[first].wait:
		case err := <-done:
			t.Fatalf("bridge returned before initiator carrier closed: %v", err)
		case <-time.After(time.Second):
			t.Fatal("missing initiator barrier")
		}
		select {
		case <-legs[1-first].terminated:
			if first == 0 {
				t.Fatal("reply leg retired early")
			}
		default:
			if first == 1 {
				t.Fatal("client not released after both FINs were forwarded")
			}
		}
		_ = legs[first].Close()
		select {
		case err := <-done:
			if !errors.Is(err, ErrControlClosed) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("reply leg did not retire")
		}
	}
}

func TestRawQUICBridgeDrainsBothLegsAfterControlFIN(t *testing.T) {
	left := &observedDrainLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), wait: make(chan struct{})}
	right := &observedDrainLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), wait: make(chan struct{})}
	left.acceptControl = &immediateBridgeControlStream{onRead: func() {}}
	forwarded := make(chan struct{})
	right.openControl = &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false),
		read: func([]byte) (int, error) { <-forwarded; return 0, io.EOF }, closeWrite: func() error { close(forwarded); return nil }}
	completed := make(chan error, 1)
	go func() { completed <- Bridge(context.Background(), left, right, DefaultLimits(), time.Second) }()
	for _, leg := range []*observedDrainLeg{left, right} {
		select {
		case <-leg.wait:
		case err := <-completed:
			t.Fatalf("closed before endpoint: %v", err)
		case <-time.After(time.Second):
			t.Fatal("never waited for endpoint")
		}
		select {
		case <-leg.terminated:
			t.Fatal("terminated before endpoint closed")
		default:
		}
		_ = leg.Close()
	}
	select {
	case err := <-completed:
		if !errors.Is(err, ErrControlClosed) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge did not join")
	}
}

func TestBridgePreservesServerUntilItConsumesClientFIN(t *testing.T) {
	kinds := []carrier.Kind{carrier.KindRawQUIC, carrier.KindWebTransport, carrier.KindWebSocket}
	for _, ck := range kinds {
		for _, sk := range kinds {
			t.Run(string(ck)+"/"+string(sk), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				client := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: ck}
				server := &reportingBridgeLeg{bridgeLifecycleSession: newBridgeLifecycleSession(), kind: sk}
				serverFIN, lastFIN, committed := make(chan struct{}), make(chan struct{}), make(chan struct{})
				client.acceptControl = &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false),
					read: func([]byte) (int, error) {
						select {
						case <-serverFIN:
							return 0, io.EOF
						case <-ctx.Done():
							return 0, ctx.Err()
						}
					},
					closeWrite: func() error { close(serverFIN); return nil }}
				server.openControl = &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false),
					read: func([]byte) (int, error) { return 0, io.EOF },
					closeWrite: func() error {
						close(lastFIN)
						select {
						case <-committed:
							return nil
						case <-ctx.Done():
							return ctx.Err()
						}
					}}
				done := make(chan error, 1)
				go func() { done <- Bridge(ctx, client, server, DefaultLimits(), time.Second) }()
				select {
				case <-lastFIN:
				case <-ctx.Done():
					t.Fatal("missing final FIN")
				}
				select {
				case <-client.terminated:
					t.Fatal("client retired before FIN commit")
				case <-server.terminated:
					t.Fatal("server retired before FIN commit")
				default:
				}
				close(committed)
				select {
				case <-client.terminated:
				case <-ctx.Done():
					t.Fatal("client was not released after FIN commit")
				}
				want := carrier.ApplicationError{Code: 1, Reason: "session closed"}
				if client.closedWith != want {
					t.Fatal(client.closedWith)
				}
				select {
				case <-server.terminated:
					t.Fatal("server retired before consuming client FIN")
				case err := <-done:
					t.Fatalf("early return: %v", err)
				default:
				}
				_ = server.Close()
				select {
				case err := <-done:
					if !errors.Is(err, ErrControlClosed) || server.closedWith != want {
						t.Fatalf("bridge: %v server: %+v", err, server.closedWith)
					}
				case <-ctx.Done():
					t.Fatal("bridge did not release server")
				}
			})
		}
	}
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

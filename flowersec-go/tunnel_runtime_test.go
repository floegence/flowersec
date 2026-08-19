package flowersec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v3/internal/carrier"
)

func TestTunnelRuntimeServeWaitsForAcceptedNativeSessions(t *testing.T) {
	session := &blockingTunnelSession{
		accepted: make(chan struct{}),
		release:  make(chan struct{}),
	}
	listener := &singleTunnelListener{session: session}
	runtime := &TunnelRuntime{listeners: []registeredAcceptorListener{listener}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.Serve(ctx) }()

	select {
	case <-session.accepted:
	case <-time.After(time.Second):
		t.Fatal("native session was not accepted")
	}
	cancel()
	select {
	case err := <-result:
		t.Fatalf("Serve() returned before accepted session cleanup: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(session.release)
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after accepted session cleanup")
	}
}

func TestReleaseTunnelRuntimeLeaseHonorsCleanupDeadline(t *testing.T) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	releaseStarted := make(chan struct{})
	releaseCanceled := make(chan struct{})
	started := time.Now()
	releaseTunnelRuntimeLease(cleanupCtx, func(ctx context.Context, _ string) {
		close(releaseStarted)
		<-ctx.Done()
		close(releaseCanceled)
	}, "lease")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("lease release exceeded cleanup bound: %v", elapsed)
	}
	select {
	case <-releaseStarted:
	case <-time.After(time.Second):
		t.Fatal("lease release callback did not start")
	}
	select {
	case <-releaseCanceled:
	case <-time.After(time.Second):
		t.Fatal("lease release callback did not observe cancellation")
	}
}

type singleTunnelListener struct {
	session carrier.Session
}

func (*singleTunnelListener) acceptorListener()             {}
func (*singleTunnelListener) Address() string               { return "test" }
func (*singleTunnelListener) Close() error                  { return nil }
func (*singleTunnelListener) acceptorCarrier() carrier.Kind { return carrier.KindRawQUIC }
func (*singleTunnelListener) acceptorPath() carrier.Path    { return carrier.PathTunnel }
func (listener *singleTunnelListener) serve(ctx context.Context, accept func(context.Context, carrier.Session) error) error {
	if err := accept(ctx, listener.session); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

type blockingTunnelSession struct {
	accepted chan struct{}
	release  chan struct{}
}

func (*blockingTunnelSession) Kind() carrier.Kind         { return carrier.KindRawQUIC }
func (*blockingTunnelSession) Path() carrier.Path         { return carrier.PathTunnel }
func (*blockingTunnelSession) MaxIncomingStreams() uint16 { return 1 }
func (*blockingTunnelSession) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, errors.New("not implemented")
}
func (session *blockingTunnelSession) AcceptStream(context.Context) (carrier.Stream, error) {
	close(session.accepted)
	<-session.release
	return nil, errors.New("session released")
}
func (*blockingTunnelSession) Termination() <-chan struct{} { return make(chan struct{}) }
func (*blockingTunnelSession) CloseWithErrorContext(context.Context, carrier.ApplicationError) error {
	return nil
}
func (*blockingTunnelSession) CloseWithError(carrier.ApplicationError) error { return nil }
func (*blockingTunnelSession) Abort(carrier.ApplicationError) error          { return nil }
func (*blockingTunnelSession) Close() error                                  { return nil }

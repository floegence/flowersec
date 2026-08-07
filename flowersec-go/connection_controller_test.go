package flowersec

import (
	"context"
	"crypto/x509"
	"sync"
	"testing"
	"time"
)

func TestConnectionControllerReplacesTerminatedSessionWithFreshLease(t *testing.T) {
	artifact := mustParseInternalFixtureArtifact(t)
	firstLease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	secondLease, err := NewArtifactLease(artifact, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	source := &controllerTestSource{leases: []ArtifactLease{firstLease, secondLease}}
	trustRoots := x509.NewCertPool()
	trustRoots.AddCert(&x509.Certificate{RawSubject: []byte("controller test root")})
	controller, err := NewConnectionController(source, ConnectorOptions{TrustRoots: trustRoots}, RetryPolicy{
		InitialDelay: time.Millisecond,
		MaxDelay:     time.Millisecond,
		Factor:       1,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := newControllerTestSession()
	second := newControllerTestSession()
	var connected []ArtifactLease
	controller.connect = func(_ context.Context, lease ArtifactLease, _ ConnectorOptions) (Session, error) {
		connected = append(connected, lease)
		if len(connected) == 1 {
			return first, nil
		}
		return second, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitControllerState(t, controller, ConnectionConnected)
	close(first.terminated)
	waitControllerSession(t, controller, second)
	if len(connected) != 2 || connected[0] != firstLease || connected[1] != secondLease {
		t.Fatalf("connection leases = %d, want two fresh leases", len(connected))
	}
	if first.closeCount() == 0 {
		t.Fatal("terminated session was not closed before replacement")
	}
	if err := controller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func waitControllerState(t *testing.T, controller *ConnectionController, want ConnectionState) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("controller state = %q, want %q", controller.Status().State, want)
}

func waitControllerSession(t *testing.T, controller *ConnectionController, want Session) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if controller.Status().Session == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("controller session was not replaced")
}

type controllerTestSource struct {
	mu     sync.Mutex
	leases []ArtifactLease
}

func (source *controllerTestSource) Acquire(context.Context) (ArtifactLease, *ArtifactSourceError) {
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.leases) == 0 {
		return ArtifactLease{}, NewTerminalArtifactSourceError(ErrInvalidArtifact)
	}
	lease := source.leases[0]
	source.leases = source.leases[1:]
	return lease, nil
}

type controllerTestSession struct {
	terminated chan struct{}
	mu         sync.Mutex
	closed     int
}

func newControllerTestSession() *controllerTestSession {
	return &controllerTestSession{terminated: make(chan struct{})}
}

func (session *controllerTestSession) RPC() RPCPeer { return nil }
func (session *controllerTestSession) UnreliableMessages() (UnreliableMessageChannel, error) {
	return nil, nil
}
func (session *controllerTestSession) OpenStream(context.Context, string, StreamMetadata) (ByteStream, error) {
	return nil, nil
}
func (session *controllerTestSession) AcceptStream(context.Context) (IncomingStream, error) {
	return IncomingStream{}, nil
}
func (session *controllerTestSession) Rekey(context.Context) error { return nil }
func (session *controllerTestSession) ProbeLiveness(context.Context) (time.Duration, error) {
	return 0, nil
}
func (session *controllerTestSession) WaitTermination(ctx context.Context) (SessionTermination, error) {
	select {
	case <-session.terminated:
		return SessionTermination{Error: SessionError{code: SessionClosed}}, nil
	case <-ctx.Done():
		return SessionTermination{}, ctx.Err()
	}
}
func (session *controllerTestSession) Close() error {
	session.mu.Lock()
	session.closed++
	session.mu.Unlock()
	return nil
}
func (session *controllerTestSession) closeCount() int {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.closed
}

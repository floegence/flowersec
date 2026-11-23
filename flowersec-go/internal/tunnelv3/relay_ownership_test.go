package tunnelv3

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/carrier"
)

type observingActivationLeg struct {
	*activationTestPendingLeg
	activation chan context.Context
}

func (leg *observingActivationLeg) Activate(ctx context.Context, role uint8) (carrier.Session, error) {
	leg.activation <- ctx
	return leg.activationTestPendingLeg.Activate(ctx, role)
}

func TestPairReleasesActivationDeadlineBeforeForwarding(t *testing.T) {
	observed := make(chan context.Context, 2)
	coordinator, err := NewCoordinator(Config{OnPair: func(ctx context.Context, _, _ carrier.Session, _, _ Authorization) error {
		for range 2 {
			if err := (<-observed).Err(); err != context.Canceled {
				t.Errorf("activation context after handoff: got %v, want canceled", err)
			}
		}
		return ctx.Err()
	}}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return Authorization{}, errors.New("unused authorizer")
	})
	if err != nil {
		t.Fatal(err)
	}
	var generation *pairGeneration
	for _, role := range []uint8{1, 2} {
		leg := newExpiryTestLeg(role, time.Now().Add(time.Minute))
		leg.pending = &observingActivationLeg{&activationTestPendingLeg{session: newActivationTestSession(false)}, observed}
		generation, err = coordinator.register(t.Context(), leg)
		if err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-generation.done:
		if generation.err != nil {
			t.Fatalf("pair context ended at activation handoff: %v", generation.err)
		}
	case <-time.After(time.Second):
		t.Fatal("pair did not finish")
	}
}

func TestTransferredAdmissionJoinsLeaseAndFinalCallback(t *testing.T) {
	leg := newExpiryTestLeg(1, time.Now().Add(time.Minute))
	leg.authorization.Claims.AuthorityScope = "authority"
	leg.authorization.Claims.EndpointInstanceID = "endpoint-client"
	coordinator, err := NewCoordinator(Config{}, func(context.Context, *artifactv3.DecodedRequest) (Authorization, error) {
		return leg.authorization, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	pending := &serveExpiryPendingLeg{expiryTestPendingLeg: &expiryTestPendingLeg{}}
	reported := make(chan error, 1)
	releaseCallback := make(chan struct{})
	finishCallback := sync.OnceFunc(func() { close(releaseCallback) })
	defer finishCallback()
	if err := coordinator.AdmitUntil(ctx, pending, time.Time{}, func(err error) {
		reported <- err
		<-releaseCallback
	}); err != nil {
		t.Fatal(err)
	}
	checkWaiting := func() {
		t.Helper()
		bound, stop := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer stop()
		if err := coordinator.WaitCleanup(bound); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("cleanup did not retain ownership: %v", err)
		}
	}
	checkWaiting()
	cause := errors.New("listener stopped")
	cancel(cause)
	select {
	case err := <-reported:
		if !errors.Is(err, cause) || leg.authorization.Lease.(*expiryTestLease).releases.Load() != 1 || pending.closes.Load() != 1 {
			t.Fatalf("callback preceded close or lease release, or lost its cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("missing final callback")
	}
	checkWaiting()
	finishCallback()
	bound, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := coordinator.WaitCleanup(bound); err != nil {
		t.Fatal(err)
	}
}

type halfCloseRelayStream struct {
	*controlLifecycleStream
	read       func([]byte) (int, error)
	written    bytes.Buffer
	closeWrite func() error
}

func (stream *halfCloseRelayStream) Read(payload []byte) (int, error) { return stream.read(payload) }
func (stream *halfCloseRelayStream) Write(payload []byte) (int, error) {
	return stream.written.Write(payload)
}
func (stream *halfCloseRelayStream) CloseWrite() error { return stream.closeWrite() }

func TestRelayDataHalfCloseAllowsPeerResponseAndReturnsPeerError(t *testing.T) {
	request := bytes.NewReader([]byte("request"))
	response := bytes.NewReader([]byte("response after FIN"))
	ctx, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	fin := make(chan struct{})
	peerError := errors.New("peer close write failed")
	left := &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false), read: request.Read, closeWrite: func() error { return peerError }}
	right := &halfCloseRelayStream{controlLifecycleStream: newControlLifecycleStream(false), read: func(payload []byte) (int, error) {
		select {
		case <-fin:
			return response.Read(payload)
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}, closeWrite: func() error { close(fin); return nil }}
	if err := spliceStreamPair(ctx, left, right, 1024, 0); !errors.Is(err, peerError) || left.written.String() != "response after FIN" || right.written.String() != "request" {
		t.Fatalf("forwarded %q / %q; error %v", right.written.String(), left.written.String(), err)
	}
}

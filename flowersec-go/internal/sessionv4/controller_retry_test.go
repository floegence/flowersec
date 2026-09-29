package sessionv4

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func TestControllerCandidateCloseCancelsInitializer(t *testing.T) {
	sessionEstablishmentDuplex(t, "preauthorized_pool", true, false, false, false, true, false, false, false, true, false, false, true)
}

func TestControllerCandidateExpiryCancelsInitializer(t *testing.T) {
	sessionEstablishmentDuplex(t, "preauthorized_pool", true, false, false, false, true, false, false, false, true, false, false, false, true)
}

func TestControllerCompletionTailCannotPublishAfterCancellation(t *testing.T) {
	sessionEstablishmentDuplex(t, "preauthorized_pool", true, false, false, false, true, false, false, false, true, false, false, false, false, true)
}

func TestControllerSourceRetryNotBeforeAndAttemptLimit(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	now, err := f.trust.clock.Sample()
	if err != nil {
		t.Fatal(err)
	}
	failure, err := NewControllerSourceError(io.EOF, now.UpperMS+1000)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 2000, DrainTimeoutMS: 1000, RuntimeBytes: 65536, MaximumAttempts: 2,
		Source: controllerSourceFunc(func(_ context.Context, request ControllerRequest) (*ControllerPreparation, error) {
			if request.Attempt != uint64(calls.Add(1)) {
				t.Error("attempt ordinal changed")
			}
			return nil, failure
		})})
	if err := c.RetryNow(context.Background()); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("idle retry acquired", err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingRetry && !s.Pending })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal("Start is not idempotent", err)
	}
	if err := c.RetryNow(context.Background()); !errors.Is(err, timev4.ErrPending) {
		t.Fatal("source not-before bypassed", err)
	}
	wait, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.WaitForSession(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("retrying wait returned old failure", err)
	}
	if calls.Load() != 1 {
		t.Fatal("extra acquire before not-before", calls.Load())
	}
	f.trust.tick.Add(1100)
	waitController(t, c, func(s ControllerSnapshot) bool { return s.Attempts == 2 && !s.Pending && !s.WaitingRetry })
	if _, err := c.WaitForSession(context.Background()); !errors.Is(err, failure) {
		t.Fatal("terminal source error lost", err)
	}
	if err := c.RetryNow(context.Background()); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("attempt limit bypassed", err)
	}
	if calls.Load() != 2 {
		t.Fatal(calls.Load())
	}
	if c.CleanupStatus().Status != protocolv4.V4CleanupStatePending {
		t.Fatal(c.CleanupStatus())
	}
}

func TestControllerRetryNowWakesOnlyOriginalBackoff(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	failure, _ := NewControllerSourceError(io.EOF, 0)
	var calls atomic.Int32
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
		Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
			if calls.Add(1) == 1 {
				return nil, failure
			}
			return nil, cryptov4.ErrConfiguration
		})})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingRetry && !s.Pending })
	if err := c.RetryNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitController(t, c, func(s ControllerSnapshot) bool { return s.Attempts == 2 && !s.Pending })
	if calls.Load() != 2 || c.Snapshot().WaitingRetry {
		t.Fatal(calls.Load(), c.Snapshot())
	}
}

func TestControllerCompletedDispatchKeepsOnlyIdentity(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	e := environmentTestOwner(t, f, 248, 1)
	c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 1000, DrainTimeoutMS: 1000, RuntimeBytes: 65536,
		Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
			return nil, cryptov4.ErrConfiguration
		})})
	borrow, err := c.reservation.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.dispatches++
	c.mu.Unlock()
	o := &UnaryOperation{controller: controllerDispatch{controller: c, identity: c.identity, borrow: borrow}, started: true, failure: io.EOF}
	o.controller.release()
	if o.controller.controller != nil || o.controller.session != nil {
		t.Fatal("detached operation retained owner graph")
	}
	if got := c.Dispatch(context.Background(), o); got.Error != io.EOF {
		t.Fatal(got)
	}
	c.Close()
	if err := c.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.CleanupStatus().Status != protocolv4.V4CleanupStateComplete {
		t.Fatal(c.CleanupStatus())
	}
}

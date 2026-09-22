package sessionv4

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func autoLiveness(t *testing.T, e *openEndpoint, threshold uint32) *Liveness {
	t.Helper()
	p, err := newTestAutomaticLiveness(t, e, make([]ProbeSlot, 8), AutomaticLivenessPolicy{IntervalMS: 30, SubmissionMS: 5, ResponseMS: 10, MissThreshold: threshold})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func nextAuto(t *testing.T, p *Liveness, now *atomic.Uint64) *Probe {
	t.Helper()
	if o, ms, err := p.automaticStep(); err != nil || o != nil || ms != 30 {
		t.Fatal("interval not preserved", o, ms, err)
	}
	now.Add(30)
	o, ms, err := p.automaticStep()
	if err != nil || o == nil || ms != 15 {
		t.Fatal("automatic admission", o, ms, err)
	}
	return o
}

func TestAutomaticLivenessExplicitPolicyAndProtectedSlot(t *testing.T) {
	e, _, now := idleEndpoints(t, 0)
	p := testLiveness(t, e, 8)
	if enabled, misses, err := p.AutomaticStatus(); enabled || misses != 0 || err != nil {
		t.Fatal(enabled, misses, err)
	}
	if err := p.RunAutomatic(context.Background()); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("implicit automatic policy", err)
	}
	e, _, now = idleEndpoints(t, 0)
	for _, policy := range []AutomaticLivenessPolicy{{}, {IntervalMS: 1, SubmissionMS: math.MaxUint64, ResponseMS: 1, MissThreshold: 1}} {
		if _, err := newTestAutomaticLiveness(t, e, make([]ProbeSlot, 8), policy); !errors.Is(err, cryptov4.ErrConfiguration) {
			t.Fatal("invalid policy", err)
		}
	}
	p = autoLiveness(t, e, 3)
	for range 7 {
		testProbe(t, p, 500)
	}
	if _, err := p.Begin(500); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("manual caller took automatic slot", err)
	}
	o := nextAuto(t, p, now)
	if !o.automatic || o.slot != 7 {
		t.Fatal("automatic sample did not use protected slot")
	}
}

func TestAutomaticLivenessOnlyQualifiedMissesCloseOriginalSession(t *testing.T) {
	client, server, now := idleEndpoints(t, 0)
	p := autoLiveness(t, client, 3)
	for attempt := uint32(1); attempt <= 3; attempt++ {
		o := nextAuto(t, p, now)
		if _, err := o.Publish(context.Background()); err != nil {
			t.Fatal(err)
		}
		nonce := receivePing(t, client, server)
		nonce[0]++
		if pong(t, server, client, p, nonce) {
			t.Fatal("unmatched PONG counted as success")
		}
		now.Add(15)
		_, _, err := p.automaticStep()
		if attempt < 3 && err != nil || attempt == 3 && !errors.Is(err, ErrLivenessPathUnresponsive) {
			t.Fatal(attempt, err)
		}
		_, misses, cause := p.AutomaticStatus()
		if misses != attempt || attempt < 3 && cause != nil || attempt == 3 && !errors.Is(cause, ErrLivenessPathUnresponsive) {
			t.Fatal(attempt, misses, cause)
		}
	}
	select {
	case <-client.engine.Done():
	default:
		t.Fatal("threshold did not close original Session")
	}
}

func TestAutomaticLivenessLocalOutcomesDoNotBecomeMisses(t *testing.T) {
	for _, mode := range []string{"unpublished", "late_handoff", "cancel", "stall", "rekey", "provider_error"} {
		t.Run(mode, func(t *testing.T) {
			client, _, now := idleEndpoints(t, 0)
			p := autoLiveness(t, client, 1)
			o := nextAuto(t, p, now)
			if mode != "unpublished" {
				client.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
					if mode == "late_handoff" {
						now.Add(6)
					}
					if mode == "provider_error" {
						return len(b), errors.New("provider failed")
					}
					return len(b), nil
				})
				_, err := o.Publish(context.Background())
				if (err != nil) != (mode == "provider_error") {
					t.Fatal(err)
				}
			}
			switch mode {
			case "cancel":
				o.Cancel()
			case "stall":
				stall, err := p.BeginLocalStall(LocalReadStall)
				if err != nil {
					t.Fatal(err)
				}
				stall.End()
			case "rekey":
				x := exchange(t, client)
				x.cancelBeforeInit()
			}
			now.Add(20)
			_, _, _ = p.automaticStep()
			if _, misses, cause := p.AutomaticStatus(); misses != 0 || cause != nil {
				t.Fatal("local failure became path failure", misses, cause)
			}
		})
	}
}

func TestAutomaticSuccessAndRekeyResetMisses(t *testing.T) {
	client, server, now := idleEndpoints(t, 0)
	p := autoLiveness(t, client, 3)
	o := nextAuto(t, p, now)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	receivePing(t, client, server)
	now.Add(15)
	if _, _, err := p.automaticStep(); err != nil {
		t.Fatal(err)
	}
	// Manual success cannot erase an automatic miss.
	manual := testProbe(t, p, 500)
	if _, err := manual.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !pong(t, server, client, p, receivePing(t, client, server)) {
		t.Fatal("manual match")
	}
	if _, misses, _ := p.AutomaticStatus(); misses != 1 {
		t.Fatal("manual success reset automatic misses", misses)
	}
	o = nextAuto(t, p, now)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !pong(t, server, client, p, receivePing(t, client, server)) {
		t.Fatal("automatic match")
	}
	if _, misses, _ := p.AutomaticStatus(); misses != 0 {
		t.Fatal("automatic success did not reset", misses)
	}
	o = nextAuto(t, p, now)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	receivePing(t, client, server)
	now.Add(15)
	if _, _, err := p.automaticStep(); err != nil {
		t.Fatal(err)
	}
	// Safe pre-INIT cancellation does not invent a successful rekey.
	cancelled := exchange(t, client)
	cancelled.cancelBeforeInit()
	if _, misses, _ := p.AutomaticStatus(); misses != 1 {
		t.Fatal("cancelled rekey reset misses", misses)
	}
	c, err := NewRekeyExchange(client.admission, cancelled.barriers, client.maintenance, rekeyTestDeadline(t, client.engine), RekeyPhaseBudgets{5000, 10000, 30000})
	if err != nil {
		t.Fatal(err)
	}
	s := exchange(t, server)
	if _, err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	exchangeProgress(t, c)
	exchangeFlight(t, client, server, s)
	exchangeProgress(t, s)
	exchangeFlight(t, server, client, c)
	if _, misses, _ := p.AutomaticStatus(); misses != 0 {
		t.Fatal("actual completed rekey did not reset", misses)
	}
}

func TestAutomaticRetainsBlockedTailAndOriginalStallOwners(t *testing.T) {
	client, _, now := idleEndpoints(t, 0)
	p := autoLiveness(t, client, 1)
	o := nextAuto(t, p, now)
	entered, release := make(chan struct{}), make(chan struct{})
	client.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return len(b), nil
	})
	done := make(chan error, 1)
	go func() { _, err := o.Publish(context.Background()); done <- err }()
	<-entered
	now.Add(100)
	if sample, ms, err := p.automaticStep(); sample != nil || ms != 0 || err != nil {
		t.Fatal("blocked tail was replaced", sample, ms, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, misses, _ := p.AutomaticStatus(); misses != 0 {
		t.Fatal("late complete tail revived expired sample", misses)
	}
	old, _ := p.BeginLocalStall(LocalResourceStall)
	old.End()
	current, _ := p.BeginLocalStall(LocalResourceStall)
	old.End()
	if sample, ms, err := p.automaticStep(); sample != nil || ms != 0 || err != nil {
		t.Fatal("stale stall clear reopened scheduler", sample, ms, err)
	}
	current.End()
	nextAuto(t, p, now)
}

func TestAutomaticWorkerClosesOnlyForQualifiedMiss(t *testing.T) {
	e := newOpenEndpoint(t, 0, 2, 2, 1)
	p, err := newTestAutomaticLiveness(t, e, make([]ProbeSlot, 1), AutomaticLivenessPolicy{IntervalMS: 10, SubmissionMS: 100, ResponseMS: 20, MissThreshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := p.RunAutomatic(ctx); !errors.Is(err, ErrLivenessPathUnresponsive) {
		t.Fatal("automatic worker", err)
	}
	if _, err := e.engine.ScopeFrontier(0, 0); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("Session still live", err)
	}
}

func TestAutomaticClockContinuityLossIsNotAMiss(t *testing.T) {
	e, _, now := idleEndpoints(t, 0)
	p := autoLiveness(t, e, 1)
	o := nextAuto(t, p, now)
	if _, err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	now.Store(1) // Original monotonic continuity is lost.
	if result, terminal := o.Result(); !terminal || !errors.Is(result.Cause, timev4.ErrContinuity) || result.ElapsedAvailable {
		t.Fatal(result, terminal)
	}
	if _, misses, cause := p.AutomaticStatus(); misses != 0 || cause != nil {
		t.Fatal(misses, cause)
	}
}

func TestAutomaticCancellationRetainsRealWorkerUntilProviderExit(t *testing.T) {
	e := newOpenEndpoint(t, 0, 2, 2, 1)
	p, err := newTestAutomaticLiveness(t, e, make([]ProbeSlot, 1), AutomaticLivenessPolicy{IntervalMS: 5, SubmissionMS: 100, ResponseMS: 20, MissThreshold: 1})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	e.maintenance.writer = idleWriterFunc(func(b []byte) (int, error) {
		close(entered)
		<-release
		return len(b), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.RunAutomatic(ctx) }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	wait, stop := context.WithCancel(context.Background())
	stop()
	if err := p.WaitAutomaticCleanup(wait); !errors.Is(err, context.Canceled) {
		t.Fatal("scheduler exit claimed provider cleanup", err)
	}
	if err := p.RunAutomatic(context.Background()); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("second scheduler replaced blocked worker", err)
	}
	close(release)
	if err := p.WaitAutomaticCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.slots[0].owner != nil {
		t.Fatal("worker exit retained original probe slot")
	}
	if _, misses, cause := p.AutomaticStatus(); misses != 0 || cause != nil {
		t.Fatal("policy cancellation became path failure", misses, cause)
	}
	if _, err := e.engine.ScopeFrontier(0, 0); err != nil {
		t.Fatal("policy cancellation closed Session", err)
	}
}

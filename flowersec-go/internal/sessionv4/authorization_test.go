package sessionv4

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// Synthetic authority for isolated transport tests only; it is never an SDK
// default and does not authenticate a deployment.
type testAuthorization struct{}

func (testAuthorization) Check() error                 { return nil }
func (testAuthorization) RemainingMS() (uint64, error) { return ^uint64(0), nil }
func (testAuthorization) Wake() <-chan struct{}        { return nil }
func (testAuthorization) Notify()                      {}
func (testAuthorization) Close(error)                  {}

type revocableAuthorization struct {
	rejected atomic.Bool
	wake     chan struct{}
}

var errAuthorizationRejected = errors.New("original trust rejected")

func (g *revocableAuthorization) Check() error {
	if g.rejected.Load() {
		return errAuthorizationRejected
	}
	return nil
}
func (g *revocableAuthorization) RemainingMS() (uint64, error) { return ^uint64(0), g.Check() }
func (g *revocableAuthorization) Wake() <-chan struct{}        { return g.wake }
func (g *revocableAuthorization) Notify() {
	select {
	case g.wake <- struct{}{}:
	default:
	}
}
func (g *revocableAuthorization) Close(error) { g.rejected.Store(true) }

type deadlineAuthorization struct{ *timev4.Deadline }

func (deadlineAuthorization) Wake() <-chan struct{} { return nil }
func (deadlineAuthorization) Notify()               {}
func (d deadlineAuthorization) Close(error)         { d.Cancel() }

func TestInitialExchangeAuthorizationRecheckedAfterBuild(t *testing.T) {
	stream := &initialMemoryStream{}
	config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
	config.Authorization = nil
	if _, err := NewInitialStream(context.Background(), config, stream); !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal("missing authorization accepted", err)
	}
	guard := &revocableAuthorization{}
	config.Authorization = guard
	x, err := NewInitialStream(context.Background(), config, stream)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	wire := initialFixture(t, "client_hello_fields")
	result, err := x.Send(protocolv4.FrameNegotiate, func(dst []byte) (int, error) {
		guard.rejected.Store(true)
		return copy(dst, wire), nil
	})
	if !errors.Is(err, errAuthorizationRejected) || result.Submitted || result.Complete {
		t.Fatal("built flight published after revocation", result, err)
	}
	guard.rejected.Store(false)
	if _, err := x.Send(protocolv4.FrameNegotiate, initialCopy(wire)); !errors.Is(err, errAuthorizationRejected) {
		t.Fatal("failed connection revived", err)
	}
}

func TestAuthorizationWatchdogExpiresWithIdleDisabled(t *testing.T) {
	clock := sessionTestClock(t)
	deadline, err := timev4.NewAge(clock, 300, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	e := newOpenEndpointAuthorization(t, protocolv4.ClientToServer, 2, 2, 1, clock, 0, deadlineAuthorization{deadline})
	w, err := NewIdleWatchdog(e.admission)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.Run(ctx); !errors.Is(err, timev4.ErrExpired) {
		t.Fatal("silent expired authorization retained", err)
	}
	select {
	case <-e.engine.Done():
	default:
		t.Fatal("expired Session engine retained")
	}
}

func TestInitialAuthorizationWatchdogClosesSilentCarrier(t *testing.T) {
	config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
	deadline, err := timev4.NewAge(sessionTestClock(t), 300, ^uint64(0))
	if err != nil {
		t.Fatal(err)
	}
	config.Authorization = deadlineAuthorization{deadline}
	stream := &initialMemoryStream{}
	x, err := NewInitialStream(context.Background(), config, stream)
	if err != nil {
		t.Fatal(err)
	}
	cleanupInitial(t, x)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := x.WaitCleanup(ctx); err != nil {
		t.Fatal("silent initial owner retained", err)
	}
	if !stream.closed.Load() {
		t.Fatal("expired carrier retained")
	}
}

func TestAuthorizationChangeWakesSilentInitialAndSessionOwners(t *testing.T) {
	for _, initial := range []bool{false, true} {
		guard := &revocableAuthorization{wake: make(chan struct{}, 1)}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if initial {
			config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
			config.Authorization = guard
			stream := &initialMemoryStream{}
			x, err := NewInitialStream(context.Background(), config, stream)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			cleanupInitial(t, x)
			guard.rejected.Store(true)
			guard.wake <- struct{}{}
			if err := x.WaitCleanup(ctx); err != nil {
				cancel()
				t.Fatal("silent carrier ignored trust event", err)
			}
		} else {
			e := newOpenEndpointAuthorization(t, protocolv4.ClientToServer, 2, 2, 1, sessionTestClock(t), 0, guard)
			w, err := NewIdleWatchdog(e.admission)
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- w.Run(ctx) }()
			guard.rejected.Store(true)
			guard.wake <- struct{}{}
			if err := <-done; !errors.Is(err, errAuthorizationRejected) {
				cancel()
				t.Fatal("silent Session ignored trust event", err)
			}
			select {
			case <-e.engine.Done():
			default:
				t.Fatal("revoked engine remained active")
			}
		}
		cancel()
	}
}

// Hold the old watchdog between its last authorization check and receive.
// This forces it to consume the final notification after ownership transfers.
type handoffAuthorization struct {
	revocableAuthorization
	checked, resume chan struct{}
}

func (g *handoffAuthorization) RemainingMS() (uint64, error) {
	err := g.Check()
	close(g.checked)
	<-g.resume
	return ^uint64(0), err
}

func TestInitialWatchdogForwardsConsumedNotificationAfterHandoff(t *testing.T) {
	guard := &handoffAuthorization{
		revocableAuthorization: revocableAuthorization{wake: make(chan struct{}, 1)},
		checked:                make(chan struct{}), resume: make(chan struct{}),
	}
	config := initialTestConfig(t, 0, protocolv4.DHProfileX25519)
	config.Authorization = guard
	stream := &initialMemoryStream{}
	x, err := NewInitialStream(context.Background(), config, stream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	defer x.cancel(nil)
	select {
	case <-guard.checked:
	case <-ctx.Done():
		close(guard.resume)
		x.Close(ctx.Err())
		t.Fatal("old watchdog did not reach authorization check")
	}
	x.mu.Lock()
	x.transferred = true
	x.mu.Unlock()
	guard.rejected.Store(true)
	guard.Notify()
	// Leave cancellation pending to select the notification receive schedule.
	close(guard.resume)
	if err := x.WaitCleanup(ctx); err != nil {
		t.Fatal("old watchdog did not exit", err)
	}
	select {
	case <-guard.Wake():
		if err := guard.Check(); !errors.Is(err, errAuthorizationRejected) {
			t.Fatal("handoff did not retain current revocation", err)
		}
	default:
		t.Fatal("old watchdog consumed the new Session's only notification")
	}
	if stream.closed.Load() {
		t.Fatal("old watchdog closed the transferred carrier")
	}
}

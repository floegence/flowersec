package sessionv4

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestCandidateTransportFailureCannotHideIndependentRefusal(t *testing.T) {
	for _, refusal := range []error{nil, cryptov4.ErrConfiguration, io.EOF} {
		f := raceMaterialFixture(t, "preauthorized_pool", []uint64{0, 1}, nil)
		p, s, lease := admittedTestRace(t, f, carrierFactoryFunc(func(_ context.Context, r CarrierPreparationRequest) (*PreparedCarrier, error) {
			if r.Config.Candidate.Index == 0 && r.AddressAttempt == 0 && refusal != nil {
				return nil, refusal
			}
			return nil, native.ErrConnectionLost
		}))
		p.config.ParallelCandidates = 1
		prepared, _, err := p.race.prepare()
		if prepared != nil || err == nil {
			t.Fatal("failed candidates accepted")
		}
		s.mu.Lock()
		retry := s.controllerTransportFailure
		s.mu.Unlock()
		if retry != (refusal == nil) {
			t.Fatal("prior refusal lost", refusal, retry)
		}
		if lease.claimed {
			t.Fatal("preparation consumed credential")
		}
	}
}

func TestControllerTransportRetryWaitsForOriginalPreparationCleanup(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	unused.Close()
	e := environmentTestOwner(t, f, 248, 1)
	provider := &preparedTestProvider{environment: f.environment, waitEntered: make(chan struct{}), waitRelease: make(chan struct{})}
	release := sync.OnceFunc(func() { close(provider.waitRelease) })
	defer release()
	config := sourceConnectTestConfig(t, f, identity, immediateMaterialProvider{lease}, carrierFactoryFunc(func(ctx context.Context, r CarrierPreparationRequest) (*PreparedCarrier, error) {
		if r.AddressAttempt != 0 {
			return nil, native.ErrAddressesExhausted
		}
		p, err := NewPreparedMessages(ctx, r.Config, provider)
		if err != nil {
			return nil, err
		}
		return p, native.ErrConnectionLost
	}))
	_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		var calls atomic.Int32
		c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 5000, DrainTimeoutMS: 1000, RuntimeBytes: 65536, MaximumAttempts: 2,
			Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
				if calls.Add(1) > 1 {
					return nil, cryptov4.ErrConfiguration
				}
				return &ControllerPreparation{Config: config, Pool: &PoolSessionInput{Store: store, Authority: authority, Consume: work}}, nil
			})})
		defer func() {
			c.Close()
			wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.WaitCleanup(wait); err != nil {
				t.Error(err)
			}
		}()
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitRaceSignal(t, provider.waitEntered)
		if calls.Load() != 1 || c.Snapshot().WaitingRetry {
			t.Fatal("cleanup tail started another attempt", c.Snapshot(), calls.Load())
		}
		if err := c.RetryNow(context.Background()); err != ErrControllerBusy {
			t.Fatal("cleanup bypassed", err)
		}
		release()
		waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingRetry || s.LastError != nil && !s.Pending })
		if !c.Snapshot().WaitingRetry {
			t.Fatal("original transport failure did not schedule retry", c.Snapshot())
		}
		if provider.retires.Load() != 1 || lease.claimed {
			t.Fatal("unretired or consumed preparation", provider.retires.Load(), lease.claimed)
		}
		if err := c.RetryNow(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitController(t, c, func(s ControllerSnapshot) bool { return s.Attempts == 2 && !s.Pending && !s.WaitingRetry })
		if calls.Load() != 2 {
			t.Fatal("attempt bound lost", calls.Load())
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestControllerFailureCapturePreservesFirstTerminalAndInitializerFence(t *testing.T) {
	for _, kind := range []string{"network", "canceled", "protocol", "initializer", "finished"} {
		t.Run(kind, func(t *testing.T) {
			s := newEnvironmentSession(nil, 0, context.Background())
			if kind == "canceled" {
				s.closeWith(context.Canceled)
			}
			if kind == "protocol" {
				s.closeWith(ErrInitialPhase)
			}
			s.closeWithSource(native.ErrConnectionLost, true)
			a := &controllerAttempt{candidate: s, done: make(chan struct{}), entered: kind == "initializer"}
			c := &ConnectionController{attempt: a, changed: make(chan struct{}), wake: make(chan struct{}, 1)}
			if kind == "finished" {
				c.finishLocked(a, context.Canceled)
			}
			c.captureAttemptFailure(a, native.ErrConnectionLost)
			if a.transportFailure != (kind == "network") {
				t.Fatal("late failure changed retry decision", kind, a.transportFailure)
			}
			if kind == "network" {
				c.finishLocked(a, context.Canceled)
				if a.transportFailure {
					t.Fatal("local cancellation retained retry")
				}
			}
		})
	}
}

type failedInitialProvider struct{ *preparedTestProvider }

func (*failedInitialProvider) Write([]byte) (int, error) { return 0, native.ErrConnectionLost }
func (*failedInitialProvider) Read([]byte) (int, error)  { return 0, native.ErrConnectionLost }

func TestControllerInitialTransportFailureAfterSpendDoesNotReuseMaterial(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	f.config.Core.MessageCarrier = false
	unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	unused.Close()
	e := environmentTestOwner(t, f, 248, 1)
	var acquisitions atomic.Int32
	config := sourceConnectTestConfig(t, f, identity, materialProviderFunc(func(context.Context, MaterialLeaseRequest) (*ArtifactLease, error) {
		acquisitions.Add(1)
		return lease, nil
	}), carrierFactoryFunc(func(ctx context.Context, r CarrierPreparationRequest) (*PreparedCarrier, error) {
		return NewPreparedStream(ctx, r.Config, &failedInitialProvider{&preparedTestProvider{environment: f.environment}})
	}))
	_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		var recipes atomic.Int32
		c := controllerForTest(t, f, e, ControllerConfig{Clock: f.trust.clock, SourceIncarnation: [16]byte{1}, AttemptTimeoutMS: 5000, DrainTimeoutMS: 1000, RuntimeBytes: 65536, MaximumAttempts: 2,
			Source: controllerSourceFunc(func(context.Context, ControllerRequest) (*ControllerPreparation, error) {
				if recipes.Add(1) > 1 {
					return nil, cryptov4.ErrConfiguration
				}
				return &ControllerPreparation{Config: config, Pool: &PoolSessionInput{Store: store, Authority: authority, Consume: work}}, nil
			})})
		defer func() {
			c.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.WaitCleanup(cleanup); err != nil {
				t.Error(err)
			}
		}()
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitController(t, c, func(s ControllerSnapshot) bool { return s.WaitingRetry || s.LastError != nil && !s.Pending })
		if !c.Snapshot().WaitingRetry {
			t.Fatal("handshake interruption lost", c.Snapshot())
		}
		lease.mu.Lock()
		claimed := lease.claimed
		lease.mu.Unlock()
		if !claimed || acquisitions.Load() != 1 {
			t.Fatal("missing actual original spend", claimed, acquisitions.Load())
		}
		if err := c.RetryNow(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitController(t, c, func(s ControllerSnapshot) bool { return s.Attempts == 2 && !s.Pending && !s.WaitingRetry })
		if acquisitions.Load() != 1 || recipes.Load() != 2 {
			t.Fatal("spent material replayed", acquisitions.Load(), recipes.Load())
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

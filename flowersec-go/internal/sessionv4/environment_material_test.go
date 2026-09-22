package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func materialEnvironment(t *testing.T, f *materialBytesFixture) *Environment {
	t.Helper()
	config := EnvironmentConfig{Positions: 2, Materials: 1, MaterialCreateMS: 100, Clock: f.admissionIntegrationFixture.trust.clock, RuntimeBytes: 65536}
	cost, err := EnvironmentCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvironment(config, f.reserve(cost), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := e.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := e.Retire(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func unusedMaterial(t *testing.T, f *materialBytesFixture) *ConnectionMaterial {
	t.Helper()
	l, err := f.lease(t)
	if err != nil {
		t.Fatal(err)
	}
	i, err := f.identity(t, protocolv4.ClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	cost, _ := ConnectionMaterialCharge(8192)
	m, err := NewConnectionMaterial(l, i, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, 8192, f.reserve(cost))
	if err != nil {
		t.Fatal(err)
	}
	i.Close()
	l.Close()
	t.Cleanup(m.Close)
	return m
}

func waitMaterialPositions(t *testing.T, e *Environment, active uint32) {
	t.Helper()
	end := time.NewTimer(time.Second)
	defer end.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		e.mu.Lock()
		current := e.materialActive
		e.mu.Unlock()
		if current == active {
			return
		}
		select {
		case <-end.C:
			t.Fatal("material position did not settle", current)
		case <-tick.C:
		}
	}
}

func TestEnvironmentMaterialExpiryAndDetachedCreationContext(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) {
			f := newMaterialBytesFixture(t, source)
			e := materialEnvironment(t, f)
			m := unusedMaterial(t, f)
			i, l := m.identity.identity, m.lease.lease
			ctx, cancel := context.WithCancel(context.Background())
			result, err := e.CreateMaterial(ctx, func(context.Context) (*ConnectionMaterial, error) { return m, nil })
			if err != nil || result != m {
				t.Fatal(result, err)
			}
			cancel()
			if err := m.check(); err != nil {
				t.Fatal("wait context still owns delivered material", err)
			}
			called := false
			_, err = e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { called = true; return nil, nil })
			if err != cryptov4.ErrCapacity || called {
				t.Fatal("material capacity checked after factory work", err)
			}
			f.admissionIntegrationFixture.trust.tick.Add(300)
			e.signalMaterials()
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := m.WaitCleanup(cleanup); err != nil {
				t.Fatal(err)
			}
			if err := i.WaitCleanup(cleanup); err != nil {
				t.Fatal(err)
			}
			if err := l.WaitCleanup(cleanup); err != nil {
				t.Fatal(err)
			}
			waitMaterialPositions(t, e, 0)
			if _, err := m.identity.identity.capture(f.environment); err == nil {
				t.Fatal("expired material regained identity")
			}
		})
	}
}

func TestEnvironmentMaterialKeepsCanceledOrAbnormalFactoryTail(t *testing.T) {
	for _, mode := range []string{"caller", "environment", "window", "panic", "goexit", "error_with_result"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialBytesFixture(t, "preauthorized_pool")
			e := materialEnvironment(t, f)
			m := unusedMaterial(t, f)
			entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var got *ConnectionMaterial
			var failure error
			go func() {
				defer close(exited)
				got, failure = e.CreateMaterial(ctx, func(call context.Context) (*ConnectionMaterial, error) {
					defer func() { close(entered); <-release }()
					if mode == "panic" {
						panic("constructor panic")
					}
					if mode == "goexit" {
						runtime.Goexit()
					}
					if mode == "error_with_result" {
						return m, errors.New("constructor failed")
					}
					return m, nil
				})
			}()
			<-entered
			switch mode {
			case "caller":
				cancel()
			case "environment":
				e.Close()
			case "window":
				f.admissionIntegrationFixture.trust.tick.Add(150)
				e.signalMaterials()
			}
			e.mu.Lock()
			active := e.materialActive
			cleaned := e.cleaned
			e.mu.Unlock()
			if active != 1 || cleaned {
				t.Fatal("factory defer was not retained")
			}
			close(release)
			<-exited
			if got != nil || mode != "goexit" && failure == nil {
				t.Fatal("failed or expired creation published", got, failure)
			}
			waitMaterialPositions(t, e, 0)
			if mode != "panic" && mode != "goexit" {
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := m.WaitCleanup(cleanup); err != nil {
					t.Fatal("late owned material not physically closed", err)
				}
			}
		})
	}
}

func TestEnvironmentMaterialRejectsDuplicateOwnershipWithoutClosingOriginal(t *testing.T) {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	e, other := materialEnvironment(t, f), materialEnvironment(t, f)
	m := unusedMaterial(t, f)
	if _, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := other.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != cryptov4.ErrTransition {
		t.Fatal("original owner replaced", err)
	}
	other.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := other.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.check(); err != nil {
		t.Fatal("rejected wrapper closed original material", err)
	}
	m.Close()
	waitMaterialPositions(t, e, 0)
}

func TestEnvironmentMaterialClockFailureClosesUnusedSnapshot(t *testing.T) {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	e := materialEnvironment(t, f)
	m := unusedMaterial(t, f)
	if _, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != nil {
		t.Fatal(err)
	}
	f.admissionIntegrationFixture.trust.clock.Close()
	e.signalMaterials()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.check(); err == nil || errors.Is(err, timev4.ErrPending) {
		t.Fatal("lost continuity returned new-use authority", err)
	}
}

func TestEnvironmentMaterialRetainsOriginalEstablishmentAfterExpiry(t *testing.T) {
	f := newMaterialBytesFixture(t, "preauthorized_pool")
	e := materialEnvironment(t, f)
	m := unusedMaterial(t, f)
	if _, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != nil {
		t.Fatal(err)
	}
	limits := EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	cost, err := EstablishmentCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	p, subscriptions, err := m.Establishment(InitialHello{Index: 0, Attempt: f.admissionIntegrationFixture.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2}, limits, MaterialGeneration{Source: [16]byte{1}, Generation: 1}, f.reserve(cost), f.reserve(protocolv4.CredentialSubscriptionsCharge()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		subscriptions.Close()
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
	f.admissionIntegrationFixture.trust.tick.Add(300)
	e.signalMaterials()
	e.Close()
	wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := e.WaitCleanup(wait); err == nil {
		t.Fatal("material charge returned before original establishment")
	}
	select {
	case <-m.done:
		t.Fatal("material erased actual captured key responsibility")
	default:
	}
	subscriptions.Close()
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := e.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	if err := m.WaitCleanup(cleanup); err != nil {
		t.Fatal(err)
	}
	waitMaterialPositions(t, e, 0)
}

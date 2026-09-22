package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type carrierFactoryFunc func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error)

func (f carrierFactoryFunc) PrepareCarrier(ctx context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
	return f(ctx, request)
}

type materialProviderFunc func(context.Context, MaterialLeaseRequest) (*ArtifactLease, error)

func (f materialProviderFunc) AcquireLease(ctx context.Context, request MaterialLeaseRequest) (*ArtifactLease, error) {
	return f(ctx, request)
}

func sourceConnectTestConfig(t *testing.T, f *admissionIntegrationFixture, identity *ApplicationIdentity, provider MaterialLeaseProvider, carrier ConsumerCarrierFactory) SourceConnectConfig {
	t.Helper()
	c := SourceConnectConfig{Identity: identity, Generation: MaterialGeneration{Source: [16]byte{1}, Generation: 1},
		Requirements: MaterialRequirements{ApplicationProfile: "transport"}, Provider: provider, Carrier: carrier,
		Hello:     InitialHello{Index: 0, Attempt: f.trust.attempt, Policy: protocolv4.HelloPolicy{BindingMode: 1}, BindingModes: 2},
		Limits:    EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536},
		Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Dependencies: f.environment,
		AttemptBudget: CarrierAttemptBudget{PreauthBytes: 131072, WorkUnits: 128}, Scope: f.scope, RuntimeBytes: 8192, MaterialRuntimeBytes: 8192, CarrierRuntimeBytes: 8192}
	reserve := func(n uint32, cost resourcev4.Vector, err error) resourcev4.Reference {
		if err != nil {
			t.Fatal(err)
		}
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, n), cost)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	charge, err := SourcePreparationCharge(c)
	c.Preparation = reserve(301, charge, err)
	charge, err = MaterialAcquisitionCharge(c.RuntimeBytes)
	c.Acquisition = reserve(302, charge, err)
	charge, err = ConnectionMaterialCharge(c.MaterialRuntimeBytes)
	c.Material = reserve(303, charge, err)
	charge, err = EstablishmentCharge(c.Limits)
	c.Establishment = reserve(304, charge, err)
	c.Subscriptions = reserve(305, protocolv4.CredentialSubscriptionsCharge(), nil)
	charge, err = PreparedCarrierCharge(c.CarrierRuntimeBytes)
	c.CarrierReservation = reserve(306, charge, err)
	return c
}

func TestEnvironmentSourceAcquisitionToDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true) })
	}
}

func TestEnvironmentSourceBlockedAcquisitionRetainsPosition(t *testing.T) {
	for _, stop := range []string{"caller", "environment", "deadline", "dependency"} {
		t.Run(stop, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			unused.Close()
			host := environmentTestOwner(t, f, 248, 1)
			provider := &blockedMaterialProvider{lease: lease, entered: make(chan MaterialLeaseRequest, 1), release: make(chan struct{})}
			defer func() {
				select {
				case <-provider.release:
				default:
					close(provider.release)
				}
			}()
			c := sourceConnectTestConfig(t, f, identity, provider, carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
				return nil, errors.New("carrier must not be called after canceled acquisition")
			}))
			if stop == "dependency" {
				var err error
				c.Dependencies, err = f.root.Reserve(admissionResourceKey(f.owner, 307), resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Dependencies.Release)
			}
			_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				input := PoolSessionInput{Store: store, Authority: authority, Consume: work}
				unavailable := c
				unavailable.Requirements = MaterialRequirements{ApplicationProfile: "services", RPCMaxGeneralOutstanding: 32}
				initial := f.root.Snapshot()
				if _, err := host.ConnectSourcePool(ctx, unavailable, input); !errors.Is(err, ErrConnectionRequirementUnavailable) || provider.calls.Load() != 0 || f.root.Snapshot() != initial {
					t.Fatal("known unavailable profile contacted issuer or consumed inputs", err)
				}
				result := make(chan error, 1)
				go func() { _, err := host.ConnectSourcePool(ctx, c, input); result <- err }()
				select {
				case <-provider.entered:
				case err := <-result:
					t.Fatal("source was not acquired", err)
				case <-time.After(3 * time.Second):
					t.Fatal("source acquisition did not start")
				}
				identity.Close()
				before := f.root.Snapshot()
				if _, err := host.ConnectSourcePool(ctx, c, input); !errors.Is(err, cryptov4.ErrCapacity) || provider.calls.Load() != 1 {
					t.Fatal("second source invocation escaped original cap", err)
				}
				switch stop {
				case "caller":
					cancel()
				case "environment":
					host.Close()
				case "deadline":
					f.trust.tick.Add(10000)
				case "dependency":
					c.Dependencies.Seal()
				}
				select {
				case err := <-result:
					if err == nil || stop == "deadline" && !errors.Is(err, timev4.ErrExpired) {
						t.Fatal("incorrect local closure result", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("blocked provider prevented original cancellation")
				}
				host.Close()
				wait, cancelWait := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancelWait()
				if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("blocked issuer asserted cleanup", err)
				}
				if f.root.Snapshot() != before {
					t.Fatal("blocked issuer/captured key refunded")
				}
				close(provider.release)
				wait, done := context.WithTimeout(context.Background(), 3*time.Second)
				defer done()
				if err := host.WaitCleanup(wait); err != nil {
					t.Fatal(err)
				}
				if err := identity.WaitCleanup(wait); err != nil {
					t.Fatal("original identity still retained", err)
				}
				if err := lease.WaitCleanup(wait); err != nil {
					t.Fatal("late lease still retained", err)
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnvironmentSourceProviderTaskExitCleansCapture(t *testing.T) {
	for _, failure := range []struct {
		name string
		call func()
	}{{"panic", func() { panic("private source detail") }}, {"goexit", runtime.Goexit}} {
		t.Run(failure.name, func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
			unused.Close()
			lease.Close()
			host := environmentTestOwner(t, f, 248, 1)
			c := sourceConnectTestConfig(t, f, identity, materialProviderFunc(func(context.Context, MaterialLeaseRequest) (*ArtifactLease, error) {
				identity.Close()
				failure.call()
				return nil, nil
			}), carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) { return nil, nil }))
			_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if _, err := host.ConnectSourcePool(ctx, c, PoolSessionInput{Store: store, Authority: authority, Consume: work}); !errors.Is(err, ErrEnvironmentTaskExit) {
					t.Fatal(err)
				}
				host.Close()
				if err := host.WaitCleanup(ctx); err != nil {
					t.Fatal(err)
				}
				if err := identity.WaitCleanup(ctx); err != nil {
					t.Fatal(err)
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnvironmentSourceLateCarrierRetainsCleanup(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	unused, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	unused.Close()
	host := environmentTestOwner(t, f, 248, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	f.provider.closeEntered, f.provider.closeRelease = make(chan struct{}), make(chan struct{})
	defer func() {
		for _, ch := range []chan struct{}{release, f.provider.closeRelease} {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
	}()
	c := sourceConnectTestConfig(t, f, identity, immediateMaterialProvider{lease}, carrierFactoryFunc(func(ctx context.Context, request CarrierPreparationRequest) (*PreparedCarrier, error) {
		if request.Config.Candidate != f.trust.candidate || request.Config.Attempt != f.trust.attempt || len(request.Route) == 0 {
			return nil, cryptov4.ErrConfiguration
		}
		close(entered)
		<-release
		// This deliberately uncooperative provider returns the original owned
		// carrier after cancellation, with no durable consumer transition.
		return f.prepared, nil
	}))
	_, err := consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		result := make(chan error, 1)
		go func() {
			_, err := host.ConnectSourcePool(context.Background(), c, PoolSessionInput{Store: store, Authority: authority, Consume: work})
			result <- err
		}()
		select {
		case <-entered:
		case err := <-result:
			t.Fatal("carrier not reached", err)
		case <-time.After(3 * time.Second):
			t.Fatal("carrier not started")
		}
		identity.Close()
		host.Close()
		if err := <-result; err == nil {
			t.Fatal("closed Environment published carrier")
		}
		close(release)
		select {
		case <-f.provider.closeEntered:
		case <-time.After(3 * time.Second):
			t.Fatal("late carrier not closed")
		}
		wait, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if err := host.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("blocked carrier close refunded Environment", err)
		}
		if err := identity.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("late carrier lost captured identity", err)
		}
		if f.provider.writes.Load() != 0 || f.provider.reads.Load() != 0 {
			t.Fatal("late carrier activated")
		}
		close(f.provider.closeRelease)
		wait, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		if err := identity.WaitCleanup(wait); err != nil {
			t.Fatal(err)
		}
		if f.provider.retires.Load() != 1 {
			t.Fatal("provider retirement count", f.provider.retires.Load())
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

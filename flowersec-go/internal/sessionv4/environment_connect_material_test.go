package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestEnvironmentConnectMaterialToDuplex(t *testing.T) {
	for _, source := range []string{"preauthorized_pool", "live_authority"} {
		t.Run(source, func(t *testing.T) { sessionEstablishmentDuplex(t, source, true, true, true, true, true, true, true) })
	}
}

func staticConnectTestConfig(t *testing.T, f *admissionIntegrationFixture, carrier ConsumerCarrierFactory) MaterialConnectConfig {
	t.Helper()
	c := sourceConnectTestConfig(t, f, nil, nil, carrier)
	c.Acquisition.Release()
	c.Material.Release()
	c.Acquisition, c.Material = resourcev4.Reference{}, resourcev4.Reference{}
	c.MaterialRuntimeBytes = 0
	return MaterialConnectConfig(c)
}

func TestEnvironmentConnectMaterialLocalRefusalPreservesOriginal(t *testing.T) {
	for _, mode := range []string{"unhosted", "foreign_environment", "generation", "capacity", "acquisition_input", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialBytesFixture(t, "preauthorized_pool")
			e := materialEnvironment(t, f)
			m := unusedMaterial(t, f)
			if mode != "unhosted" {
				if _, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign_environment" {
				e = materialEnvironment(t, f)
			}
			c := staticConnectTestConfig(t, f.admissionIntegrationFixture, carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
				t.Error("local refusal reached provider")
				return nil, cryptov4.ErrClosed
			}))
			if mode == "generation" {
				c.Generation.Generation++
			}
			if mode == "capacity" {
				c.Preparation = f.reserve(resourcev4.Vector{resourcev4.SDKBytes: 1, resourcev4.Items: 1})
			}
			if mode == "acquisition_input" {
				c.Acquisition = c.Preparation
			}
			_, err := consumeSessionPool(t, f.admissionIntegrationFixture, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if mode == "cancelled" {
					cancel()
				}
				before := f.root.Snapshot()
				if _, err := e.ConnectMaterialPool(ctx, m, c, PoolSessionInput{Store: store, Authority: authority, Consume: work}); err == nil {
					t.Fatal("invalid local static input accepted")
				}
				if f.root.Snapshot() != before {
					t.Fatal("local refusal changed resource ownership")
				}
				m.mu.Lock()
				changed := m.used || m.closed || m.building || m.preparing
				m.mu.Unlock()
				m.lease.lease.mu.Lock()
				claimed := m.lease.lease.claimed || m.lease.lease.preparing != nil
				m.lease.lease.mu.Unlock()
				if changed || claimed {
					t.Fatal("local refusal consumed original material")
				}
				if err := m.check(); err != nil {
					t.Fatal("original material no longer usable", err)
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnvironmentConnectMaterialCancellationRetainsOriginalPreparation(t *testing.T) {
	for _, mode := range []string{"caller", "environment", "material_close", "material_expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := newMaterialBytesFixture(t, "preauthorized_pool")
			e := materialEnvironment(t, f)
			m := unusedMaterial(t, f)
			if _, err := e.CreateMaterial(context.Background(), func(context.Context) (*ConnectionMaterial, error) { return m, nil }); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			c := staticConnectTestConfig(t, f.admissionIntegrationFixture, carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
				close(entered)
				<-release
				return nil, ErrCandidateExhausted
			}))
			_, err := consumeSessionPool(t, f.admissionIntegrationFixture, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				input := PoolSessionInput{Store: store, Authority: authority, Consume: work}
				result := make(chan error, 1)
				go func() { _, err := e.ConnectMaterialPool(ctx, m, c, input); result <- err }()
				select {
				case <-entered:
				case err := <-result:
					t.Fatal("static provider did not start", err)
				case <-time.After(3 * time.Second):
					t.Fatal("provider timeout")
				}
				before := f.root.Snapshot()
				if _, err := e.ConnectMaterialPool(ctx, m, c, input); err == nil {
					t.Fatal("duplicate material acquired a second preparation")
				}
				switch mode {
				case "caller":
					cancel()
				case "environment":
					e.Close()
				case "material_close":
					m.Close()
				case "material_expiry":
					f.admissionIntegrationFixture.trust.tick.Add(300)
					e.signalMaterials()
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("sealed preparation published")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("blocked provider hid original closure")
				}
				e.Close()
				wait, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer stop()
				if err := e.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("blocked static provider released Environment", err)
				}
				if f.root.Snapshot() != before {
					t.Fatal("blocked preparation refunded original backing")
				}
				if err := m.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("blocked preparation released material keys", err)
				}
				releaseOnce.Do(func() { close(release) })
				cleanup, finish := context.WithTimeout(context.Background(), 3*time.Second)
				defer finish()
				if err := e.WaitCleanup(cleanup); err != nil {
					t.Fatal(err)
				}
				if err := m.WaitCleanup(cleanup); err != nil {
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

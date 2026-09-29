package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestDirectExporterUnavailableBeforePoolConsumption(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	p := environmentTestEstablishment(t, f)
	p.material.Hello.Policy.BindingMode, p.material.Hello.BindingModes = 0, 1
	_, err := consumeSessionPool(t, f, a, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
		core, err := p.ConnectPool(a, store, authority, work)
		if core != nil || !errors.Is(err, protocolv4.ErrRequiredGuaranteeUnavailable) {
			t.Fatal("unqualified exporter reached establishment", err)
		}
		if a.claimed || a.committed || a.activated || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
			t.Fatal("unavailable exporter consumed or published credentials")
		}
		// A separate explicit authenticated-context attempt can still spend
		// this unchanged SQLite record: no failed exporter consume occurred.
		proof, err := f.trust.proof.Bytes()
		if err != nil {
			return nil, err
		}
		return a.ConsumePoolSQLite(store, authority, f.trust.authority, proof, work)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSourceRejectsCallerSuppliedExporterBeforeOwnership(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	_, identity, lease := materialTestBundle(t, f, protocolv4.ClientToServer, 280)
	c := sourceConnectTestConfig(t, f, identity, immediateMaterialProvider{lease}, carrierFactoryFunc(func(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error) {
		t.Fatal("invalid caller exporter reached provider")
		return nil, nil
	}))
	c.Hello.Policy.BindingMode, c.Hello.BindingModes = 0, 1
	c.Hello.Policy.Exporter = make([]byte, 32)
	before := f.root.Snapshot()
	if _, err := SourcePreparationCharge(c); err == nil {
		t.Fatal("caller bytes claimed original exporter capability")
	}
	if after := f.root.Snapshot(); before != after {
		t.Fatal("invalid configuration took ownership")
	}
}

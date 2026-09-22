package sessionv4

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type poolSQLiteAuthority struct {
	acceptedSQLiteAuthority
	original protocolv4.PoolSpendFields
}

func (a poolSQLiteAuthority) CheckPoolSpend(i ledgerv4.SQLiteIdentity, f protocolv4.PoolSpendFacts) error {
	fields, err := f.Fields()
	if err != nil || i != a.identity || fields != a.original {
		return ledgerv4.ErrConflict
	}
	return nil
}

func consumeSessionPool(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, connect ...func(*ledgerv4.SQLiteStore, poolSQLiteAuthority, resourcev4.Reference) (*InitialExchange, error)) (*InitialExchange, error) {
	t.Helper()
	proof, err := f.trust.proof.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	facts, err := f.trust.authority.PoolSpendFacts(proof)
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := facts.Fields()
	authority := poolSQLiteAuthority{acceptedSQLiteAuthority: acceptedSQLiteAuthority{identity: ledgerv4.SQLiteIdentity{Authority: "local.consumer", StoreID: [32]byte{2}, Generation: 1}}, original: fields}
	var result *InitialExchange
	err = withSessionSQLite(t, f, a, authority.identity, authority, 4096, func(store *ledgerv4.SQLiteStore, reserve func(uint32, resourcev4.Vector) resourcev4.Reference) error {
		charge, _ := ledgerv4.SQLitePoolSpendCharge(4096)
		work := reserve(242, charge)
		var callErr error
		if len(connect) > 0 {
			result, callErr = connect[0](store, authority, work)
		} else {
			result, callErr = a.ConsumePoolSQLite(store, authority, f.trust.authority, proof, work)
		}
		return callErr
	})
	return result, err
}

func withSessionSQLite(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, recordBytes uint32, run func(*ledgerv4.SQLiteStore, func(uint32, resourcev4.Vector) resourcev4.Reference) error) error {
	t.Helper()
	limits := ledgerv4.SQLiteLimits{MaxPages: 64, MaxRecords: 16, MaxRecordBytes: recordBytes, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	reserve := func(n uint32, cost resourcev4.Vector) resourcev4.Reference {
		r, err := f.root.Reserve(admissionResourceKey(f.owner, n), cost, f.scope.Session, f.scope.Tenant)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Release)
		return r
	}
	path := filepath.Join(t.TempDir(), "spend.db")
	diskCost, _ := ledgerv4.SQLiteBackingCharge(limits)
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, reserve(240, diskCost), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	storeCost, _ := ledgerv4.SQLiteStoreCharge(limits)
	store, err := ledgerv4.CreateSQLite(context.Background(), backing, identity, continuity, reserve(241, storeCost), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a != nil {
			a.Close()
			if err := a.WaitCleanup(context.Background()); err != nil {
				t.Error(err)
				return
			}
			if err := a.Retire(); err != nil {
				t.Error(err)
				return
			}
		}
		store.Close()
		if err := store.WaitCleanup(context.Background()); err != nil {
			t.Error(err)
			return
		}
		if err := store.Retire(); err != nil {
			t.Error(err)
			return
		}
		backing.Close()
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	return run(store, reserve)
}

func TestConsumerPoolOriginalSQLiteActivation(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	x, err := consumeSessionPool(t, f, a)
	if err != nil || x == nil || !a.committed || !a.activated {
		t.Fatal("original TxA-P did not activate", err)
	}
	if _, err := a.activate(f.trust.authority); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("activated twice", err)
	}
	if f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
		t.Fatal("construction published credentials")
	}
}

func TestConsumerPoolRejectsRevokedActivationBeforeConsume(t *testing.T) {
	f := admissionIntegration(t, context.Background(), "preauthorized_pool")
	a := f.reserve(t, context.Background())
	f.trust.trust.rejected.Store(true)
	if x, err := consumeSessionPool(t, f, a); err == nil || x != nil {
		t.Fatal("revoked activation consumed", err)
	}
	if a.claimed || a.committed || a.activated {
		t.Fatal("revocation crossed claim gate")
	}
}

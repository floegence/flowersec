package sessionv4

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

type acceptedSQLiteAuthority struct {
	identity ledgerv4.SQLiteIdentity
	facts    protocolv4.AdmissionFacts
}

func (a acceptedSQLiteAuthority) Check(identity ledgerv4.SQLiteIdentity, epoch uint64, create bool) error {
	if identity != a.identity || create && epoch != 0 {
		return ledgerv4.ErrFenced
	}
	return nil
}
func (a acceptedSQLiteAuthority) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	want, _ := a.facts.Fields()
	actual, err := facts.Fields()
	if err != nil || identity != a.identity || want.Tenant != actual.Tenant || want.Issuer != actual.Issuer || want.ServerIdentity != actual.ServerIdentity || want.Audience != actual.Audience {
		return ledgerv4.ErrFenced
	}
	return nil
}

func admitAcceptedSQLite(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation) (*InitialExchange, protocolv4.AdmissionResponse) {
	t.Helper()
	limits := ledgerv4.SQLiteLimits{MaxPages: 64, MaxRecords: 16, MaxRecordBytes: 4096, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	reserve := func(position uint32, charge resourcev4.Vector) resourcev4.Reference {
		r, err := f.root.Reserve(admissionResourceKey(f.owner, position), charge, f.scope.Session, f.scope.Tenant)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Release)
		return r
	}
	path := filepath.Join(t.TempDir(), "admission.db")
	diskCharge, err := ledgerv4.SQLiteBackingCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, reserve(230, diskCharge), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	storeCharge, err := ledgerv4.SQLiteStoreCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	authority := acceptedSQLiteAuthority{identity: ledgerv4.SQLiteIdentity{Authority: "admission.service", StoreID: [32]byte{1}, Generation: 1}, facts: a.acceptedFacts}
	store, err := ledgerv4.CreateSQLite(context.Background(), backing, authority.identity, authority, reserve(231, storeCharge), f.environment)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := a.Retire(); err != nil {
			t.Error(err)
		}
		store.Close()
		if err := store.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		if err := store.Retire(); err != nil {
			t.Error(err)
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
	buffers, invocation, err := ledgerv4.SQLiteAdmissionCharges(limits.MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	owner := ledgerv4.AdmissionOwner{Acceptor: [16]byte{1}, Invocation: [16]byte{2}, Carrier: [16]byte{3}, Generation: 1}
	x, response, err := a.AdmitSQLite(store, authority, owner, reserve(232, buffers), reserve(233, invocation))
	if err != nil {
		fields, _ := a.acceptedFacts.Fields()
		t.Fatalf("%v: deadline %d, activation %d, same clock %v, tenant %q", err, a.config.Initial.Deadline.Cap(), fields.ActivationEnd, a.config.Initial.Deadline.BelongsTo(a.config.Core.Clock), fields.Tenant)
	}
	return x, response
}

func TestAcceptedAdmissionBooleanCannotManufactureDurableCAS(t *testing.T) {
	_, e, _, a, _ := acceptedAdmissionFixture(t)
	claim, err := a.beginClaim()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.finishClaim(claim, true); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("boolean created durable permission", err)
	}
	if a.committed || a.activated || e.guard.admitted {
		t.Fatal("boolean opened FSA/Noise")
	}
}

func TestAcceptedAdmissionResponseMustMatchOriginalCASEpochAndKey(t *testing.T) {
	for _, field := range []string{"epoch", "key"} {
		t.Run(field, func(t *testing.T) {
			f, e, client, a, _ := acceptedAdmissionFixture(t)
			server, response := admitAcceptedSQLite(t, f, a)
			if field == "epoch" {
				response.ServerEpoch++
			} else {
				response.ReservationKey[0] ^= 1
			}
			codec, err := protocolv4.NewSignedMapCodec("FSA4", 16384, 4096)
			if err != nil {
				t.Fatal(err)
			}
			signed, result, err := server.SendAdmissionResponse(codec, f.trust.certificates[1], response, f.trust.signers[1], func() error { return e.guard.checkAdmitted() })
			if signed != nil {
				signed.Release()
				t.Error("replacement CAS value reached signer")
			}
			if err != protocolv4.CBORFailure("admission_response_binding") || result.Submitted {
				t.Fatal("replacement CAS published", result, err)
			}
			client.Close(cryptov4.ErrClosed)
		})
	}
}

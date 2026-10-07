package sessionv4

import (
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

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

func consumeSessionPool(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, connect ...func(*ledgerv4.SQLiteStore, poolSQLiteAuthority, resourcev4.Reference) (*InitialExchange, error)) (*InitialExchange, error) {
	return authorityConsumePool(t, f.authorityFixture, a, connect...)
}
func withSessionSQLite(t *testing.T, f *admissionIntegrationFixture, a *SessionAdmissionReservation, identity ledgerv4.SQLiteIdentity, continuity ledgerv4.SQLiteContinuity, recordBytes uint32, run func(*ledgerv4.SQLiteStore, func(uint32, resourcev4.Vector) resourcev4.Reference) error) error {
	return authoritySessionSQLite(t, f.authorityFixture, a, identity, continuity, recordBytes, run)
}

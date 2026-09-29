package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type liveFactQuery func(context.Context, SQLiteIdentity, LiveSpendReadTarget) (LiveAuthorizationFact, error)

func (f liveFactQuery) QueryAuthorization(ctx context.Context, identity SQLiteIdentity, target LiveSpendReadTarget) (LiveAuthorizationFact, error) {
	return f(ctx, identity, target)
}

func TestSQLiteLiveReconcileAuthorizesFactWithoutMaterial(t *testing.T) {
	f := newLiveReadFixture(t, true, 0)
	query := liveFactQuery(func(_ context.Context, identity SQLiteIdentity, target LiveSpendReadTarget) (LiveAuthorizationFact, error) {
		if identity != f.identity || target != f.access.target {
			t.Fatal("query lost immutable request binding")
		}
		return LiveAuthorizationFact{Target: target, Outcome: AuthorizationAuthorized}, nil
	})
	r, err := f.reader(t).ReconcileAuthorization(query)
	if err != nil || r.State != SpendConsumed || r.AuthorizationOutcome != AuthorizationAuthorized {
		t.Fatal(r, err)
	}
	row, err := f.store.readLiveSpend(f.key, make([]byte, 65536))
	if err != nil || row.version != 3 || len(row.proof) != 0 || !bytes.Equal(row.spending, f.spending) || row.materialEnd != 108000 {
		t.Fatal("reconciliation changed original material projection", row.version, err)
	}
	err = f.reader(t).DeliverClientMaterial(func(context.Context, []byte) error {
		t.Fatal("state-only authorized manufactured material")
		return nil
	})
	if !errors.Is(err, ErrMaterialNotReady) {
		t.Fatal(err)
	}
	_, err = f.reader(t).ReconcileAuthorization(liveFactQuery(func(context.Context, SQLiteIdentity, LiveSpendReadTarget) (LiveAuthorizationFact, error) {
		t.Fatal("definite history triggered an external query")
		return LiveAuthorizationFact{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteLiveReconcileRejectsUnboundAndNotStartedFacts(t *testing.T) {
	for _, mode := range []string{"identity", "not_started", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveReadFixture(t, true, 0)
			r := f.reader(t)
			_, err := r.ReconcileAuthorization(liveFactQuery(func(_ context.Context, _ SQLiteIdentity, target LiveSpendReadTarget) (LiveAuthorizationFact, error) {
				fact := LiveAuthorizationFact{Target: target, Outcome: AuthorizationAuthorized}
				switch mode {
				case "identity":
					fact.Target.ClientIdentity[0]++
				case "not_started":
					fact.Outcome = AuthorizationNotStarted
				case "cancel":
					r.Close()
				}
				return fact, nil
			}))
			if err == nil {
				t.Fatal("invalid fact changed durable history")
			}
			row, err := f.store.readLiveSpend(f.key, make([]byte, 65536))
			if err != nil || row.version != 2 || row.outcome != 0 {
				t.Fatal("refused query mutated original record", row.version, row.outcome, err)
			}
		})
	}
}

func TestSQLiteLiveReconcileConcurrentCASPreservesDefiniteWinner(t *testing.T) {
	f := newLiveReadFixture(t, true, 0)
	first, second := f.reader(t), f.reader(t)
	_, err := first.ReconcileAuthorization(liveFactQuery(func(_ context.Context, _ SQLiteIdentity, target LiveSpendReadTarget) (LiveAuthorizationFact, error) {
		_, err := second.ReconcileAuthorization(liveFactQuery(func(context.Context, SQLiteIdentity, LiveSpendReadTarget) (LiveAuthorizationFact, error) {
			return LiveAuthorizationFact{Target: target, Outcome: AuthorizationDenied}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		return LiveAuthorizationFact{Target: target, Outcome: AuthorizationAuthorized}, nil
	}))
	if !errors.Is(err, ErrConflict) {
		t.Fatal("late conflicting fact replaced definite result", err)
	}
	r, err := f.reader(t).Receipt()
	if err != nil || r.AuthorizationOutcome != AuthorizationDenied {
		t.Fatal(r, err)
	}
}

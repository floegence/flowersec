package ledgerv4

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// These storage fixtures bypass signature construction, as sqliteOriginal
// does. Session establishment tests exercise the verified-facts constructor.
func sqlitePoolOriginal(t *testing.T, f *sqliteFixture, store, parent *SQLiteStore, candidate byte) *SQLiteAdmission {
	t.Helper()
	a := sqliteOriginal(t, f, store, 2)
	a.record.fields.Source = "preauthorized_pool"
	a.record.fields.WinnerAuthority = "parent.test"
	a.record.fields.CandidateSet = [32]byte{1}
	a.record.fields.Candidate = [16]byte{candidate}
	a.record.fields.Route = [32]byte{candidate}
	var err error
	a.parent = parent.sqliteStore
	a.parentReference, err = parent.reservation.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	a.reservedSize, err = a.record.encode(a.reserved, admissionReserved, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestParentWinnerPrecedesIndependentAdmissionStoresAndSurvivesRestart(t *testing.T) {
	parentFixture := newSQLiteFixture(t, "")
	parent := parentFixture.create()
	firstFixture, otherFixture := newSQLiteFixture(t, ""), newSQLiteFixture(t, "")
	firstStore, otherStore := firstFixture.create(), otherFixture.create()
	first := sqlitePoolOriginal(t, firstFixture, firstStore, parent, 1)
	called := false
	if err := first.Admit(func(context.Context, protocolv4.AdmissionResponse) error { called = true; return nil }); err != nil || !called {
		t.Fatal("first winner did not admit", err)
	}
	if err := first.Cleanup(); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, parent)
	var err error
	parent, err = parentFixture.open(false)
	if err != nil {
		t.Fatal(err)
	}
	other := sqlitePoolOriginal(t, otherFixture, otherStore, parent, 2)
	if err := other.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
		t.Error("losing candidate dispatched")
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("restart forgot shared winner", err)
	}
	row, err := otherStore.readAdmission(other.key[:other.keySize], other.scratch)
	if err != nil || row.found {
		t.Fatal("loser wrote AdmissionLedger before matching parent", row, err)
	}
	// Identical fact reads do not overwrite or extend the parent's selection.
	other.record.fields.Candidate, other.record.fields.Route = [16]byte{1}, [32]byte{1}
	n, err := other.record.encodeParentWinner(other.target)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = parent.matchParentWinner(context.Background(), other.key[:other.keySize], other.target[:n], other.scratch, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	count, err := parent.scalar("SELECT winner_rows FROM manifest WHERE id=1")
	if err != nil || count != int64(1) {
		t.Fatal("matching fact consumed another root", count, err)
	}
}

func TestParentWinnerFailureClosesOriginalBeforeAdmission(t *testing.T) {
	for _, mode := range []string{"missing", "ambiguous_commit", "admission_failure"} {
		t.Run(mode, func(t *testing.T) {
			pf, af := newSQLiteFixture(t, ""), newSQLiteFixture(t, "")
			parent, store := pf.create(), af.create()
			a := sqlitePoolOriginal(t, af, store, parent, 1)
			switch mode {
			case "missing":
				a.parent = nil
			case "ambiguous_commit":
				fault := &sqliteExecFault{ExecerContext: parent.execer, afterCommit: func() error { return ErrUnknown }}
				fault.commits.Store(1)
				parent.execer = fault
			case "admission_failure":
				store.execer = parentAdmissionRefusal{store.execer}
			}
			if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
				t.Error("failed claim dispatched")
				return nil
			}); err == nil {
				t.Fatal("failure accepted")
			}
			if !a.closed {
				t.Fatal("failed parent attempt reopened candidate race")
			}
			if mode != "admission_failure" {
				row, err := store.readAdmission(a.key[:a.keySize], a.scratch)
				if err != nil || row.found {
					t.Fatal("failed parent wrote local admission", err)
				}
			}
			if mode != "missing" {
				_, found, err := parent.readParentWinner(a.key[:a.keySize], a.scratch)
				if err != nil || !found {
					t.Fatal("later failure released parent selection", err)
				}
			}

		})
	}
}

type parentAdmissionRefusal struct{ driver.ExecerContext }

func (f parentAdmissionRefusal) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query == "BEGIN IMMEDIATE" {
		return nil, ErrStorageUnavailable
	}
	return f.ExecerContext.ExecContext(ctx, query, args)
}

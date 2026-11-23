package ledgerv4

import (
	"context"
	"errors"
	"testing"
)

// The storage fixture fixes its private projection directly. Session tests
// exercise the signature-derived constructor and original activation gate.
func poolSQLiteOriginal(t *testing.T, f *sqliteFixture, s *SQLiteStore) *SQLitePoolSpend {
	t.Helper()
	i := invocation(t, nil)
	charge, err := SQLitePoolSpendCharge(f.backing.limits.MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, _, _, err := s.admissionReference(f.environment)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.reserve(charge, 1).Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	p := &SQLitePoolSpend{&sqlitePoolSpend{ctx: context.Background(), store: s.sqliteStore, deadline: i.deadline, guard: func() error { return nil }, reservation: held, storeReference: ref, projection: []byte("fixed original signed pool material and owner"), fence: s.epoch, keySize: 34}}
	p.key[0], p.key[1], p.key[2], p.key[18] = 1, 't', 1, 2
	p.projectionSize = len(p.projection)
	t.Cleanup(func() {
		if err := p.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func TestSQLitePoolLostCommitNeverConfirmsOrDispatches(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	p := poolSQLiteOriginal(t, f, s)
	fault := &sqliteExecFault{ExecerContext: s.execer, afterCommit: func() error { return errors.New("lost pool commit response") }}
	// This helper injects its fault at commit number two; pool has just one.
	fault.commits.Store(1)
	s.execer = fault
	called := false
	if err := p.Consume(func() error { called = true; return nil }); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if called || fault.commits.Load() != 2 {
		t.Fatal("unknown pool commit dispatched or rewrote")
	}
	count, err := s.scalar("SELECT count(*) FROM spend WHERE source=1 AND state=1")
	if err != nil || count != int64(1) {
		t.Fatal("lost response erased consume", count, err)
	}
	if err := p.Consume(func() error { t.Error("resumed closed owner"); return nil }); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	other := poolSQLiteOriginal(t, f, s)
	if err := other.Consume(func() error { t.Error("new owner reused lease"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

func TestSQLitePoolCancellationKeepsDurableHistory(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	p := poolSQLiteOriginal(t, f, s)
	fault := &sqliteExecFault{ExecerContext: s.execer, afterCommit: func() error { p.Close(context.Canceled); return nil }}
	fault.commits.Store(1)
	s.execer = fault
	if err := p.Consume(func() error { t.Error("cancelled pool owner dispatched"); return nil }); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	if err := p.Cleanup(); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, s)
	reopened, err := f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	other := poolSQLiteOriginal(t, f, reopened)
	if err := other.Consume(func() error { t.Error("reopen restored activation"); return nil }); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

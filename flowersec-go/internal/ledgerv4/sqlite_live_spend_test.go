package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// The fixture installs the same fixed projection as the reader tests. Session
// establishment tests exercise the verified-plan constructor and signing path.
func liveSQLiteOriginal(t *testing.T, f *liveReadFixture) *SQLiteLiveSpend {
	t.Helper()
	limit := f.backing.limits.MaxRecordBytes
	charge, invocationCharge, err := SQLiteLiveSpendCharges(limit)
	if err != nil {
		t.Fatal(err)
	}
	ref, _, fence, _, err := f.store.admissionReference(f.environment)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.reserve(charge, 1).Take(charge)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeLiveSpending(f.spending)
	if err != nil {
		t.Fatal(err)
	}
	deadline, err := f.time.deadline.Fork(v.claimEnd)
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewInvocation(context.Background(), f.time.clock, deadline, fence, admissionKeyBytes, int(limit), f.reserve(invocationCharge, 1))
	if err != nil {
		t.Fatal(err)
	}
	a := &SQLiteLiveSpend{&sqliteLiveSpend{
		store: f.store.sqliteStore, invocation: i, guard: func() error { return nil },
		reservation: held, storeReference: ref, authority: f.identity.Authority, fence: fence,
		spending: bytes.Clone(f.spending), spendingSize: len(f.spending), target: make([]byte, limit),
	}}
	a.keySize = copy(a.key[:], f.key)
	t.Cleanup(func() {
		if err := a.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func TestSQLiteLiveOriginalCancellationRecordsNotStarted(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "lost_ack"}[lost], func(t *testing.T) {
			f := newLiveReadFixture(t, false, 0)
			a := liveSQLiteOriginal(t, f)
			if err := f.store.exec("DELETE FROM spend"); err != nil {
				t.Fatal(err)
			}
			if err := f.store.exec("UPDATE manifest SET spend_rows=0 WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			fault := &sqliteExecFault{ExecerContext: f.store.execer, afterCommit: func() error {
				a.Close(context.Canceled)
				if lost {
					return errors.New("lost original response")
				}
				return nil
			}}
			fault.commits.Store(1)
			f.store.execer = fault
			if err := a.Authorize(func(context.Context) (bool, error) {
				t.Fatal("canceled invocation dispatched policy")
				return false, nil
			}, func(context.Context, []byte) error {
				t.Fatal("not_started published material")
				return nil
			}); err == nil {
				t.Fatal("cancellation reported success")
			}
			r := f.reader(t)
			receipt, err := r.Receipt()
			if err != nil || receipt.State != SpendConsumed || receipt.AuthorizationOutcome != AuthorizationNotStarted {
				t.Fatal(receipt, err)
			}
			v, err := f.store.readLiveSpend(f.key, make([]byte, 65536))
			if err != nil || len(v.proof) != 0 || !bytes.Equal(v.spending, f.spending) || v.version != 2 {
				t.Fatal("terminal write changed the original projection", err)
			}
			if err := a.Authorize(func(context.Context) (bool, error) {
				t.Fatal("not_started revived callback")
				return false, nil
			}, func(context.Context, []byte) error { return nil }); !errors.Is(err, ErrOwner) {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteLiveNotStartedCannotReplaceUnknownDispatchedOrOtherOwner(t *testing.T) {
	for _, mode := range []string{"dispatched", "expired", "different_intent"} {
		t.Run(mode, func(t *testing.T) {
			f := newLiveReadFixture(t, false, 0)
			a := liveSQLiteOriginal(t, f)
			if mode == "different_intent" {
				a.spending[len(a.spending)-1] ^= 1
			} else {
				if err := f.store.exec("DELETE FROM spend"); err != nil {
					t.Fatal(err)
				}
				if err := f.store.exec("UPDATE manifest SET spend_rows=0 WHERE id=1"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "expired" {
				fault := &sqliteExecFault{ExecerContext: f.store.execer, afterCommit: func() error {
					f.advance.Store(1000)
					return nil
				}}
				fault.commits.Store(1)
				f.store.execer = fault
			}
			calls := 0
			err := a.Authorize(func(context.Context) (bool, error) {
				calls++
				a.Close(context.Canceled)
				return false, nil
			}, func(context.Context, []byte) error {
				t.Fatal("failed owner published material")
				return nil
			})
			if err == nil || (calls == 1) != (mode == "dispatched") {
				t.Fatal(calls, err)
			}
			v, err := f.store.readLiveSpend(f.key, make([]byte, 65536))
			if err != nil || !v.found || v.consumed || !bytes.Equal(v.spending, f.spending) {
				t.Fatal("invalid not_started claim", err)
			}
		})
	}
}

package ledgerv4

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func TestSQLiteExecutionFullPromisedOutputAtExactPageBound(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	var work [2]*SQLiteExecutionWork
	for i := range work {
		q := f.request(byte(i + 1))
		q.ResponseLimitBytes = 1 << 20
		_, w, err := f.register(s, q)
		if err != nil {
			t.Fatal(err)
		}
		work[i] = w
		if err = w.Enter(ctx, allowBusiness); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte{0xa5}, 1<<20)
	for i, w := range work {
		if err := w.Finish(ctx, 0, payload, allowBusiness); err != nil {
			t.Fatal("promised full result lost its capacity", err)
		}
		q := f.request(byte(i + 1))
		q.ResponseLimitBytes = 1 << 20
		var result [1 << 20]byte
		if _, n, err := s.ReadResult(ctx, q, result[:], allowBusiness); err != nil || n != len(payload) || !bytes.Equal(result[:], payload) {
			t.Fatal(n, err)
		}
		if err := w.Exit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	pages, err := s.store.scalar("PRAGMA page_count")
	if err != nil || pages.(int64) > int64(f.backing.limits.MaxPages) {
		t.Fatal(pages, err)
	}
}

func TestSQLiteExecutionEmptyUnaryResult(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Finish(ctx, 0, nil, allowBusiness); err != nil {
		t.Fatal("valid empty result", err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	o, n, err := s.ReadResult(ctx, q, nil, allowBusiness)
	if err != nil || n != 0 || !o.ResultFormed || !o.ResultAvailable || o.ResultBytes != 0 {
		t.Fatal(o, n, err)
	}
}

func TestSQLiteExecutionRolledBackOwnerCannotSettleLaterRegistration(t *testing.T) {
	for _, sameDigest := range []bool{true, false} {
		t.Run(map[bool]string{true: "matching_request", false: "different_request"}[sameDigest], func(t *testing.T) {
			f := newBusinessFixture(t, "")
			s := f.createBusiness()
			ctx := context.Background()
			q := f.request(1)
			s.store.execer = &businessCommitFault{ExecerContext: s.store.execer, before: true}
			_, old, err := f.register(s, q)
			if !errors.Is(err, ErrUnknown) || old == nil {
				t.Fatal(old, err)
			}
			if !sameDigest {
				q.RequestDigest = [32]byte{9}
			}
			_, current, err := f.register(s, q)
			if err != nil || current == nil {
				t.Fatal(current, err)
			}
			if err = old.Exit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = current.Enter(ctx, allowBusiness); err != nil {
				t.Fatal("old cleanup ended the new invocation", err)
			}
			o, err := s.Query(ctx, q, allowBusiness)
			if err != nil || !o.WorkActive || !o.Dispatched || o.State != SQLiteExecutionExecuting {
				t.Fatal(o, err)
			}
			if err = current.Exit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteExecutionRenewalPreservesOffersAndAcceptedTerms(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.InstallContract(ctx, 1, f.wire, nil, false, allowBusiness); !errors.Is(err, ErrOwner) {
		t.Fatal("withdrew an unexpired promise", err)
	}
	if _, err = s.InstallContract(ctx, 1, f.wire, []timev4.Interval{{LowerMS: 0, UpperMS: 100}, {LowerMS: 50, UpperMS: 200}}, true, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal("Offer renewal invalidated accepted work", err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := s.Query(ctx, q, allowBusiness)
	if err != nil || o.RegistrationRevision != 1 {
		t.Fatal("replaced original registered terms", o, err)
	}
}

func TestSQLiteExecutionUnavailableTimeDoesNotExpireResultOrAdvanceFloor(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Finish(ctx, 0, []byte("original"), allowBusiness); err != nil {
		t.Fatal(err)
	}
	f.config.Clock.Close()
	o, err := s.Query(ctx, q, allowBusiness)
	if err != nil || !o.Found || !o.ResultFormed || o.ResultDeleted || o.ResultAvailable {
		t.Fatal(o, err)
	}
	var output [32]byte
	if _, _, err = s.ReadResult(ctx, q, output[:], allowBusiness); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal("missing time became expiration", err)
	}
	if err = s.Collect(ctx); !errors.Is(err, timev4.ErrUnavailable) {
		t.Fatal(err)
	}
	floor, err := s.floor(q.Key.CallerAuthority)
	if err != nil || floor != 0 {
		t.Fatal(floor, err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal("actual cleanup required fresh time", err)
	}
}

func TestSQLiteExecutionFloorAndDetailGCCommitTogether(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before_commit", false: "after_commit"}[before], func(t *testing.T) {
			f := newBusinessFixture(t, "")
			s := f.createBusiness()
			ctx := context.Background()
			q := f.request(1)
			o, w, err := f.register(s, q)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Enter(ctx, allowBusiness); err != nil {
				t.Fatal(err)
			}
			if err = w.Exit(ctx); err != nil {
				t.Fatal(err)
			}
			f.tick.Store(o.HistoryNotBeforeGCMS)
			s.store.execer = &businessCommitFault{ExecerContext: s.store.execer, before: before}
			if err = s.Collect(ctx); !errors.Is(err, ErrUnknown) {
				t.Fatal(err)
			}
			o, err = s.Query(ctx, q, allowBusiness)
			if before {
				if err != nil || !o.Found {
					t.Fatal("rolled-back GC lost history", o, err)
				}
				floor, err := s.floor(q.Key.CallerAuthority)
				if err != nil || floor != 0 {
					t.Fatal("partial floor transaction", floor, err)
				}
			} else if !errors.Is(err, ErrExecutionHistoryUnknown) {
				t.Fatal("committed GC lacked floor", o, err)
			}
			if err = s.Collect(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Query(ctx, q, allowBusiness); !errors.Is(err, ErrExecutionHistoryUnknown) {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteExecutionResultExpiryKeepsActualWorkAndHistory(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Finish(ctx, 0, []byte("original"), allowBusiness); err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot().Charged
	f.tick.Store(100000)
	if err = s.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := s.Query(ctx, q, allowBusiness)
	if err != nil || !o.Found || !o.ResultDeleted || o.ResultAvailable || !o.WorkActive || w.CleanupComplete() {
		t.Fatal(o, err)
	}
	if f.root.Snapshot().Charged != before {
		t.Fatal("result TTL refunded actual work or disk")
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	if !w.CleanupComplete() {
		t.Fatal("settled original tail remained live")
	}
	o, err = s.Query(ctx, q, allowBusiness)
	if err != nil || !o.Found || o.WorkActive {
		t.Fatal("result expiry erased history", o, err)
	}
}

func TestSQLiteExecutionUncertainResultCannotBeReplaced(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before_commit", false: "after_commit"}[before], func(t *testing.T) {
			f := newBusinessFixture(t, "")
			s := f.createBusiness()
			ctx := context.Background()
			q := f.request(1)
			_, w, err := f.register(s, q)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Enter(ctx, allowBusiness); err != nil {
				t.Fatal(err)
			}
			s.store.execer = &businessCommitFault{ExecerContext: s.store.execer, before: before}
			if err = w.Finish(ctx, 0, []byte("original"), allowBusiness); !errors.Is(err, ErrUnknown) {
				t.Fatal(err)
			}
			if err = w.Finish(ctx, 0, []byte("replacement"), allowBusiness); !errors.Is(err, ErrOwner) {
				t.Fatal("replaced uncertain result", err)
			}
			if err = w.Exit(ctx); err != nil {
				t.Fatal(err)
			}
			o, err := s.Query(ctx, q, allowBusiness)
			if err != nil || o.WorkActive || o.ResultFormed == before {
				t.Fatal(o, err)
			}
			if !before {
				var result [32]byte
				if _, n, err := s.ReadResult(ctx, q, result[:], allowBusiness); err != nil || string(result[:n]) != "original" {
					t.Fatal(n, err)
				}
			}
		})
	}
}

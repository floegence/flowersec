package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// Storage unit fixtures supply fixed verified facts directly. The independent
// protocol tests cover their signature-derived constructor; Session integration
// tests exercise that constructor and actual SQLite through original carriers.
func sqliteOriginal(t *testing.T, f *sqliteFixture, s *SQLiteStore, lease byte) *SQLiteAdmission {
	t.Helper()
	clockOwner := invocation(t, nil)
	ownerCharge, invocationCharge, err := SQLiteAdmissionCharges(f.backing.limits.MaxRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := f.reserve(ownerCharge, 1).Take(ownerCharge)
	if err != nil {
		t.Fatal(err)
	}
	i, err := NewInvocation(context.Background(), clockOwner.clock, clockOwner.deadline, s.epoch, admissionKeyBytes, int(f.backing.limits.MaxRecordBytes), f.reserve(invocationCharge, 1))
	if err != nil {
		t.Fatal(err)
	}
	ref, _, _, _, err := s.admissionReference(f.environment)
	if err != nil {
		t.Fatal(err)
	}
	fields := protocolv4.AdmissionFields{Tenant: "tenant", Audience: "service", Profile: "test-profile", Source: "live_authority", SpendAuthority: "spend", Issuer: [16]byte{1}, Lease: [16]byte{lease}, Attempt: [16]byte{7}, AdmissionBinding: [32]byte{9}, ServerIdentity: [32]byte{10}, ActivationEnd: 110000, SessionEnd: 120000}
	a := &SQLiteAdmission{&sqliteAdmission{store: s.sqliteStore, invocation: i, guard: func() error { return nil }, reservation: owned, storeReference: ref, reserved: make([]byte, 4096), target: make([]byte, 4096), scratch: make([]byte, 4096), record: admissionRecord{fields: fields, owner: AdmissionOwner{Acceptor: [16]byte{1}, Invocation: [16]byte{lease}, Carrier: [16]byte{lease}, Generation: 1}, authority: s.identity.Authority, storeID: s.identity.StoreID, storeGeneration: s.identity.Generation, fence: s.epoch, deadline: 110000, reservedAt: 100000}}}
	a.keySize, err = a.record.key(a.key[:])
	if err != nil {
		t.Fatal(err)
	}
	a.reservedSize, err = a.record.encode(a.reserved, admissionReserved, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	return a
}

type sqliteCommitBarrier struct {
	driver.ExecerContext
	entered, release chan struct{}
	commits          int
}

func (b *sqliteCommitBarrier) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "COMMIT" {
		b.commits++
		if b.commits == 2 {
			close(b.entered)
			<-b.release
		}
	}
	return b.ExecerContext.ExecContext(ctx, q, args)
}

func TestSQLiteAdmissionRealCommitTailStaysChargedAfterClose(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	a := sqliteOriginal(t, f, s, 6)
	barrier := &sqliteCommitBarrier{ExecerContext: s.execer, entered: make(chan struct{}), release: make(chan struct{})}
	s.execer = barrier
	done := make(chan error, 1)
	go func() {
		done <- a.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
			t.Error("closed tail dispatched")
			return nil
		})
	}()
	<-barrier.entered
	before := f.root.Snapshot().Charged
	a.Close(context.Canceled)
	s.Close()
	if err := a.Cleanup(); !errors.Is(err, ErrCapacity) {
		t.Fatal("detached original method", err)
	}
	if err := s.Retire(); !errors.Is(err, ErrOwner) {
		t.Fatal("detached actual SQLite connection", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	if err := s.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
	if f.root.Snapshot().Charged != before || len(a.target) == 0 {
		t.Fatal("logical Close refunded real commit tail")
	}
	close(barrier.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, s)
}

type sqliteCrashBoundary struct {
	driver.ExecerContext
	boundary int
	commits  int
}

func (b *sqliteCrashBoundary) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "COMMIT" {
		b.commits++
		if b.commits == 2 && b.boundary == 1 {
			os.Exit(0)
		}
	}
	r, err := b.ExecerContext.ExecContext(ctx, q, args)
	if err == nil && q == "COMMIT" && (b.commits == 1 && b.boundary == 0 || b.commits == 2 && b.boundary == 2) {
		os.Exit(0)
	}
	return r, err
}

func TestSQLiteAdmissionCrashBoundariesNeverReleaseLease(t *testing.T) {
	const pathEnv = "FLOWERSEC_SQLITE_ADMISSION_CRASH_PATH"
	const boundaryEnv = "FLOWERSEC_SQLITE_ADMISSION_CRASH_BOUNDARY"
	if path := os.Getenv(pathEnv); path != "" {
		boundary, err := strconv.Atoi(os.Getenv(boundaryEnv))
		if err != nil {
			t.Fatal(err)
		}
		f := newSQLiteFixture(t, path)
		s := f.create()
		a := sqliteOriginal(t, f, s, 7)
		s.execer = &sqliteCrashBoundary{ExecerContext: s.execer, boundary: boundary}
		if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
			t.Error("crossed crash boundary")
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		t.Fatal("did not crash at boundary")
	}
	for boundary := 0; boundary < 3; boundary++ {
		t.Run(strconv.Itoa(boundary), func(t *testing.T) {
			f := newSQLiteFixture(t, "")
			cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteAdmissionCrashBoundariesNeverReleaseLease$")
			cmd.Env = append(os.Environ(), pathEnv+"="+f.backing.path, boundaryEnv+"="+strconv.Itoa(boundary))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("crash helper: %v\n%s", err, out)
			}
			s, err := f.open(false)
			if err != nil {
				t.Fatal(err)
			}
			a := sqliteOriginal(t, f, s, 7)
			r, err := s.readAdmission(a.key[:a.keySize], a.scratch)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(admissionReserved)
			if boundary == 2 {
				want = admissionAdmitted
			}
			if !r.found || r.state != want || r.CommitFence != 1 || r.CurrentFence != 2 {
				t.Fatal("crash lost original state/fence", r)
			}
			if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
				t.Error("restored row granted dispatch")
				return nil
			}); !errors.Is(err, ErrConflict) {
				t.Fatal(err)
			}
		})
	}
}

func TestSQLiteAdmissionCASAndLeaseRoot(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	a := sqliteOriginal(t, f, s, 2)
	var response protocolv4.AdmissionResponse
	err := a.Admit(func(_ context.Context, r protocolv4.AdmissionResponse) error { response = r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !response.Admitted || response.ServerEpoch != s.epoch || response.ReservationKey == ([32]byte{}) || response.AdmissionBinding != a.record.fields.AdmissionBinding {
		t.Fatal("CAS did not bind FSA facts", response)
	}
	var saved [4096]byte
	r, err := s.readAdmission(a.key[:a.keySize], saved[:])
	if err != nil {
		t.Fatal(err)
	}
	if !r.found || r.state != admissionAdmitted || r.CommitVersion != 2 || !bytes.Equal(saved[:r.ProjectionBytes], a.target[:a.targetSize]) {
		t.Fatal("admitted projection changed", r)
	}
	if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error { t.Error("duplicate dispatch"); return nil }); !errors.Is(err, ErrOwner) {
		t.Fatal(err)
	}
	competitor := sqliteOriginal(t, f, s, 2)
	competitor.record.fields.Attempt[0] ^= 1
	competitor.record.fields.Candidate[0] ^= 1
	competitor.record.fields.AdmissionNonce[0] ^= 1
	competitor.reservedSize, err = competitor.record.encode(competitor.reserved, admissionReserved, 0, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.key[:a.keySize], competitor.key[:competitor.keySize]) {
		t.Fatal("candidate/attempt changed unique lease root")
	}
	if err := competitor.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
		t.Error("competing carrier dispatched")
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := a.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := competitor.Cleanup(); err != nil {
		t.Fatal(err)
	}
	closeSQLite(t, s)
	s, err = f.open(false)
	if err != nil {
		t.Fatal(err)
	}
	restored := sqliteOriginal(t, f, s, 2)
	if err := restored.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
		t.Error("restart recovered dispatch")
		return nil
	}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

type sqliteExecFault struct {
	driver.ExecerContext
	afterCommit func() error
	commits     atomic.Int32
}

func (f *sqliteExecFault) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	r, err := f.ExecerContext.ExecContext(ctx, query, args)
	if err == nil && query == "COMMIT" && f.commits.Add(1) == 2 && f.afterCommit != nil {
		return r, f.afterCommit()
	}
	return r, err
}

func TestSQLiteAdmissionConfirmsOriginalAfterLostCommitResult(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	a := sqliteOriginal(t, f, s, 3)
	fault := &sqliteExecFault{ExecerContext: s.execer, afterCommit: func() error { return errors.New("lost original commit result") }}
	s.execer = fault
	calls := 0
	if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || fault.commits.Load() != 2 || a.invocation.current.reads != 1 {
		t.Fatal("confirmation rewrote or redispatched", calls, fault.commits.Load(), a.invocation.current.reads)
	}
}

func TestSQLiteAdmissionCancellationAfterCommitNeverDispatches(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	a := sqliteOriginal(t, f, s, 4)
	s.execer = &sqliteExecFault{ExecerContext: s.execer, afterCommit: func() error { a.Close(context.Canceled); return errors.New("cancelled after durable commit") }}
	if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error {
		t.Error("cancelled original dispatched")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r, err := s.readAdmission(a.key[:a.keySize], a.scratch)
	if err != nil || r.state != admissionAdmitted {
		t.Fatal("cancel erased committed admission", r, err)
	}
}

func TestSQLiteAdmissionFiniteHistoryCapacity(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	for n := byte(1); n <= byte(f.backing.limits.MaxRecords); n++ {
		a := sqliteOriginal(t, f, s, n)
		if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error { return nil }); err != nil {
			t.Fatal(n, err)
		}
		if err := a.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	a := sqliteOriginal(t, f, s, 99)
	if err := a.Admit(func(context.Context, protocolv4.AdmissionResponse) error { t.Error("capacity dispatched"); return nil }); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	count, err := s.scalar("SELECT count(*) FROM admission")
	if err != nil || count != int64(f.backing.limits.MaxRecords) {
		t.Fatal("capacity discarded existing facts", count, err)
	}
}

func TestSQLiteAdmissionExactReservedProjectionCAS(t *testing.T) {
	f := newSQLiteFixture(t, "")
	s := f.create()
	a := sqliteOriginal(t, f, s, 5)
	if err := a.reserve(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.targetState = admissionAdmitted
	var err error
	a.targetSize, err = a.record.encode(a.target, a.targetState, 100001, [32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.exec("UPDATE admission SET projection=?1", named(1, []byte("replaced complete binding"))); err != nil {
		t.Fatal(err)
	}
	tx := Transaction{Kind: AdmissionCommit, Authority: a.record.authority, Key: a.key[:a.keySize], BeforeVersion: 1, CommitVersion: 2, FencingEpoch: s.epoch, Projection: a.target[:a.targetSize]}
	if _, err := (admissionCommitStore{a.sqliteAdmission}).Commit(context.Background(), tx, a.scratch); !errors.Is(err, ErrConflict) {
		t.Fatal("CAS accepted changed reserved row", err)
	}
	r, err := s.readAdmission(tx.Key, a.scratch)
	if err != nil || r.state != admissionReserved {
		t.Fatal(r, err)
	}
}

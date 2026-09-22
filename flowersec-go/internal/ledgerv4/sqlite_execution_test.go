package ledgerv4

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type executionContinuityFunc func(SQLiteIdentity, SQLiteExecutionService, uint64, bool) error

func (f executionContinuityFunc) CheckExecutionHistory(i SQLiteIdentity, s SQLiteExecutionService, e uint64, c bool) error {
	return f(i, s, e, c)
}

type businessFixture struct {
	*sqliteFixture
	config SQLiteExecutionConfig
	proof  SQLiteExecutionContinuity
	tick   atomic.Uint64
	wire   []byte
	digest [32]byte
}

func newBusinessFixture(t *testing.T, path string) *businessFixture {
	t.Helper()
	f := &businessFixture{sqliteFixture: newSQLiteFixtureWithLimits(t, path, SQLiteLimits{MaxPages: 872, MaxRecords: 2, MaxRecordBytes: 1 << 20, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536})}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 1 << 40, MaxRoundTripMS: 100}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: f.tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	f.config = SQLiteExecutionConfig{Root: f.root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{31}, Backing: [16]byte{31}, Kind: 1}, Clock: clock, Service: SQLiteExecutionService{"tenant", "audience", "acme/files"}, CallerAuthorities: [][32]byte{{8}}, Active: 2, ContractNodes: 512, WorkRuntimeBytes: 4096}
	data, err := os.ReadFile("../../../testdata/transport_v4/domains.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Vectors []struct {
			ID     string `json:"id"`
			Inputs struct {
				Contract struct {
					Bytes string `json:"$bytes"`
				} `json:"contract"`
			} `json:"inputs"`
		} `json:"vectors"`
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Vectors {
		if v.ID == "domain_service_unary_execution" {
			f.wire, err = hex.DecodeString(v.Inputs.Contract.Bytes)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	codec, _ := protocolv4.NewServiceContractCodec(512)
	contract, err := codec.Decode(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := contract.MethodShapeDigest()
	if err != nil {
		t.Fatal(err)
	}
	f.digest, _ = contract.Digest()
	contract.Release()
	f.config.Methods = []SQLiteExecutionMethod{{Type: 1, Shape: shape}}
	f.proof = executionContinuityFunc(func(i SQLiteIdentity, s SQLiteExecutionService, _ uint64, _ bool) error {
		if i != f.identity || s != f.config.Service {
			return ErrFenced
		}
		return nil
	})
	return f
}

func (f *businessFixture) openBusiness(create bool) (*SQLiteExecutions, error) {
	f.t.Helper()
	charge, err := SQLiteExecutionsCharge(f.backing.limits, f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	ref := f.reserve(charge, 1)
	var s *SQLiteExecutions
	if create {
		s, err = CreateSQLiteExecutions(context.Background(), f.backing, f.identity, f.proof, f.config, ref, f.environment)
	} else {
		s, err = OpenSQLiteExecutions(context.Background(), f.backing, f.identity, f.proof, f.config, ref, f.environment)
	}
	if s != nil {
		f.stores = append(f.stores, s.store)
	}
	ref.Release()
	return s, err
}

func (f *businessFixture) createBusiness() *SQLiteExecutions {
	f.t.Helper()
	s, err := f.openBusiness(true)
	if err != nil {
		f.t.Fatal(err)
	}
	if revision, err := s.InstallContract(context.Background(), 0, f.wire, []timev4.Interval{{LowerMS: 0, UpperMS: 100}}, true, allowBusiness); err != nil || revision != 1 {
		f.t.Fatal(revision, err)
	}
	return s
}

func allowBusiness() error { return nil }

func (f *businessFixture) request(id byte) SQLiteExecutionRequest {
	q := SQLiteExecutionRequest{Key: SQLiteExecutionKey{CallerAuthority: [32]byte{8}, CallerSubject: "caller"}, RequestDigest: [32]byte{id}, ContractDigest: f.digest, RegistrationRevision: 1, DeadlineAtMS: 500, ResponseLimitBytes: 32}
	binary.BigEndian.PutUint64(q.Key.OperationID[:], 100)
	q.Key.OperationID[31] = id
	return q
}

func (f *businessFixture) register(s *SQLiteExecutions, q SQLiteExecutionRequest) (SQLiteExecutionObservation, *SQLiteExecutionWork, error) {
	f.t.Helper()
	charge, _ := SQLiteExecutionWorkCharge(f.config.WorkRuntimeBytes)
	ref := f.reserve(charge, 1)
	o, w, err := s.Register(context.Background(), q, ref, allowBusiness)
	ref.Release()
	if w != nil {
		f.t.Cleanup(func() {
			if !w.closed {
				if err := w.Exit(context.Background()); err != nil {
					f.t.Error(err)
				}
			}
		})
	}
	return o, w, err
}

func TestSQLiteExecutionOriginalWorkResultAndDuplicateFirst(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	o, w, err := f.register(s, q)
	if err != nil || w == nil || o.State != SQLiteExecutionAccepted {
		t.Fatal(o, w, err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); !errors.Is(err, ErrOwner) {
		t.Fatal("dispatched twice", err)
	}
	f.tick.Store(600)
	if _, err = s.InstallContract(ctx, 1, f.wire, nil, false, allowBusiness); err != nil {
		t.Fatal(err)
	}
	duplicate := q
	duplicate.RegistrationRevision = 999
	duplicate.DeadlineAtMS = 1
	o, again, err := s.Register(ctx, duplicate, resourcev4.Reference{}, allowBusiness)
	if err != nil || again != nil || !o.Found || !o.Dispatched {
		t.Fatal("duplicate required new Offer/deadline/work", o, again, err)
	}
	conflict := duplicate
	conflict.RequestDigest = [32]byte{9}
	if _, _, err = s.Register(ctx, conflict, resourcev4.Reference{}, allowBusiness); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err = w.Finish(ctx, 0, []byte("actual result"), allowBusiness); err != nil {
		t.Fatal(err)
	}
	o, err = s.Query(ctx, q, allowBusiness)
	if err != nil || !o.ResultAvailable || !o.WorkActive || o.State != SQLiteExecutionCompleted || o.ResultNotAfterMS != 60625 {
		t.Fatal(o, err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	var dst [32]byte
	o, n, err := s.ReadResult(ctx, q, dst[:], allowBusiness)
	if err != nil || string(dst[:n]) != "actual result" || o.WorkActive {
		t.Fatal(o, n, err)
	}
	closeSQLite(t, s.store)
	s, err = f.openBusiness(false)
	if err != nil {
		t.Fatal(err)
	}
	o, n, err = s.ReadResult(ctx, q, dst[:], allowBusiness)
	if err != nil || string(dst[:n]) != "actual result" || o.Epoch != 1 || o.ResultNotAfterMS != 60625 {
		t.Fatal("reopen changed original result", o, n, err)
	}
	f.tick.Store(o.HistoryNotBeforeGCMS)
	if err = s.Collect(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Query(ctx, q, allowBusiness); !errors.Is(err, ErrExecutionHistoryUnknown) {
		t.Fatal("GC fabricated absence", err)
	}
	closeSQLite(t, s.store)
	s, err = f.openBusiness(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Query(ctx, q, allowBusiness); !errors.Is(err, ErrExecutionHistoryUnknown) {
		t.Fatal("floor did not survive restart", err)
	}
}

func TestSQLiteExecutionCapacityAndActualCloseTail(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	_, a, err := f.register(s, f.request(1))
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := f.register(s, f.request(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, w, err := f.register(s, f.request(3)); !errors.Is(err, ErrCapacity) || w != nil {
		t.Fatal(w, err)
	}
	before := f.root.Snapshot().Charged
	s.Close()
	f.root.Close()
	select {
	case <-s.store.done:
		t.Fatal("closed provider under original work")
	default:
	}
	if f.root.Snapshot().Charged != before {
		t.Fatal("logical close refunded live work")
	}
	if err = a.Enter(ctx, allowBusiness); err == nil {
		t.Fatal("entered closed store")
	}
	alias := *a
	if err = a.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = alias.Exit(ctx); !errors.Is(err, ErrOwner) {
		t.Fatal("copied owner released twice", err)
	}
	select {
	case <-s.store.done:
		t.Fatal("closed provider with second work tail")
	default:
	}
	if err = b.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.WaitCleanup(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteExecutionCancellationAndOfferIntervals(t *testing.T) {
	f := newBusinessFixture(t, "")
	s, openErr := f.openBusiness(true)
	if openErr != nil {
		t.Fatal(openErr)
	}
	ctx := context.Background()
	q := f.request(1)
	if _, err := s.InstallContract(ctx, 0, f.wire, []timev4.Interval{{LowerMS: 0, UpperMS: 75}, {LowerMS: 50, UpperMS: 150}}, true, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if _, w, err := f.register(s, q); !errors.Is(err, ErrExecutionWindowClosed) || w != nil {
		t.Fatal("joined adjacent Offers", w, err)
	}
	f.tick.Store(25)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.RequestCancel(ctx, q, allowBusiness)
	if err != nil || !o.CancelRequested || !o.WorkActive {
		t.Fatal(o, err)
	}
	if err = w.Enter(ctx, allowBusiness); !errors.Is(err, timev4.ErrCancelled) {
		t.Fatal(err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	o, err = s.Query(ctx, q, allowBusiness)
	if err != nil || o.State != SQLiteExecutionFailed || o.Dispatched || o.WorkActive || o.Reason != SQLiteExecutionReasonCancelled {
		t.Fatal(o, err)
	}
}

type businessCommitFault struct {
	driver.ExecerContext
	before bool
	failed bool
}

func (f *businessCommitFault) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query == "COMMIT" && !f.failed {
		f.failed = true
		if !f.before {
			if _, err := f.ExecerContext.ExecContext(ctx, query, args); err != nil {
				return nil, err
			}
		}
		return nil, errors.New("original business COMMIT result lost")
	}
	return f.ExecerContext.ExecContext(ctx, query, args)
}

func TestSQLiteExecutionUnknownRegistrationNeverGrantsWork(t *testing.T) {
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "before_commit", false: "after_commit"}[before], func(t *testing.T) {
			f := newBusinessFixture(t, "")
			s := f.createBusiness()
			ctx := context.Background()
			q := f.request(1)
			s.store.execer = &businessCommitFault{ExecerContext: s.store.execer, before: before}
			_, w, err := f.register(s, q)
			if !errors.Is(err, ErrUnknown) || w == nil {
				t.Fatal(w, err)
			}
			if err = w.Enter(ctx, allowBusiness); !errors.Is(err, ErrOwner) {
				t.Fatal("uncertain registration granted work", err)
			}
			o, err := s.Query(ctx, q, allowBusiness)
			if err != nil || o.Found == before {
				t.Fatal(o, err)
			}
			if err = w.Exit(ctx); err != nil {
				t.Fatal(err)
			}
			o, err = s.Query(ctx, q, allowBusiness)
			if err != nil || o.WorkActive || !before && (o.Dispatched || o.State != SQLiteExecutionFailed) {
				t.Fatal(o, err)
			}
		})
	}
}

func TestSQLiteExecutionUnknownHandoffDoesNotRetryDispatch(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	s.store.execer = &businessCommitFault{ExecerContext: s.store.execer}
	if err = w.Enter(ctx, allowBusiness); !errors.Is(err, ErrUnknown) {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); !errors.Is(err, ErrOwner) {
		t.Fatal("uncertain handoff dispatched again", err)
	}
	if err = w.Finish(ctx, 0, nil, allowBusiness); !errors.Is(err, ErrOwner) {
		t.Fatal("unentered handler formed a result", err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := s.Query(ctx, q, allowBusiness)
	if err != nil || o.State != SQLiteExecutionUnknown || !o.Dispatched || o.WorkActive {
		t.Fatal(o, err)
	}
}

func TestSQLiteExecutionCrashRecoveryHasNoFreshWork(t *testing.T) {
	const variable = "FLOWERSEC_BUSINESS_CRASH_PATH"
	if path := os.Getenv(variable); path != "" {
		f := newBusinessFixture(t, path)
		s := f.createBusiness()
		if _, _, err := f.register(s, f.request(1)); err != nil {
			t.Fatal(err)
		}
		_, w, err := f.register(s, f.request(2))
		if err != nil {
			t.Fatal(err)
		}
		if err = w.Enter(context.Background(), allowBusiness); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	f := newBusinessFixture(t, "")
	cmd := exec.Command(os.Args[0], "-test.run=^TestSQLiteExecutionCrashRecoveryHasNoFreshWork$")
	cmd.Env = append(os.Environ(), variable+"="+f.backing.path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v\n%s", err, output)
	}
	proof := f.proof
	f.proof = executionContinuityFunc(func(SQLiteIdentity, SQLiteExecutionService, uint64, bool) error { return ErrExecutionHistoryUnknown })
	if s, err := f.openBusiness(false); !errors.Is(err, ErrExecutionHistoryUnknown) || s != nil {
		t.Fatal("recovered without independent history", s, err)
	}
	f.proof = proof
	s, err := f.openBusiness(false)
	if err != nil {
		t.Fatal(err)
	}
	for i := byte(1); i <= 2; i++ {
		q := f.request(i)
		o, w, err := s.Register(context.Background(), q, resourcev4.Reference{}, allowBusiness)
		if err != nil || w != nil || !o.Found || o.WorkActive || o.Epoch != 1 || o.Dispatched != (i == 2) {
			t.Fatal(o, w, err)
		}
		want := SQLiteExecutionFailed
		if i == 2 {
			want = SQLiteExecutionUnknown
		}
		if o.State != want {
			t.Fatal(o)
		}
	}
	if s.store.epoch != 2 {
		t.Fatal(s.store.epoch)
	}
}

func TestSQLiteExecutionScopeFormatAndResultIntegrity(t *testing.T) {
	f := newBusinessFixture(t, "")
	s := f.createBusiness()
	ctx := context.Background()
	q := f.request(1)
	charge, _ := SQLiteExecutionWorkCharge(f.config.WorkRuntimeBytes)
	foreign := f.reserve(charge, 2)
	if _, w, err := s.Register(ctx, q, foreign, allowBusiness); err == nil || w != nil {
		t.Fatal("foreign work scope", w, err)
	}
	_, w, err := f.register(s, q)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Enter(ctx, allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Finish(ctx, 42, []byte("undeclared error"), allowBusiness); err == nil {
		t.Fatal("invented application code")
	}
	if err = w.Finish(ctx, 0, []byte("original"), allowBusiness); err != nil {
		t.Fatal(err)
	}
	if err = w.Exit(ctx); err != nil {
		t.Fatal(err)
	}
	key, _ := s.encodeKey(q.Key)
	if err = s.store.exec("UPDATE executions SET payload=zeroblob(32) WHERE key=?1", named(1, key[:])); err != nil {
		t.Fatal(err)
	}
	output := bytes.Repeat([]byte{7}, 32)
	if _, n, err := s.ReadResult(ctx, q, output, allowBusiness); !errors.Is(err, ErrStorageFormat) || n != 0 || !bytes.Equal(output[:8], make([]byte, 8)) {
		t.Fatal(n, err, output)
	}
	closeSQLite(t, s.store)
	if ledger, err := f.open(false); !errors.Is(err, ErrStorageFormat) || ledger != nil {
		t.Fatal("business history opened as ledger", ledger, err)
	}
}

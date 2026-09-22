package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type durableDispatchContinuity struct {
	identity ledgerv4.SQLiteIdentity
	service  ledgerv4.SQLiteExecutionService
}

func (p durableDispatchContinuity) CheckExecutionHistory(i ledgerv4.SQLiteIdentity, s ledgerv4.SQLiteExecutionService, _ uint64, _ bool) error {
	if i != p.identity || s != p.service {
		return ledgerv4.ErrFenced
	}
	return nil
}

type durableDispatchFixture struct {
	f        *executorFixture
	dispatch ExecutionDispatch
	clock    *timev4.Clock
	contract *protocolv4.ServiceContract
	policy   protocolv4.ServiceContractPolicy
	store    *ledgerv4.SQLiteExecutions
}

func newDurableDispatchFixture(t *testing.T) *durableDispatchFixture {
	t.Helper()
	f := &executorFixture{config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 64 * 1024}}
	cfg := resourcev4.Config{ProfileRevision: [32]byte{1}, AccountSlots: 8, ReservationSlots: 64, ReferenceSlots: 128}
	for i := range cfg.Limit {
		cfg.Limit[i] = 1 << 32
	}
	var err error
	f.root, err = resourcev4.NewRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.root.Close()
		if !f.root.Snapshot().CleanupComplete {
			t.Error("durable dispatcher retained original backing", f.root.Snapshot())
		}
	})
	charge, _ := ApplicationExecutorCharge(f.config)
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	clock, err := timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 100, MaxAgeMS: 10000, MaxRoundTripMS: 100}, func() (timev4.Tick, error) { return timev4.Tick{Incarnation: [16]byte{1}}, nil })
	if err != nil {
		t.Fatal(err)
	}
	mark, _ := clock.Monotonic()
	if err = clock.InstallTrusted(mark, timev4.Interval{LowerMS: 25, UpperMS: 25}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(clock.Close)
	body := initialFixture(t, "service_notify_execution")
	codec, _ := protocolv4.NewServiceContractCodec(256)
	contract, err := codec.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(contract.Release)
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	shape, err := contract.MethodShapeDigest()
	if err != nil {
		t.Fatal(err)
	}
	routesConfig := rpcv4.ContractRoutesConfig{Methods: []rpcv4.MethodRoutes{{Contracts: [][]byte{body}}}, ContractNodes: 256, RuntimeBytes: 1024, Clock: clock}
	charge, _ = rpcv4.ContractRoutesCharge(routesConfig)
	routes, err := rpcv4.NewContractRoutes(routesConfig, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(routes.Close)
	environment := f.reserve(t, 1, resourcev4.Vector{resourcev4.Items: 1})
	limits := ledgerv4.SQLiteLimits{MaxPages: 128, MaxRecords: 2, MaxRecordBytes: 1024, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	path := filepath.Join(t.TempDir(), "business.db")
	charge, _ = ledgerv4.SQLiteBackingCharge(limits)
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, f.reserve(t, 1, charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{240}, Backing: [16]byte{240}, Kind: 12}
	service := ledgerv4.SQLiteExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}
	storeConfig := ledgerv4.SQLiteExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: service, CallerAuthorities: [][32]byte{{8}}, Methods: []ledgerv4.SQLiteExecutionMethod{{Type: policy.Type, Shape: shape}}, Active: 2, ContractNodes: 256, WorkRuntimeBytes: 4096}
	identity := ledgerv4.SQLiteIdentity{Authority: "business.test", StoreID: [32]byte{3}, Generation: 1}
	charge, err = ledgerv4.SQLiteExecutionsCharge(limits, storeConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ledgerv4.CreateSQLiteExecutions(context.Background(), backing, identity, durableDispatchContinuity{identity, service}, storeConfig, f.reserve(t, 1, charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.InstallContract(context.Background(), 0, body, []timev4.Interval{{LowerMS: 1, UpperMS: 1000}}, true, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	c := rpcv4.DurableExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: rpcv4.ExecutionService{Tenant: service.Tenant, Audience: service.Audience, Namespace: service.Namespace}, Store: store, Active: 2, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 4096, WorkRuntimeBytes: 4096}
	charge, _ = rpcv4.DurableExecutionsCharge(c)
	history, err := rpcv4.NewDurableExecutions(c, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	access := executionDispatchAccess{f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	result := &durableDispatchFixture{f: f, clock: clock, contract: contract, policy: policy, store: store, dispatch: ExecutionDispatch{DurableHistory: history, Routes: routes, Executor: f.executor, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Access: access}}
	t.Cleanup(func() {
		f.executor.Close()
		waitExecutorIdle(t, f.executor)
		history.Close()
		if err := history.Collect(context.Background()); err != nil {
			t.Error(err)
		}
		if !history.CleanupComplete() {
			t.Error("durable history retained actual work")
		}
		store.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := store.WaitCleanup(ctx); err != nil {
			t.Error(err)
			return
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
	return result
}

func (f *durableDispatchFixture) input(t *testing.T, id byte) (*rpcv4.VerifiedInput, rpcv4.ExecutionTarget) {
	t.Helper()
	var operation [32]byte
	binary.BigEndian.PutUint64(operation[:], 500)
	operation[31] = id
	fields := protocolv4.ApplicationHeaderFields{Type: f.policy.Type, DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest, OperationID: operation}
	codec, _ := protocolv4.NewApplicationHeaderCodec()
	var header [512]byte
	_, h, err := codec.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(h, f.contract, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, h, err = codec.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	charge, _ := rpcv4.ContractRouteCharge(512)
	route, err := f.dispatch.Routes.Capture(f.policy.Digest, f.f.reserve(t, 1, charge), 512)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(route.Release)
	c := rpcv4.InputConfig{Clock: f.clock, Capture: true, RuntimeBytes: 1024, HashRuntimeBytes: 512}
	charge, err = rpcv4.RequestInputCharge(h, c)
	if err != nil {
		t.Fatal(err)
	}
	input, err := route.NewNotifyInput(h, c, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Close)
	if err = input.Finish(); err != nil {
		t.Fatal(err)
	}
	verified, err := input.Take()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verified.Close)
	return verified, rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: f.policy.Namespace}, Caller: f.dispatch.Caller, Operation: operation, RequestDigest: fields.RequestDigest, ContractDigest: fields.ServiceContractDigest}
}

func TestDurableExecutionDispatchActualExecutorAndAbnormalExit(t *testing.T) {
	for _, mode := range []string{"return", "panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			f := newDurableDispatchFixture(t)
			input, target := f.input(t, 1)
			outcome := make(chan error, 1)
			_, err := f.dispatch.DispatchWithOutcome(context.Background(), input, func(_ context.Context, borrow rpcv4.InputBorrow) (uint32, []byte, error) {
				if _, _, err := borrow.Bytes(); err != nil {
					return 0, nil, err
				}
				if mode == "panic" {
					panic("private")
				}
				if mode == "goexit" {
					runtime.Goexit()
				}
				return 0, nil, nil
			}, func(_ uint32, _ []byte, err error) error { outcome <- err; return nil })
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-outcome:
				if mode == "return" && err != nil || mode != "return" && !errors.Is(err, ErrCompletionCallbackExit) {
					t.Fatal(mode, err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("original callback did not exit")
			}
			waitExecutorIdle(t, f.f.executor)
			o, err := f.dispatch.DurableHistory.Query(context.Background(), target, f.dispatch.Access)
			if err != nil {
				t.Fatal(err)
			}
			want := rpcv4.ExecutionCompleted
			if mode != "return" {
				want = rpcv4.ExecutionUnknown
			}
			if o.State != want || !o.Dispatched || o.WorkActive || !input.CleanupComplete() {
				t.Fatal(o, input.CleanupComplete())
			}
		})
	}
}

func TestDurableExecutionDispatchDuplicateAndCancellationKeepActualTask(t *testing.T) {
	f := newDurableDispatchFixture(t)
	input, target := f.input(t, 1)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.f.executor) })
	var calls atomic.Int32
	handler := func(ctx context.Context, _ rpcv4.InputBorrow) (uint32, []byte, error) {
		calls.Add(1)
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return 0, nil, nil
	}
	if _, err := f.dispatch.Dispatch(context.Background(), input, handler); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler not entered")
	}
	duplicate, _ := f.input(t, 1)
	o, err := f.dispatch.Dispatch(context.Background(), duplicate, handler)
	if err != nil || !o.Found || !o.WorkActive || calls.Load() != 1 {
		t.Fatal(o, err, calls.Load())
	}
	o, err = f.dispatch.DurableHistory.RequestCancel(context.Background(), target, f.dispatch.Access)
	if err != nil || !o.CancelRequested {
		t.Fatal(o, err)
	}
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("original context not cancelled")
	}
	if f.f.executor.Snapshot().Running != 1 || input.CleanupComplete() {
		t.Fatal("cancel refunded actual task")
	}
	once.Do(func() { close(release) })
	waitExecutorIdle(t, f.f.executor)
	o, err = f.dispatch.DurableHistory.Query(context.Background(), target, f.dispatch.Access)
	if err != nil || o.State != rpcv4.ExecutionCompleted || o.WorkActive || calls.Load() != 1 {
		t.Fatal(o, err, calls.Load())
	}
}

func TestDurableExecutionDispatchExecutorCapacityPrecedesRegistration(t *testing.T) {
	f := newDurableDispatchFixture(t)
	input, target := f.input(t, 1)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); waitExecutorIdle(t, f.f.executor) })
	for range 2 {
		task, backing := f.f.job(t, 1)
		if _, err := f.f.executor.TrySubmit(ApplicationShort, task, backing, func() { <-release }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.dispatch.Dispatch(context.Background(), input, func(context.Context, rpcv4.InputBorrow) (uint32, []byte, error) {
		t.Error("handler bypassed occupied executor")
		return 0, nil, nil
	}); err == nil {
		t.Fatal("accepted without actual executor position")
	}
	o, err := f.dispatch.DurableHistory.Query(context.Background(), target, f.dispatch.Access)
	if err != nil || o.Found {
		t.Fatal("executor refusal left admission record", o, err)
	}
}

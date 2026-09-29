package sessionv4

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type durableServiceStorage struct {
	store    *ledgerv4.SQLiteExecutions
	history  *rpcv4.DurableExecutions
	path     string
	shutdown func()
}

func newDurableServiceStorage(t *testing.T, f *executorFixture, clock *timev4.Clock, environment resourcev4.Reference, contract *protocolv4.ServiceContract, wire []byte, configure ...func(*ledgerv4.SQLiteExecutionConfig)) *durableServiceStorage {
	t.Helper()
	path := os.Getenv("FLOWERSEC_TEST_DURABLE_EXECUTION_PATH")
	create := path == ""
	if create {
		path = filepath.Join(t.TempDir(), "execution.db")
	}
	return durableServiceStorageAt(t, f, clock, environment, contract, wire, path, create, configure...)
}

// Explicit reopen keeps the original path and registration; it does not create
// a second execution authority or install replacement admission windows.
func durableServiceStorageAt(t *testing.T, f *executorFixture, clock *timev4.Clock, environment resourcev4.Reference, contract *protocolv4.ServiceContract, wire []byte, path string, create bool, configure ...func(*ledgerv4.SQLiteExecutionConfig)) *durableServiceStorage {
	t.Helper()
	limits := ledgerv4.SQLiteLimits{MaxPages: 8192, MaxRecords: 16, MaxRecordBytes: 1 << 20, RuntimeBytes: 65536, ProviderRuntimeBytes: 1 << 20, DiskOverheadBytes: 65536}
	charge, err := ledgerv4.SQLiteBackingCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	backing, err := ledgerv4.NewSQLiteBacking(path, limits, f.reserve(t, 1, charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	shape, err := contract.MethodShapeDigest()
	if err != nil {
		t.Fatal(err)
	}
	service := ledgerv4.SQLiteExecutionService{Tenant: "tenant", Audience: "audience", Namespace: policy.Namespace}
	identity := ledgerv4.SQLiteIdentity{Authority: "business.test", StoreID: [32]byte{3}, Generation: 1}
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{240}, Backing: [16]byte{240}, Kind: 12}
	config := ledgerv4.SQLiteExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: service, CallerAuthorities: [][32]byte{{8}}, Methods: []ledgerv4.SQLiteExecutionMethod{{Type: policy.Type, Shape: shape}}, Active: 4, ContractNodes: 256, WorkRuntimeBytes: 4096}
	for _, apply := range configure {
		apply(&config)
	}
	charge, err = ledgerv4.SQLiteExecutionsCharge(limits, config)
	if err != nil {
		t.Fatal(err)
	}
	open := ledgerv4.OpenSQLiteExecutions
	if create {
		open = ledgerv4.CreateSQLiteExecutions
	}
	store, err := open(context.Background(), backing, identity, durableDispatchContinuity{identity, service}, config, f.reserve(t, 1, charge), environment)
	if err != nil {
		t.Fatal(err)
	}
	if create {
		windows := []timev4.Interval{{LowerMS: 1000, UpperMS: 2000}}
		if len(configure) != 0 {
			now, sampleErr := clock.Sample()
			if sampleErr != nil {
				t.Fatal(sampleErr)
			}
			windows = []timev4.Interval{{LowerMS: now.LowerMS, UpperMS: now.LowerMS + 1000}}
		}
		if _, err = store.InstallContract(context.Background(), 0, wire, windows, true, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	hc := rpcv4.DurableExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: rpcv4.ExecutionService(service), Store: store, Active: 4, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 4096, WorkRuntimeBytes: 4096}
	charge, err = rpcv4.DurableExecutionsCharge(hc)
	if err != nil {
		t.Fatal(err)
	}
	history, err := rpcv4.NewDurableExecutions(hc, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	shutdown := func() {
		if closed {
			return
		}
		closed = true
		history.Close()
		if err := history.Collect(context.Background()); err != nil {
			t.Error(err)
		}
		if !history.CleanupComplete() {
			t.Error("original durable work still live")
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
	}
	t.Cleanup(func() {
		shutdown()
		backing.Close()
		// The child is the final file owner. The parent repeats the removal
		// idempotently to discharge its own disk reservation after child exit.
		for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
			if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
				t.Error(err)
			}
		}
		if err := backing.ReleaseRemoved(); err != nil {
			t.Error(err)
		}
	})
	return &durableServiceStorage{store: store, history: history, path: path, shutdown: shutdown}
}

// Uses the original wire receiver, registered handler, provider task and
// response publisher. A new OS process reopens the database and joins the
// original result. Carrier handshake qualification belongs to the final suite.
func TestServiceDurableUnaryRestartChain(t *testing.T) {
	child := os.Getenv("FLOWERSEC_TEST_DURABLE_EXECUTION_PATH") != ""
	var calls atomic.Uint32
	f := newServiceDispatchFixtureContract(t, func(_ context.Context, request UnaryRequest, response *UnaryResponse) (uint32, error) {
		calls.Add(1)
		if child {
			t.Error("restart replayed business handler")
		}
		input, _, err := request.Input.Bytes()
		if err != nil {
			return 0, err
		}
		_, err = response.Write(append([]byte("reply:"), input...))
		return 0, err
	}, false, ApplicationShort, true, "service_unary_durable_chain")
	target := f.executionRequest(t, 1, []byte("persisted"), 0)
	if err := f.dispatch.Admit(f.receiver, f.publisher); err != nil {
		t.Fatal(err)
	}
	for _, reply := range f.executionReplies(t, 1) {
		if reply.header.Kind() != "execution_unary_response" || !bytes.Equal(reply.body, []byte("reply:persisted")) {
			t.Fatal("original durable response", reply.header.Kind(), reply.body)
		}
	}
	f.closeSession()
	access := executionDispatchAccess{f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})}
	observation, err := f.durable.history.Query(context.Background(), target, access)
	if err != nil || observation.State != rpcv4.ExecutionCompleted || !observation.ResultAvailable || observation.WorkActive {
		t.Fatal("original durable facts", observation, err)
	}
	var output [1024]byte
	_, n, err := f.durable.history.ReadResult(context.Background(), target, access, output[:])
	if err != nil || string(output[:n]) != "reply:persisted" {
		t.Fatal("original retained result", n, err)
	}
	wantCalls := uint32(1)
	if child {
		wantCalls = 0
	}
	if calls.Load() != wantCalls {
		t.Fatal("business execution count", calls.Load())
	}
	if child {
		return
	}
	f.dispatch.executionRegistry.Close()
	f.durable.shutdown()
	if t.Failed() {
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestServiceDurableUnaryRestartChain$", "-test.count=1", "-test.timeout=20s")
	command.Env = append(os.Environ(), "FLOWERSEC_TEST_DURABLE_EXECUTION_PATH="+f.durable.path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("restart process: %v\n%s", err, output)
	}
}

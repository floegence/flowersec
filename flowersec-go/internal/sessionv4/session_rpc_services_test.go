package sessionv4

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func rpcServicesPlanFixture(t *testing.T, scoped ...bool) (*executorFixture, *SessionPlan, RPCServicesConfig) {
	t.Helper()
	// Component capacity covers all original future channel owners. This is
	// synthetic geometry, not qualification of a supported deployment preset.
	limit := resourcev4.Vector{resourcev4.SDKBytes: 16 << 20, resourcev4.Items: 4096, resourcev4.Tasks: 128, resourcev4.WorkSlots: 128, resourcev4.Timers: 64}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 160, ReferenceSlots: 320})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		root.Close()
		if !root.Snapshot().CleanupComplete {
			t.Error("RPC assembly leaked owners", root.Snapshot())
		}
	})
	f := &executorFixture{root: root, config: ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, Ready: 4, ResidentReady: 2, CompletionRunning: 1, CompletionReserved: 2, QueryOwners: 4, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}}
	charge, err := ApplicationExecutorCharge(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.executor, err = NewApplicationExecutor(f.config, f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.executor.Close(); awaitApplicationTask(t, f.executor.Done()) })
	var accounts []resourcev4.Account
	if len(scoped) != 0 && scoped[0] {
		for i, kind := range []resourcev4.AccountKind{resourcev4.TenantAccount, resourcev4.SessionAccount} {
			account, err := root.Account(resourcev4.AccountKey{Kind: kind, ID: [16]byte{byte(i + 1)}}, limit)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(account.Close)
			accounts = append(accounts, account)
		}
	}
	plan := applicationTestPlan(t, f, SessionPlanConfig{Services: true, ContractQueries: true, RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		return AuthorizeApplicationResult{}, ErrApplicationAuthorization
	}}, accounts...)
	clock := sessionTestClock(t)
	config := RPCServicesConfig{NotifyReceivePending: 16, NotifyPublishPending: 16, NotificationWaitMS: 10000, NotificationCleanupMS: 10000, CompletionGraceMS: 5000, ShortRequestBytes: 8192, ShortResponseBytes: 8192, ShortTaskCharge: f.executor.TaskCharge(), ShortCompletionCharge: f.executor.CompletionFloorCharge(), CryptoProfile: protocolv4.DHProfileX25519, Bootstrap: SessionStreamConfig{ReceivePoolBytes: 360448, ReceiveBytes: 32768, InitialReceiveLimit: 16384, SendBytes: 1024, QueueBytes: 16384, RuntimeBytes: 4096, WriteWaiters: 2, MaxPlaintext: 1152, Chunk: 1024}, MaxDataPayloadBytes: 1024, Root: root, Owner: resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{81}, Backing: [16]byte{81}, Kind: 81},
		Session: testSessionContract(t, protocolv4.DHProfileX25519, "services", 65536, 16, 0, 5000, 1<<20).Contract, Clock: clock, Query: rpcv4.QueryBinding{Type: 7, Contract: [32]byte{9}},
		Routes: rpcv4.ContractRoutesConfig{ContractNodes: 256, RuntimeBytes: 4096, Clock: clock}, Slots: 4, ResidentSlots: 2, MaxCaptureBytes: 1048576, RuntimeBytes: 4096, InputRuntimeBytes: 4096, HashRuntimeBytes: 512, InvocationRuntimeBytes: 4096}
	config.Accounts = accounts
	return f, plan, config
}

func TestRPCServicesAtomicReservationAndFixedOwners(t *testing.T) {
	f, p, c := rpcServicesPlanFixture(t)
	total, count, err := RPCServicesRequirements(c)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot()
	r, err := p.InstallRPCServices(c)
	if err != nil {
		t.Fatal(err, "required", total, "available", before)
	}
	expected, _ := before.Charged.Add(total)
	if after := f.root.Snapshot(); after.Charged != expected || after.Reservations != before.Reservations+count {
		t.Fatal("incomplete common owner vector", before, after, total)
	}
	if p.services != r.dispatch || p.queries.service != r.incoming || r.network.CheckQueryService(r.incoming) != nil || r.network.CheckServiceClock(c.Clock) != nil {
		t.Fatal("split original services")
	}
	if err := p.checkPreparation(); err != nil {
		t.Fatal(err)
	}
	snapshot := f.root.Snapshot()
	if _, err := p.InstallRPCServices(c); !errors.Is(err, cryptov4.ErrTransition) || f.root.Snapshot() != snapshot {
		t.Fatal("replaced ordinary network", err)
	}
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.releaseAfterCleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	if !r.retired || !r.network.Snapshot().CleanupComplete {
		t.Fatal("closed assembly not retired")
	}
}

func TestRPCServicesCapacityFailureKeepsPlanUnclaimed(t *testing.T) {
	for _, dimension := range []int{resourcev4.SDKBytes, resourcev4.Items, resourcev4.Tasks, resourcev4.WorkSlots} {
		t.Run(fmt.Sprint(dimension), func(t *testing.T) {
			f, p, c := rpcServicesPlanFixture(t)
			total, _, err := RPCServicesRequirements(c)
			if err != nil {
				t.Fatal(err)
			}
			before := f.root.Snapshot()
			hold := resourcev4.Vector{}
			hold[dimension] = before.Limit[dimension] - before.Charged[dimension] - total[dimension] + 1
			ref := f.reserve(t, 1, hold)
			before = f.root.Snapshot()
			if r, err := p.InstallRPCServices(c); r != nil || !errors.Is(err, resourcev4.ErrCapacity) {
				t.Fatal("admitted partial service graph", err)
			}
			if after := f.root.Snapshot(); after != before || p.rpc != nil || p.services != nil || p.queries != nil || p.closed || p.rpcPreparing {
				t.Fatal("failed batch changed original plan", before, after)
			}
			ref.Release()
			if _, err := p.InstallRPCServices(c); err != nil {
				t.Fatal("capacity failure consumed plan", err)
			}
		})
	}
}

func TestRPCServicesInvalidRegistryUnwindsWholeBatch(t *testing.T) {
	f, p, c := rpcServicesPlanFixture(t)
	c.Routes.Methods = []rpcv4.MethodRoutes{{Contracts: [][]byte{{0xa0}}}}
	before := f.root.Snapshot()
	if r, err := p.InstallRPCServices(c); r != nil || err == nil {
		t.Fatal("accepted malformed registry", err)
	}
	if after := f.root.Snapshot(); after != before || p.rpc != nil || p.rpcPreparing {
		t.Fatal("constructor failure leaked original owners", before, after)
	}
}

func TestRPCServicesRejectsMismatchedOriginalClockBeforeReservation(t *testing.T) {
	f, p, c := rpcServicesPlanFixture(t)
	c.Routes.Clock = sessionTestClock(t)
	before := f.root.Snapshot()
	if r, err := p.InstallRPCServices(c); r != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
		t.Fatal(err)
	}
	if f.root.Snapshot() != before {
		t.Fatal("clock mismatch reserved resources")
	}
}

func TestRPCServicesAdoptsOneEnclosingAdmissionBatch(t *testing.T) {
	f, p, c := rpcServicesPlanFixture(t)
	var batch rpcServicesBatch
	if err := prepareRPCServicesBatch(&batch, p, c, nil); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	before := f.root.Snapshot()
	var requests [rpcServicesOwnerCapacity + 1]resourcev4.Request
	var refs [rpcServicesOwnerCapacity + 1]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		var err error
		requests[i], err = batch.request(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	// The enclosing admission owns this separate non-RPC responsibility.
	requests[batch.count] = resourcev4.Request{Owner: c.Owner, Charge: resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1}}
	if f.root.Snapshot() != before {
		t.Fatal("preparation admitted a second budget")
	}
	if err := f.root.ReserveBatch(requests[:batch.count+1], refs[:batch.count+1]); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	admitted := f.root.Snapshot()
	r, err := batch.adopt(refs[:batch.count])
	if err != nil {
		t.Fatal(err)
	}
	if after := f.root.Snapshot(); after.Charged != admitted.Charged || after.Reservations != admitted.Reservations {
		t.Fatal("adoption admitted duplicate backing", admitted, after)
	}
	if _, err := batch.adopt(refs[:batch.count]); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("reused original admission", err)
	}
	if p.rpc != r {
		t.Fatal("detached original application graph")
	}
}

func TestRPCServicesCombinedAdmissionRollsBackEveryOwner(t *testing.T) {
	f, p, c := rpcServicesPlanFixture(t)
	var batch rpcServicesBatch
	if err := prepareRPCServicesBatch(&batch, p, c, nil); err != nil {
		t.Fatal(err)
	}
	defer batch.release()
	var requests [rpcServicesOwnerCapacity + 1]resourcev4.Request
	var refs [rpcServicesOwnerCapacity + 1]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		var err error
		requests[i], err = batch.request(i)
		if err != nil {
			t.Fatal(err)
		}
	}
	before := f.root.Snapshot()
	requests[batch.count] = resourcev4.Request{Owner: c.Owner, Charge: before.Limit}
	if err := f.root.ReserveBatch(requests[:batch.count+1], refs[:batch.count+1]); !errors.Is(err, resourcev4.ErrCapacity) {
		t.Fatal(err)
	}
	if after := f.root.Snapshot(); after != before {
		t.Fatal("failed enclosing owner left partial RPC admission", before, after)
	}
	for _, ref := range refs {
		if ref != (resourcev4.Reference{}) {
			t.Fatal("failed batch exposed an owner")
		}
	}
	if p.rpc != nil || p.claimed || p.closed {
		t.Fatal("failed batch consumed the application plan")
	}
}

package sessionv4

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func fillAdmissionReferences(t *testing.T, ref resourcev4.Reference) []resourcev4.Reference {
	t.Helper()
	var held []resourcev4.Reference
	for {
		alias, err := ref.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, alias)
	}
	t.Cleanup(func() {
		for _, alias := range held {
			alias.Release()
		}
	})
	return held
}

func TestControllerHeadroomAdmitsTransportAtFullReferences(t *testing.T) {
	for _, services := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport", true: "delegated_services"}[services], func(t *testing.T) {
			f := admissionIntegration(t, context.Background(), "preauthorized_pool")
			if services {
				ef := &executorFixture{root: f.root, config: ApplicationExecutorConfig{Running: 4, ResidentRunning: 3, RuntimeBytes: 8192, RuntimeBytesPerTask: 16384}}
				charge, err := ApplicationExecutorCharge(ef.config)
				if err != nil {
					t.Fatal(err)
				}
				ef.executor, err = NewApplicationExecutor(ef.config, ef.reserve(t, 1, charge))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ef.executor.Close(); awaitApplicationTask(t, ef.executor.Done()) })
				plan := newStreamHandlerTestPlan(t, ef, StreamHandlerPlanConfig{RuntimeBytes: 8192, Handlers: []RawStreamHandlerConfig{{Kind: "test/service", Slots: 2,
					Delegated: &DelegatedStreamService{Options: delegatedRawOptions(), Setup: func(context.Context, any, []byte) (DelegatedStreamServe, error) {
						return func(context.Context, net.Conn) error { return nil }, nil
					}}}}})
				f.config.Core.Streams = factoryStreamConfig()
				f.config.Core.Handlers = SessionStreamHandlerConfig{Concurrency: 2, TimeoutMS: 1000, RuntimeBytes: 8192, RuntimeBytesPerInvocation: 16384, Plan: plan}
			}
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope})
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			parents, preauth, session := h.coreBorrows, h.preauth, h.sessionSlot
			floors := h.serviceFloors
			if services && len(floors) != 2 {
				t.Fatal("delegated service floor was not reserved before Acquire")
			}
			fillAdmissionReferences(t, f.environment)
			full := f.root.Snapshot()
			f.config.headroom = h
			a := f.reserve(t, context.Background())
			for _, ref := range append(parents[:], preauth, session) {
				if ref != (resourcev4.Reference{}) && !errors.Is(ref.Check(), resourcev4.ErrOwner) {
					t.Fatal("original parent alias survived transfer")
				}
				ref.Release()
			}
			h.close()
			a.mu.Lock()
			err = a.checkLocked()
			a.mu.Unlock()
			if f.root.Snapshot() != full || err != nil {
				t.Fatal("transport adoption replaced or released original references", err)
			}
			if services && &a.core.serviceFloors[0] != &floors[0] {
				t.Fatal("delegated service floor was replaced")
			}
		})
	}
}

// This covers the RPC/core constructor boundary separately from the later
// credential-specific namespace subscriptions and irreversible admission gate.
func TestControllerHeadroomBuildsRPCAtFullReferences(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "unary", true: "stream"}[stream], func(t *testing.T) {
			fixture := sessionWorkloadFixture
			if stream {
				fixture = sessionStreamWorkloadFixture
			}
			f, e := fixture(t)
			key := admissionResourceKey(f.owner, 202)
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: key, Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			network, receive, guards, workload := h.network, h.receivePool, h.receiveProtection, h.workloads
			queries := h.queries
			executor := f.config.Application.executor
			if snapshot := executor.Snapshot(); snapshot.QueryOwners != 2 || snapshot.QueryReady != 0 || snapshot.QueryRunning != 0 {
				t.Fatal("pre-Acquire queries did not remain dormant", snapshot)
			}
			var group sdkQueryGroup
			for i := range 2 {
				ref, err := f.root.Reserve(admissionResourceKey(f.owner, uint32(241+i)), sdkQueryProtectionCharge())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(ref.Release)
				borrow, err := f.environment.Borrow()
				if err != nil {
					t.Fatal(err)
				}
				guard, err := executor.protectSDKQuery(&group, ref, borrow)
				borrow.Release()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(guard.Close)
			}
			aliases := h.rpcReferences
			fillAdmissionReferences(t, f.environment)
			full := f.root.Snapshot()
			f.config.headroom = h
			var batch sessionAdmissionBatch
			if err := batch.prepare(f.config, f.root, key, f.environment, f.scope); err != nil {
				t.Fatal("preparation borrowed another parent", err)
			}
			defer batch.release()
			var requests [sessionAdmissionOwnerCapacity + 2]resourcev4.Request
			var refs [sessionAdmissionOwnerCapacity + 2]resourcev4.Reference
			defer func() {
				for _, ref := range refs {
					ref.Release()
				}
			}()
			for i := range batch.count {
				requests[i], err = batch.request(i)
				if err != nil {
					t.Fatal(err)
				}
			}
			metadata, initial, err := sessionAdmissionCharges(f.config)
			if err != nil {
				t.Fatal(err)
			}
			n := batch.count
			requests[n] = resourcev4.Request{Owner: admissionResourceKey(key, coreOwnerCapacity), Charge: metadata, Accounts: batch.core.accounts[:batch.core.accountCount]}
			requests[n+1] = resourcev4.Request{Owner: admissionResourceKey(key, coreOwnerCapacity+1), Charge: initial, Accounts: []resourcev4.Account{f.scope.Tenant}}
			if err := h.claim(requests[:n+2], refs[:n+2], &batch, f.preauth); err != nil {
				t.Fatal("claim required another reference", err)
			}
			for _, ref := range aliases.aliases() {
				if *ref != (resourcev4.Reference{}) && !errors.Is(ref.Check(), resourcev4.ErrOwner) {
					t.Fatal("stale RPC alias remained live")
				}
			}
			aliases.close()
			r, err := batch.rpc.adopt(refs[batch.core.count:n])
			if err != nil {
				t.Fatal("RPC assembly required another reference", err)
			}
			if r.network != network || r.receivePool != receive || r.receiveProtection != guards || batch.rpc.workloadHeadroom != workload {
				t.Fatal("RPC assembly replaced the original graph")
			}
			if f.config.Application.queries != queries || f.config.Application.queryPreparation != nil || executor.Snapshot().QueryOwners != 4 {
				t.Fatal("RPC assembly replaced its original fixed query positions")
			}
			if err := workload.slots[0].network.CheckOriginal(r.network, stream); err != nil {
				t.Fatal("RPC assembly lost original workload capacity", err)
			}
			h.close()
			if f.root.Snapshot() != full {
				t.Fatal("RPC assembly changed original resource accounting", full, f.root.Snapshot())
			}
		})
	}
}

func TestControllerHeadroomRejectsChangedPreauthAlias(t *testing.T) {
	f, e := sessionStreamWorkloadFixture(t)
	before := f.root.Snapshot()
	h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	replacement, err := f.preauth.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	reserved := f.root.Snapshot()
	f.config.headroom = h
	hostWorkloadPlan(t, f, e)
	a, err := NewSessionAdmissionReservation(context.Background(), f.config, f.prepared, f.trust.subscriptions[0], f.root, admissionResourceKey(f.owner, 202), f.environment, replacement, f.scope, nil, nil)
	if a != nil || !errors.Is(err, resourcev4.ErrOwner) || h.claimed || f.root.Snapshot() != reserved {
		t.Fatal("changed preauth source consumed original admission", err)
	}
	replacement.Release()
	h.close()
	if f.root.Snapshot() != before {
		t.Fatal("rejected source retained original references", before, f.root.Snapshot())
	}
}

func TestControllerHeadroomReferenceShortageUnwindsParents(t *testing.T) {
	for _, free := range []int{1, 3, 30, -1} {
		f, e := sessionStreamWorkloadFixture(t)
		if free == -1 {
			before := f.root.Snapshot()
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if err != nil {
				t.Fatal(err)
			}
			free = int(f.root.Snapshot().References-before.References) - 1
			h.close()
			if f.root.Snapshot() != before {
				t.Fatal("unused headroom retained references")
			}
		}
		held := fillAdmissionReferences(t, f.environment)
		for _, alias := range held[:free] {
			alias.Release()
		}
		before := f.root.Snapshot()
		h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
		if h != nil || !errors.Is(err, resourcev4.ErrCapacity) || f.root.Snapshot() != before {
			t.Fatal("partial reference admission retained responsibility", free, err, before, f.root.Snapshot())
		}
	}
}

func TestControllerHeadroomQueryShortageFailsBeforeAcquire(t *testing.T) {
	f, e := sessionWorkloadFixture(t)
	executor := f.config.Application.executor
	var group sdkQueryGroup
	for i := range 3 {
		ref, err := f.root.Reserve(admissionResourceKey(f.owner, uint32(241+i)), sdkQueryProtectionCharge())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ref.Release)
		borrow, err := f.environment.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		guard, err := executor.protectSDKQuery(&group, ref, borrow)
		borrow.Release()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(guard.Close)
	}
	before := f.root.Snapshot()
	h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
	if h != nil || err == nil || f.root.Snapshot() != before || executor.Snapshot().QueryOwners != 3 || f.config.Application.queryPreparation != nil {
		t.Fatal("query shortage consumed partial original admission", err)
	}
}

func TestControllerHeadroomAdmitsServicesAtFullBytesAndReferences(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "unary", true: "stream"}[stream], func(t *testing.T) {
			fixture := sessionWorkloadFixture
			if stream {
				fixture = sessionStreamWorkloadFixture
			}
			f, e := fixture(t)
			h, err := reserveSessionHeadroom(SourceConnectConfig{Admission: f.config, Root: f.root, Owner: admissionResourceKey(f.owner, 202), Environment: f.environment, Preauth: f.preauth, Scope: f.scope}, e)
			if err != nil {
				t.Fatal(err)
			}
			defer h.close()
			workload, network, pool := h.workloads, h.network, h.receivePool
			before := f.root.Snapshot()
			fill, err := f.root.Reserve(admissionResourceKey(f.owner, 240), resourcev4.Vector{resourcev4.SDKBytes: before.Limit[resourcev4.SDKBytes] - before.Charged[resourcev4.SDKBytes]})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(fill.Release)
			fillAdmissionReferences(t, fill)
			full := f.root.Snapshot()
			f.config.headroom = h
			hostWorkloadPlan(t, f, e)
			a := f.reserve(t, context.Background())
			if a.application.rpc.initialWorkloads[0] != workload || a.application.rpc.network != network || a.core.receivePool != pool || f.root.Snapshot() != full {
				t.Fatal("original services admission replaced or recharged capacity", full, f.root.Snapshot())
			}
			if workload.slots[0].authority == nil || a.claimed || a.committed || a.activated || f.provider.reads.Load() != 0 || f.provider.writes.Load() != 0 {
				t.Fatal("resource transfer crossed original authority or provider boundary")
			}
			h.close()
			if f.root.Snapshot() != full {
				t.Fatal("stale headroom released adopted resources")
			}
		})
	}
}

package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

type managementAccessSink struct {
	wire []byte
	full bool
}

func (s *managementAccessSink) TryAcceptManagement(ctx context.Context, wire []byte, gate rpcv4.ManagementPublicationGate) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.full {
		return 0, cryptov4.ErrCapacity
	}
	transfer := func() error { s.wire = append(s.wire[:0], wire...); return nil }
	if gate != nil {
		if err := gate(transfer); err != nil {
			return 0, err
		}
	} else {
		_ = transfer()
	}
	return uint64(len(s.wire)), nil
}

func notificationManagementFixture(t *testing.T, f *notificationFixture) (*RPCServices, *rpcv4.ExecutionManagementWire, *managementAccessSink) {
	t.Helper()
	// Isolate the real resolver and wire path from channel opening. The full M
	// channel's allocation, workers and transport are covered by runtime tests.
	r := &RPCServices{plan: f.plan, executionRegistry: f.d.executionRegistry, session: testSessionContract(t, protocolv4.DHProfileX25519, "execution", 65536, 16, 0, 5000, 1<<20).Contract}
	r.refs[rpcServicesMetadata] = f.d.reservation
	sink := &managementAccessSink{}
	charge, err := rpcv4.ExecutionManagementWireCharge(4096)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := rpcv4.NewExecutionManagementWire(rpcv4.ExecutionManagementWireConfig{Clock: f.trust.clock, Sink: sink, RuntimeBytes: 4096}, f.f.reserve(t, 1, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wire.Close)
	return r, wire, sink
}

func managementAccessReply(t *testing.T, f *notificationFixture, r *RPCServices, wire *rpcv4.ExecutionManagementWire, sink *managementAccessSink, target rpcv4.ExecutionTarget, cancel bool) rpcv4.ManagementReply {
	t.Helper()
	if _, err := wire.TryRequest(context.Background(), cancel, target, 3000, executionDispatchAccess{f.f.executor.reservation}); err != nil {
		t.Fatal(err)
	}
	reply, err := wire.HandleRequest(context.Background(), r, sink.wire)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func managementAccessResult(t *testing.T, wire *rpcv4.ExecutionManagementWire, sink *managementAccessSink, reply rpcv4.ManagementReply) rpcv4.ManagementResponse {
	t.Helper()
	if err := reply.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, _, disposition, err := wire.AcceptResponse(sink.wire)
	if err != nil || disposition != rpcv4.ManagementResponseDelivered {
		t.Fatal(result, disposition, err)
	}
	return result
}

func TestManagementHistoryUsesAuthenticatedIdentityAndIndependentPermissions(t *testing.T) {
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { return nil })
	target, err := f.executionNotify(t, 1, "completed")
	if err != nil {
		t.Fatal(err)
	}
	f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
	r, wire, sink := notificationManagementFixture(t, f)
	call := func(target rpcv4.ExecutionTarget, cancel bool) rpcv4.ManagementResponse {
		return managementAccessResult(t, wire, sink, managementAccessReply(t, f, r, wire, sink, target, cancel))
	}
	if got := call(target, false); got.Status != "unauthorized" || got.Observation.Found {
		t.Fatal("dispatch permission silently granted history access", got)
	}
	if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, true, false); err != nil {
		t.Fatal(err)
	}
	if err := f.plan.lease.SetNotificationAccess(f.policy.Namespace, f.policy.Type, false); err != nil {
		t.Fatal(err)
	}
	f.routes.Close()
	if got := call(target, false); got.Status != "ok" || got.Observation.State != rpcv4.ExecutionCompleted {
		t.Fatal("old exact contract became unqueryable", got)
	}
	if got := call(target, true); got.Status != "unauthorized" {
		t.Fatal("query access silently granted cancellation", got)
	}
	for _, change := range []func(*rpcv4.ExecutionTarget){
		func(v *rpcv4.ExecutionTarget) { v.Service.Tenant = "other" },
		func(v *rpcv4.ExecutionTarget) { v.Service.Audience = "other" },
		func(v *rpcv4.ExecutionTarget) { v.Service.Namespace = "other" },
		func(v *rpcv4.ExecutionTarget) { v.Caller.Authority[0]++ },
		func(v *rpcv4.ExecutionTarget) { v.Caller.Subject = "other" },
	} {
		forged := target
		change(&forged)
		if got := call(forged, false); got.Status != "unauthorized" || got.Observation.Found {
			t.Fatal("wire fields selected another history authority", got)
		}
	}
	missing := target
	missing.Operation[31]++
	if got := call(missing, false); got.Status != "history_unknown" || got.Observation.Found || got.Observation.Reason != "history_unknown" {
		t.Fatal("current empty RAM branch invented original continuity", got)
	}
	conflict := target
	conflict.RequestDigest[0]++
	if got := call(conflict, false); got.Status != "operation_conflict" {
		t.Fatal("original digest conflict was lost", got)
	}
}

func TestManagementHistoryRevocationBeforeResponsePublication(t *testing.T) {
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { return nil })
	target, err := f.executionNotify(t, 1, "completed")
	if err != nil {
		t.Fatal(err)
	}
	f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
	r, wire, sink := notificationManagementFixture(t, f)
	for _, conflict := range []bool{false, true} {
		if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, true, false); err != nil {
			t.Fatal(err)
		}
		request := target
		if conflict {
			request.RequestDigest[0]++
		}
		reply := managementAccessReply(t, f, r, wire, sink, request, false)
		sink.full = true
		if err := reply.Publish(context.Background()); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal(err)
		}
		if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, false, false); err != nil {
			t.Fatal(err)
		}
		sink.full = false
		if got := managementAccessResult(t, wire, sink, reply); got.Status != "unauthorized" || got.Observation.Found || got.Observation.State != 0 {
			t.Fatal("waiting response disclosed revoked history", got)
		}
	}
}

func TestManagementHistoryCancelsQueuedWorkAtSaturatedRoot(t *testing.T) {
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { t.Error("canceled execution ran"); return nil })
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	defer a.Close()
	defer b.Close()
	target, err := f.executionNotify(t, 1, "queued")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.plan.lease.SetExecutionHistoryAccess(f.policy.Namespace, false, true); err != nil {
		t.Fatal(err)
	}
	r, wire, sink := notificationManagementFixture(t, f)
	before := f.f.root.Snapshot()
	var remaining resourcev4.Vector
	for dimension := range remaining {
		remaining[dimension] = before.Limit[dimension] - before.Charged[dimension]
	}
	hold := f.f.reserve(t, 1, remaining)
	defer hold.Release()
	got := managementAccessResult(t, wire, sink, managementAccessReply(t, f, r, wire, sink, target, true))
	if got.Status != "ok" || got.Cancel.Kind != "requested" || !got.Observation.CancelRequested || !got.Observation.WorkActive {
		t.Fatal("protected cancellation did not reach original queued execution", got)
	}
	f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
}

type managementRingAuthorization struct {
	testAuthorization
	mu sync.Mutex
}

func (a *managementRingAuthorization) Check() error { a.mu.Lock(); defer a.mu.Unlock(); return nil }

func TestManagementPublicationGuardUsesFinalOriginalRingGate(t *testing.T) {
	authority := &managementRingAuthorization{}
	charge, _ := RPCBatchWriterCharge(4096)
	f := newServiceFixtureResources(t, 1, [3]uint32{1}, 16384, 2, authority, true, []resourcev4.Vector{StreamOwnershipCharge(), charge})
	q, _ := f.open(t, BusinessStream, 64, &serviceTestWriter{frames: make(chan []byte, 16)})
	owner := ownFixtureStream(t, f, OpenHandle{f.local.admission, f.flows[0].receive.scope}, f.reserve(t, StreamOwnershipCharge()))
	writer, err := newManagementBatchWriter(owner, f.reserve(t, charge), 4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close(); q.Stop(cryptov4.ErrClosed); _ = writer.Retire() })
	denied := func(func() error) error { return rpcv4.ErrExecutionUnauthorized }
	if _, err := writer.TryAcceptManagement(context.Background(), []byte{0, 1, 2}, denied); !errors.Is(err, rpcv4.ErrExecutionUnauthorized) || owner.AcceptedBytes() != 0 {
		t.Fatal("failed permission consumed ring bytes", err)
	}
	guard := func(transfer func() error) error {
		authority.mu.Lock()
		defer authority.mu.Unlock()
		return transfer()
	}
	if tail, err := writer.TryAcceptManagement(context.Background(), []byte{0, 1, 2}, guard); err != nil || tail != 3 || owner.AcceptedBytes() != 3 {
		t.Fatal("final guarded copy reentered crypto authorization", tail, err)
	}
}

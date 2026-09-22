package sessionv4

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func notificationHistoryFixture(t *testing.T, f *executorFixture, clock *timev4.Clock, namespace string) (*rpcv4.VolatileExecutions, *rpcv4.ServiceRegistry) {
	t.Helper()
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{120}, Backing: [16]byte{120}, Kind: 12}
	hc := rpcv4.VolatileExecutionConfig{Root: f.root, Owner: owner, Clock: clock, Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: namespace}, CallerAuthorities: [][32]byte{{8}}, Records: 16, Active: 4, TaskCharge: f.executor.TaskCharge(), RuntimeBytes: 4096, WorkRuntimeBytes: 4096, ResultRuntimeBytes: 4096}
	charge, err := rpcv4.VolatileExecutionsCharge(hc)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := f.root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	history, err := rpcv4.NewVolatileExecutions(hc, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(history.Close)
	owner.Instance, owner.Backing = [16]byte{121}, [16]byte{121}
	rc := rpcv4.ServiceRegistryConfig{Root: f.root, Owner: owner, Entries: 4, RuntimeBytes: 4096}
	charge, err = rpcv4.ServiceRegistryCharge(rc)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = f.root.Reserve(owner, charge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ref.Release)
	registry, err := rpcv4.NewServiceRegistry(rc, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(registry.Close)
	if err = registry.Bind(rpcv4.ServiceBinding{Authority: rpcv4.ServiceAuthority{Tenant: "tenant", Audience: "audience", Namespace: namespace}, History: history}); err != nil {
		t.Fatal(err)
	}
	return history, registry
}

func (f *notificationFixture) executionNotify(t *testing.T, id byte, payload string) (rpcv4.ExecutionTarget, error) {
	t.Helper()
	var operation [32]byte
	binary.BigEndian.PutUint64(operation[:8], 1500)
	operation[31] = id
	fields := protocolv4.ApplicationHeaderFields{OperationID: operation, Type: f.policy.Type, PayloadBytes: uint32(len(payload)), DeadlineAtMS: 2000, ServiceContractDigest: f.policy.Digest}
	var header [512]byte
	_, h, err := f.codec.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	fields.RequestDigest, err = protocolv4.ComputeExecutionRequestDigest(h, f.contract, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := f.codec.Encode(header[:], "execution_notify", fields)
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, n+2+len(payload))
	prefix, err := f.codec.EncodeNotifyPrefix(wire, header[:n])
	if err != nil {
		t.Fatal(err)
	}
	copy(wire[prefix:], payload)
	for _, b := range wire {
		if err := f.receiver.Feed([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	target := rpcv4.ExecutionTarget{Service: rpcv4.ExecutionService{Tenant: "tenant", Audience: "audience", Namespace: f.policy.Namespace}, Caller: rpcv4.ExecutionPrincipal{Authority: [32]byte{8}, Subject: "caller"}, Operation: operation, ContractDigest: f.policy.Digest, RequestDigest: fields.RequestDigest}
	return target, f.d.Admit(f.receiver)
}

func (f *notificationFixture) executionState(t *testing.T, target rpcv4.ExecutionTarget) rpcv4.ExecutionObservation {
	t.Helper()
	state, err := f.history.Query(target, rpcv4.ExecutionContinuity{}, executionDispatchAccess{f.f.executor.reservation})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestNotificationExecutionOneBusinessDispatchAndFanout(t *testing.T) {
	var calls, observations atomic.Uint32
	f := newNotificationFixtureWithExecution(t, func(_ context.Context, request NotificationRequest) error {
		if request.ApplicationContext != "notification context" || request.Binding.ApplicationProfile != "execution" {
			t.Error("lost authenticated application context")
		}
		bytes, _, err := request.Input.Bytes()
		if err != nil || string(bytes) != "event" {
			t.Error("wrong execution input", err)
		}
		bytes[0] = 'X'
		calls.Add(1)
		return nil
	})
	f.subscribe(t, NotificationDropNewest, notificationStrings(func(_ context.Context, value string) error {
		if value != "event" {
			t.Error("handler mutated observer input", value)
		}
		observations.Add(1)
		return nil
	}))
	target, err := f.executionNotify(t, 1, "event")
	if err != nil {
		t.Fatal(err)
	}
	f.until(t, func() bool { return observations.Load() == 1 && !f.executionState(t, target).WorkActive })
	if got := f.executionState(t, target); got.State != rpcv4.ExecutionCompleted || !got.Dispatched || got.ResultAvailable || got.ResultDeleted || got.ResultBytes != 0 {
		t.Fatal("NOTIFY did not retain its response-free execution fact", got)
	}
	if _, err = f.executionNotify(t, 1, "event"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.executionNotify(t, 1, "changed"); !errors.Is(err, rpcv4.ErrExecutionConflict) {
		t.Fatal("same key with another digest did not conflict", err)
	}
	if got := f.receiver.Status(); got.Rejected != 1 || got.LastRejection != "operation_conflict" {
		t.Fatal("execution refusal missing from finite local receiver status", got)
	}
	if _, err = f.executionNotify(t, 2, "event"); err != nil {
		t.Fatal("a refused message blocked the next valid notification", err)
	}
	f.until(t, func() bool { return calls.Load() == 2 && observations.Load() == 2 })
	if _, err = f.d.Subscribe(0, NotificationLatestPending, notificationStrings(func(context.Context, string) error { return nil })); err == nil {
		t.Fatal("execution accepted latest_pending")
	}
}

func TestNotificationExecutionDoesNotFanoutToLaterSubscription(t *testing.T) {
	var calls, early, late atomic.Uint32
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { calls.Add(1); return nil })
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	defer a.Close()
	defer b.Close()
	f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { early.Add(1); return nil }))
	target, err := f.executionNotify(t, 1, "queued")
	if err != nil {
		t.Fatal(err)
	}
	f.subscribe(t, NotificationDropNewest, notificationStrings(func(context.Context, string) error { late.Add(1); return nil }))
	if got := f.executionState(t, target); !got.WorkActive || got.Dispatched {
		t.Fatal("queued execution ran before a real ordinary slot", got)
	}
	a.Close()
	b.Close()
	f.until(t, func() bool { return early.Load() == 1 && !f.executionState(t, target).WorkActive })
	if calls.Load() != 1 || late.Load() != 0 {
		t.Fatal("execution replayed an old notification", calls.Load(), early.Load(), late.Load())
	}
	if _, err = f.executionNotify(t, 2, "new"); err != nil {
		t.Fatal(err)
	}
	f.until(t, func() bool { return early.Load() == 2 && late.Load() == 1 })
}

func TestNotificationExecutionFullCapacityStillDeduplicates(t *testing.T) {
	var calls atomic.Uint32
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { calls.Add(1); return nil })
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	defer a.Close()
	defer b.Close()
	var targets [4]rpcv4.ExecutionTarget
	for index := range targets {
		var err error
		targets[index], err = f.executionNotify(t, byte(index+1), "queued")
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.executionNotify(t, 1, "queued"); err != nil {
		t.Fatal("duplicate acquired another execution slot", err)
	}
	target, err := f.executionNotify(t, 5, "queued")
	if !errors.Is(err, rpcv4.ErrCapacity) || f.executionState(t, target).Found {
		t.Fatal("capacity refusal registered another operation", err)
	}
	a.Close()
	b.Close()
	f.until(t, func() bool {
		for _, target := range targets {
			if f.executionState(t, target).WorkActive {
				return false
			}
		}
		return true
	})
	if calls.Load() != 4 {
		t.Fatal("unexpected business dispatch count", calls.Load())
	}
}

func TestNotificationExecutionCloseRetainsRealTaskAndInput(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var borrowed rpcv4.InputBorrow
	var ctx context.Context
	f := newNotificationFixtureWithExecution(t, func(c context.Context, request NotificationRequest) error {
		borrowed, ctx = request.Input, c
		close(entered)
		<-release
		bytes, _, err := borrowed.Bytes()
		if err != nil || string(bytes) != "held" {
			t.Error("Session close refunded live execution input", err)
		}
		return nil
	})
	target, err := f.executionNotify(t, 1, "held")
	if err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	f.plan.Close()
	f.d.Advance()
	if ctx.Err() == nil || !f.executionState(t, target).WorkActive {
		t.Fatal("close did not preserve canceled real work")
	}
	select {
	case <-f.d.done:
		t.Fatal("close completed while the business handler was still running")
	default:
	}
	once.Do(func() { close(release) })
	f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
	if got := f.executionState(t, target); got.State != rpcv4.ExecutionCompleted {
		t.Fatal("Session close erased a real late completion", got)
	}
	if _, _, err := borrowed.Bytes(); err == nil {
		t.Fatal("retained request input alias still readable after actual task exit")
	}
}

func TestNotificationExecutionQueuedRevocationSealsDispatch(t *testing.T) {
	var calls atomic.Uint32
	f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error { calls.Add(1); return nil })
	a, b := holdOrdinaryPermit(t, f.f), holdOrdinaryPermit(t, f.f)
	defer a.Close()
	defer b.Close()
	target, err := f.executionNotify(t, 1, "queued")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.plan.lease.SetNotificationAccess(f.policy.Namespace, f.policy.Type, false); err != nil {
		t.Fatal(err)
	}
	f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
	if got := f.executionState(t, target); got.State != rpcv4.ExecutionFailed || got.Dispatched || calls.Load() != 0 {
		t.Fatal("revoked queued work dispatched", got, calls.Load())
	}
}

func TestNotificationExecutionHandlerExitRetainsUnknown(t *testing.T) {
	for _, outcome := range []string{"error", "panic", "goexit"} {
		t.Run(outcome, func(t *testing.T) {
			var calls atomic.Uint32
			f := newNotificationFixtureWithExecution(t, func(context.Context, NotificationRequest) error {
				calls.Add(1)
				switch outcome {
				case "panic":
					panic("private failure")
				case "goexit":
					runtime.Goexit()
				}
				return errors.New("side effect outcome uncertain")
			})
			target, err := f.executionNotify(t, 1, "event")
			if err != nil {
				t.Fatal(err)
			}
			f.until(t, func() bool { return !f.executionState(t, target).WorkActive })
			if got := f.executionState(t, target); got.State != rpcv4.ExecutionUnknown || !got.Dispatched {
				t.Fatal("handler exit invented a business outcome", got)
			}
			if _, err = f.executionNotify(t, 1, "event"); err != nil || calls.Load() != 1 {
				t.Fatal("unknown execution was redispatched", calls.Load(), err)
			}
		})
	}
}

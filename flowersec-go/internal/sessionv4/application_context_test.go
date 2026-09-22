package sessionv4

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
)

func TestInvocationPreparationKeepsOriginalTryNowAndExpiredOrigin(t *testing.T) {
	_, r, route := shortCallerFixture(t)
	backing := r.plan.reservation
	ctx, exit, err := enterApplicationContext(context.Background(), r.plan.executor, ordinaryApplicationLane, ApplicationResident, backing, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	o, err := r.PrepareUnaryContext(ctx, route, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, true, func(context.Context, rpcv4.InputBorrow) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if o.header.Fields().AdmissionMode != 1 || o.dependencies.count != 1 {
		t.Fatal("lost original nested admission")
	}
	exit()
	if _, err = r.PrepareUnaryContext(ctx, route, nil, rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, true, func(context.Context, rpcv4.InputBorrow) error { return nil }); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal("exited callback created work", err)
	}
	if started := o.Start(context.Background()); !started.NotAdmitted || !errors.Is(started.Error, ErrApplicationDependency) || started.Call != nil {
		t.Fatal("Background replaced original preparation origin", started)
	}
	if r.network.Snapshot().OutgoingGeneral != 0 {
		t.Fatal("failed nested admission allocated a request")
	}
}

func TestInvocationReferencesRemainChargedThroughAcceptedChild(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.executor, ordinaryApplicationLane, ApplicationShort, backing, nil)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot().Charged
	exit()
	backing.Release()
	if f.root.Snapshot().Charged != before {
		t.Fatal("parent exit refunded a real child dependency")
	}
	dependencies.release()
	if f.root.Snapshot().Charged == before {
		t.Fatal("last dependency did not release metadata")
	}
	if _, err := checkApplicationContext(ctx); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal(err)
	}
}

func TestCompletionDependencyProtectsFutureServiceWithoutRunningIt(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 2, 4)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 16384, resourcev4.Items: 1})
	reserve := func() *CompletionReservation {
		p, err := e.ReserveCompletion(f.reserve(t, 1, e.CompletionCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	parent, child, other, rejected := reserve(), reserve(), reserve(), reserve()
	entered, release := make(chan context.Context, 1), make(chan struct{})
	defer close(release)
	parentTask, err := parent.Submit(func() error {
		ctx, exit, err := enterApplicationContext(context.Background(), e, completionApplicationLane, ApplicationShort, backing, nil)
		if err != nil {
			return err
		}
		defer exit()
		entered <- ctx
		<-release
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := <-entered
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.release()
	claim, err := child.claimDependency(&dependencies, sessionTestClock(t))
	if err != nil || claim == nil {
		t.Fatal(claim, err)
	}
	if s := e.Snapshot(); s.CompletionRunning != 1 || s.CompletionClaims != 1 {
		t.Fatal(s)
	}
	if _, err = rejected.claimDependency(&dependencies, sessionTestClock(t)); !errors.Is(err, ErrCompletionDependency) {
		t.Fatal("oversubscribed future Completion service", err)
	}
	otherEntered := make(chan struct{})
	otherTask, err := other.Submit(func() error { close(otherEntered); return nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-otherEntered:
		t.Fatal("ordinary result stole future service claim")
	default:
	}
	childTask, err := child.Submit(func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = childTask.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if err = otherTask.Wait(wait); err != nil {
		t.Fatal(err)
	}
	if s := e.Snapshot(); s.CompletionRunning != 1 || s.CompletionClaims != 0 {
		t.Fatal(s)
	}
	_ = parentTask
}

func TestOrdinaryInvocationDoesNotClaimCompletionService(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 16384, resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.executor, ordinaryApplicationLane, ApplicationResident, backing, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.release()
	p, err := f.executor.ReserveCompletion(f.reserve(t, 1, f.executor.CompletionCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if claim, err := p.claimDependency(&dependencies, sessionTestClock(t)); err != nil || claim != nil {
		t.Fatal("ordinary nested call consumed Completion claim", claim, err)
	}
}

func TestCompletionDependencyRejectedRejoinPreservesOriginalPromise(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 2, 3)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 16384, resourcev4.Items: 1})
	reserve := func() *CompletionReservation {
		p, err := e.ReserveCompletion(f.reserve(t, 1, e.CompletionCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return p
	}
	release := make(chan struct{})
	defer close(release)
	start := func(parent context.Context) context.Context {
		entered := make(chan context.Context, 1)
		_, err := reserve().Submit(func() error {
			ctx, exit, err := enterApplicationContext(parent, e, completionApplicationLane, ApplicationShort, backing, nil)
			if err != nil {
				return err
			}
			defer exit()
			entered <- ctx
			<-release
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case ctx := <-entered:
			return ctx
		case <-time.After(3 * time.Second):
			t.Fatal("parent never entered")
			return nil
		}
	}
	first, err := captureApplicationDependencies(start(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	child := reserve()
	clock := sessionTestClock(t)
	claim, err := child.claimDependency(&first, clock)
	if err != nil {
		t.Fatal(err)
	}
	child.releaseDependencyClaim()
	claim.mu.Lock()
	states, count, deadline, window := claim.states, claim.count, claim.deadline, claim.window
	claim.mu.Unlock()
	shorter, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	second, err := captureApplicationDependencies(start(shorter))
	if err != nil {
		t.Fatal(err)
	}
	defer second.release()
	if _, err = child.claimDependency(&second, clock); !errors.Is(err, ErrCompletionDependency) {
		t.Fatal("rejoin oversubscribed actual Completion service", err)
	}
	claim.mu.Lock()
	unchanged := claim.states == states && claim.count == count && claim.deadline == deadline && claim.window == window
	claim.mu.Unlock()
	if !unchanged {
		t.Fatal("rejected observer changed the first promise")
	}
	if s := e.Snapshot(); s.CompletionRunning != 2 || s.CompletionClaims != 0 {
		t.Fatal(s)
	}
}

func TestCompletionDependencyRejoinChecksOriginalWindowBeforeCoordinator(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 16384, resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.executor, completionApplicationLane, ApplicationShort, backing, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	dependencies, err := captureApplicationDependencies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer dependencies.release()
	p, err := f.executor.ReserveCompletion(f.reserve(t, 1, f.executor.CompletionCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var now uint64
	clock := newTestRekeyClock(t, RekeyClockRate{Numerator: 1, Denominator: 10000, QuantizationMS: 2}, func() (RekeyClockSample, error) {
		return RekeyClockSample{Milliseconds: now, Incarnation: [16]byte{1}}, nil
	})
	claim, err := p.claimDependency(&dependencies, clock)
	if err != nil {
		t.Fatal(err)
	}
	p.releaseDependencyClaim()
	now = maxCompletionDependencyWaitMS
	if _, err = p.claimDependency(&dependencies, clock); !errors.Is(err, ErrCompletionDependency) {
		t.Fatal("rejoin renewed the original wait window", err)
	}
	select {
	case <-claim.expired:
	default:
		t.Fatal("expired original wait was not detached")
	}
	if s := f.executor.Snapshot(); s.CompletionClaims != 0 || s.CompletionReserved != 1 {
		t.Fatal("wait expiry canceled the independent original future", s)
	}
}

func TestInvocationCleanupKeepsOriginalClosedDomainResponsibility(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
	f.root.Close()
	ctx, exit, err := enterCleanupApplicationContext(f.executor, backing)
	if err != nil {
		t.Fatal("closed admission prevented original cleanup", err)
	}
	defer exit()
	if _, err = captureApplicationDependencies(ctx); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("cleanup reopened new work", err)
	}
	backing.Release()
	if err = backing.CheckRetained(); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("released backing retained cleanup rights", err)
	}
}

package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func applicationTestPlan(t *testing.T, f *executorFixture, config SessionPlanConfig, accounts ...resourcev4.Account) *SessionPlan {
	t.Helper()
	charge, err := SessionPlanCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1}, accounts...)
	borrow, err := dependencies.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewSessionPlan(config, f.executor, f.reserve(t, 1, charge, accounts...), f.reserve(t, 1, f.executor.TaskCharge(), accounts...), f.reserve(t, 1, f.executor.CompletionCharge(), accounts...), borrow)
	borrow.Release()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := p.releaseAfterCleanup(ctx); err != nil {
			t.Error(err)
			return
		}
		if err := p.Retire(); err != nil {
			p.mu.Lock()
			t.Logf("application retirement state: closed=%t running=%t rpc_preparing=%t registration_preparing=%t started=%t", p.closed, p.running, p.rpcPreparing, p.registrationPreparing, p.started)
			rpc := p.rpc
			p.mu.Unlock()
			if rpc != nil {
				rpc.mu.Lock()
				if !rpc.retired {
					var first, future, caller int
					for _, owner := range rpc.firstFuture.owners {
						if !owner.CleanupComplete() {
							first++
						}
					}
					for channelIndex, channel := range rpc.futureChannels {
						for ownerIndex, owner := range channel.owners {
							if !owner.CleanupComplete() {
								future++
								t.Logf("RPC pending future: channel=%d owner=%d", channelIndex, ownerIndex)
							}
						}
					}
					for _, owner := range rpc.shortCaller {
						if !owner.CleanupComplete() {
							caller++
						}
					}
					t.Logf("RPC retirement state: closed=%t first_binding=%t management=%t management_calls=%d first_owners=%d future_owners=%d caller_owners=%d completion=%t inputs=%t routes=%t incoming=%t outgoing=%t", rpc.closed, rpc.firstBinding, rpc.management != nil, rpc.managementCalls, first, future, caller, rpc.completionFloor.CleanupComplete(), rpc.inputs.CleanupComplete(), rpc.routes.CleanupComplete(), rpc.incoming.CleanupComplete(), rpc.outgoing.CleanupComplete())
				}
				rpc.mu.Unlock()
			}
			t.Error(err)
		}
	})
	return p
}

func TestSessionApplicationFreezesHandlersAndOriginalContext(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 2)
	config := streamHandlerTestConfig()
	var seen any
	config.Handlers[0].AuthorizeOpen = func(_ context.Context, binding any, _ []byte) error { seen = binding; return nil }
	handlers := newStreamHandlerTestPlan(t, f, config)
	var request AuthenticatedRequestContext
	var released atomic.Uint32
	p := applicationTestPlan(t, f, SessionPlanConfig{Handlers: handlers, RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		request = c
		mismatch := c.Binding()
		mismatch.Attempt[0]++
		if _, err := c.ReserveLease(mismatch, nil, func(context.Context) error { return nil }); !errors.Is(err, ErrApplicationAuthorization) {
			t.Error("accepted different original lookup", err)
		}
		lease, err := c.ReserveLease(c.Binding(), "trusted context", func(context.Context) error { released.Add(1); return nil })
		return AuthorizeApplicationResult{Handlers: handlers, Lease: lease}, err
	}})
	if _, err := handlers.Capture("example/raw"); !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal("captured before application authorization", err)
	}
	if err := handlers.claimSession(); err != nil {
		t.Fatal(err)
	}
	p.claimed = true // The aggregate adoption gate is exercised by the real-carrier test.
	binding := ApplicationBinding{Artifact: [32]byte{1}, Attempt: [16]byte{2}}
	if err := p.authorize(context.Background(), binding, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := request.ReserveLease(binding, nil, func(context.Context) error { return nil }); !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal("retained callback capability remained live", err)
	}
	capture, err := handlers.Capture("example/raw")
	if err != nil {
		t.Fatal(err)
	}
	if err := capture.Authorize(context.Background(), nil); err != nil || seen != "trusted context" {
		t.Fatal(seen, err)
	}
	capture.Release()
	if err := p.authorize(context.Background(), binding, func() error { return nil }); !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal("second authorization", err)
	}
	p.lease.Revoke()
	if err := p.checkAuthorized(); !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal("revoked lease remained authorized", err)
	}
	p.Close()
	handlers.Close()
	if err := handlers.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if released.Load() != 0 {
		t.Fatal("release ran before aggregate cleanup")
	}
	if err := p.releaseAfterCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if released.Load() != 1 {
		t.Fatal("original release count", released.Load())
	}
}

func TestSessionApplicationRetainsLateLeaseAndActualReleaseTail(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	entered, resume, releasing, release := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	defer once.Do(func() { close(resume) })
	defer releaseOnce.Do(func() { close(release) })
	var lease *ApplicationLease
	p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		close(entered)
		<-resume
		var err error
		lease, err = c.ReserveLease(c.Binding(), "late value", func(context.Context) error { close(releasing); <-release; return nil })
		return AuthorizeApplicationResult{Lease: lease}, err
	}})
	p.claimed = true
	returned := make(chan error, 1)
	go func() {
		returned <- p.authorize(context.Background(), ApplicationBinding{}, func() error { return nil })
	}()
	<-entered
	host := newEnvironmentSession(nil, 0, context.Background())
	host.application = p
	otherRelease := make(chan struct{})
	var otherOnce sync.Once
	defer otherOnce.Do(func() { close(otherRelease) })
	otherTask, err := f.executor.TrySubmit(ApplicationShort, f.reserve(t, 1, f.executor.TaskCharge()), f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128}), func() { <-otherRelease })
	if err != nil {
		t.Fatal(err)
	}
	before := f.root.Snapshot().Charged
	if status := host.CleanupStatus(); status.PendingCallbacks != 1 || status.CoreCleanup != protocolv4.V4CoreCleanupPending || f.root.Snapshot().Charged != before {
		t.Fatal("passive Session status lost its callback or counted another owner", status)
	}
	otherOnce.Do(func() { close(otherRelease) })
	<-otherTask.Done()
	p.Close()
	f.executor.Close()
	if f.executor.Snapshot().Running != 1 {
		t.Fatal("forgot canceled callback")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.releaseAfterCleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	once.Do(func() { close(resume) })
	if err := <-returned; !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal("late callback delivered authorization", err)
	}
	cleanup := make(chan error, 1)
	go func() { cleanup <- p.releaseAfterCleanup(context.Background()) }()
	<-releasing
	// The real Completion callback still runs after transport core/provider
	// exit. The passive projection must distinguish those original facts.
	host.admission = &SessionAdmissionReservation{core: &SessionCorePlan{cleaned: true}, prepared: &PreparedCarrier{&preparedCarrier{complete: true}}}
	close(host.watchDone)
	host.closed, host.cleanupDeadline = true, time.Now().Add(-time.Second)
	before = f.root.Snapshot().Charged
	if status := host.CleanupStatus(); status.Status != protocolv4.V4CleanupStateCleanupIncomplete || status.CoreCleanup != protocolv4.V4CoreCleanupComplete || status.PendingCallbacks != 1 || status.Validate() != nil || f.root.Snapshot().Charged != before {
		t.Fatal("release callback was confused with unfinished core cleanup", status)
	}
	if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("refunded running release", err)
	}
	if s := f.executor.Snapshot(); s.CompletionReserved != 1 || s.CompletionRunning != 1 {
		t.Fatal(s)
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-cleanup; err != nil {
		t.Fatal(err)
	}
	if err := p.Retire(); err != nil {
		t.Fatal(err)
	}
	if status := host.CleanupStatus(); status.PendingCallbacks != 0 {
		t.Fatal("exited callback remained pending", status)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.context != nil || lease.release != nil || lease.authorization != nil {
		t.Fatal("retained lease retained dependencies")
	}
}

func TestSessionApplicationBurnsRegisteredLeaseOnCallbackFailure(t *testing.T) {
	for _, mode := range []string{"error", "panic", "goexit", "wrong_plan", "wrong_lease"} {
		t.Run(mode, func(t *testing.T) {
			f := newExecutorFixture(t, 2, 1, 1, 1)
			var released atomic.Uint32
			p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(_ context.Context, c AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
				lease, err := c.ReserveLease(c.Binding(), nil, func(context.Context) error { released.Add(1); return nil })
				if err != nil {
					return AuthorizeApplicationResult{}, err
				}
				switch mode {
				case "error":
					return AuthorizeApplicationResult{}, errors.New("private policy error")
				case "panic":
					panic("private panic")
				case "goexit":
					runtime.Goexit()
				case "wrong_plan":
					return AuthorizeApplicationResult{Lease: lease, Handlers: &StreamHandlerPlan{}}, nil
				}
				return AuthorizeApplicationResult{Lease: &ApplicationLease{}}, nil
			}})
			p.claimed = true
			if err := p.authorize(context.Background(), ApplicationBinding{}, func() error { return nil }); !errors.Is(err, ErrApplicationAuthorization) {
				t.Fatal(err)
			}
			p.Close()
			if err := p.releaseAfterCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := p.releaseAfterCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if released.Load() != 1 {
				t.Fatal("lost/repeated original release", released.Load())
			}
		})
	}
}

// Preparation transfers ownership before issuer/provider work. A failure there
// must return both the unused ordinary charge and protected Completion slot.
func TestSessionApplicationUnclaimedPreparationOwnership(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	handlers := newStreamHandlerTestPlan(t, f, streamHandlerTestConfig())
	p := applicationTestPlan(t, f, SessionPlanConfig{RuntimeBytes: 4096, Handlers: handlers, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
		t.Error("unverified input entered authorization")
		return AuthorizeApplicationResult{}, nil
	}})
	host := &Environment{reservation: p.reservation}
	first, second := &EnvironmentSession{environment: host}, &EnvironmentSession{environment: host}
	if err := p.claimPreparation(first); err != nil {
		t.Fatal(err)
	}
	if err := p.claimPreparation(second); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("plan moved to a second attempt", err)
	}
	if err := p.claimPreparation(first); err != nil {
		t.Fatal("original intake could not continue", err)
	}
	p.undoPreparation(second)
	if err := p.claimPreparation(second); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("foreign owner undid original claim", err)
	}
	if err := p.retireUnclaimed(); err != nil {
		t.Fatal(err)
	}
	if s := f.executor.Snapshot(); s.CompletionReserved != 0 {
		t.Fatal("unused cleanup responsibility retained", s)
	}
	if _, err := handlers.Capture("example/raw"); err == nil {
		t.Fatal("unclaimed failed plan left a handler open")
	}
}

func TestSessionApplicationIsRequiredBeforeDurableAdmission(t *testing.T) {
	_, e, _, a, _ := acceptedAdmissionFixture(t, func(f *admissionIntegrationFixture, c *SessionAdmissionConfig) {
		reserve := func(n uint32, charge resourcev4.Vector) resourcev4.Reference {
			ref, err := f.root.Reserve(admissionResourceKey(f.owner, n), charge)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(ref.Release)
			return ref
		}
		config := ApplicationExecutorConfig{Running: 2, ResidentRunning: 1, CompletionRunning: 1, CompletionReserved: 1, RuntimeBytes: 4096, RuntimeBytesPerTask: 65536}
		charge, err := ApplicationExecutorCharge(config)
		if err != nil {
			t.Fatal(err)
		}
		executor, err := NewApplicationExecutor(config, reserve(340, charge))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			executor.Close()
			select {
			case <-executor.Done():
			case <-time.After(3 * time.Second):
				t.Error("reserved Completion never retired")
			}
		})
		plan := SessionPlanConfig{RuntimeBytes: 4096, AuthorizeApplication: func(context.Context, AuthenticatedRequestContext) (AuthorizeApplicationResult, error) {
			t.Error("durable entry bypassed original establishment callback")
			return AuthorizeApplicationResult{}, nil
		}}
		charge, err = SessionPlanCharge(plan)
		if err != nil {
			t.Fatal(err)
		}
		borrow, err := f.environment.Borrow()
		if err != nil {
			t.Fatal(err)
		}
		c.Application, err = NewSessionPlan(plan, executor, reserve(341, charge), reserve(342, executor.TaskCharge()), reserve(343, executor.CompletionCharge()), borrow)
		borrow.Release()
		if err != nil {
			t.Fatal(err)
		}
	})
	// A nil store is intentional: the original application gate must reject
	// before constructing or calling the durable adapter at all.
	_, _, err := a.AdmitSQLite(nil, nil, ledgerv4.AdmissionOwner{}, resourcev4.Reference{}, resourcev4.Reference{})
	if !errors.Is(err, ErrApplicationAuthorization) {
		t.Fatal(err)
	}
	if a.claimed || a.ledger != nil || a.committed || a.activated || e.guard.admitted {
		t.Fatal("missing application authorization reached durable admission")
	}
}

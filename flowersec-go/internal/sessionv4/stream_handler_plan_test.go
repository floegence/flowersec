package sessionv4

import (
	"context"
	"errors"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func streamHandlerTestConfig() StreamHandlerPlanConfig {
	return StreamHandlerPlanConfig{RuntimeBytes: 4096, Handlers: []RawStreamHandlerConfig{{Kind: "example/raw", Slots: 1, WorkClass: ApplicationResident,
		Handler: func(context.Context, any, []byte, *StreamOwnership) error { return nil }}}}
}

func cleanupStreamHandlerPlan(t *testing.T, p *StreamHandlerPlan) {
	t.Helper()
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error("handler plan retained original capture", err)
			return
		}
		if err := p.Retire(); err != nil {
			t.Error(err)
		}
	})
}

func newStreamHandlerTestPlan(t *testing.T, f *executorFixture, config StreamHandlerPlanConfig) *StreamHandlerPlan {
	t.Helper()
	charge, err := StreamHandlerPlanCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	delegates := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1})
	borrow, err := delegates.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	p, err := NewStreamHandlerPlan(config, f.executor, f.reserve(t, 1, charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreamHandlerPlan(t, p)
	return p
}

func TestStreamHandlerPlanRejectsInvalidSnapshotBeforeTakingResources(t *testing.T) {
	for name, mutate := range map[string]func(*StreamHandlerPlanConfig){
		"no registrations": func(c *StreamHandlerPlanConfig) { c.Handlers = nil },
		"empty kind":       func(c *StreamHandlerPlanConfig) { c.Handlers[0].Kind = "" },
		"long kind":        func(c *StreamHandlerPlanConfig) { c.Handlers[0].Kind = strings.Repeat("x", 129) },
		// This decomposed spelling is rejected, never silently merged with NFC.
		"noncanonical kind": func(c *StreamHandlerPlanConfig) { c.Handlers[0].Kind = "example/e\u0301" },
		"invalid UTF-8":     func(c *StreamHandlerPlanConfig) { c.Handlers[0].Kind = "example/\xff" },
		"duplicate kind":    func(c *StreamHandlerPlanConfig) { c.Handlers = append(c.Handlers, c.Handlers[0]) },
		"no slots":          func(c *StreamHandlerPlanConfig) { c.Handlers[0].Slots = 0 },
		"invalid class":     func(c *StreamHandlerPlanConfig) { c.Handlers[0].WorkClass = ApplicationResident + 1 },
		"no handler":        func(c *StreamHandlerPlanConfig) { c.Handlers[0].Handler = nil },
		"no runtime bound":  func(c *StreamHandlerPlanConfig) { c.RuntimeBytes = 0 },
		"size overflow":     func(c *StreamHandlerPlanConfig) { c.RuntimeBytes = math.MaxUint64 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newExecutorFixture(t, 2, 1)
			config := streamHandlerTestConfig()
			charge, _ := StreamHandlerPlanCharge(config)
			reservation := f.reserve(t, 1, charge)
			delegates := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512})
			borrow, err := delegates.Borrow()
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.Release()
			before := f.root.Snapshot()
			mutate(&config)
			if plan, err := NewStreamHandlerPlan(config, f.executor, reservation, borrow); plan != nil || !errors.Is(err, cryptov4.ErrConfiguration) {
				t.Fatal("invalid registration snapshot was installed", err)
			}
			if f.root.Snapshot() != before || reservation.Check() != nil || borrow.Check() != nil {
				t.Fatal("configuration rejection consumed original registration resources")
			}
		})
	}
}

func TestStreamHandlerPlanFreezesRegistrationAndOriginalApplicationBinding(t *testing.T) {
	f := newExecutorFixture(t, 2, 1)
	config := streamHandlerTestConfig()
	bound := &struct{ id int }{1}
	config.ApplicationContext = bound
	var authorizations atomic.Uint32
	config.Handlers[0].AuthorizeOpen = func(ctx context.Context, binding any, metadata []byte) error {
		if ctx == nil || binding != bound || string(metadata) != "authenticated" {
			t.Error("authorization lost original local binding or metadata")
		}
		authorizations.Add(1)
		return nil
	}
	p := newStreamHandlerTestPlan(t, f, config)
	config.ApplicationContext = &struct{ id int }{2}
	config.Handlers[0] = RawStreamHandlerConfig{Kind: "replacement", Slots: 100, WorkClass: ApplicationShort,
		AuthorizeOpen: func(context.Context, any, []byte) error { t.Error("mutable configuration callback ran"); return nil }}
	capture, err := p.Capture("example/raw")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Release()
	if capture.Kind() != "example/raw" || capture.Generation() != 1 || capture.WorkClass() != ApplicationResident || capture.Executor() != f.executor || p.Executor() != f.executor {
		t.Fatal("capture followed mutable caller registration")
	}
	if _, err := p.Capture("replacement"); !errors.Is(err, ErrStreamHandlerKind) {
		t.Fatal("caller inserted another kind after snapshot", err)
	}
	if _, err := p.Capture("example/raw"); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("caller enlarged immutable per-kind capacity", err)
	}
	task, backing := f.job(t, 1)
	result := make(chan error, 1)
	job, err := f.executor.TrySubmit(capture.WorkClass(), task, backing, func() { result <- capture.Authorize(context.Background(), []byte("authenticated")) })
	if err != nil {
		t.Fatal(err)
	}
	waitApplicationPermitTask(t, job)
	if err := <-result; err != nil || authorizations.Load() != 1 {
		t.Fatal(err, authorizations.Load())
	}
	if err := capture.Authorize(context.Background(), nil); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("one OPEN invoked authorization twice", err)
	}
	if err := capture.Accept(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Capture("example/raw"); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("acceptance created another free per-kind slot", err)
	}
	capture.Release()
	replacement, err := p.Capture("example/raw")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Release()
	if replacement.generation == capture.generation || replacement.slot != capture.slot {
		t.Fatal("test did not reuse the original fixed slot with a new generation")
	}
	capture.Release()
	if err := capture.Accept(); !errors.Is(err, resourcev4.ErrClosed) {
		t.Fatal("stale registration capture affected its replacement", err)
	}
}

func TestStreamHandlerPlanCloseRetainsLateAuthorizationAndItsCause(t *testing.T) {
	for _, fails := range []bool{false, true} {
		t.Run(map[bool]string{false: "late accept", true: "original rejection"}[fails], func(t *testing.T) {
			f := newExecutorFixture(t, 2, 1)
			config := streamHandlerTestConfig()
			entered, release := make(chan struct{}), make(chan struct{})
			stop := sync.OnceFunc(func() { close(release) })
			defer stop()
			original := errors.New("original application rejection")
			config.Handlers[0].AuthorizeOpen = func(context.Context, any, []byte) error {
				close(entered)
				<-release
				if fails {
					return original
				}
				return nil
			}
			p := newStreamHandlerTestPlan(t, f, config)
			capture, err := p.Capture("example/raw")
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Release()
			task, backing := f.job(t, 1)
			result := make(chan error, 1)
			job, err := f.executor.TrySubmit(capture.WorkClass(), task, backing, func() { result <- capture.Authorize(context.Background(), []byte("held")) })
			if err != nil {
				t.Fatal(err)
			}
			waitInitialCoreGate(t, entered, "authorization")
			before := f.root.Snapshot()
			p.Close()
			capture.Release()
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			if err := p.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
				t.Fatal("close forgot the original application callback", err)
			}
			if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) || f.root.Snapshot() != before {
				t.Fatal("late authorization lost its delegate or complete charge", err)
			}
			if err := capture.Accept(); !errors.Is(err, resourcev4.ErrClosed) {
				t.Fatal("closed plan permitted late acceptance", err)
			}
			stop()
			waitApplicationPermitTask(t, job)
			want := resourcev4.ErrClosed
			if fails {
				want = original
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatal("late callback changed its original outcome", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := p.WaitCleanup(ctx); err != nil {
				t.Fatal(err)
			}
			before = f.root.Snapshot()
			if p.Executor() != f.executor {
				t.Fatal("cleanup observation prematurely retired the registration snapshot")
			}
			if err := p.Retire(); err != nil || f.root.Snapshot().Reservations+1 != before.Reservations {
				t.Fatal("actual retirement retained plan metadata", err)
			}
		})
	}
}

func TestStreamHandlerPlanAcceptedHandlerSurvivesRegistrationClose(t *testing.T) {
	config := streamHandlerTestConfig()
	entered, release := make(chan struct{}), make(chan struct{})
	stop := sync.OnceFunc(func() { close(release) })
	defer stop()
	var p *StreamHandlerPlan
	var want *StreamOwnership
	var calls atomic.Uint32
	config.Handlers[0].Handler = func(ctx context.Context, binding any, metadata []byte, stream *StreamOwnership) error {
		defer func() { close(entered); <-release }()
		if ctx == nil || binding != "original" || string(metadata) != "accepted" || stream != want {
			t.Error("handler lost its accepted original projection")
		}
		p.Close() // Reentrant registration close cannot deadlock application code.
		calls.Add(1)
		return nil
	}
	config.ApplicationContext = "original"
	charge, err := StreamHandlerPlanCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	delegateCharge := resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1}
	f := newScopeFixtureResources(t, 60000, charge, delegateCharge, resourcev4.Vector{})
	delegates := f.reserve(t, delegateCharge)
	t.Cleanup(delegates.Release)
	borrow, err := delegates.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	p, err = NewStreamHandlerPlan(config, f.executor, f.reserve(t, charge), borrow)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreamHandlerPlan(t, p)
	want = ownFixtureStream(t, f.serviceFixture, f.h, f.reserve(t, StreamOwnershipCharge()))
	capture, err := p.Capture("example/raw")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Release()
	if err := capture.Handle(context.Background(), nil, want); !errors.Is(err, cryptov4.ErrTransition) {
		t.Fatal("unaccepted capture exposed Stream I/O", err)
	}
	if err := capture.Accept(); err != nil {
		t.Fatal(err)
	}
	p.Close()
	result := make(chan error, 1)
	job, err := f.executor.TrySubmit(capture.WorkClass(), f.reserve(t, f.executor.TaskCharge()), delegates, func() { result <- capture.Handle(context.Background(), []byte("accepted"), want) })
	if err != nil {
		t.Fatal(err)
	}
	waitInitialCoreGate(t, entered, "handler defer")
	capture.Release()
	if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("accepted callback defer lost the original registration", err)
	}
	stop()
	waitApplicationPermitTask(t, job)
	if err := <-result; err != nil || calls.Load() != 1 {
		t.Fatal("registration close changed the already accepted callback", err, calls.Load())
	}
}

func TestStreamHandlerPlanChecksSharedRootEnvironmentAndOnceOnlySessionClaim(t *testing.T) {
	f, foreign := newExecutorFixture(t, 2, 1), newExecutorFixture(t, 2, 1)
	config := streamHandlerTestConfig()
	charge, _ := StreamHandlerPlanCharge(config)
	reservation := f.reserve(t, 1, charge)
	delegates := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 512})
	borrow, err := delegates.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	defer borrow.Release()
	before := f.root.Snapshot()
	if p, err := NewStreamHandlerPlan(config, foreign.executor, reservation, borrow); p != nil || !errors.Is(err, resourcev4.ErrOwner) || f.root.Snapshot() != before {
		t.Fatal("private executor bypassed the original root", err)
	}
	p, err := NewStreamHandlerPlan(config, f.executor, reservation, borrow)
	if err != nil {
		t.Fatal(err)
	}
	cleanupStreamHandlerPlan(t, p)
	wrongEnvironment := f.reserve(t, 2, resourcev4.Vector{resourcev4.Items: 1})
	if err := p.CheckEnvironment(wrongEnvironment); !errors.Is(err, resourcev4.ErrOwner) {
		t.Fatal("plan accepted another Environment", err)
	}
	if err := p.CheckEnvironment(delegates); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Uint32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if err := p.claimSession(); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, cryptov4.ErrTransition) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatal("one handler plan bound to multiple Sessions", winners.Load())
	}
}

func TestStreamHandlerPlanCallbackExitPreservesTailsAndExecutor(t *testing.T) {
	for _, handling := range []bool{false, true} {
		for _, exit := range []string{"panic", "nil panic", "Goexit"} {
			t.Run(map[bool]string{false: "authorize", true: "handle"}[handling]+"/"+exit, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				stop := sync.OnceFunc(func() { close(release) })
				defer stop()
				callback := func() error {
					defer func() { close(entered); <-release }()
					switch exit {
					case "panic":
						panic(struct{ private string }{"application value must not escape"})
					case "nil panic":
						panic(nil)
					default:
						runtime.Goexit()
					}
					return nil
				}
				config := streamHandlerTestConfig()
				if handling {
					config.Handlers[0].Handler = func(context.Context, any, []byte, *StreamOwnership) error { return callback() }
				} else {
					config.Handlers[0].AuthorizeOpen = func(context.Context, any, []byte) error { return callback() }
				}
				charge, err := StreamHandlerPlanCharge(config)
				if err != nil {
					t.Fatal(err)
				}
				delegateCharge := resourcev4.Vector{resourcev4.SDKBytes: 512, resourcev4.Items: 1}
				f := newScopeFixtureResources(t, 60000, charge, delegateCharge, resourcev4.Vector{})
				delegates := f.reserve(t, delegateCharge)
				t.Cleanup(delegates.Release)
				borrow, err := delegates.Borrow()
				if err != nil {
					t.Fatal(err)
				}
				defer borrow.Release()
				p, err := NewStreamHandlerPlan(config, f.executor, f.reserve(t, charge), borrow)
				if err != nil {
					t.Fatal(err)
				}
				cleanupStreamHandlerPlan(t, p)
				capture, err := p.Capture("example/raw")
				if err != nil {
					t.Fatal(err)
				}
				defer capture.Release()
				var owner *StreamOwnership
				if handling {
					owner = ownFixtureStream(t, f.serviceFixture, f.h, f.reserve(t, StreamOwnershipCharge()))
					if err := capture.Accept(); err != nil {
						t.Fatal(err)
					}
				}
				beforeTask := f.root.Snapshot()
				result := make(chan error, 1)
				job, err := f.executor.TrySubmit(capture.WorkClass(), f.reserve(t, f.executor.TaskCharge()), delegates, func() {
					if handling {
						result <- capture.Handle(context.Background(), nil, owner)
					} else {
						result <- capture.Authorize(context.Background(), nil)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				waitInitialCoreGate(t, entered, "exiting application defer")
				duringTail := f.root.Snapshot()
				if _, err := p.Capture("example/raw"); !errors.Is(err, cryptov4.ErrCapacity) {
					t.Fatal("callback exit released its shared position before defer completion", err)
				}
				if err := p.Retire(); !errors.Is(err, cryptov4.ErrCapacity) || f.root.Snapshot() != duringTail || f.executor.Snapshot().Running != 1 {
					t.Fatal("application defer lost its original charged tail", err)
				}
				stop()
				waitApplicationPermitTask(t, job)
				if exit == "Goexit" {
					select {
					case err := <-result:
						t.Fatal("Goexit incorrectly returned to its caller", err)
					default:
					}
				} else if err := <-result; err != ErrStreamHandlerCallbackExit {
					t.Fatal("panic was not isolated as the fixed callback-exit cause", err)
				}
				if err := capture.Accept(); err != ErrStreamHandlerCallbackExit {
					t.Fatal("abnormal exit lost its denial or first callback cause", err)
				}
				if f.root.Snapshot() != beforeTask || f.executor.Snapshot().Running != 0 {
					t.Fatal("callback completion did not return exactly its original execution charge")
				}
				var continued atomic.Bool
				next, err := f.executor.TrySubmit(ApplicationResident, f.reserve(t, f.executor.TaskCharge()), delegates, func() { continued.Store(true) })
				if err != nil {
					t.Fatal("callback exit closed unrelated ordinary execution", err)
				}
				waitApplicationPermitTask(t, next)
				if !continued.Load() || f.root.Snapshot() != beforeTask {
					t.Fatal("executor did not reuse and release the original position exactly")
				}
				p.Close()
				capture.Release()
				waitInitialCoreGate(t, p.Done(), "callback plan cleanup")
				if f.root.Snapshot() != beforeTask {
					t.Fatal("cleanup observation retired the immutable callback snapshot")
				}
				if err := p.Retire(); err != nil {
					t.Fatal(err)
				}
				want := beforeTask
				want.Reservations--
				want.References -= 2 // The metadata primary and original delegate borrow.
				for dimension, amount := range charge {
					want.Charged[dimension] -= amount
				}
				if got := f.root.Snapshot(); got != want {
					t.Fatal("retirement did not refund exactly the plan's original charge", got, want)
				}
			})
		}
	}
}

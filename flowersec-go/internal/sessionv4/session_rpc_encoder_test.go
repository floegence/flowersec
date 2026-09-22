package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func synchronousOptions() rpcv4.UnaryPreparation {
	return rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}
}

func synchronousResult(_ context.Context, input []byte) (any, error) { return input, nil }

func runSynchronousParent(t *testing.T, f *serviceDispatchFixture, class ApplicationWorkClass, work func(context.Context)) {
	t.Helper()
	backing := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: applicationContextBytes(), resourcev4.Items: 1})
	permit, err := f.f.executor.TryAcquire(class, f.f.reserve(t, 1, f.f.executor.TaskCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer permit.Close()
	if err := permit.runInline(func() {
		ctx, exit, err := enterApplicationContext(context.Background(), f.f.executor, ordinaryApplicationLane, class, backing, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer exit()
		work(ctx)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSynchronousUnaryReusesFullOrdinaryCapacityAndImmutablePreparation(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	other, err := f.f.executor.TryAcquire(ApplicationShort, f.f.reserve(t, 1, f.f.executor.TaskCharge()), f.plan.reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var encoded atomic.Int32
	input := []byte("input")
	var escaped, parent context.Context
	var scratchAlias, inputAlias []byte
	var operation *UnaryOperation
	runSynchronousParent(t, f, ApplicationResident, func(ctx context.Context) {
		parent = ctx
		before := f.f.executor.Snapshot()
		operation, err = r.PrepareEncodedShortUnaryResult(ctx, route, input, synchronousOptions(), SynchronousUnaryCodec{
			MaxEncodedBytes: 32, ScratchBytes: 32,
			Encode: func(stage context.Context, value, scratch []byte) ([]byte, error) {
				encoded.Add(1)
				escaped, inputAlias, scratchAlias = stage, value, scratch
				if got := f.f.executor.Snapshot(); got != before || got.Running != 2 || got.ResidentRunning != 1 {
					t.Fatal("synchronous stage acquired another slot or lost resident class", got, before)
				}
				child, _ := stage.Value(applicationContextKey{}).(*applicationContext)
				original, _ := ctx.Value(applicationContextKey{}).(*applicationContext)
				if child.state != original.state || child.state.class != ApplicationResident {
					t.Fatal("synchronous encoder replaced its actual ordinary owner")
				}
				n := copy(scratch, value)
				n += copy(scratch[n:], " encoded")
				return scratch[:n], nil
			},
		}, synchronousResult)
		if err != nil {
			t.Fatal(err)
		}
		defer operation.Close()
		if !bytes.Equal(inputAlias, make([]byte, len(inputAlias))) || !bytes.Equal(scratchAlias, make([]byte, len(scratchAlias))) || string(input) != "input" {
			t.Fatal("borrow cleanup corrupted application input or retained codec scratch")
		}
		if _, err := checkApplicationContext(escaped); err == nil {
			t.Fatal("returned stage context remained usable", err)
		}
		if _, err := checkApplicationContext(parent); err != nil {
			t.Fatal("returning a stage did not restore its parent", err)
		}
		if operation.header.Fields().AdmissionMode != 1 {
			t.Fatal("nested preparation lost try_now")
		}
		started := operation.Start(ctx)
		if started.Error != nil || started.Call == nil {
			t.Fatal(started)
		}
		if again := operation.Start(ctx); again.Call != started.Call || again.Error != nil || encoded.Load() != 1 {
			t.Fatal("Start encoded or submitted again", again, encoded.Load())
		}
		for range 3 {
			if _, err := f.publisher.Step(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Contains(f.sink.wire, []byte("input encoded")) {
			t.Fatal("published bytes did not survive scratch cleanup")
		}
		finishShortResponse(t, f, operation.header, 1, []byte("result"))
		r.AdvanceCalls()
		result, status, err := started.Call.TakeEncodedResult(resultTestContext(t))
		if err != nil || string(result) != "result" || !status.Delivered {
			t.Fatal(result, status, err)
		}
	})
	if _, err := checkApplicationContext(parent); !errors.Is(err, ErrApplicationDependency) {
		t.Fatal("exited ordinary owner retained creation rights", err)
	}
}

func TestSynchronousUnaryExternalAndCompletionRequireRealOrdinarySlot(t *testing.T) {
	for _, completion := range []bool{false, true} {
		t.Run(map[bool]string{false: "external", true: "completion"}[completion], func(t *testing.T) {
			f, r, route, _ := deferredCallerFixture(t)
			var calls atomic.Int32
			codec := SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(ctx context.Context, _, _ []byte) ([]byte, error) {
				calls.Add(1)
				if s := f.f.executor.Snapshot(); s.Running != 1 || s.Ready != 0 {
					t.Fatal("encoder did not hold a real ordinary position", s)
				}
				deps, err := captureApplicationDependencies(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer deps.release()
				if deps.hasCompletion(f.f.executor) != completion {
					t.Fatal("ordinary encoding laundered Completion ancestry")
				}
				return []byte("encoded"), nil
			}}
			var held [2]*ApplicationPermit
			for j := range held {
				var err error
				held[j], err = f.f.executor.TryAcquire(ApplicationShort, f.f.reserve(t, 1, f.f.executor.TaskCharge()), f.plan.reservation)
				if err != nil {
					t.Fatal(err)
				}
				defer held[j].Close()
			}
			work := func(ctx context.Context) {
				before := f.f.root.Snapshot()
				op, err := r.PrepareEncodedUnaryResult(ctx, route, nil, synchronousOptions(), ApplicationShort, codec, synchronousResult)
				if !errors.Is(err, cryptov4.ErrCapacity) || op != nil || calls.Load() != 0 || f.f.root.Snapshot() != before {
					t.Fatal("capacity rejection entered codec or leaked the original batch", err, calls.Load(), before, f.f.root.Snapshot())
				}
				for _, p := range held {
					p.Close()
				}
				op, err = r.PrepareEncodedUnaryResult(ctx, route, nil, synchronousOptions(), ApplicationShort, codec, synchronousResult)
				if err != nil || calls.Load() != 1 || f.f.executor.Snapshot().Running != 0 {
					t.Fatal(err, calls.Load(), f.f.executor.Snapshot())
				}
				op.Close()
			}
			if !completion {
				work(context.Background())
				return
			}
			future, err := f.f.executor.ReserveCompletion(f.f.reserve(t, 1, f.f.executor.CompletionCharge()), f.plan.reservation)
			if err != nil {
				t.Fatal(err)
			}
			defer future.Close()
			task, err := future.Submit(func() error {
				ctx, exit, err := enterApplicationContext(context.Background(), f.f.executor, completionApplicationLane, ApplicationShort, f.plan.reservation, nil)
				if err != nil {
					return err
				}
				defer exit()
				work(ctx)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			awaitApplicationTask(t, task.Done())
		})
	}
}

func TestSynchronousUnarySerialNestingAndDetectableConcurrency(t *testing.T) {
	_, r, route, _ := deferredCallerFixture(t)
	var calls int
	var encode func(context.Context, []byte, []byte) ([]byte, error)
	encode = func(ctx context.Context, _, _ []byte) ([]byte, error) {
		calls++
		var nestedErr error
		if calls == 1 {
			// The original caller's token is suspended until this real stage exits.
			outer := ctx.Value(applicationContextKey{}).(*applicationContext).Context
			if _, e := checkApplicationContext(outer); !errors.Is(e, ErrApplicationDependency) {
				t.Fatal("suspended parent token remained reusable", e)
			}
			concurrent := make(chan error, 1)
			go func() {
				_, err := r.PrepareEncodedUnaryResult(outer, route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: encode}, synchronousResult)
				concurrent <- err
			}()
			if err := <-concurrent; !errors.Is(err, ErrApplicationDependency) {
				t.Fatal("detectable concurrent parent reuse was not rejected", err)
			}
		}
		op, nestedErr := r.PrepareEncodedUnaryResult(ctx, route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: encode}, synchronousResult)
		if calls == maxApplicationAncestors && op == nil {
			if !errors.Is(nestedErr, ErrApplicationDependency) {
				t.Fatal("unbounded serial nesting", nestedErr)
			}
			return []byte("encoded"), nil
		}
		if nestedErr != nil {
			t.Fatal(nestedErr)
		}
		op.Close()
		return []byte("encoded"), nil
	}
	op, err := r.PrepareEncodedUnaryResult(context.Background(), route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: encode}, synchronousResult)
	if err != nil || calls != maxApplicationAncestors {
		t.Fatal("legal direct serial nesting failed", err, calls)
	}
	op.Close()
}

func TestSynchronousUnaryFailureCleanupAndOwnedOutput(t *testing.T) {
	for _, mode := range []string{"error", "panic", "goexit", "oversize", "expired", "success"} {
		t.Run(mode, func(t *testing.T) {
			f, r, route, _ := deferredCallerFixture(t)
			before := f.f.root.Snapshot()
			owned := []byte("owned")
			var escaped context.Context
			var got error
			var calls int
			done := make(chan struct{})
			go func() {
				defer close(done)
				op, err := r.PrepareEncodedUnaryResult(context.Background(), route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(ctx context.Context, _, _ []byte) ([]byte, error) {
					calls++
					escaped = ctx
					switch mode {
					case "error":
						return nil, context.Canceled
					case "panic":
						panic("application private details")
					case "goexit":
						runtime.Goexit()
					case "oversize":
						return make([]byte, 17), nil
					case "expired":
						f.trust.tick.Store(1000)
					}
					return owned, nil
				}}, synchronousResult)
				got = err
				if op != nil {
					op.Close()
				}
			}()
			awaitApplicationTask(t, done)
			if calls != 1 || string(owned) != "owned" || f.f.executor.Snapshot().Running != 0 || f.f.root.Snapshot() != before {
				t.Fatal("real encoder exit did not settle original ownership", calls, string(owned), before, f.f.root.Snapshot())
			}
			if _, err := checkApplicationContext(escaped); err == nil {
				t.Fatal("escaped encoder context retained new-work rights")
			}
			switch mode {
			case "success", "goexit":
				if got != nil {
					t.Fatal(got)
				}
			case "error":
				if !errors.Is(got, context.Canceled) {
					t.Fatal(got)
				}
			case "panic":
				if !errors.Is(got, ErrSynchronousEncoderExit) {
					t.Fatal(got)
				}
			case "oversize":
				if !errors.Is(got, cryptov4.ErrCapacity) {
					t.Fatal(got)
				}
			case "expired":
				if !errors.Is(got, timev4.ErrExpired) {
					t.Fatal(got)
				}
			}
		})
	}
}

func TestSynchronousUnaryCloseRetainsNoncooperativeEncoderUntilRealExit(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	before := f.f.root.Snapshot()
	entered := make(chan context.Context, 1)
	release, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var got error
	go func() {
		defer close(done)
		_, got = r.PrepareEncodedUnaryResult(context.Background(), route, []byte("input"), synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, ScratchBytes: 16, Encode: func(ctx context.Context, input, scratch []byte) ([]byte, error) {
			copy(scratch, input)
			entered <- ctx
			<-release
			if string(input) != "input" || string(scratch[:5]) != "input" {
				t.Error("Close released a live encoder borrow")
			}
			return input, nil
		}}, synchronousResult)
	}()
	ctx := <-entered
	r.mu.Lock()
	var operation *UnaryOperation
	for _, op := range r.operations {
		if op != nil {
			operation = op
			break
		}
	}
	r.mu.Unlock()
	if operation == nil {
		t.Fatal("encoder lacked original operation owner")
	}
	during := f.f.root.Snapshot()
	operation.Close()
	if ctx.Err() == nil || f.f.root.Snapshot() != during || f.f.executor.Snapshot().Running != 1 || operation.detached {
		t.Fatal("Close waited or refunded a noncooperative callback", ctx.Err(), during, f.f.root.Snapshot())
	}
	once.Do(func() { close(release) })
	awaitApplicationTask(t, done)
	if !errors.Is(got, context.Canceled) || f.f.root.Snapshot() != before || !operation.detached {
		t.Fatal("actual callback exit did not release original resources", got, before, f.f.root.Snapshot())
	}
}

func TestSynchronousUnaryRejectsBeforeEncodingAndKeepsExplicitAdmissionChoice(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	var calls int
	codec := SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(context.Context, []byte, []byte) ([]byte, error) { calls++; return nil, nil }}
	for _, options := range []rpcv4.UnaryPreparation{
		{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, RequireExecution: true},
		{DeadlineAtMS: 2000, ResponseLimitBytes: 1024, AdmissionMode: 2},
		{DeadlineAtMS: 1, ResponseLimitBytes: 1024},
	} {
		before := f.f.root.Snapshot()
		if op, err := r.PrepareEncodedUnaryResult(context.Background(), route, nil, options, ApplicationShort, codec, synchronousResult); err == nil || op != nil || calls != 0 || f.f.root.Snapshot() != before {
			t.Fatal("invalid preparation entered encoder or leaked", err, calls)
		}
	}
	runSynchronousParent(t, f, ApplicationShort, func(ctx context.Context) {
		options := synchronousOptions()
		options.ExplicitAdmissionMode = true
		before := f.f.root.Snapshot()
		if op, err := r.PrepareEncodedUnaryResult(ctx, route, nil, options, ApplicationShort, codec, synchronousResult); !errors.Is(err, ErrApplicationDependency) || op != nil || calls != 0 || f.f.root.Snapshot() != before {
			t.Fatal("explicit queued was silently rewritten or entered the encoder", err, calls)
		}
	})
	saturateServiceRoot(t, f)
	before := f.f.root.Snapshot()
	if op, err := r.PrepareEncodedUnaryResult(context.Background(), route, nil, synchronousOptions(), ApplicationShort, codec, synchronousResult); !errors.Is(err, resourcev4.ErrCapacity) || op != nil || calls != 0 || f.f.root.Snapshot() != before {
		t.Fatal("codec ran before full input/output/scratch admission", err, calls)
	}
}

func TestSynchronousUnaryFixesExecutionIdentityBeforeEncoderAndCannotStartIncomplete(t *testing.T) {
	f := newServiceDispatchFixtureProfile(t, func(context.Context, UnaryRequest, *UnaryResponse) (uint32, error) { return 0, nil }, false, ApplicationShort, true)
	f, r, route := callerForServiceFixture(t, f)
	options := rpcv4.UnaryPreparation{DefaultLifetimeMS: 800, AdmissionNotAfterMS: 1800, ResponseLimitBytes: 1024, Offer: protocolv4.AdmissionOfferBounds{Digest: f.policy.Digest, NotBeforeMS: 1000, NotAfterMS: 1600}}
	var original protocolv4.ApplicationHeaderFields
	payload := []byte("execution encoded")
	codec := SynchronousUnaryCodec{MaxEncodedBytes: 32, Encode: func(context.Context, []byte, []byte) ([]byte, error) {
		r.mu.Lock()
		operation := r.operations[0]
		r.mu.Unlock()
		operation.mu.Lock()
		prepared := operation.request
		operation.mu.Unlock()
		original = prepared.Header().Fields()
		if original.OperationID == ([32]byte{}) || original.DeadlineAtMS == 0 {
			t.Fatal("encoder ran before original identity/deadline selection")
		}
		called := false
		err := prepared.WithStart(context.Background(), func(rpcv4.ContractRoute, protocolv4.ApplicationHeader, []byte, []byte) error {
			called = true
			return nil
		})
		if !errors.Is(err, rpcv4.ErrPreparationIncomplete) || called {
			t.Fatal("incomplete encoding gained publication rights", err, called)
		}
		f.trust.tick.Store(100)
		return payload, nil
	}}
	op, err := r.prepareUnaryEncoding(context.Background(), route, nil, options, ApplicationShort, true, func(context.Context, rpcv4.InputBorrow) error { return nil }, nil, &codec)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	fields := op.header.Fields()
	if fields.OperationID != original.OperationID || fields.DeadlineAtMS != original.DeadlineAtMS || fields.PayloadBytes != uint32(len(payload)) {
		t.Fatal("encoding changed the original execution identity or deadline")
	}
	digest, err := protocolv4.ComputeExecutionRequestDigest(op.header, f.contract, payload)
	if err != nil || digest != fields.RequestDigest {
		t.Fatal("finalized digest did not bind the immutable encoded request", err)
	}
	if err := op.request.FinalizePayload([]byte("second")); !errors.Is(err, rpcv4.ErrOwner) {
		t.Fatal("a second finalization replaced original request bytes", err)
	}
	started := op.Start(context.Background())
	if started.Error != nil || started.Call == nil {
		t.Fatal(started)
	}
	finishShortResponse(t, f, op.header, 1, []byte("result"))
	finishShortDecode(t, r)
}

func TestSynchronousUnaryCoordinatorCancelsOriginalDeadlineWithoutRefundingLiveTail(t *testing.T) {
	f, r, route, _ := deferredCallerFixture(t)
	entered := make(chan context.Context, 1)
	release, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var got error
	go func() {
		defer close(done)
		_, got = r.PrepareEncodedUnaryResult(context.Background(), route, nil, synchronousOptions(), ApplicationShort, SynchronousUnaryCodec{MaxEncodedBytes: 16, Encode: func(ctx context.Context, _, _ []byte) ([]byte, error) {
			entered <- ctx
			<-release
			return []byte("late"), nil
		}}, synchronousResult)
	}()
	ctx := <-entered
	during := f.f.root.Snapshot()
	f.trust.tick.Store(1000)
	r.advanceOperations()
	if ctx.Err() == nil || f.f.executor.Snapshot().Running != 1 || f.f.root.Snapshot() != during {
		t.Fatal("deadline failed to cancel or refunded a still-running encoder")
	}
	once.Do(func() { close(release) })
	awaitApplicationTask(t, done)
	if !errors.Is(got, context.Canceled) || f.f.executor.Snapshot().Running != 0 {
		t.Fatal(got, f.f.executor.Snapshot())
	}
}

func TestSynchronousStageTokensExpireIndependentlyOfContextCancellation(t *testing.T) {
	f, _, _, _ := deferredCallerFixture(t)
	runSynchronousParent(t, f, ApplicationResident, func(parent context.Context) {
		stage, exit, err := enterSynchronousStage(parent, f.f.executor)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := captureApplicationDependencies(parent); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal("suspended parent created new SDK work", err)
		}
		exit()
		if stage.Err() != nil {
			t.Fatal("stage test accidentally used cancellation")
		}
		if _, err := captureApplicationDependencies(stage); !errors.Is(err, ErrApplicationDependency) {
			t.Fatal("expired stage token created new SDK work", err)
		}
		deps, err := captureApplicationDependencies(parent)
		if err != nil {
			t.Fatal("stage exit did not restore parent", err)
		}
		deps.release()
	})
}

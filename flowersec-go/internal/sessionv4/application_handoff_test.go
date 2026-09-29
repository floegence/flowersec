package sessionv4

import (
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

func TestApplicationHandoffOrdersOriginExitAndRejectsStaleStage(t *testing.T) {
	f := queryExecutorFixture(t, 1)
	ref := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.executor, ordinaryApplicationLane, ApplicationShort, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	stage, leave, err := enterSynchronousStage(ctx, f.executor)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = withApplicationHandoff(ctx, func() error { called = true; return nil }); err != ErrApplicationDependency || called {
		t.Fatal("suspended origin installed", err)
	}
	leave()
	if err = withApplicationHandoff(stage, func() error { called = true; return nil }); err != ErrApplicationDependency || called {
		t.Fatal("stale stage installed", err)
	}
	entered, release, delivered, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(delivered)
		err = withApplicationHandoff(ctx, func() error { close(entered); <-release; called = true; return nil })
	}()
	awaitQuery(t, entered)
	go func() { exit(); close(exited) }()
	select {
	case <-exited:
		t.Fatal("origin exited inside handoff gate")
	default:
	}
	close(release)
	awaitQuery(t, delivered)
	awaitQuery(t, exited)
	if err != nil || !called {
		t.Fatal(err)
	}
	called = false
	if err = withApplicationHandoff(ctx, func() error { called = true; return nil }); err != ErrApplicationDependency || called {
		t.Fatal("exited origin installed", err)
	}
}

func TestApplicationHandoffStaticBindRejectsExitedAndSuspendedOrigin(t *testing.T) {
	f, r, e, definition := serviceShapesFixture(t)
	ref := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})
	ctx, exit, err := enterApplicationContext(context.Background(), f.f.executor, ordinaryApplicationLane, ApplicationShort, ref, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer exit()
	stage, leave, err := enterSynchronousStage(ctx, f.f.executor)
	if err != nil {
		t.Fatal(err)
	}
	defer leave()
	for _, rejected := range []context.Context{ctx, ordinaryCleanupContext{Context: context.Background()}} {
		if client, err := r.bindMethods(rejected, definition, UnaryServiceBindOptions{}); err != ErrApplicationDependency || client != nil {
			t.Fatal("invalid origin published a static binding", err)
		}
	}
	leave()
	exit()
	for _, rejected := range []context.Context{ctx, stage} {
		if client, err := r.bindMethods(rejected, definition, UnaryServiceBindOptions{}); err != ErrApplicationDependency || client != nil {
			t.Fatal("exited origin published a static binding", err)
		}
	}
	if e.OperationsSnapshot().BoundMethods != 0 {
		t.Fatal("rejected Bind retained method positions")
	}
}

func TestApplicationHandoffUnaryBeginOrdersOriginExit(t *testing.T) {
	for _, begun := range []bool{false, true} {
		t.Run(map[bool]string{false: "before BEGIN", true: "after BEGIN"}[begun], func(t *testing.T) {
			f, r, route := shortCallerFixture(t)
			ref := f.f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 4096, resourcev4.Items: 1})
			ctx, exit, err := enterApplicationContext(context.Background(), f.f.executor, ordinaryApplicationLane, ApplicationShort, ref, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer exit()
			op, err := r.PrepareUnaryContext(ctx, route, []byte("request"), rpcv4.UnaryPreparation{DeadlineAtMS: 2000, ResponseLimitBytes: 1024}, ApplicationShort, true, func(_ context.Context, _ rpcv4.InputBorrow) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer op.Close()
			started := op.Start(ctx)
			if started.Error != nil || started.Call == nil {
				t.Fatal(started)
			}
			invocation := started.Call.invocation
			if begun {
				if _, err := f.publisher.Step(context.Background()); err != nil {
					t.Fatal(err)
				}
				if !invocation.publication.Progress().HeaderAccepted {
					t.Fatal("fixture did not commit the original BEGIN")
				}
			}
			exit()
			called := false
			err = invocation.WithRequestPublication(op.header, func() error { called = true; return nil })
			if begun && (err != nil || !called) || !begun && (err != ErrApplicationDependency || called) {
				t.Fatal("origin exit changed original publication rights", begun, called, err)
			}
		})
	}
}

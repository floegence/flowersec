package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func TestCompletionFloorRetainsFuturePositionBetweenActualResults(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1024})
	floor, err := e.NewCompletionFloor(f.reserve(t, 1, e.CompletionFloorCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	otherCharge := f.reserve(t, 1, e.CompletionCharge())
	before := f.root.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 10 {
		if _, err := e.ReserveCompletion(otherCharge, backing); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("unrelated call occupied protected future", err)
		}
		p, err := floor.Checkout()
		if err != nil {
			t.Fatal(err)
		}
		if s := e.Snapshot(); s.CompletionRunning != 0 || s.CompletionReserved != 1 {
			t.Fatal("future result occupied running worker", s)
		}
		job, err := p.Submit(func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if err := job.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		p.Close()
		if after := f.root.Snapshot(); after != before {
			t.Fatal("result released shared future charge", before, after)
		}
	}
}

func TestCompletionFloorClosePreservesSubmittedAndFutureOriginalWork(t *testing.T) {
	for _, submitted := range []bool{false, true} {
		t.Run(map[bool]string{false: "future", true: "running"}[submitted], func(t *testing.T) {
			f := newExecutorFixture(t, 2, 1, 1, 1)
			e := f.executor
			backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1024})
			floor, err := e.NewCompletionFloor(f.reserve(t, 1, e.CompletionFloorCharge()), backing)
			if err != nil {
				t.Fatal(err)
			}
			p, err := floor.Checkout()
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			work := func() error { close(entered); <-release; runtime.Goexit(); return nil }
			var job *CompletionTask
			if submitted {
				job, err = p.Submit(work)
				if err != nil {
					t.Fatal(err)
				}
				awaitApplicationTask(t, entered)
			}
			floor.Close()
			e.Close()
			if floor.CleanupComplete() {
				t.Fatal("closed ahead of original responsibility")
			}
			if _, err := floor.Checkout(); !errors.Is(err, cryptov4.ErrClosed) {
				t.Fatal(err)
			}
			if !submitted {
				job, err = p.Submit(work)
				if err != nil {
					t.Fatal("lost accepted future after closure", err)
				}
				awaitApplicationTask(t, entered)
			}
			once.Do(func() { close(release) })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := job.Wait(ctx); !errors.Is(err, ErrCompletionCallbackExit) {
				t.Fatal(err)
			}
			if !floor.CleanupComplete() {
				t.Fatal("actual exit did not release floor")
			}
			awaitApplicationTask(t, e.Done())
		})
	}
}

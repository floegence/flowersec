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

func TestCompletionKeepsReservedCleanupUnderOrdinarySaturationAndClose(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 2)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 8192, resourcev4.Items: 1})
	var ordinary [2]*ApplicationPermit
	for i := range ordinary {
		var err error
		ordinary[i], err = e.TryAcquire(ApplicationShort, f.reserve(t, 1, e.TaskCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		defer ordinary[i].Close()
	}
	var completions [2]*CompletionReservation
	for i := range completions {
		var err error
		completions[i], err = e.ReserveCompletion(f.reserve(t, 1, e.CompletionCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		defer completions[i].Close()
	}
	if _, err := e.ReserveCompletion(f.reserve(t, 1, e.CompletionCharge()), backing); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal(err)
	}
	entered, release, second := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	first, err := completions[0].Submit(func() error { close(entered); <-release; runtime.Goexit(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	e.Close()
	// This responsibility was accepted before Close. It must still be able
	// to join the original protected queue without fresh resource admission.
	last, err := completions[1].Submit(func() error { close(second); return nil })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-second:
		t.Fatal("exceeded protected running cap")
	default:
	}
	select {
	case <-e.Done():
		t.Fatal("forgot reserved/running completion")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s := e.Snapshot(); s.CompletionReserved != 2 || s.CompletionRunning != 1 {
		t.Fatal(s)
	}
	once.Do(func() { close(release) })
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := first.Wait(wait); !errors.Is(err, ErrCompletionCallbackExit) {
		t.Fatal(err)
	}
	if err := last.Wait(wait); err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Done():
	case <-wait.Done():
		t.Fatal("executor did not join original cleanup")
	}
}

func TestDormantCompletionDescriptorsShareOnlyActualRunningStackCapacity(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 2, 16)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 128, resourcev4.Items: 1})
	before := f.root.Snapshot()
	if before.Charged[resourcev4.Tasks] != 2 || before.Charged[resourcev4.WorkSlots] != 2 {
		t.Fatal("root did not preadmit actual Completion service", before)
	}
	var reservations [16]*CompletionReservation
	for j := range reservations {
		var err error
		reservations[j], err = e.ReserveCompletion(f.reserve(t, 1, e.CompletionCharge()), backing)
		if err != nil {
			t.Fatal(err)
		}
		defer reservations[j].Close()
	}
	after := f.root.Snapshot()
	if after.Charged[resourcev4.Tasks] != before.Charged[resourcev4.Tasks] || after.Charged[resourcev4.WorkSlots] != before.Charged[resourcev4.WorkSlots] {
		t.Fatal("dormant results reserved private workers", before, after)
	}
	if e.CompletionCharge()[resourcev4.SDKBytes] >= f.config.RuntimeBytesPerTask {
		t.Fatal("descriptor contains an entire future stack")
	}
}

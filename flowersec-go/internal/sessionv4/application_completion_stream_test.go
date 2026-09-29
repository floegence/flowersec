package sessionv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func TestCompletionStreamKeepsOriginalFutureAcrossItemsAtFullReferences(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1024})
	floor, err := e.NewCompletionFloor(f.reserve(t, 1, e.CompletionFloorCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	use, err := floor.borrowStream(backing)
	if err != nil {
		t.Fatal(err)
	}
	defer use.close()
	var pins []resourcev4.Reference
	defer func() {
		for _, pin := range pins {
			pin.Release()
		}
	}()
	for {
		pin, err := backing.Borrow()
		if errors.Is(err, resourcev4.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		pins = append(pins, pin)
	}
	before := f.root.Snapshot()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 3 {
		if _, err := floor.Checkout(); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("another result took the gap between stream items", err)
		}
		if _, err := floor.borrowStream(backing); !errors.Is(err, cryptov4.ErrCapacity) {
			t.Fatal("another stream took the original use", err)
		}
		future, err := use.checkout()
		if err != nil {
			t.Fatal("item allocated a new root reference", err)
		}
		task, err := future.Submit(func() error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		if err := task.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		if s := e.Snapshot(); s.CompletionRunning != 0 || s.CompletionReserved != 1 {
			t.Fatal("dormant stream lost its future or retained a worker", s)
		}
		if f.root.Snapshot() != before {
			t.Fatal("item completion changed the original result vector")
		}
	}
	// Closing a declaration seals new streams, while the accepted original
	// stream can still consume its next item from the same future descriptor.
	floor.Close()
	e.Close()
	future, err := use.checkout()
	if err != nil {
		t.Fatal("declaration close revoked an accepted multi-item stream", err)
	}
	future.Close()
	if floor.CleanupComplete() {
		t.Fatal("idle item gap refunded an accepted stream")
	}
	use.close()
	if !floor.CleanupComplete() {
		t.Fatal("actual stream exit retained its future")
	}
}

func TestCompletionStreamCloseKeepsActualDecoderTail(t *testing.T) {
	f := newExecutorFixture(t, 2, 1, 1, 1)
	e := f.executor
	backing := f.reserve(t, 1, resourcev4.Vector{resourcev4.SDKBytes: 1024})
	floor, err := e.NewCompletionFloor(f.reserve(t, 1, e.CompletionFloorCharge()), backing)
	if err != nil {
		t.Fatal(err)
	}
	defer floor.Close()
	use, err := floor.borrowStream(backing)
	if err != nil {
		t.Fatal(err)
	}
	defer use.close()
	future, err := use.checkout()
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	task, err := future.offer(func() error { close(entered); <-release; return nil })
	if err != nil {
		t.Fatal(err)
	}
	awaitApplicationTask(t, entered)
	future.Close()
	use.close()
	if err := floor.checkAvailable(); !errors.Is(err, cryptov4.ErrCapacity) {
		t.Fatal("decoder cancellation refunded its actual tail", err)
	}
	once.Do(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := task.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if err := floor.checkAvailable(); err != nil {
		t.Fatal("original floor did not return after actual decoder exit", err)
	}
}

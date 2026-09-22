package sessionv4

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

type runtimeOpaqueContext struct {
	done       chan struct{}
	canceled   atomic.Bool
	valueCalls atomic.Int32
	reason     error
}

func (c *runtimeOpaqueContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *runtimeOpaqueContext) Done() <-chan struct{}       { return c.done }
func (c *runtimeOpaqueContext) Value(any) any               { c.valueCalls.Add(1); return nil }
func (c *runtimeOpaqueContext) Err() error {
	if c.canceled.Load() {
		return c.reason
	}
	return nil
}
func (c *runtimeOpaqueContext) cancel() { c.canceled.Store(true); close(c.done) }

func TestSessionRuntimeOpaqueCancellationKeepsOriginalTasksAndReader(t *testing.T) {
	for _, native := range []bool{false, true} {
		for _, reason := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(fmt.Sprintf("native=%v/%s", native, reason), func(t *testing.T) {
				endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
				held := &resourceHeldReader{source: bytes.NewReader(nil), entered: make(chan struct{}), release: make(chan struct{})}
				input := &runtimeTestInput{Reader: held}
				f := newRuntimeFixture(t, endpoint, input, native)
				r := f.startOwner(t)
				var cancelSignaled atomic.Bool
				input.interrupt = func() {
					select {
					case <-r.context.Done():
						cancelSignaled.Store(true)
					default:
					}
				}
				var once sync.Once
				release := func() { once.Do(func() { close(held.release) }) }
				defer release()
				parent := &runtimeOpaqueContext{done: make(chan struct{}), reason: reason}
				done := make(chan error, 1)
				go func() { done <- r.Run(parent) }()
				select {
				case <-held.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("reader not started")
				}
				before := f.resources.root.Snapshot().Charged
				// Hold the runtime gate to delay its observer. A leaf's Err check
				// must still fence work and signal Done without acquiring that gate.
				r.mu.Lock()
				parent.cancel()
				observed := make(chan error, 1)
				go func() { observed <- r.context.Err() }()
				select {
				case err := <-observed:
					if !errors.Is(err, reason) {
						r.mu.Unlock()
						t.Fatal("original cancellation was not observed", err)
					}
				case <-time.After(5 * time.Second):
					r.mu.Unlock()
					t.Fatal("context inverted the runtime gate")
				}
				select {
				case <-r.context.Done():
				default:
					r.mu.Unlock()
					t.Fatal("Err reported cancellation without closing Done")
				}
				r.mu.Unlock()
				if err := waitRuntime(t, done); !errors.Is(err, reason) {
					t.Fatal(err)
				}
				if parent.valueCalls.Load() != 0 || !cancelSignaled.Load() || input.interrupts.Load() != 1 {
					t.Fatal("hidden parent propagation or incorrect shutdown ordering")
				}
				canceled, stop := context.WithCancel(context.Background())
				stop()
				if err := r.WaitCleanup(canceled); !errors.Is(err, context.Canceled) {
					t.Fatal("blocked reader claimed cleanup", err)
				}
				if err := r.Retire(); !errors.Is(err, cryptov4.ErrCapacity) || f.resources.root.Snapshot().Charged != before {
					t.Fatal("blocked reader lost its original reservation", err)
				}
				release()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := r.WaitCleanup(ctx); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(r.Err(), reason) || !errors.Is(r.context.Err(), reason) {
					t.Fatal("late reader exit changed original cancellation")
				}
				if err := r.Retire(); err != nil {
					t.Fatal(err)
				}
				if r.parent != nil || r.context.parent != nil {
					t.Fatal("retired runtime retained its parent")
				}
			})
		}
	}
}

func TestSessionRuntimeAlreadyCanceledOpaqueParentPreventsRead(t *testing.T) {
	for _, native := range []bool{false, true} {
		endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
		held := &resourceHeldReader{source: bytes.NewReader(nil), entered: make(chan struct{}), release: make(chan struct{})}
		close(held.release)
		input := &runtimeTestInput{Reader: held}
		f := newRuntimeFixture(t, endpoint, input, native)
		r := f.startOwner(t)
		parent := &runtimeOpaqueContext{done: make(chan struct{}), reason: context.DeadlineExceeded}
		parent.cancel()
		if err := r.Run(parent); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := r.WaitCleanup(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		select {
		case <-held.entered:
			t.Fatal("canceled parent entered provider")
		default:
		}
		if parent.valueCalls.Load() != 0 || input.interrupts.Load() != 1 {
			t.Fatal("opaque parent registered propagation or interrupted twice")
		}
	}
}

func TestSessionRuntimeCloseKeepsFirstChildCancellation(t *testing.T) {
	endpoint := newOpenEndpoint(t, 0, 2, 2, 1)
	input := &runtimeCleanupInput{entered: make(chan struct{}), stopped: make(chan struct{})}
	f := newRuntimeFixture(t, endpoint, input, false)
	r := f.startOwner(t)
	parent := &runtimeOpaqueContext{done: make(chan struct{}), reason: context.DeadlineExceeded}
	done := make(chan error, 1)
	go func() { done <- r.Run(parent) }()
	select {
	case <-input.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not start")
	}
	r.Close()
	if err := waitRuntime(t, done); !errors.Is(err, cryptov4.ErrClosed) {
		t.Fatal("explicit Close changed its result", err)
	}
	parent.cancel()
	if !errors.Is(r.context.Err(), context.Canceled) {
		t.Fatal("late parent deadline changed prior child cancellation")
	}
}

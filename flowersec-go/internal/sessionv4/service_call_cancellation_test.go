package sessionv4

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

type serviceCallValueKey struct{}

type serviceCallReadBlock struct {
	entered, resume chan struct{}
	once            sync.Once
	exit            func()
}

func (b *serviceCallReadBlock) release() { b.once.Do(func() { close(b.resume) }) }

type serviceCallOpaqueContext struct {
	context.Context
	done         chan struct{}
	deadline     time.Time
	err          error
	canceled     atomic.Bool
	block        atomic.Pointer[serviceCallReadBlock]
	registration atomic.Uint32
	stop         context.CancelCauseFunc
}

func newServiceCallOpaqueContext(err error) *serviceCallOpaqueContext {
	base, stop := context.WithCancelCause(context.Background())
	return &serviceCallOpaqueContext{Context: base, done: make(chan struct{}), deadline: time.Now().Add(time.Hour), err: err, stop: stop}
}
func (c *serviceCallOpaqueContext) Done() <-chan struct{}       { return c.done }
func (c *serviceCallOpaqueContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *serviceCallOpaqueContext) Err() error {
	if !c.canceled.Load() {
		return nil
	}
	if b := c.block.Swap(nil); b != nil {
		close(b.entered)
		<-b.resume
		if b.exit != nil {
			b.exit()
		}
	}
	return c.err
}
func (c *serviceCallOpaqueContext) Value(key any) any {
	if _, ok := key.(serviceCallValueKey); ok {
		return "original caller"
	}
	return c.Context.Value(key)
}
func (c *serviceCallOpaqueContext) AfterFunc(func()) func() bool {
	c.registration.Add(1)
	panic("opaque parent registered an unowned cancellation callback")
}
func (c *serviceCallOpaqueContext) cancel(cause error) {
	if c.canceled.CompareAndSwap(false, true) {
		c.stop(cause)
		close(c.done)
	}
}

func TestServiceCallCancellationPreservesCauseDeadlineAndValues(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	input := newServiceCallOpaqueContext(context.DeadlineExceeded)
	defer input.cancel(context.Canceled)
	slot, call, _, _, err := client.enter(input, definition.Methods[0].Type, 0, nil, synchronousOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer client.leave(slot)
	if deadline, ok := call.Deadline(); !ok || deadline != input.deadline || call.Value(serviceCallValueKey{}) != "original caller" {
		t.Fatal("SDK context changed the caller deadline or values")
	}
	descendant, stop := context.WithCancel(call)
	defer stop()
	cause := errors.New("original deadline cause")
	input.cancel(cause)
	awaitApplicationTask(t, slot.cancellation.done)
	awaitApplicationTask(t, descendant.Done())
	if call.Err() != context.DeadlineExceeded || descendant.Err() != context.DeadlineExceeded || context.Cause(call) != cause || context.Cause(descendant) != cause {
		t.Fatal("original cancellation facts changed", call.Err(), descendant.Err(), context.Cause(call))
	}
	if input.registration.Load() != 0 {
		t.Fatal("SDK registered a second cancellation relay")
	}
}

func TestServiceCallCloseRetainsBlockedCancellationRead(t *testing.T) {
	_, r, _, definition := serviceShapesFixture(t)
	client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	input := newServiceCallOpaqueContext(context.DeadlineExceeded)
	defer input.cancel(context.Canceled)
	slot, call, _, _, err := client.enter(input, definition.Methods[0].Type, 0, nil, synchronousOptions())
	if err != nil {
		t.Fatal(err)
	}
	owner := slot.cancellation
	b := &serviceCallReadBlock{entered: make(chan struct{}), resume: make(chan struct{})}
	defer b.release()
	input.block.Store(b)
	input.cancel(context.DeadlineExceeded)
	awaitApplicationTask(t, b.entered)
	closed := make(chan struct{})
	go func() { client.Close(); client.leave(slot); close(closed) }()
	awaitApplicationTask(t, closed)
	awaitApplicationTask(t, call.Done())
	if client.advance() || client.CleanupStatus().CoreCleanup != protocolv4.V4CoreCleanupPending {
		t.Fatal("Close refunded the blocked original cancellation observer")
	}
	client.mu.Lock()
	retained := client.active == 1 && client.callHead == slot && !slot.running
	client.mu.Unlock()
	if !retained {
		t.Fatal("caller exit released a live observer's actual slot")
	}
	b.release()
	awaitApplicationTask(t, owner.done)
	if !client.advance() {
		t.Fatal("actual observer exit retained a closed binding")
	}
	if call.Err() != context.Canceled || context.Cause(call) != context.Canceled {
		t.Fatal("late parent read changed the winning Close result")
	}
}

func TestServiceCallAbnormalCancellationReadSettlesOriginalObserver(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("context") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, r, _, definition := serviceShapesFixture(t)
			client, err := r.bindMethods(context.Background(), definition, UnaryServiceBindOptions{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			input := newServiceCallOpaqueContext(context.Canceled)
			defer input.cancel(context.Canceled)
			slot, call, _, _, err := client.enter(input, definition.Methods[0].Type, 0, nil, synchronousOptions())
			if err != nil {
				t.Fatal(err)
			}
			owner := slot.cancellation
			b := &serviceCallReadBlock{entered: make(chan struct{}), resume: make(chan struct{}), exit: tc.exit}
			defer b.release()
			input.block.Store(b)
			input.cancel(context.Canceled)
			awaitApplicationTask(t, b.entered)
			b.release()
			awaitApplicationTask(t, owner.done)
			if call.Err() == nil || context.Cause(call) != errServiceCallContext {
				t.Fatal("abnormal observer did not seal its original child")
			}
			client.leave(slot)
			client.mu.Lock()
			active := client.active
			client.mu.Unlock()
			if active != 0 {
				t.Fatal("actual observer exit retained the call", active)
			}
		})
	}
}

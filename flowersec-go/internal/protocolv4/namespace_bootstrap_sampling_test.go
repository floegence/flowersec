package protocolv4

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

func bootstrapSamplingFixture(t *testing.T) (*onlineBootstrapFixture, *authorizationClockSource) {
	t.Helper()
	source := &authorizationClockSource{}
	f := onlineBootstrapConfigured(t, nil, func(f *onlineBootstrapFixture) {
		clock, err := timev4.NewClock(f.owner.clock.Profile(), source.read)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(clock.Close)
		mark, err := clock.Monotonic()
		if err != nil {
			t.Fatal(err)
		}
		if err = clock.InstallTrusted(mark, f.namespace.now); err != nil {
			t.Fatal(err)
		}
		f.owner.clock = clock
	})
	return f, source
}

func TestBootstrapCloseDuringInitialClockReadRetainsActualTail(t *testing.T) {
	f, source := bootstrapSamplingFixture(t)
	var queries atomic.Uint32
	provider := f.provider
	provider.query = func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) { queries.Add(1); return 0, nil }
	before := f.namespace.resources.Snapshot().Charged
	b := source.pause(t, nil)
	done := make(chan error, 1)
	go func() { _, err := f.operation.Run(context.Background(), provider); done <- err }()
	awaitAuthorizationSignal(t, b.entered)
	closed := make(chan struct{})
	go func() { f.operation.Close(); close(closed) }()
	awaitAuthorizationSignal(t, closed)
	if err := f.operation.Retire(); err == nil {
		t.Fatal("blocked initial read released bootstrap storage")
	}
	if f.namespace.resources.Snapshot().Charged != before {
		t.Fatal("Close refunded live clock setup")
	}
	b.release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("late setup revived closed operation")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap setup did not finish")
	}
	if queries.Load() != 0 {
		t.Fatal("closed bootstrap started provider work")
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
}

type bootstrapOpaqueContext struct {
	context.Context
	block atomic.Pointer[authorizationClockBlock]
}

func (c *bootstrapOpaqueContext) Err() error {
	if b := c.block.Swap(nil); b != nil {
		close(b.entered)
		<-b.resume
	}
	return c.Context.Err()
}

// Core code must not inspect caller Value to discover context internals or
// register an unbudgeted cancellation relay. Provider-owned Value calls remain
// possible outside the SDK gate through the original task context.
func (*bootstrapOpaqueContext) Value(any) any { panic("opaque caller Value") }

func TestBootstrapCloseDuringOpaqueContextRead(t *testing.T) {
	f := onlineBootstrap(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &bootstrapOpaqueContext{Context: parent}
	b := &authorizationClockBlock{entered: make(chan struct{}), resume: make(chan struct{})}
	ctx.block.Store(b)
	t.Cleanup(b.release)
	done := make(chan error, 1)
	provider := f.provider
	provider.query = func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) { return 0, context.Canceled }
	go func() { _, err := f.operation.Run(ctx, provider); done <- err }()
	awaitAuthorizationSignal(t, b.entered)
	closed := make(chan struct{})
	go func() { f.operation.Close(); close(closed) }()
	awaitAuthorizationSignal(t, closed)
	if err := f.operation.Retire(); err == nil {
		t.Fatal("blocked context read lost its owner")
	}
	b.release()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled bootstrap published")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("context read tail did not finish")
	}
	if err := f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapAbnormalInitialClockReadCompletesCleanup(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("clock") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, source := bootstrapSamplingFixture(t)
			b := source.pause(t, tc.exit)
			done := make(chan struct{})
			go func() { defer close(done); _, _ = f.operation.Run(context.Background(), f.provider) }()
			awaitAuthorizationSignal(t, b.entered)
			b.release()
			awaitAuthorizationSignal(t, done)
			if err := f.operation.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := f.operation.Retire(); err != nil {
				t.Fatal("abnormal setup left immortal bootstrap", err)
			}
		})
	}
}

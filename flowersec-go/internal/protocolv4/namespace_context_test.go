package protocolv4

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type namespaceContextKey struct{}

type namespaceOpaqueContext struct {
	context.Context
	block     atomic.Pointer[authorizationClockBlock]
	doneReads atomic.Uint32
	doneExit  func()
}

func (c *namespaceOpaqueContext) Value(key any) any {
	if _, ok := key.(namespaceContextKey); ok {
		return "original provider value"
	}
	panic("SDK consulted opaque context internals")
}

func (c *namespaceOpaqueContext) Done() <-chan struct{} {
	c.doneReads.Add(1)
	if c.doneExit != nil {
		c.doneExit()
	}
	return c.Context.Done()
}

func (c *namespaceOpaqueContext) Err() error {
	if b := c.block.Swap(nil); b != nil {
		close(b.entered)
		<-b.resume
		if b.exit != nil {
			b.exit()
		}
	}
	return c.Context.Err()
}

func TestNamespaceOwnsCancellationAndPreservesProviderValues(t *testing.T) {
	f := newNamespaceFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &namespaceOpaqueContext{Context: parent}
	n, _, _ := liveNamespaceContextFixture(t, f, 4000, false, ctx)
	head, content := f.bindHead(t, 2, [2]uint64{})
	if err := n.Observe(head); err != nil {
		t.Fatal(err)
	}
	p, err := n.Pending()
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if err = p.Fetch(func(call context.Context, key NamespaceContent, out []byte) (int, error) {
		if call.Value(namespaceContextKey{}) != "original provider value" {
			t.Fatal("provider lost its original caller values")
		}
		return namespaceRead(content)(call, key, out)
	}); err != nil {
		t.Fatal(err)
	}
	if ctx.doneReads.Load() != 1 {
		t.Fatal("namespace registered another parent observer", ctx.doneReads.Load())
	}
	cancel()
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := n.WaitCleanup(wait); err != nil {
		t.Fatal("original watchdog did not observe Environment cancellation", err)
	}
}

func TestNamespaceCloseDoesNotWaitForParentContextRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"return", nil}, {"panic", func() { panic("context") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNamespaceFixture(t)
			ctx := &namespaceOpaqueContext{Context: context.Background()}
			n, _, _ := liveNamespaceContextFixture(t, f, 4000, false, ctx)
			before := f.resources.Snapshot().Charged
			b := &authorizationClockBlock{entered: make(chan struct{}), resume: make(chan struct{}), exit: tc.exit}
			t.Cleanup(b.release)
			ctx.block.Store(b)
			n.signal()
			awaitAuthorizationSignal(t, b.entered)
			closed := make(chan struct{})
			go func() { n.Close(nil); close(closed) }()
			awaitAuthorizationSignal(t, closed)
			if n.CleanupComplete() || f.resources.Snapshot().Charged != before {
				t.Fatal("blocked context read lost its original lifetime")
			}
			b.release()
			wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if err := n.WaitCleanup(wait); err != nil {
				t.Fatal("actual context tail did not settle", err)
			}
		})
	}
}

func TestNamespaceAbnormalContextSetupReturnsUnpublishedOwners(t *testing.T) {
	for _, tc := range []struct {
		name string
		exit func()
	}{
		{"panic", func() { panic("context") }}, {"goexit", runtime.Goexit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNamespaceFixture(t)
			clock, _ := namespaceClockFixture(t, f, false)
			head, content := f.bindHead(t, 1, [2]uint64{})
			allocation := f.namespaceAllocation(t)
			before := f.resources.Snapshot().Charged
			ctx := &namespaceOpaqueContext{Context: context.Background(), doneExit: tc.exit}
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = recover() }()
				_, _ = NewBootstrappedNamespace(ctx, clock, &testNamespaceTrust{}, NamespaceBootstrap{Rules: f.rules, Head: head, State: content}, 4000, 2, 8, allocation)
			}()
			awaitAuthorizationSignal(t, done)
			if f.resources.Snapshot().Charged != before {
				t.Fatal("abnormal setup retained unpublished State or namespace backing")
			}
		})
	}
}

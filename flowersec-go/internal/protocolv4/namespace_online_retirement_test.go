package protocolv4

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func retirementFixture(t *testing.T) (*onlineBootstrapFixture, *NamespaceRegistry, *LiveNamespace) {
	t.Helper()
	f, r := registryFixture(t, OnlineBootstrap, 1)
	n, err := f.operation.Run(context.Background(), f.provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.operation.Retire(); err != nil {
		t.Fatal(err)
	}
	return f, r, n
}
func retirementOperation(t *testing.T, f *onlineBootstrapFixture, r *NamespaceRegistry, next *NamespaceTrustStore) (*NamespaceOnlineRetirement, error) {
	t.Helper()
	limits := f.operation.limits
	charge, err := NamespaceOnlineRetirementCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	return NewNamespaceOnlineRetirement(context.Background(), r, f.owner, next, limits, f.namespace.namespaceAllocation(t), f.namespace.reserve(t, charge))
}
func TestOnlineRetirementRefusesOriginalSubscriberAndBorrow(t *testing.T) {
	for _, kind := range []string{"subscriber", "result_reference"} {
		t.Run(kind, func(t *testing.T) {
			f, r, n := retirementFixture(t)
			next := registryAnchor(t, f, f.owner.root.Authority)
			var release func()
			if kind == "subscriber" {
				subscription, err := n.subscribe(make(chan struct{}, 1))
				if err != nil {
					t.Fatal(err)
				}
				release = subscription.release
			} else {
				reference, err := n.PreparationReferenceFor(n.clock, n.reservation)
				if err != nil {
					t.Fatal(err)
				}
				release = reference.Release
			}
			defer release()
			if operation, err := retirementOperation(t, f, r, next); err == nil || operation != nil {
				t.Fatal("retired an actually attached owner")
			}
			if r.used != 1 || r.entries[0].retirement != nil || n.terminal != nil {
				t.Fatal("refusal altered live history or slot")
			}
			if err := r.CheckNamespace(n); err != nil {
				t.Fatal("refused retirement revoked current authorization", err)
			}
		})
	}
}
func TestOnlineRetirementCoversHistoryBeforeSlotReuse(t *testing.T) {
	f, r, n := retirementFixture(t)
	root, clock, limits := f.owner.root, f.owner.clock, f.owner.limits
	next := registryAnchor(t, f, root.Authority)
	operation, err := retirementOperation(t, f, r, next)
	if err != nil {
		t.Fatal(err)
	}
	before := f.namespace.resources.Snapshot().Charged
	if r.used != 1 || r.entries[0].retirement != operation || n.terminal == nil {
		t.Fatal("bootstrap did not retain and fence the original slot")
	}
	if _, err = r.Lookup(root.Tenant, root.Authority); err == nil {
		t.Fatal("retiring namespace admitted an attachment")
	}
	if err = operation.Run(context.Background(), f.provider); err != nil {
		t.Fatal(err)
	}
	if r.used != 0 || !operation.deleted || !n.destroyed || !f.owner.retired || !next.retired {
		t.Fatal("complete coverage did not physically retire history")
	}
	after := f.namespace.resources.Snapshot().Charged
	if after[resourcev4.SDKBytes] >= before[resourcev4.SDKBytes] {
		t.Fatal("retirement retained discarded backing")
	}
	cost, err := NamespaceTrustCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	dep := f.namespace.reserve(t, resourcev4.Vector{resourcev4.Items: 1})
	borrowed, err := dep.Borrow()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := NewNamespaceTrustAnchor(root, limits, clock, f.namespace.reserve(t, cost), borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = r.Register(fresh); err != nil {
		t.Fatal("independent fresh revisit could not reserve the retired slot", err)
	}
	if fresh.namespace != nil || fresh.continuityReady || fresh.count != 0 {
		t.Fatal("empty history inherited old authorization")
	}
	if _, err = fresh.Rules(); err == nil {
		t.Fatal("fresh anchor bypassed full independent bootstrap")
	}
	if err = r.CheckNamespace(n); err == nil {
		t.Fatal("slot reuse revived the permanently closed old namespace")
	}
}
func TestOnlineRetirementMissingCoveragePreservesSameSlotRecovery(t *testing.T) {
	f, r, n := retirementFixture(t)
	next := registryAnchor(t, f, f.owner.root.Authority)
	operation, err := retirementOperation(t, f, r, next)
	if err != nil {
		t.Fatal(err)
	}
	refused := bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			return 0, errors.New("independent authority unavailable")
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Fatal("fetch after bootstrap refusal")
			return 0, nil
		},
	}
	if err = operation.Run(context.Background(), refused); err == nil {
		t.Fatal("missing coverage deleted history")
	}
	if r.used != 1 || n.destroyed || f.owner.retired || n.active == nil || n.observed == nil {
		t.Fatal("failed independent bootstrap forgot the original history")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = operation.PreserveForReplacement(ctx); err != nil {
		t.Fatal(err)
	}
	if r.used != 1 || r.entries[0].retirement != nil || r.entries[0].trust != next || r.entries[0].historyCount != 1 || r.entries[0].history[0].trust != f.owner {
		t.Fatal("same-slot recovery turned failed history into an empty cache")
	}
	if _, err = r.Lookup(f.owner.root.Tenant, f.owner.root.Authority); err != nil {
		t.Fatal(err)
	}
	if next.continuityReady {
		t.Fatal("failed bootstrap opened fresh authorization")
	}
}

func referenceFactoryFixture(t *testing.T, f *onlineBootstrapFixture, r *NamespaceRegistry) *NamespaceReferenceFactory {
	t.Helper()
	config := NamespaceReferenceConfig{Root: f.owner.root, Trust: f.owner.limits, Bootstrap: f.operation.limits, Allocation: f.namespace.namespaceAllocation(t), Owner: f.namespace.resourceOwner(), Provider: f.provider}
	configs := []NamespaceReferenceConfig{config}
	charge, err := NamespaceReferenceFactoryCharge(configs, 65536)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewNamespaceReferenceFactory(context.Background(), r, f.owner.clock, configs, 65536, f.namespace.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		factory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := factory.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return factory
}

func TestReferenceFactoryRevisitUsesCompleteIndependentBootstrap(t *testing.T) {
	f, r, _ := retirementFixture(t)
	root := f.owner.root
	factory := referenceFactoryFixture(t, f, r)
	closeRetirementRecoveryOwner(t, f.owner)
	operation, provider, err := factory.PrepareNamespaceRetirement(context.Background(), r, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if err = operation.Run(context.Background(), provider); err != nil {
		t.Fatal(err)
	}
	// The slot belongs to the complete original physical retirement tail.
	factory.mu.Lock()
	cleanup := factory.slots[0].cleanup
	factory.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	case <-cleanup:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	owner, err := r.Resolve(context.Background(), root.Tenant, root.Authority)
	if err != nil {
		t.Fatal(err)
	}
	if owner == f.owner || owner == operation.next || !owner.continuityReady || owner.namespace == nil {
		t.Fatal("revisit reused old authorization or skipped complete bootstrap")
	}
	if err = r.CheckNamespace(owner.namespace); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceFactoryColdVisitNeverTrustsCacheOrUnknownAuthority(t *testing.T) {
	f := onlineBootstrap(t)
	config := NamespaceRegistryConfig{Continuity: OnlineBootstrap, Entries: 1, RuntimeBytes: 4096}
	charge, err := NamespaceRegistryCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewNamespaceRegistry(config, f.namespace.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	factory := referenceFactoryFixture(t, f, r)
	t.Cleanup(func() {
		r.Close()
		factory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := factory.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		for _, entry := range r.entries[:r.used] {
			if entry.trust.namespace != nil {
				if err := entry.trust.namespace.WaitCleanup(ctx); err != nil {
					t.Error(err)
				}
			}
		}
		f.namespace.resources.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	before := f.namespace.resources.Snapshot().Charged
	if _, err = r.Resolve(context.Background(), "tenant-1", "unknown-authority"); err == nil {
		t.Fatal("peer-selected authority created trust")
	}
	if f.namespace.resources.Snapshot().Charged != before || r.used != 0 {
		t.Fatal("unknown authority allocated a new history")
	}
	owner, err := r.Resolve(context.Background(), "tenant-1", "revocation-1")
	if err != nil {
		t.Fatal(err)
	}
	if owner == f.owner || owner.count == 0 || owner.namespace == nil || !owner.continuityReady {
		t.Fatal("cold visit did not complete independent full bootstrap")
	}
	if err = r.CheckNamespace(owner.namespace); err != nil {
		t.Fatal(err)
	}
}

func TestReferenceFactoryFailedColdBootstrapRecoversSameSlot(t *testing.T) {
	f := onlineBootstrap(t)
	config := NamespaceRegistryConfig{Continuity: OnlineBootstrap, Entries: 2, RuntimeBytes: 4096}
	charge, err := NamespaceRegistryCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewNamespaceRegistry(config, f.namespace.reserve(t, charge))
	if err != nil {
		t.Fatal(err)
	}
	factory := referenceFactoryFixture(t, f, r)
	t.Cleanup(func() {
		r.Close()
		factory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := factory.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		for _, entry := range r.entries[:r.used] {
			if entry.trust.namespace != nil {
				if err := entry.trust.namespace.WaitCleanup(ctx); err != nil {
					t.Error(err)
				}
			}
			for _, history := range entry.history[:entry.historyCount] {
				if history.trust.namespace != nil {
					if err := history.trust.namespace.WaitCleanup(ctx); err != nil {
						t.Error(err)
					}
				}
			}
		}
		f.namespace.resources.Close()
		if err := r.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	factory.mu.Lock()
	factory.slots[0].config.Provider = bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			return 0, errors.New("authority unavailable")
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Fatal("fetch after refused bootstrap")
			return 0, nil
		},
	}
	factory.mu.Unlock()
	if _, err = r.Resolve(context.Background(), "tenant-1", "revocation-1"); err == nil {
		t.Fatal("failed authority created an available namespace")
	}
	if r.used != 1 || !r.entries[0].trust.closed {
		t.Fatal("failed cold bootstrap lost its occupied slot")
	}
	original := r.entries[0].trust
	factory.mu.Lock()
	factory.slots[0].config.Provider = f.provider
	factory.mu.Unlock()
	next, err := r.Resolve(context.Background(), "tenant-1", "revocation-1")
	if err != nil {
		t.Fatal(err)
	}
	if next == original || r.used != 1 || r.entries[0].historyCount != 1 || r.entries[0].history[0].trust != original || !next.continuityReady {
		t.Fatal("normal revisit did not replace in the same history slot")
	}
}

// A host stop may reenter read-only SDK status before it physically exits.
// Closing Done is only cancellation notification, not cancellation completion.
type retirementHostStopContext struct {
	context.Context
	done, entered, release chan struct{}
	stopOnce               sync.Once
	hook                   func()
}

func (c *retirementHostStopContext) Done() <-chan struct{} { return c.done }
func (c *retirementHostStopContext) AfterFunc(func()) func() bool {
	return func() bool {
		c.stopOnce.Do(func() {
			if c.hook != nil {
				c.hook()
			}
			close(c.entered)
			<-c.release
		})
		return true
	}
}
func TestRetirementCloseJoinsHostStopOutsideOwnerGate(t *testing.T) {
	for _, kind := range []string{"service", "operation"} {
		t.Run(kind, func(t *testing.T) {
			host := &retirementHostStopContext{Context: context.Background(), done: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(host.release) }) }
			defer release()
			ctx, cancel := context.WithCancel(host)
			var closeOwner func()
			var waitOwner func(context.Context) error
			if kind == "service" {
				s := &NamespaceRetirementService{ctx: ctx, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}
				host.hook = func() { _ = s.Status() }
				go s.run()
				closeOwner = s.Close
				waitOwner = s.WaitCleanup
			} else {
				// A completed deletion still owes its original cancellation method exit.
				o := &NamespaceOnlineRetirement{ctx: ctx, cancel: func(error) { cancel() }, done: make(chan struct{}), deleted: true}
				host.hook = func() { o.mu.Lock(); o.mu.Unlock() }
				closeOwner = o.Close
				waitOwner = o.WaitCleanup
			}
			closed := make(chan struct{})
			go func() { closeOwner(); close(closed) }()
			timeout, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			select {
			case <-host.entered:
			case <-timeout.Done():
				t.Fatal("host stop reentry deadlocked original owner", timeout.Err())
			}
			short, stopShort := context.WithTimeout(context.Background(), 25*time.Millisecond)
			err := waitOwner(short)
			stopShort()
			if err != context.DeadlineExceeded {
				t.Fatal("cleanup refunded an active host stop", err)
			}
			release()
			select {
			case <-closed:
			case <-timeout.Done():
				t.Fatal(timeout.Err())
			}
			if err := waitOwner(timeout); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRetirementAutomaticDeadlineJoinsOriginalHostStop(t *testing.T) {
	host := &retirementHostStopContext{Context: context.Background(), done: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(host.release) }) }
	defer release()
	base, cancel := context.WithCancelCause(context.WithoutCancel(host))
	deadline := time.Now().Add(10 * time.Millisecond)
	o := &NamespaceOnlineRetirement{
		ctx: &namespaceRetirementContext{Context: base, deadline: deadline}, cancel: cancel,
		done: make(chan struct{}), environmentCallbackExited: make(chan struct{}), deadlineExited: make(chan struct{}), deleted: true,
	}
	host.hook = func() { o.mu.Lock(); o.mu.Unlock() }
	o.startCancellation(host, deadline)
	timeout, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	select {
	case <-host.entered:
	case <-timeout.Done():
		t.Fatal("automatic deadline did not enter original cancellation", timeout.Err())
	}
	if o.ctx.Err() != context.DeadlineExceeded {
		t.Fatal("automatic cancellation lost deadline error", o.ctx.Err())
	}
	closed := make(chan struct{})
	go func() { o.Close(); close(closed) }()
	short, stopShort := context.WithTimeout(context.Background(), 25*time.Millisecond)
	err := o.WaitCleanup(short)
	stopShort()
	if err != context.DeadlineExceeded {
		t.Fatal("cleanup completed before deadline cancellation physically exited", err)
	}
	select {
	case <-closed:
		t.Fatal("explicit Close bypassed original deadline cancellation")
	default:
	}
	release()
	select {
	case <-closed:
	case <-timeout.Done():
		t.Fatal("explicit Close did not join automatic cancellation", timeout.Err())
	}
	if err := o.WaitCleanup(timeout); err != nil {
		t.Fatal(err)
	}
	// A second observer must also join a timer stopped by an earlier caller.
	o.Close()
}

func TestRetirementRepeatedCloseJoinsStoppedDeadline(t *testing.T) {
	base, cancel := context.WithCancelCause(context.Background())
	deadline := time.Now().Add(time.Hour)
	o := &NamespaceOnlineRetirement{
		ctx: &namespaceRetirementContext{Context: base, deadline: deadline}, cancel: cancel,
		done: make(chan struct{}), environmentCallbackExited: make(chan struct{}), deadlineExited: make(chan struct{}), deleted: true,
	}
	o.startCancellation(context.Background(), deadline)
	o.Close()
	closed := make(chan struct{})
	go func() { o.Close(); close(closed) }()
	timeout, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	select {
	case <-closed:
	case <-timeout.Done():
		t.Fatal("repeated Close waited for an already stopped timer", timeout.Err())
	}
	if err := o.WaitCleanup(timeout); err != nil {
		t.Fatal(err)
	}
}

// Registration itself may be a slow host method. The registry cannot expose
// an operation whose cancellation/timer initialization has not exited yet.
type retirementRegistrationContext struct {
	context.Context
	done, entered, release, stopped chan struct{}
	stopOnce                        sync.Once
}

func (c *retirementRegistrationContext) Done() <-chan struct{} { return c.done }
func (c *retirementRegistrationContext) AfterFunc(func()) func() bool {
	close(c.entered)
	<-c.release
	return func() bool { c.stopOnce.Do(func() { close(c.stopped) }); return true }
}
func TestRetirementRegistersCancellationBeforeRegistryPublication(t *testing.T) {
	f, r, _ := retirementFixture(t)
	next := registryAnchor(t, f, f.owner.root.Authority)
	defer next.Close()
	host := &retirementRegistrationContext{Context: context.Background(), done: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{}), stopped: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(host.release) }) }
	defer release()
	limits := f.operation.limits
	charge, err := NamespaceOnlineRetirementCharge(limits)
	if err != nil {
		t.Fatal(err)
	}
	reservation := f.namespace.reserve(t, charge)
	allocation := f.namespace.namespaceAllocation(t)
	result := make(chan error, 1)
	go func() {
		operation, err := NewNamespaceOnlineRetirement(host, r, f.owner, next, limits, allocation, reservation)
		if operation != nil {
			operation.Close()
			result <- errors.New("published an operation after registry close")
			return
		}
		result <- err
	}()
	timeout, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	select {
	case <-host.entered:
	case <-timeout.Done():
		t.Fatal("constructor did not register original cancellation", timeout.Err())
	}
	r.mu.Lock()
	published := r.entries[0].retirement != nil
	r.mu.Unlock()
	if published {
		t.Fatal("registry exposed partial cancellation initialization")
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-timeout.Done():
		t.Fatal("host registration ran under registry gate", timeout.Err())
	}
	release()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("registry close did not refuse construction")
		}
	case <-timeout.Done():
		t.Fatal("construction refusal did not join initialization", timeout.Err())
	}
	select {
	case <-host.stopped:
	default:
		t.Fatal("construction refunded original owner before host stop exited")
	}
}

func TestRetirementRunCanceledBeforeProviderAdmission(t *testing.T) {
	f, r, _ := retirementFixture(t)
	next := registryAnchor(t, f, f.owner.root.Authority)
	operation, err := retirementOperation(t, f, r, next)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	provider := bootstrapTestProvider{
		query: func(context.Context, NamespaceBootstrapRequest, []byte) (int, error) {
			t.Error("canceled Run admitted authority provider")
			return 0, context.Canceled
		},
		fetch: func(context.Context, NamespaceContent, []byte) (int, error) {
			t.Error("canceled Run admitted content provider")
			return 0, context.Canceled
		},
	}
	if err := operation.Run(canceled, provider); err != context.Canceled {
		t.Fatal(err)
	}
	if err := operation.PreserveForReplacement(context.Background()); err != nil {
		t.Fatal(err)
	}
}

package protocolv4

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceOnlineRetirement is one admitted, independent bootstrap operation
// under history pressure. The original slot stays occupied until complete
// coverage and every actual owner tail has retired. It is not cache eviction.
// A failed operation preserves the exact closed histories in the same slot.
type NamespaceOnlineRetirement struct {
	mu                                          sync.Mutex
	registry                                    *NamespaceRegistry
	previous, next                              *NamespaceTrustStore
	bootstrap                                   *NamespaceOnlineBootstrap
	tail                                        resourcev4.Reference
	clock                                       *timev4.Clock
	window                                      *timev4.Window
	ctx                                         context.Context
	cancel                                      context.CancelCauseFunc
	cancelOnce                                  sync.Once
	stopEnvironment                             func() bool
	environmentCallbackExited                   chan struct{}
	environmentExitOnce                         sync.Once
	environmentStopOnce                         sync.Once
	deadlineTimer                               *time.Timer
	deadlineExited                              chan struct{}
	deadlineExitOnce                            sync.Once
	deadlineStopOnce                            sync.Once
	owners                                      [17]namespaceRetirementOwner
	ownerCount                                  int
	references                                  []resourcev4.Reference
	done                                        chan struct{}
	started, finished, closed, deleted, retired bool
	terminal                                    error
}

type namespaceRetirementOwner struct {
	trust     *NamespaceTrustStore
	namespace *LiveNamespace
	pin       resourcev4.Reference
}

// NamespaceOnlineRetirementCharge includes the complete original bootstrap,
// history reference index, cancellation/timer and final cleanup job. Existing
// histories, the new trust owner and State allocations remain additional actual
// charges in the same Environment/namespace/control aggregate.
func NamespaceOnlineRetirementCharge(l NamespaceBootstrapLimits) (resourcev4.Vector, error) {
	if l.Subscribers == 0 || l.Subscribers > 4096 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	charge, err := NamespaceBootstrapCharge(l)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{
		resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceOnlineRetirement{})) + uint64(unsafe.Sizeof(namespaceRetirementContext{})) + 18*uint64(l.Subscribers)*uint64(unsafe.Sizeof(resourcev4.Reference{})) + l.RuntimeBytes,
		resourcev4.Items:    1, resourcev4.Tasks: 3, resourcev4.Timers: 1,
	})
}

// NewNamespaceOnlineRetirement consumes the full new-operation budget before
// fencing an eligible owner. next must be an unused independently configured
// anchor for the same immutable authority, Clock and Environment. The only
// authority evidence comes from its original bootstrap provider, not old cache.
// This path deliberately excludes durable_restore: missing atomic deletion
// evidence there must retain the history rather than borrow an online fallback.
func NewNamespaceOnlineRetirement(environment context.Context, r *NamespaceRegistry, previous, next *NamespaceTrustStore, l NamespaceBootstrapLimits, allocation NamespaceAllocation, reservation resourcev4.Reference) (*NamespaceOnlineRetirement, error) {
	if environment == nil || r == nil || previous == nil || next == nil || previous == next {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	charge, err := NamespaceOnlineRetirementCharge(l)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckMinimum(charge); err != nil {
		return nil, err
	}
	previous.mu.Lock()
	originalRoot, originalClock := previous.root, previous.clock
	previous.mu.Unlock()
	next.mu.Lock()
	valid := next.registry == nil && next.namespace == nil && next.count == 0 && !next.closed && !next.retired && !next.bootstrapStarted && next.root == originalRoot && next.clock == originalClock
	clock := next.clock
	next.mu.Unlock()
	if !valid {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	window, err := timev4.NewWindow(clock, l.DurationMS)
	if err != nil {
		return nil, err
	}
	// The host timer is a cancellation hint. The original Clock window is the
	// authorization check before/after I/O and at the final deletion boundary.
	// Parent and deadline callbacks enter the same cancellation owner. Letting
	// a timer context cancel itself would make a later CancelFunc return while
	// the first cancellation is still executing a host AfterFunc stop.
	base, cancel := context.WithCancelCause(context.WithoutCancel(environment))
	deadline := time.Now().Add(time.Duration(l.DurationMS) * time.Millisecond)
	if parentDeadline, ok := environment.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	ctx := &namespaceRetirementContext{Context: base, deadline: deadline}
	bootstrap, err := NewNamespaceOnlineBootstrap(environment, next, l, allocation, reservation)
	if err != nil {
		cancel(context.Canceled)
		return nil, err
	}
	tail, err := bootstrap.reservation.Borrow()
	if err != nil {
		cancel(context.Canceled)
		bootstrap.Close()
		_ = bootstrap.Retire()
		return nil, err
	}
	operation := &NamespaceOnlineRetirement{tail: tail, registry: r, previous: previous, next: next, bootstrap: bootstrap, clock: clock, window: window, ctx: ctx, cancel: cancel, done: make(chan struct{}), environmentCallbackExited: make(chan struct{}), deadlineExited: make(chan struct{})}
	operation.references = make([]resourcev4.Reference, 18*int(l.Subscribers))
	// Install all original callback/timer handles before claim can publish this
	// owner in the registry. Host registration stays outside registry gates;
	// any construction refusal still joins these actual initialization tails.
	operation.startCancellation(environment, deadline)
	if err = operation.claim(); err != nil {
		operation.joinCancellationExit()
		bootstrap.Close()
		_ = bootstrap.Retire()
		tail.Release()
		return nil, err
	}
	// Closing is synchronous only for admission. Physical provider exit remains
	// the refresh owner's background responsibility; waiting here could outlive
	// the caller's retirement deadline and make Prepare/Close unresponsive.
	operation.closeClaimedRefreshes()
	return operation, nil
}

func (o *NamespaceOnlineRetirement) closeClaimedRefreshes() {
	for i := 0; i < o.ownerCount; i++ {
		n := o.owners[i].namespace
		if n == nil {
			continue
		}
		n.mu.Lock()
		refresh := n.refresh
		n.mu.Unlock()
		if refresh == nil {
			continue
		}
		refresh.Close()
		go func(refresh *NamespaceRefresh) {
			refresh.waitCleanupFinal()
			_ = refresh.Retire()
		}(refresh)
	}
}

func (o *NamespaceOnlineRetirement) signalEnvironmentExit() {
	o.environmentExitOnce.Do(func() { close(o.environmentCallbackExited) })
}
func (o *NamespaceOnlineRetirement) signalDeadlineExit() {
	o.deadlineExitOnce.Do(func() { close(o.deadlineExited) })
}
func (o *NamespaceOnlineRetirement) runCancellation(cause error) {
	// Only the original cancel function is unique. Stopping the parent callback
	// is a separate join step so a timer callback can never wait for a parent
	// callback that is itself waiting on this Once.
	o.cancelOnce.Do(func() { o.cancel(cause) })
}
func (o *NamespaceOnlineRetirement) startCancellation(environment context.Context, deadline time.Time) {
	ready := make(chan struct{})
	o.stopEnvironment = context.AfterFunc(environment, func() {
		defer o.signalEnvironmentExit()
		<-ready
		o.runCancellation(environment.Err())
	})
	o.deadlineTimer = time.AfterFunc(time.Until(deadline), func() {
		defer o.signalDeadlineExit()
		<-ready
		o.runCancellation(context.DeadlineExceeded)
		// The timer owns actual parent-stop exit too. It never joins its own
		// timer signal, and the parent callback never joins its own registration.
		o.joinEnvironmentCancellation()
	})
	close(ready)
}

// Context cancellation keeps the original deadline/error contract while the
// explicit owner, rather than context's private timer, performs cancellation.
type namespaceRetirementContext struct {
	context.Context
	deadline time.Time
}

func (c *namespaceRetirementContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *namespaceRetirementContext) Err() error {
	if c.Context.Err() == nil {
		return nil
	}
	return context.Cause(c.Context)
}

// claim holds the same registry/namespace/trust gates used by attachment. It
// seals exact reference sets in one root operation; a subscriber, result, cursor,
// source, callback or borrow that won first makes the whole attempt refuse.
func (o *NamespaceOnlineRetirement) claim() error {
	r := o.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := o.ctx.Err(); err != nil {
		return err
	}
	if r.closed || r.continuity != OnlineBootstrap {
		return CBORFailure("revocation_continuity_binding")
	}
	var entry *namespaceRegistryEntry
	for i := range r.entries[:r.used] {
		if r.entries[i].trust == o.previous {
			entry = &r.entries[i]
			break
		}
	}
	if entry == nil || entry.retirement != nil || r.used < r.capacity && entry.historyCount == 0 {
		return CBORFailure("revocation_namespace_retiring")
	}
	for _, history := range entry.history[:entry.historyCount] {
		o.owners[o.ownerCount] = namespaceRetirementOwner{trust: history.trust, pin: history.pin}
		o.ownerCount++
	}
	o.owners[o.ownerCount] = namespaceRetirementOwner{trust: entry.trust, pin: entry.pin}
	o.ownerCount++
	// Inspect immutable namespace associations first. An in-progress owner
	// bootstrap or trust publisher cannot pass the later locked checks.
	for i := 0; i < o.ownerCount; i++ {
		owner := &o.owners[i]
		owner.trust.mu.Lock()
		owner.namespace = owner.trust.namespace
		owner.trust.mu.Unlock()
		if owner.namespace != nil {
			owner.namespace.mu.Lock()
		}
		owner.trust.mu.Lock()
	}
	defer func() {
		for i := o.ownerCount - 1; i >= 0; i-- {
			owner := &o.owners[i]
			owner.trust.mu.Unlock()
			if owner.namespace != nil {
				owner.namespace.mu.Unlock()
			}
		}
	}()
	var groups [68]resourcev4.ExclusiveReferences
	groupCount, referenceCount := 0, 0
	for i := 0; i < o.ownerCount; i++ {
		owner := &o.owners[i]
		t, n := owner.trust, owner.namespace
		if t.namespace != n || t.retired || t.busy || t.closing || t.bootstrap || t.restoring || t.sampling != 0 {
			return CBORFailure("revocation_namespace_owner")
		}
		groups[groupCount] = resourcev4.ExclusiveReferences{Primary: t.reservation, References: []resourcev4.Reference{owner.pin}}
		groupCount++
		if n == nil {
			continue
		}
		if n.destroyed || n.initializing || n.sampling != 0 || n.refreshFencing || n.durable != nil || n.pin != nil && n.pin.running || len(n.subscribers) > int(o.bootstrap.limits.Subscribers) {
			return CBORFailure("revocation_namespace_owner")
		}
		begin := referenceCount
		for _, subscriber := range n.subscribers {
			if subscriber.wake != nil {
				return CBORFailure("revocation_namespace_owner")
			}
			if subscriber.reservation != (resourcev4.Reference{}) {
				o.references[referenceCount] = subscriber.reservation
				referenceCount++
			}
		}
		groups[groupCount] = resourcev4.ExclusiveReferences{Primary: n.reservation, References: o.references[begin:referenceCount]}
		groupCount++
		groups[groupCount] = resourcev4.ExclusiveReferences{Primary: n.active.workspace.reservation}
		groupCount++
		groups[groupCount] = resourcev4.ExclusiveReferences{Primary: n.spare.reservation}
		groupCount++
	}
	o.next.mu.Lock()
	if o.next.root != o.previous.root || o.next.clock != o.previous.clock || o.next.registry != nil || o.next.namespace != nil || o.next.count != 0 || o.next.closed || o.next.retired || !o.next.bootstrap || o.next.limits.Configurations < uint32(o.previous.count) {
		o.next.mu.Unlock()
		return CBORFailure("revocation_namespace_binding")
	}
	if err := r.reservation.CheckSameEnvironment(o.next.reservation); err != nil {
		o.next.mu.Unlock()
		return err
	}
	o.next.mu.Unlock()
	if err := resourcev4.SealExclusiveGroup(groups[:groupCount]); err != nil {
		return err
	}
	// Exact subscriber/reference qualification succeeded. Fence refresh
	// admission while the registry and namespace gates are still held; the
	// physical worker is closed only after all gates are released below.
	for i := 0; i < o.ownerCount; i++ {
		if n := o.owners[i].namespace; n != nil && (n.refresh != nil || n.refreshActive) {
			n.refreshFencing = true
		}
	}
	// A refusal above changed no ownership. From here all old incarnations are
	// permanently fenced; provider/copy failure must preserve their same slot.
	entry.retirement = o
	for i := 0; i < o.ownerCount; i++ {
		owner := &o.owners[i]
		owner.trust.closed = true
		if owner.namespace != nil {
			owner.namespace.closeLocked(CBORFailure("revocation_namespace_retiring"))
			owner.namespace.cleanup()
		}
	}
	o.next.mu.Lock()
	o.next.registry = r
	o.next.continuity = OnlineBootstrap
	o.next.replacementOf = o.previous
	o.next.retirementOnly = true
	o.next.restoring = true
	o.next.mu.Unlock()
	// Copying original finite signed history is verification work, with new
	// backing charged to next. No provider call or wait occurs under these gates.
	for i := 0; i < o.previous.count; i++ {
		wire, err := o.previous.configurations[i].signed.Bytes()
		if err == nil {
			err = o.next.update(wire, true)
		}
		if err != nil {
			o.next.mu.Lock()
			o.next.restoring = false
			o.next.mu.Unlock()
			o.terminal = err
			return nil
		}
	}
	o.next.mu.Lock()
	o.next.restoring = false
	o.next.mu.Unlock()
	return nil
}

func (o *NamespaceOnlineRetirement) checkAt(sample timev4.Sample) error {
	if err := o.ctx.Err(); err != nil {
		return err
	}
	current, err := o.clock.RefreshSample(sample)
	if err != nil {
		return err
	}
	if err = o.window.CheckAt(current.Mark); err != nil {
		return err
	}
	b := o.bootstrap
	if b.deadline == nil {
		return CBORFailure("revocation_bootstrap_binding")
	}
	if err = b.deadline.CheckUsingSample(current); err != nil {
		return err
	}
	if err = b.window.CheckAt(current.Mark); err != nil {
		return err
	}
	t := o.next
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.retired || t.busy || t.sampling != 0 || !t.continuityReady || t.count == 0 || t.registry != o.registry {
		return CBORFailure("revocation_namespace_owner")
	}
	if err = t.dependencies.Check(); err != nil {
		return err
	}
	return t.checkTimeAt(&t.configurations[t.count-1], current)
}

// Run uses one fixed bootstrap baseline and the original finite deadline. It
// never returns a Session-capable candidate or retries with a different Head.
// Unknown/failed coverage leaves the old compact histories and slot occupied.
func (o *NamespaceOnlineRetirement) Run(ctx context.Context, provider NamespaceBootstrapProvider) (err error) {
	if o == nil || ctx == nil || provider == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	o.mu.Lock()
	if o.started || o.closed {
		o.mu.Unlock()
		return CBORFailure("revocation_namespace_owner")
	}
	o.started = true
	initial := o.terminal
	o.mu.Unlock()
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(callbackDone); o.runCancellation(ctx.Err()) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		o.joinCancellationExit()
		o.mu.Lock()
		o.finished = true
		if err != nil {
			o.terminal = err
		}
		if o.deleted {
			o.tail.Release()
		}
		close(o.done)
		o.mu.Unlock()
	}()
	if inputErr := ctx.Err(); inputErr != nil {
		o.runCancellation(inputErr)
		return inputErr
	}
	if initial != nil {
		return initial
	}
	// Fence refresh scheduling first, then join the actual methods and watchers.
	// Cancellation never refunds a stalled provider or drops its original history.
	for i := 0; i < o.ownerCount; i++ {
		n := o.owners[i].namespace
		if n == nil {
			continue
		}
		n.mu.Lock()
		refresh := n.refresh
		n.mu.Unlock()
		if refresh != nil {
			refresh.Close()
			if err = refresh.WaitCleanup(o.ctx); err != nil {
				go func(refresh *NamespaceRefresh) { refresh.waitCleanupFinal(); _ = refresh.Retire() }(refresh)
				return err
			}
			if err = refresh.Retire(); err != nil {
				return err
			}
		}
		if err = n.WaitCleanup(o.ctx); err != nil {
			return err
		}
	}
	if err = o.window.Check(); err != nil {
		return err
	}
	candidate, err := o.bootstrap.Run(o.ctx, provider)
	if err != nil {
		return err
	}
	// The independent complete pair has covered every previous incarnation in
	// the original chain. Close this private candidate before joining its tail.
	if err = o.next.checkReplacementCoverage(candidate); err != nil {
		return err
	}
	sample, err := o.clock.Sample()
	if err != nil {
		return err
	}
	if err = o.checkAt(sample); err != nil {
		return err
	}
	o.next.Close()
	if err = candidate.WaitCleanup(o.ctx); err != nil {
		return err
	}
	sample, err = o.clock.Sample()
	if err != nil {
		return err
	}
	r := o.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return CBORFailure("revocation_namespace_owner")
	}
	slot := -1
	for i := range r.entries[:r.used] {
		if r.entries[i].retirement == o && r.entries[i].trust == o.previous {
			slot = i
			break
		}
	}
	if slot < 0 {
		return CBORFailure("revocation_namespace_owner")
	}
	if err = o.checkAt(sample); err != nil {
		return err
	}
	for i := 0; i < o.ownerCount; i++ {
		owner := &o.owners[i]
		if err = retirementQuiescent(owner.trust, owner.namespace); err != nil {
			return err
		}
	}
	if err = retirementQuiescent(o.next, candidate); err != nil {
		return err
	}
	// The proof candidate was never delivered, but exact resource references
	// still decide whether a trusted caller retained an actual dependency.
	candidate.mu.Lock()
	o.next.mu.Lock()
	borrowed := o.references[17*int(o.bootstrap.limits.Subscribers) : 17*int(o.bootstrap.limits.Subscribers)]
	for _, slot := range candidate.subscribers {
		if slot.reservation != (resourcev4.Reference{}) {
			borrowed = append(borrowed, slot.reservation)
		}
	}
	proofGroups := []resourcev4.ExclusiveReferences{
		{Primary: o.next.reservation},
		{Primary: candidate.reservation, References: borrowed},
		{Primary: candidate.active.workspace.reservation},
		{Primary: candidate.spare.reservation},
	}
	err = resourcev4.SealExclusiveGroup(proofGroups)
	o.next.mu.Unlock()
	candidate.mu.Unlock()
	if err != nil {
		return err
	}
	// This is the live online deletion eligibility boundary. No storage I/O is
	// performed and no new attachment can pass while the original slot is held.
	for i := 0; i < o.ownerCount; i++ {
		authorizeRetirementDeletion(o.owners[i].trust, o.owners[i].namespace)
	}
	authorizeRetirementDeletion(o.next, candidate)
	for i := 0; i < o.ownerCount; i++ {
		owner := &o.owners[i]
		if err = owner.trust.DestroyEnvironment(); err != nil {
			return err
		}
		owner.pin.Release()
	}
	if err = o.bootstrap.Retire(); err != nil {
		return err
	}
	if err = o.next.DestroyEnvironment(); err != nil {
		return err
	}
	r.entries[slot] = r.entries[r.used-1]
	r.entries[r.used-1] = namespaceRegistryEntry{}
	r.used--
	r.historyPressure = false
	o.mu.Lock()
	o.deleted = true
	o.mu.Unlock()
	// All complete old/new backing and bootstrap tails have physically retired
	// before the occupied slot becomes available to an independent fresh visit.
	clear(o.references)
	o.references = nil
	return nil
}

func retirementQuiescent(t *NamespaceTrustStore, n *LiveNamespace) error {
	if n != nil {
		n.mu.Lock()
		defer n.mu.Unlock()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed || t.namespace != n || t.busy || t.closing || t.sampling != 0 || t.restoring {
		return CBORFailure("revocation_namespace_owner")
	}
	if n != nil {
		if !n.cleaned || n.refresh != nil || n.refreshActive || n.sampling != 0 || n.pin != nil && n.pin.running {
			return CBORFailure("revocation_namespace_owner")
		}
		for _, subscriber := range n.subscribers {
			if subscriber.wake != nil {
				return CBORFailure("revocation_namespace_owner")
			}
		}
	}
	return nil
}
func authorizeRetirementDeletion(t *NamespaceTrustStore, n *LiveNamespace) {
	if n != nil {
		n.mu.Lock()
		n.retirementDeletion = true
		n.mu.Unlock()
	}
	t.mu.Lock()
	t.retirementDeletion = true
	t.mu.Unlock()
}
func (o *NamespaceOnlineRetirement) joinCancellation() { o.runCancellation(context.Canceled) }
func (o *NamespaceOnlineRetirement) joinEnvironmentCancellation() {
	if o.stopEnvironment != nil {
		o.environmentStopOnce.Do(func() {
			if o.stopEnvironment() {
				o.signalEnvironmentExit()
			}
		})
		<-o.environmentCallbackExited
	}
}
func (o *NamespaceOnlineRetirement) joinCancellationExit() {
	o.runCancellation(context.Canceled)
	o.joinEnvironmentCancellation()
	if o.deadlineTimer != nil {
		o.deadlineStopOnce.Do(func() {
			if o.deadlineTimer.Stop() {
				o.signalDeadlineExit()
			}
		})
		<-o.deadlineExited
	}
}
func (o *NamespaceOnlineRetirement) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.retired {
		o.mu.Unlock()
		return
	}
	o.closed = true
	started, deleted := o.started, o.deleted
	o.mu.Unlock()
	// Unique host cancellation has actual completion semantics. No host code
	// or wait runs under the operation gate, and Run joins this same execution.
	o.joinCancellationExit()
	if !deleted {
		o.bootstrap.Close()
		o.next.Close()
	}
	o.mu.Lock()
	if !started && !o.finished {
		o.finished = true
		close(o.done)
	}
	o.mu.Unlock()
}
func (o *NamespaceOnlineRetirement) WaitCleanup(ctx context.Context) error {
	if o == nil || ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// destroyEnvironment is the conservative cleanup path for an unsuccessful
// retirement. Its original slot/history remains unavailable until Environment
// destruction, which already fences the complete dependency graph.
func (o *NamespaceOnlineRetirement) destroyEnvironment() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.retired {
		return nil
	}
	if !o.finished {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := o.bootstrap.Retire(); err != nil {
		return err
	}
	if err := o.next.DestroyEnvironment(); err != nil {
		return err
	}
	o.retired = true
	clear(o.references)
	o.references = nil
	o.tail.Release()
	return nil
}
func (*NamespaceOnlineRetirement) String() string               { return "Flowersec.NamespaceOnlineRetirement" }
func (*NamespaceOnlineRetirement) GoString() string             { return "Flowersec.NamespaceOnlineRetirement" }
func (*NamespaceOnlineRetirement) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// PreserveForReplacement ends a failed job's physical ownership while keeping
// all learned trust/State and the same occupied slot. A subsequent explicit
// ReplaceFailed and independent bootstrap must cover the complete chain. This
// does not revive any old authorization or automatically retry the operation.
// If the bounded history/borrow capacity is unavailable, the pending owner
// remains retained and this method refuses without making the slot blank.
func (o *NamespaceOnlineRetirement) PreserveForReplacement(ctx context.Context) error {
	if o == nil || ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// This is an observation of the same original job, never another Run or
	// proof window. Done includes its actual cancellation/provider invocation.
	if err := o.WaitCleanup(ctx); err != nil {
		return err
	}
	o.mu.Lock()
	deleted, retired := o.deleted, o.retired
	o.mu.Unlock()
	if deleted {
		return CBORFailure("revocation_namespace_owner")
	}
	if retired {
		return nil
	}
	o.Close()
	if err := o.bootstrap.WaitCleanup(ctx); err != nil {
		return err
	}
	for i := 0; i < o.ownerCount; i++ {
		if previous := o.owners[i].namespace; previous != nil {
			if err := previous.WaitCleanup(ctx); err != nil {
				return err
			}
		}
	}
	o.next.mu.Lock()
	candidate := o.next.namespace
	o.next.mu.Unlock()
	if candidate != nil {
		if err := candidate.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	r := o.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	// Two bounded observers may join the same physical tail. Only one can
	// commit the history transfer; subsequent observers report its same result.
	o.mu.Lock()
	retired, deleted = o.retired, o.deleted
	o.mu.Unlock()
	if retired && !deleted {
		return nil
	}
	if r.closed || deleted {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var entry *namespaceRegistryEntry
	for i := range r.entries[:r.used] {
		if r.entries[i].retirement == o && r.entries[i].trust == o.previous {
			entry = &r.entries[i]
			break
		}
	}
	if entry == nil || entry.historyCount == len(entry.history) {
		return CBORFailure("configuration_capacity")
	}
	o.next.mu.Lock()
	if o.next.retired || o.next.busy || o.next.sampling != 0 || o.next.closing || !o.next.closed {
		o.next.mu.Unlock()
		return CBORFailure("revocation_namespace_owner")
	}
	pin, err := o.next.reservation.Borrow()
	o.next.mu.Unlock()
	if err != nil {
		return err
	}
	if err = o.bootstrap.Retire(); err != nil {
		pin.Release()
		return err
	}
	entry.history[entry.historyCount] = namespaceRegistryHistory{trust: entry.trust, pin: entry.pin}
	entry.historyCount++
	entry.trust, entry.pin, entry.retirement = o.next, pin, nil
	// Completing cleanup never schedules a new proof. Only explicit same-slot
	// replacement may establish a fresh independently authenticated baseline.
	entry.retirementFailed = true
	o.mu.Lock()
	o.retired = true
	clear(o.references)
	o.references = nil
	o.mu.Unlock()
	o.tail.Release()
	if service := r.pressureService; service != nil {
		service.mu.Lock()
		if service.current == o {
			service.current = nil
		}
		service.retainedFailure = true
		service.mu.Unlock()
	}
	return nil
}

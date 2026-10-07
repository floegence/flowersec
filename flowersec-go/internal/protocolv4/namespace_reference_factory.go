package protocolv4

import (
	"context"
	"crypto/rand"
	"math"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceReferenceConfig is installed by the trusted deployment. Neither a
// credential nor a lookup name can supply a root, provider, allocation account
// or capacity. The same immutable configuration governs cold visits and the
// independent complete bootstrap used to prove history retirement.
type NamespaceReferenceConfig struct {
	Root       NamespaceTrustRoot
	Trust      NamespaceTrustLimits
	Bootstrap  NamespaceBootstrapLimits
	Allocation NamespaceAllocation
	Owner      resourcev4.OwnerKey
	Accounts   []resourcev4.Account
	Provider   NamespaceBootstrapProvider
	Refresh    NamespaceRefreshConfig
}

type NamespaceRefreshConfig struct {
	Limits   NamespaceRefreshLimits
	Provider NamespaceRefreshProvider
}

type namespaceReferenceSlot struct {
	config          NamespaceReferenceConfig
	busy            bool
	observing       bool
	operation       *NamespaceOnlineRetirement
	cleanup         chan struct{}
	refresh         *NamespaceRefresh
	refreshStarting bool
}

// NamespaceReferenceFactory is a bounded online reference composition. A
// missing history always creates an independently anchored full bootstrap. An
// occupied failed history remains in its original slot; it is never treated as
// a cold visit or silently reset. Each configured authority has one work slot
// and no caller queue. Actual provider exit precedes release of that slot.
type NamespaceReferenceFactory struct {
	mu                        sync.Mutex
	registry                  *NamespaceRegistry
	clock                     *timev4.Clock
	slots                     []namespaceReferenceSlot
	reservation, dependency   resourcev4.Reference
	ctx                       context.Context
	cancel                    context.CancelFunc
	cancelOnce                sync.Once
	cancelExited              bool
	done                      chan struct{}
	active                    uint32
	incarnation               uint64
	closed, finished, retired bool
}

func NamespaceReferenceFactoryCharge(configs []NamespaceReferenceConfig, runtimeBytes uint64) (resourcev4.Vector, error) {
	if len(configs) == 0 || len(configs) > 4096 || runtimeBytes == 0 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	bytes := uint64(unsafe.Sizeof(NamespaceReferenceFactory{})) + 256
	if runtimeBytes > math.MaxUint64-bytes {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	bytes += runtimeBytes
	for i, c := range configs {
		if c.Root.Tenant == "" || len(c.Root.Tenant) > 128 || c.Root.Authority == "" || len(c.Root.Authority) > 128 || c.Root.KeyID == ([16]byte{}) || c.Root.PublicKey == ([32]byte{}) || c.Root.MaxLifetimeMS == 0 || c.Provider == nil || c.Allocation.Root == nil || len(c.Accounts) > resourcev4.MaxAccountsPerCharge || len(c.Allocation.Accounts) > resourcev4.MaxAccountsPerCharge {
			return resourcev4.Vector{}, CBORFailure("revocation_namespace_binding")
		}
		for _, owner := range c.Allocation.Owners {
			if owner.Environment != c.Owner.Environment || owner.ProfileRevision != c.Owner.ProfileRevision {
				return resourcev4.Vector{}, CBORFailure("revocation_namespace_binding")
			}
		}
		if _, err := NamespaceTrustCharge(c.Trust); err != nil {
			return resourcev4.Vector{}, err
		}
		if _, err := NamespaceOnlineRetirementCharge(c.Bootstrap); err != nil {
			return resourcev4.Vector{}, err
		}
		if c.Refresh.Provider != nil {
			if _, err := NamespaceRefreshCharge(c.Refresh.Limits, c.Trust.ConfigBytes); err != nil {
				return resourcev4.Vector{}, err
			}
		} else if c.Refresh.Limits != (NamespaceRefreshLimits{}) {
			return resourcev4.Vector{}, CBORFailure("revocation_namespace_binding")
		}
		for j := 0; j < i; j++ {
			if configs[j].Root.Tenant == c.Root.Tenant && configs[j].Root.Authority == c.Root.Authority {
				return resourcev4.Vector{}, CBORFailure("revocation_namespace_binding")
			}
		}
		add := uint64(unsafe.Sizeof(namespaceReferenceSlot{})) + uint64(len(c.Root.Tenant)+len(c.Root.Authority)) + uint64(len(c.Accounts)+len(c.Allocation.Accounts))*uint64(unsafe.Sizeof(resourcev4.Account{}))
		if add > math.MaxUint64-bytes {
			return resourcev4.Vector{}, CBORFailure("configuration_capacity")
		}
		bytes += add
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: bytes, resourcev4.Items: 1 + uint64(len(configs)), resourcev4.WorkSlots: uint64(len(configs)), resourcev4.Tasks: 2 * uint64(len(configs)), resourcev4.Timers: uint64(len(configs))}
	for _, c := range configs {
		if c.Refresh.Provider != nil {
			refreshCharge, err := NamespaceRefreshCharge(c.Refresh.Limits, c.Trust.ConfigBytes)
			if err != nil {
				return resourcev4.Vector{}, err
			}
			charge, err = charge.Add(refreshCharge)
			if err != nil {
				return resourcev4.Vector{}, err
			}
		}
	}
	return charge, nil
}

func NewNamespaceReferenceFactory(environment context.Context, registry *NamespaceRegistry, clock *timev4.Clock, configs []NamespaceReferenceConfig, runtimeBytes uint64, reservation resourcev4.Reference) (*NamespaceReferenceFactory, error) {
	if environment == nil || environment.Err() != nil || registry == nil || clock == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	charge, err := NamespaceReferenceFactoryCharge(configs, runtimeBytes)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	adopted := false
	ctx, cancel := context.WithCancel(environment)
	defer func() {
		if !adopted {
			cancel()
			owned.Release()
		}
	}()
	// Context adapter setup may execute host methods. The complete constructor
	// is admitted first and performs that setup outside the registry gate.
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.closed || registry.continuity != OnlineBootstrap || registry.referenceFactory != nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err = owned.CheckSameEnvironment(registry.reservation); err != nil {
		return nil, err
	}
	for _, config := range configs {
		if err = owned.CheckAllocationScope(config.Allocation.Root, config.Owner, config.Accounts); err != nil {
			return nil, err
		}
		for _, owner := range config.Allocation.Owners {
			if err = owned.CheckAllocationScope(config.Allocation.Root, owner, config.Allocation.Accounts); err != nil {
				return nil, err
			}
		}
	}
	dependency, err := registry.reservation.Borrow()
	if err != nil {
		return nil, err
	}
	f := &NamespaceReferenceFactory{registry: registry, clock: clock, reservation: owned, dependency: dependency, ctx: ctx, cancel: cancel, done: make(chan struct{}), slots: make([]namespaceReferenceSlot, len(configs))}
	for i, c := range configs {
		c.Root.Tenant = strings.Clone(c.Root.Tenant)
		c.Root.Authority = strings.Clone(c.Root.Authority)
		c.Accounts = append([]resourcev4.Account(nil), c.Accounts...)
		c.Allocation.Accounts = append([]resourcev4.Account(nil), c.Allocation.Accounts...)
		f.slots[i].config = c
	}
	registry.referenceFactory = f
	adopted = true
	return f, nil
}

func (f *NamespaceReferenceFactory) claim(tenant, authority string) (int, NamespaceReferenceConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.retired || f.ctx.Err() != nil {
		return 0, NamespaceReferenceConfig{}, CBORFailure("revocation_namespace_owner")
	}
	if err := f.reservation.Check(); err != nil {
		return 0, NamespaceReferenceConfig{}, err
	}
	for i := range f.slots {
		slot := &f.slots[i]
		if slot.config.Root.Tenant != tenant || slot.config.Root.Authority != authority {
			continue
		}
		if slot.busy || slot.observing || f.incarnation == math.MaxUint64 {
			return 0, NamespaceReferenceConfig{}, CBORFailure("configuration_capacity")
		}
		slot.busy = true
		slot.cleanup = make(chan struct{})
		f.active++
		f.incarnation++
		return i, slot.config, nil
	}
	return 0, NamespaceReferenceConfig{}, CBORFailure("revocation_namespace_binding")
}
func (f *NamespaceReferenceFactory) release(index int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.slots[index].busy = false
	f.slots[index].operation = nil
	close(f.slots[index].cleanup)
	f.active--
	if f.closed && f.cancelExited && f.active == 0 && !f.finished {
		f.finished = true
		close(f.done)
	}
}

// claimPreservation admits one passive observer of the already retained job.
// The original cleanup callback keeps its work slot; no queue or proof owner
// is introduced. Factory cleanup includes this observer's actual method exit.
func (f *NamespaceReferenceFactory) claimPreservation(tenant, authority string, operation *NamespaceOnlineRetirement) (func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.retired || f.ctx.Err() != nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := f.reservation.Check(); err != nil {
		return nil, err
	}
	for index := range f.slots {
		slot := &f.slots[index]
		if slot.config.Root.Tenant != tenant || slot.config.Root.Authority != authority {
			continue
		}
		if slot.observing || slot.busy && slot.operation != operation {
			return nil, CBORFailure("configuration_capacity")
		}
		slot.observing = true
		f.active++
		released := false
		return func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if released {
				return
			}
			released = true
			f.slots[index].observing = false
			f.active--
			if f.closed && f.cancelExited && f.active == 0 && !f.finished {
				f.finished = true
				close(f.done)
			}
		}, nil
	}
	return nil, CBORFailure("revocation_namespace_binding")
}

func namespaceReferenceOwner(template resourcev4.OwnerKey) (resourcev4.OwnerKey, error) {
	var identity [32]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return resourcev4.OwnerKey{}, err
	}
	copy(template.Instance[:], identity[:16])
	copy(template.Backing[:], identity[16:])
	return template, nil
}
func namespaceReferenceAllocation(config NamespaceReferenceConfig) (NamespaceAllocation, error) {
	allocation := config.Allocation
	for i := range allocation.Owners {
		owner, err := namespaceReferenceOwner(allocation.Owners[i])
		if err != nil {
			return NamespaceAllocation{}, err
		}
		allocation.Owners[i] = owner
	}
	return allocation, nil
}

// allocate admits trust and the complete original operation as one resource
// transaction. The same root and Environment checks precede any anchor use.
func (f *NamespaceReferenceFactory) allocate(c NamespaceReferenceConfig, retirement bool) (*NamespaceTrustStore, resourcev4.Reference, NamespaceAllocation, error) {
	trustCharge, err := NamespaceTrustCharge(c.Trust)
	if err != nil {
		return nil, resourcev4.Reference{}, NamespaceAllocation{}, err
	}
	jobCharge, err := NamespaceBootstrapCharge(c.Bootstrap)
	if retirement {
		jobCharge, err = NamespaceOnlineRetirementCharge(c.Bootstrap)
	}
	if err != nil {
		return nil, resourcev4.Reference{}, NamespaceAllocation{}, err
	}
	allocation, err := namespaceReferenceAllocation(c)
	if err != nil {
		return nil, resourcev4.Reference{}, NamespaceAllocation{}, err
	}
	var refs [2]resourcev4.Reference
	var requests [2]resourcev4.Request
	for i, charge := range []resourcev4.Vector{trustCharge, jobCharge} {
		owner, e := namespaceReferenceOwner(c.Owner)
		if e != nil {
			return nil, resourcev4.Reference{}, NamespaceAllocation{}, e
		}
		requests[i] = resourcev4.Request{Owner: owner, Charge: charge, Accounts: c.Accounts}
	}
	if err = c.Allocation.Root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, resourcev4.Reference{}, NamespaceAllocation{}, err
	}
	fail := func(e error) (*NamespaceTrustStore, resourcev4.Reference, NamespaceAllocation, error) {
		refs[0].Release()
		refs[1].Release()
		return nil, resourcev4.Reference{}, NamespaceAllocation{}, e
	}
	if err = refs[0].CheckSameEnvironment(f.reservation); err != nil {
		return fail(err)
	}
	dependency, err := f.registry.Borrow(f.reservation)
	if err != nil {
		return fail(err)
	}
	trust, err := NewNamespaceTrustAnchor(c.Root, c.Trust, f.clock, refs[0], dependency)
	if err != nil {
		dependency.Release()
		return fail(err)
	}
	trust.referenceFactory = f
	return trust, refs[1], allocation, nil
}

// disposeUnpublished discards only an unregistered candidate whose history is
// still retained by its original registered predecessor. It seals the exact
// sole backing first; this never deletes registered security history.
func disposeNamespaceReferenceCandidate(trust *NamespaceTrustStore) {
	trust.Close()
	trust.mu.Lock()
	unpublished := trust.registry == nil && trust.namespace == nil && !trust.bootstrap && !trust.busy && !trust.restoring && trust.sampling == 0
	if unpublished && resourcev4.SealExclusiveGroup([]resourcev4.ExclusiveReferences{{Primary: trust.reservation}}) == nil {
		trust.retirementDeletion = true
	}
	trust.mu.Unlock()
	if unpublished {
		_ = trust.DestroyEnvironment()
	}
}

// Resolve completes cold bootstrap before publishing a missing owner. It uses
// the caller's original cancellation in addition to the fixed factory and
// bootstrap deadlines. Present history is returned only after its own complete
// continuity is ready; failures cannot switch to a cache or another authority.
func (f *NamespaceReferenceFactory) startRefresh(index int, c NamespaceReferenceConfig, trust *NamespaceTrustStore) error {
	if c.Refresh.Provider == nil {
		return nil
	}
	if _, err := NamespaceRefreshCharge(c.Refresh.Limits, c.Trust.ConfigBytes); err != nil {
		return err
	}
	if trust == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	n := trust.namespace
	if n == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	f.mu.Lock()
	if f.closed || f.retired || index < 0 || index >= len(f.slots) {
		f.mu.Unlock()
		return CBORFailure("revocation_namespace_owner")
	}
	slot := &f.slots[index]
	if slot.refreshStarting {
		f.mu.Unlock()
		return CBORFailure("revocation_namespace_owner")
	}
	slotRefresh := slot.refresh
	f.mu.Unlock()

	// A second Resolve of the same installed owner must reuse its factory-owned
	// refresh. A slot refresh attached to another namespace is a binding error;
	// never replace it or install a second worker on the same namespace.
	n.mu.Lock()
	namespaceRefresh := n.refresh
	n.mu.Unlock()
	if slotRefresh != nil {
		slotRefresh.mu.Lock()
		valid := namespaceRefresh == slotRefresh && slotRefresh.namespace == n && slotRefresh.trust == trust && !slotRefresh.closed && !slotRefresh.retired
		slotRefresh.mu.Unlock()
		if !valid {
			return CBORFailure("revocation_namespace_owner")
		}
		f.mu.Lock()
		stillInstalled := !f.closed && !f.retired && index < len(f.slots) && f.slots[index].refresh == slotRefresh
		f.mu.Unlock()
		if !stillInstalled {
			return CBORFailure("revocation_namespace_owner")
		}
		return nil
	}
	if namespaceRefresh != nil {
		return CBORFailure("revocation_namespace_owner")
	}

	f.mu.Lock()
	if f.closed || f.retired || index >= len(f.slots) || f.slots[index].refresh != nil || f.slots[index].refreshStarting {
		f.mu.Unlock()
		return CBORFailure("revocation_namespace_owner")
	}
	f.slots[index].refreshStarting = true
	f.active++
	f.mu.Unlock()
	clearStarting := func() {
		f.mu.Lock()
		if index >= 0 && index < len(f.slots) && f.slots[index].refreshStarting {
			f.slots[index].refreshStarting = false
			if f.active > 0 {
				f.active--
			}
			if f.closed && f.cancelExited && f.active == 0 && !f.finished {
				f.finished = true
				close(f.done)
			}
		}
		f.mu.Unlock()
	}
	refreshOwner, err := f.reservation.Borrow()
	if err != nil {
		clearStarting()
		return err
	}
	refresh, err := newNamespaceRefreshOwned(n, trust, c.Refresh.Limits, refreshOwner)
	if err != nil {
		clearStarting()
		return err
	}
	// Publish and charge the physical tail before Start. Close can now always
	// find it, and the single observer remains responsible even if Start loses
	// a race with factory shutdown.
	f.mu.Lock()
	if f.closed || f.retired || f.slots[index].refresh != nil {
		f.slots[index].refreshStarting = false
		if f.active > 0 {
			f.active--
		}
		if f.closed && f.cancelExited && f.active == 0 && !f.finished {
			f.finished = true
			close(f.done)
		}
		f.mu.Unlock()
		refresh.Close()
		_ = refresh.Retire()
		return CBORFailure("revocation_namespace_owner")
	}
	f.slots[index].refresh = refresh
	f.slots[index].refreshStarting = false
	f.mu.Unlock()
	go f.observeRefresh(index, refresh)
	if err = refresh.Start(c.Refresh.Provider); err != nil {
		// The observer owns final retirement and active-slot release. Keep this
		// charge live until the worker's done signal even on Start refusal.
		refresh.Close()
		return err
	}
	return nil
}

// observeRefresh owns the single final cleanup responsibility for a factory
// refresh. A bounded wait is only an early completion check; timeout transfers
// the same responsibility to the worker's done signal instead of dropping the
// slot or active resource charge.
func (f *NamespaceReferenceFactory) observeRefresh(index int, refresh *NamespaceRefresh) {
	refresh.waitCleanupFinal()
	if err := refresh.Retire(); err != nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.slots[index].refresh != refresh {
		return
	}
	f.slots[index].refresh = nil
	if f.active > 0 {
		f.active--
	}
	if f.closed && f.cancelExited && f.active == 0 && !f.finished {
		f.finished = true
		close(f.done)
	}
}

func (f *NamespaceReferenceFactory) Resolve(ctx context.Context, tenant, authority string) (*NamespaceTrustStore, error) {
	if f == nil || ctx == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	// A previous pressure job may have exhausted its bounded cleanup observer.
	// Continue only its same preservation after physical exit; do not treat the
	// occupied entry as a missing-history visit or dispatch another proof.
	var pending *NamespaceOnlineRetirement
	var cleanupExited <-chan struct{}
	var c NamespaceReferenceConfig
	f.mu.Lock()
	if f.closed || f.retired || f.ctx.Err() != nil {
		f.mu.Unlock()
		return nil, CBORFailure("revocation_namespace_owner")
	}
	r, clock := f.registry, f.clock
	for index := range f.slots {
		slot := &f.slots[index]
		if slot.config.Root.Tenant == tenant && slot.config.Root.Authority == authority {
			c = slot.config
			if slot.busy {
				if slot.operation == nil {
					f.mu.Unlock()
					return nil, CBORFailure("configuration_capacity")
				}
				pending, cleanupExited = slot.operation, slot.cleanup
			}
			break
		}
	}
	f.mu.Unlock()
	if c.Provider == nil {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	r.mu.Lock()
	if !r.closed {
		for _, entry := range r.entries[:r.used] {
			if entry.trust.root.Tenant == tenant && entry.trust.root.Authority == authority {
				if entry.retirement != nil {
					pending = entry.retirement
				}
				break
			}
		}
	}
	r.mu.Unlock()
	if pending != nil {
		pending.previous.mu.Lock()
		matching := pending.previous.root == c.Root && pending.previous.clock == clock
		pending.previous.mu.Unlock()
		if !matching {
			return nil, CBORFailure("revocation_namespace_binding")
		}
		releaseObserver, err := f.claimPreservation(tenant, authority, pending)
		if err != nil {
			return nil, err
		}
		defer releaseObserver()
		cleanup, cancel := context.WithTimeout(ctx, time.Duration(c.Bootstrap.DurationMS)*time.Millisecond)
		preserveErr := pending.PreserveForReplacement(cleanup)
		if preserveErr == nil && cleanupExited != nil {
			// Only the original cleanup callback can release its slot. Completing
			// preservation alone cannot refund a still-running factory task.
			select {
			case <-cleanupExited:
			case <-cleanup.Done():
				preserveErr = cleanup.Err()
			}
		}
		cancel()
		if preserveErr != nil {
			return nil, preserveErr
		}
		releaseObserver()
	}
	index, claimed, err := f.claim(tenant, authority)
	if err != nil {
		return nil, err
	}
	defer f.release(index)
	c = claimed
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, CBORFailure("revocation_namespace_owner")
	}
	var previous *NamespaceTrustStore
	for _, entry := range r.entries[:r.used] {
		if entry.trust.root.Tenant != tenant || entry.trust.root.Authority != authority {
			continue
		}
		t := entry.trust
		t.mu.Lock()
		matching := t.root == c.Root && t.clock == f.clock && !t.retired
		ready := entry.retirement == nil && matching && !t.closed && t.continuityReady
		recoverable := entry.retirement == nil && matching && !t.busy && !t.bootstrap && !t.restoring && (t.closed || !t.bootstrapStarted && t.count == 0)
		n := t.namespace
		if n != nil {
			recoverable = entry.retirement == nil && matching && !t.busy && !t.bootstrap && !t.restoring
		}
		t.mu.Unlock()
		if n != nil {
			n.mu.Lock()
			failed := n.terminal != nil || n.destroyed || n.initializing
			n.mu.Unlock()
			if failed {
				ready = false
			}
		}
		if ready {
			r.mu.Unlock()
			if err := f.startRefresh(index, c, t); err != nil {
				return nil, err
			}
			return t, nil
		}
		if !recoverable {
			r.mu.Unlock()
			return nil, CBORFailure("revocation_namespace_owner")
		}
		if n != nil {
			n.mu.Lock()
			failed := n.terminal != nil && !n.destroyed
			n.mu.Unlock()
			if !failed {
				r.mu.Unlock()
				return nil, CBORFailure("revocation_namespace_owner")
			}
		}
		previous = t
		break
	}
	if previous == nil && r.used >= r.capacity {
		r.requestPressureLocked()
		r.mu.Unlock()
		return nil, CBORFailure("configuration_capacity")
	}
	r.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	trust, job, allocation, err := f.allocate(c, false)
	if err != nil {
		return nil, err
	}
	if previous != nil {
		// A failed bootstrap's complete history remains in this occupied slot.
		// Replacement carries that history and proves coverage through independent
		// full bootstrap. It is never installed as a missing-history cold visit.
		previous.Close()
		err = r.ReplaceFailed(previous, trust)
	} else {
		err = r.Register(trust)
	}
	if err != nil {
		job.Release()
		disposeNamespaceReferenceCandidate(trust)
		return nil, err
	}
	bootstrap, err := NewNamespaceOnlineBootstrap(f.ctx, trust, c.Bootstrap, allocation, job)
	if err != nil {
		job.Release()
		trust.Close()
		return nil, err
	}
	_, runErr := bootstrap.Run(ctx, c.Provider)
	// Run returns only after all actual provider, cancellation and clock tails.
	retireErr := bootstrap.Retire()
	if runErr != nil {
		trust.Close()
		return nil, runErr
	}
	if retireErr != nil {
		trust.Close()
		return nil, retireErr
	}
	if err = f.startRefresh(index, c, trust); err != nil {
		trust.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		trust.Close()
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	for _, entry := range r.entries[:r.used] {
		if entry.trust == trust && entry.retirement == nil {
			trust.mu.Lock()
			ready := !trust.closed && !trust.retired && trust.continuityReady
			trust.mu.Unlock()
			if ready {
				return trust, nil
			}
			break
		}
	}
	return nil, CBORFailure("revocation_namespace_owner")
}

// PrepareNamespaceRetirement implements the normal SDK reference factory for
// the original bounded pressure worker. It never returns cache-derived trust.
func (f *NamespaceReferenceFactory) PrepareNamespaceRetirement(ctx context.Context, registry *NamespaceRegistry, previous *NamespaceTrustStore) (*NamespaceOnlineRetirement, NamespaceBootstrapProvider, error) {
	if f == nil || ctx == nil || ctx.Err() != nil || registry != f.registry || previous == nil {
		return nil, nil, CBORFailure("revocation_namespace_owner")
	}
	previous.mu.Lock()
	root := previous.root
	clock := previous.clock
	previous.mu.Unlock()
	index, c, err := f.claim(root.Tenant, root.Authority)
	if err != nil {
		return nil, nil, err
	}
	if root != c.Root || clock != f.clock {
		f.release(index)
		return nil, nil, CBORFailure("revocation_namespace_binding")
	}
	next, job, allocation, err := f.allocate(c, true)
	if err != nil {
		f.release(index)
		return nil, nil, err
	}
	operation, err := NewNamespaceOnlineRetirement(f.ctx, registry, previous, next, c.Bootstrap, allocation, job)
	if err != nil {
		f.release(index)
		job.Release()
		disposeNamespaceReferenceCandidate(next)
		return nil, nil, err
	}
	// The slot remains occupied through the operation's actual provider and
	// cleanup tails. A returned handle never permits a second bootstrap to race
	// the first one; a failed/unknown tail keeps the slot charged.
	f.mu.Lock()
	f.slots[index].operation = operation
	closed := f.closed
	f.mu.Unlock()
	if closed {
		operation.Close()
	}
	go func() {
		<-operation.done
		// Run may fail before bootstrap starts, or while the private candidate
		// still has a physical watcher tail. Seal that same job before joining
		// its cleanup; waiting alone cannot finish an unstarted bootstrap.
		operation.Close()
		_ = operation.bootstrap.WaitCleanup(context.Background())
		for i := 0; i < operation.ownerCount; i++ {
			if n := operation.owners[i].namespace; n != nil {
				_ = n.WaitCleanup(context.Background())
			}
		}
		next.mu.Lock()
		candidate := next.namespace
		next.mu.Unlock()
		if candidate != nil {
			_ = candidate.WaitCleanup(context.Background())
		}
		operation.mu.Lock()
		failed := !operation.deleted && !operation.retired
		operation.mu.Unlock()
		if failed {
			// The original admitted cleanup task continues preservation after
			// actual exit, even if the service's bounded observer has detached.
			// Capacity refusal retains entry.retirement for explicit Resolve.
			_ = operation.PreserveForReplacement(context.Background())
		}
		f.release(index)
	}()
	if err := ctx.Err(); err != nil {
		// The claim and its refresh closure remain owned by the operation. Close
		// it so the background cleanup worker can preserve the occupied history;
		// returning the caller error must not release its slot or tail early.
		operation.Close()
		return nil, nil, err
	}
	return operation, c.Provider, nil
}

func (f *NamespaceReferenceFactory) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if f.retired {
		f.mu.Unlock()
		return
	}
	f.closed = true
	refreshes := make([]*NamespaceRefresh, 0, len(f.slots))
	operations := make([]*NamespaceOnlineRetirement, 0, len(f.slots))
	for i := range f.slots {
		if f.slots[i].refresh != nil {
			refreshes = append(refreshes, f.slots[i].refresh)
		}
		if f.slots[i].operation != nil {
			operations = append(operations, f.slots[i].operation)
		}
	}
	f.mu.Unlock()
	// Close unstarted operations before their observer waits on done. Running
	// operations receive the same cancellation and join their own Run tail.
	for _, operation := range operations {
		operation.Close()
	}
	for _, refresh := range refreshes {
		refresh.Close()
	}
	// Host context cancellation, including an original AfterFunc stop, has one
	// execution owner. Concurrent Close callers join its actual exit outside
	// the factory gate; slot release alone cannot complete factory cleanup.
	f.cancelOnce.Do(func() {
		f.cancel()
		f.mu.Lock()
		f.cancelExited = true
		if f.active == 0 && !f.finished {
			f.finished = true
			close(f.done)
		}
		f.mu.Unlock()
	})
}
func (f *NamespaceReferenceFactory) WaitCleanup(ctx context.Context) error {
	if f == nil || ctx == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	select {
	case <-f.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *NamespaceReferenceFactory) retireLocked(r *NamespaceRegistry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.retired {
		return nil
	}
	if !f.closed || !f.finished || f.active != 0 || f.registry != r {
		return CBORFailure("revocation_namespace_owner")
	}
	f.slots = nil
	f.ctx = nil
	f.cancel = nil
	f.clock = nil
	f.registry = nil
	f.retired = true
	f.dependency.Release()
	f.reservation.Release()
	f.dependency, f.reservation = resourcev4.Reference{}, resourcev4.Reference{}
	r.referenceFactory = nil
	return nil
}
func (*NamespaceReferenceFactory) String() string               { return "Flowersec.NamespaceReferenceFactory" }
func (*NamespaceReferenceFactory) GoString() string             { return "Flowersec.NamespaceReferenceFactory" }
func (*NamespaceReferenceFactory) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Resolve performs only the configured independent cold-start composition.
// Registries without that configuration keep their original safe lookup path.
func (r *NamespaceRegistry) Resolve(ctx context.Context, tenant, authority string) (*NamespaceTrustStore, error) {
	if r == nil || ctx == nil {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	r.mu.Lock()
	factory := r.referenceFactory
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if factory != nil {
		return factory.Resolve(ctx, tenant, authority)
	}
	return r.Lookup(tenant, authority)
}

package protocolv4

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// VerificationContinuity is fixed by trusted Environment construction. It is
// local configuration, never peer negotiation or a storage-failure fallback.
type VerificationContinuity uint8

const (
	OnlineBootstrap VerificationContinuity = iota + 1
	DurableRestore
)

type NamespaceRegistryConfig struct {
	Continuity   VerificationContinuity
	Entries      uint32
	RuntimeBytes uint64
}

type namespaceRegistryHistory struct {
	trust *NamespaceTrustStore
	pin   resourcev4.Reference
}

type namespaceRegistryEntry struct {
	history          [16]namespaceRegistryHistory
	historyCount     int
	trust            *NamespaceTrustStore
	pin              resourcev4.Reference
	retirement       *NamespaceOnlineRetirement
	retirementFailed bool
}

// NamespaceRegistry keeps the exact original authority owners in one bounded
// Environment table. Anchors enter before startup work; failed or closed
// entries are retained and can only be replaced through independent bootstrap
// with complete history coverage. Complete
// trust/State/candidate/refresh allocations remain charged to their original
// owners. This registry neither duplicates them nor treats their digests as
// substitutes for retained history.
type NamespaceRegistry struct {
	sampling                 uint32
	mu                       sync.Mutex
	continuity               VerificationContinuity
	entries                  []namespaceRegistryEntry
	used                     uint32
	capacity                 uint32
	reservation              resourcev4.Reference
	closed, closing, retired bool
	fenced                   atomic.Bool
	pressureService          *NamespaceRetirementService
	pressureSignal           atomic.Pointer[NamespaceRetirementService]
	historyPressure          bool
	referenceFactory         *NamespaceReferenceFactory
}

func NamespaceRegistryCharge(c NamespaceRegistryConfig) (resourcev4.Vector, error) {
	if c.Continuity != OnlineBootstrap && c.Continuity != DurableRestore || c.Entries == 0 || c.Entries > 4096 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, CBORFailure("configuration_capacity")
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(NamespaceRegistry{})) + uint64(c.Entries)*uint64(unsafe.Sizeof(namespaceRegistryEntry{})), resourcev4.Items: uint64(c.Entries) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewNamespaceRegistry(c NamespaceRegistryConfig, reservation resourcev4.Reference) (*NamespaceRegistry, error) {
	charge, err := NamespaceRegistryCharge(c)
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	if err = owned.ClaimVerificationRegistry(); err != nil {
		owned.Release()
		return nil, err
	}
	return &NamespaceRegistry{continuity: c.Continuity, capacity: c.Entries, entries: make([]namespaceRegistryEntry, c.Entries), reservation: owned}, nil
}

// Register fixes an independently configured, unused trust anchor before any
// bootstrap or recovery provider call. Namespace identity, not an untrusted
// capacity digest or endpoint, selects its only slot. Re-registering the exact
// anchor is idempotent; replacing a failed owner requires ReplaceFailed.
func (r *NamespaceRegistry) Register(t *NamespaceTrustStore) error {
	if r == nil || t == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return CBORFailure("revocation_namespace_owner")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.retired {
		return CBORFailure("revocation_trust_owner")
	}
	if err := r.reservation.CheckSameEnvironment(t.reservation); err != nil {
		return err
	}
	for _, entry := range r.entries[:r.used] {
		if entry.trust == t {
			if entry.retirement != nil {
				return CBORFailure("revocation_namespace_retiring")
			}
			return nil
		}
		// Registered roots are immutable, including during owner destruction.
		if entry.trust.root.Tenant == t.root.Tenant && entry.trust.root.Authority == t.root.Authority {
			return CBORFailure("revocation_namespace_binding")
		}
	}
	if t.registry != nil || t.bootstrapStarted || t.namespace != nil || t.count != 0 || t.busy {
		return CBORFailure("revocation_namespace_owner")
	}
	if int(r.used) == len(r.entries) {
		r.requestPressureLocked()
		return CBORFailure("configuration_capacity")
	}
	pin, err := t.reservation.Borrow()
	if err != nil {
		return err
	}
	t.registry, t.continuity = r, r.continuity
	r.entries[r.used] = namespaceRegistryEntry{trust: t, pin: pin}
	r.used++
	return nil
}

func (r *NamespaceRegistry) Borrow(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if r == nil {
		return resourcev4.Reference{}, CBORFailure("revocation_namespace_owner")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return resourcev4.Reference{}, CBORFailure("revocation_namespace_owner")
	}
	if err := r.reservation.CheckSameEnvironment(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return r.reservation.Borrow()
}

// Lookup returns the original dependency, without creating a replacement,
// provider task or new lifetime. Possessing this pointer grants no authority;
// its normal signature, continuity and current authorization gates still apply.
func (r *NamespaceRegistry) Lookup(tenant, authority string) (*NamespaceTrustStore, error) {
	if r == nil || tenant == "" || len(tenant) > 128 || authority == "" || len(authority) > 128 {
		return nil, CBORFailure("revocation_namespace_binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, CBORFailure("revocation_namespace_owner")
	}
	if err := r.reservation.Check(); err != nil {
		return nil, err
	}
	for _, entry := range r.entries[:r.used] {
		if t := entry.trust; t.root.Tenant == tenant && t.root.Authority == authority {
			if entry.retirement != nil {
				return nil, CBORFailure("revocation_namespace_retiring")
			}
			return t, nil
		}
	}
	if r.used >= r.capacity {
		r.requestPressureLocked()
	}
	return nil, CBORFailure("revocation_namespace_binding")
}

// CheckNamespace is the local admission gate for the exact original owner.
// A valid signature in an independently constructed duplicate graph cannot
// substitute for the registered bootstrap/recovery incarnation.
func (r *NamespaceRegistry) CheckNamespace(n *LiveNamespace) error {
	if r == nil || n == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	sample, err := n.sampleCurrent()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return CBORFailure("revocation_namespace_owner")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.destroyed || n.initializing || n.terminal != nil || n.active == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	if err := r.reservation.CheckSameEnvironment(n.reservation); err != nil {
		return err
	}
	t, ok := n.trust.(*NamespaceTrustStore)
	if !ok {
		return CBORFailure("revocation_namespace_binding")
	}
	current := false
	for _, entry := range r.entries[:r.used] {
		if entry.trust == t && entry.retirement == nil {
			current = true
			break
		}
	}
	if !current {
		return CBORFailure("revocation_namespace_owner")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.registry != r || t.namespace != n || !t.continuityReady || t.continuity != r.continuity || (n.durable != nil) != (r.continuity == DurableRestore) {
		return CBORFailure("revocation_continuity_binding")
	}
	return t.checkCurrentLockedAt(sample)
}

// Close fences each original trust/namespace owner without waiting for I/O.
// The entries and all pins remain until actual owner cleanup and permanent
// Environment destruction; closing the last Session does not evict history.
func (r *NamespaceRegistry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed, r.closing = true, true
	r.fenced.Store(true)
	r.reservation.Seal()
	entries := r.entries[:r.used]
	service := r.pressureService
	factory := r.referenceFactory
	r.mu.Unlock()
	if service != nil {
		service.Close()
	}
	if factory != nil {
		factory.Close()
	}
	for _, entry := range entries {
		if entry.retirement != nil {
			entry.retirement.Close()
		}
		entry.trust.Close()
		for _, history := range entry.history[:entry.historyCount] {
			history.trust.Close()
		}
	}
	r.mu.Lock()
	r.closing = false
	r.mu.Unlock()
}

// DestroyEnvironment runs after the separately owned bootstrap/refresh jobs,
// namespace subscribers and trust owners have physically retired. No ordinary
// unbind/evict method exists: without independent history coverage, capacity
// exhaustion must refuse additional namespaces.
func (r *NamespaceRegistry) DestroyEnvironment() error {
	if r == nil {
		return CBORFailure("revocation_namespace_owner")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return nil
	}
	if !r.closed || r.closing || r.sampling != 0 || !r.reservation.EnvironmentClosed() {
		return CBORFailure("revocation_namespace_owner")
	}
	if service := r.pressureService; service != nil {
		service.mu.Lock()
		finished := service.closed && service.finished && !service.running
		service.mu.Unlock()
		if !finished {
			return CBORFailure("revocation_namespace_owner")
		}
	}
	for _, entry := range r.entries[:r.used] {
		if entry.retirement != nil {
			if err := entry.retirement.destroyEnvironment(); err != nil {
				return err
			}
		}
		for _, history := range entry.history[:entry.historyCount] {
			if err := history.trust.DestroyEnvironment(); err != nil {
				return err
			}
		}
		entry.trust.mu.Lock()
		retired := entry.trust.retired
		referenceOwned := entry.trust.referenceFactory == r.referenceFactory && r.referenceFactory != nil
		entry.trust.mu.Unlock()
		if !retired && referenceOwned {
			if err := entry.trust.DestroyEnvironment(); err != nil {
				return err
			}
			retired = true
		}
		if !retired {
			return CBORFailure("revocation_namespace_owner")
		}
	}
	// A failed service keeps its original job pointer until that job's actual
	// bootstrap/candidate cleanup and Environment destruction have completed.
	if r.pressureService != nil {
		if err := r.pressureService.retireLocked(r); err != nil {
			return err
		}
	}
	if r.referenceFactory != nil {
		if err := r.referenceFactory.retireLocked(r); err != nil {
			return err
		}
	}
	for _, entry := range r.entries[:r.used] {
		entry.pin.Release()
		for _, history := range entry.history[:entry.historyCount] {
			history.pin.Release()
		}
	}
	clear(r.entries)
	r.entries, r.used = nil, 0
	r.retired = true
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	return nil
}

func (*NamespaceRegistry) String() string               { return "Flowersec.VerificationNamespaces" }
func (*NamespaceRegistry) GoString() string             { return "Flowersec.VerificationNamespaces" }
func (*NamespaceRegistry) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func (t *NamespaceTrustStore) checkContinuityProfile(profile VerificationContinuity) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.checkContinuityProfileLocked(profile)
}

func (t *NamespaceTrustStore) checkContinuityProfileLocked(profile VerificationContinuity) error {
	if t.registry != nil && (t.registry.fenced.Load() || t.continuity != profile) {
		return CBORFailure("revocation_continuity_binding")
	}
	return nil
}

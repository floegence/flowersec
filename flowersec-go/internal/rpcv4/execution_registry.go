package rpcv4

import (
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

var (
	ErrServiceAlreadyBound = errors.New("rpcv4: service authority already bound")
	ErrServiceNotBound     = errors.New("rpcv4: service authority not bound")
)

// ServiceAuthority is the trusted logical owner key. It deliberately excludes
// Session, stream, endpoint and certificate identifiers: those values may
// rotate while a single application owner remains live.
type ServiceAuthority struct {
	Tenant, Audience, Namespace string
}

func (a ServiceAuthority) valid() bool {
	return executionIdentifier(a.Tenant) && executionIdentifier(a.Audience) && executionIdentifier(a.Namespace)
}

// ServiceBinding is installed once for one logical service authority. The
// registry owns the one live execution history owner across all Sessions.
// Callers retain the returned binding until every attached Session and callback
// has physically exited.
type ServiceBinding struct {
	Recovery       *RecoveryVerifier
	Authority      ServiceAuthority
	History        *VolatileExecutions
	DurableHistory *DurableExecutions
}

type ServiceRegistryConfig struct {
	Root         *resourcev4.Root
	Owner        resourcev4.OwnerKey
	Accounts     []resourcev4.Account
	Entries      uint32
	RuntimeBytes uint64
}

type serviceRegistryEntry struct {
	binding     ServiceBinding
	pin         resourcev4.Reference
	recoveryPin resourcev4.Reference
}

type ServiceRegistry struct {
	mu            sync.Mutex
	root          *resourcev4.Root
	reservation   resourcev4.Reference
	entries       []serviceRegistryEntry
	used          uint32
	cursor        int
	durableCursor int
	closed        bool
}

func ServiceRegistryCharge(c ServiceRegistryConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Entries == 0 || c.Entries > 1024 || c.RuntimeBytes == 0 || len(c.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ServiceRegistry{})) + uint64(c.Entries)*(uint64(unsafe.Sizeof(serviceRegistryEntry{}))+3*128), resourcev4.Items: uint64(c.Entries) + 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func NewServiceRegistry(c ServiceRegistryConfig, reservation resourcev4.Reference) (*ServiceRegistry, error) {
	charge, err := ServiceRegistryCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, c.Accounts); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	return &ServiceRegistry{root: c.Root, reservation: owned, entries: make([]serviceRegistryEntry, c.Entries)}, nil
}

// Bind reserves the authority atomically. A second live binding for the same
// trusted tuple is rejected even if it points at a different RAM history.
func (r *ServiceRegistry) Bind(binding ServiceBinding) error {
	if r == nil || !binding.valid() || !binding.Authority.valid() {
		return ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return err
	}
	index := -1
	for i, entry := range r.entries {
		if entry.binding.valid() && entry.binding.Authority == binding.Authority {
			return ErrServiceAlreadyBound
		}
		if !entry.binding.valid() && index < 0 {
			index = i
		}
	}
	if index < 0 {
		return ErrCapacity
	}
	pin, err := binding.borrow(r.reservation)
	if err != nil {
		return err
	}
	var recoveryPin resourcev4.Reference
	if binding.Recovery != nil {
		if binding.DurableHistory == nil || !binding.DurableHistory.config.Store.SupportsCheckpoints() {
			pin.Release()
			return ErrExecutionUnsupported
		}
		recoveryPin, err = binding.Recovery.borrowService(binding.Authority, r.reservation)
		if err != nil {
			pin.Release()
			return err
		}
	}
	binding.Authority.Tenant = strings.Clone(binding.Authority.Tenant)
	binding.Authority.Audience = strings.Clone(binding.Authority.Audience)
	binding.Authority.Namespace = strings.Clone(binding.Authority.Namespace)
	r.entries[index] = serviceRegistryEntry{binding: binding, pin: pin, recoveryPin: recoveryPin}
	r.used++
	return nil
}

func (r *ServiceRegistry) Lookup(a ServiceAuthority) (ServiceBinding, error) {
	if r == nil {
		return ServiceBinding{}, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ServiceBinding{}, ErrClosed
	}
	for _, entry := range r.entries {
		if entry.binding.valid() && entry.binding.Authority == a {
			return entry.binding, nil
		}
	}
	return ServiceBinding{}, ErrServiceNotBound
}

// CheckSameEnvironment binds an external coordinator to the registry's
// original resource root. It is a read-only composition check; it does not
// grant lookup or service authority.
func (r *ServiceRegistry) CheckSameEnvironment(ref resourcev4.Reference) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	return r.reservation.CheckSameEnvironment(ref)
}

// Borrow pins registry backing for one participating Environment. Closing the
// caller-owned registry seals its API but cannot refund that live dependency.
func (r *ServiceRegistry) Borrow(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if r == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	if err := r.reservation.CheckSameEnvironment(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return r.reservation.Borrow()
}

// Collect advances at most eight service owners per coordinator turn. Each
// store advances its own bounded record cursor; no registry gate spans clock
// sampling, store cleanup or cancellation delivery.
func (r *ServiceRegistry) Collect() bool {
	if r == nil {
		return false
	}
	var owners [8]*VolatileExecutions
	r.mu.Lock()
	if r.closed || r.used == 0 {
		r.mu.Unlock()
		return false
	}
	count := 0
	for range min(8, len(r.entries)) {
		owners[count] = r.entries[r.cursor].binding.History
		r.cursor = (r.cursor + 1) % len(r.entries)
		count++
	}
	r.mu.Unlock()
	for _, history := range owners[:count] {
		if history != nil {
			_ = history.Collect()
		}
	}
	return true
}

// CollectDurable advances one original durable owner on an already admitted
// provider task. Callers must not run this on the finite SDK coordinator lane.
// The registry gate ends before any provider work starts.
func (r *ServiceRegistry) CollectDurable(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	if r.closed || r.used == 0 {
		r.mu.Unlock()
		return nil
	}
	var history *DurableExecutions
	for range min(8, len(r.entries)) {
		history = r.entries[r.durableCursor].binding.DurableHistory
		r.durableCursor = (r.durableCursor + 1) % len(r.entries)
		if history != nil {
			break
		}
	}
	r.mu.Unlock()
	if history != nil {
		return history.Collect(ctx)
	}
	return nil
}

func (r *ServiceRegistry) Unbind(a ServiceAuthority, history *VolatileExecutions) error {
	return r.unbind(ServiceBinding{Authority: a, History: history})
}

func (r *ServiceRegistry) UnbindDurable(a ServiceAuthority, history *DurableExecutions) error {
	return r.unbind(ServiceBinding{Authority: a, DurableHistory: history})
}

func (r *ServiceRegistry) unbind(binding ServiceBinding) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	for i, entry := range r.entries {
		if !entry.binding.valid() || entry.binding.Authority != binding.Authority {
			continue
		}
		if !binding.valid() || binding.History != entry.binding.History || binding.DurableHistory != entry.binding.DurableHistory {
			return ErrAssociation
		}
		// All original history captures, tasks and result readers must exit before
		// this authority can be rebound. A Session close alone cannot establish it.
		if binding.History != nil && !binding.History.CleanupComplete() || binding.DurableHistory != nil && !binding.DurableHistory.CleanupComplete() {
			return ErrCapacity
		}
		entry.pin.Release()
		entry.recoveryPin.Release()
		r.entries[i] = serviceRegistryEntry{}
		r.used--
		return nil
	}
	return ErrServiceNotBound
}

func (r *ServiceRegistry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	for _, entry := range r.entries {
		entry.pin.Release()
		entry.recoveryPin.Release()
	}
	r.used = 0
	clear(r.entries)
	r.entries = nil
	r.reservation.Release()
	r.reservation = resourcev4.Reference{}
	r.root = nil
}

func (r *ServiceRegistry) String() string             { return "Flowersec.ServiceRegistry" }
func (r *ServiceRegistry) GoString() string           { return "Flowersec.ServiceRegistry" }
func (*ServiceRegistry) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

package assemblyv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/carrierv4/native"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// CarrierSet is the immutable built-in dispatcher for a finite mixed-carrier
// candidate set. The existing Connect owner performs candidate racing and
// winner selection. This component only prepares the exact requested member;
// it never retries, substitutes a route, or starts a second claim.
type CarrierSet struct {
	root                     *resourcev4.Root
	owner                    resourcev4.OwnerKey
	clock                    *timev4.Clock
	environment              resourcev4.Reference
	providerCharge           resourcev4.Vector
	preparations             []carrierSetPreparation
	parallel                 uint8
	serial                   uint64
	mu                       sync.Mutex
	factories                []carrierSetFactory
	reservation, shared      resourcev4.Reference
	calls                    uint32
	closed, closing, cleaned bool
	changed, done            chan struct{}
}

func carrierSetOwner(owner resourcev4.OwnerKey, index int) resourcev4.OwnerKey {
	var seed [36]byte
	copy(seed[:16], owner.Backing[:])
	copy(seed[16:32], "carrier-set-v4")
	binary.BigEndian.PutUint32(seed[32:], uint32(index))
	digest := sha256.Sum256(seed[:])
	copy(owner.Backing[:], digest[:16])
	return owner
}

func CarrierSetCharge(c CarrierSetConfig) (resourcev4.Vector, error) {
	if c.Root == nil || c.Clock == nil || len(c.Endpoints) == 0 || len(c.Endpoints) > 16 || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for i := range c.Endpoints {
		if _, err := c.factoryCharge(i); err != nil {
			return resourcev4.Vector{}, err
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(c.Endpoints[i].Route, c.Endpoints[j].Route) {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		}
	}
	parallel := min(2, len(c.Endpoints))
	perPreparation := uint64(unsafe.Sizeof(carrierSetPreparation{})) + uint64(parallel)*(uint64(unsafe.Sizeof(factoryPreparation{}))+native.EnvironmentBorrowBytes())
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(CarrierSet{})) +
		uint64(len(c.Endpoints))*uint64(unsafe.Sizeof(carrierSetFactory{})) + uint64(c.ConnectionsPerRoute)*perPreparation,
		resourcev4.Items: 1 + uint64(c.ConnectionsPerRoute)*(1+2*uint64(parallel))}).
		Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewCarrierSet reserves all child factory backing in one transaction
// before constructing any child. Its own metadata has a separate original
// reservation. Every failed child is joined before the constructor returns.
func NewCarrierSet(c CarrierSetConfig, reservation, environment resourcev4.Reference, accounts ...resourcev4.Account) (_ *CarrierSet, err error) {
	charge, err := CarrierSetCharge(c)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckAllocationScope(c.Root, c.Owner, accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if reservation == environment {
		return nil, resourcev4.ErrOwner
	}
	var requests [16]resourcev4.Request
	var refs [16]resourcev4.Reference
	for i := range c.Endpoints {
		cost, err := c.factoryCharge(i)
		if err != nil {
			return nil, err
		}
		requests[i] = resourcev4.Request{Owner: carrierSetOwner(c.Owner, i), Charge: cost, Accounts: accounts}
	}
	if err = c.Root.ReserveBatch(requests[:len(c.Endpoints)], refs[:len(c.Endpoints)]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	shared, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		shared.Release()
		return nil, err
	}
	providerCharge, err := c.maximumProviderCharge()
	if err != nil {
		owned.Release()
		shared.Release()
		return nil, err
	}
	s := &CarrierSet{root: c.Root, owner: c.Owner, clock: c.Clock, environment: environment, providerCharge: providerCharge,
		parallel: uint8(min(2, len(c.Endpoints))), preparations: make([]carrierSetPreparation, c.ConnectionsPerRoute), reservation: owned, shared: shared, factories: make([]carrierSetFactory, len(c.Endpoints)), changed: make(chan struct{}, 1), done: make(chan struct{})}
	defer func() {
		if err != nil {
			s.Close()
			_ = s.WaitCleanup(context.Background())
		}
	}()
	for i := range c.Endpoints {
		s.factories[i], err = c.newFactory(i, refs[i], environment)
		if err != nil {
			return nil, err
		}
		s.factories[i].owner.attachSet(s)
	}
	return s, nil
}

func (s *CarrierSet) PrepareCarrier(ctx context.Context, request sessionv4.CarrierPreparationRequest) (*sessionv4.PreparedCarrier, error) {
	if s == nil || ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, resourcev4.ErrClosed
	}
	if s.calls >= uint32(len(s.factories))*1024 {
		s.mu.Unlock()
		return nil, resourcev4.ErrCapacity
	}
	if err := s.shared.Check(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var selected *carrierSetFactory
	for i := range s.factories {
		factory := &s.factories[i]
		factory.mu.Lock()
		matches := !*factory.closed && *factory.document != nil && bytes.Equal(request.Route, (*factory.document).Bytes())
		factory.mu.Unlock()
		if matches {
			selected = factory
			break
		}
	}
	if selected == nil {
		s.mu.Unlock()
		return nil, protocolv4.CBORFailure("carrier_binding_invalid")
	}
	s.calls++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.calls--
		select {
		case s.changed <- struct{}{}:
		default:
		}
		s.mu.Unlock()
	}()
	return selected.PrepareCarrier(ctx, request)
}

func (s *CarrierSet) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closing = true
	for i := range s.preparations {
		if s.preparations[i].active {
			s.closePreparationGroupLocked(&s.preparations[i])
		}
	}
	factories := s.factories
	s.mu.Unlock()
	for _, factory := range factories {
		if factory.owner != nil {
			factory.Close()
		}
	}
	s.mu.Lock()
	s.closing = false
	s.mu.Unlock()
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// WaitCleanup observes the original children. Live Sessions keep their own
// factory backing; closing this set cannot revoke or refund those providers.
func (s *CarrierSet) WaitCleanup(ctx context.Context) error {
	if s == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	for {
		s.mu.Lock()
		if s.cleaned {
			s.mu.Unlock()
			return nil
		}
		s.cleanupPreparationsLocked()
		pending := false
		for i := range s.preparations {
			pending = pending || s.preparations[i].active
		}
		closed, calls, factories := s.closed && !s.closing && !pending, s.calls, s.factories
		s.mu.Unlock()
		if closed && calls == 0 {
			for _, factory := range factories {
				if factory.owner != nil {
					if err := factory.WaitCleanup(ctx); err != nil {
						return err
					}
				}
			}
			s.mu.Lock()
			if !s.cleaned {
				s.cleaned = true
				s.factories = nil
				s.preparations = nil
				s.shared.Release()
				s.reservation.Release()
				close(s.done)
			}
			s.mu.Unlock()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return nil
		case <-s.changed:
		}
	}
}

var _ sessionv4.ConsumerCarrierFactory = (*CarrierSet)(nil)

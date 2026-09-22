package protocolv4

import (
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type namespaceSubscriber struct {
	generation  uint64
	wake        chan struct{}
	reservation resourcev4.Reference
}

// A copied stale handle cannot release a replacement using the same slot.
type namespaceSubscription struct {
	owner      *LiveNamespace
	index      int
	generation uint64
}

func (n *LiveNamespace) subscribe(wake chan struct{}) (namespaceSubscription, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if wake == nil || cap(wake) != 1 {
		return namespaceSubscription{}, CBORFailure("revocation_subscription_owner")
	}
	if _, err := n.check(); err != nil {
		return namespaceSubscription{}, err
	}
	for i := range n.subscribers {
		slot := &n.subscribers[i]
		if slot.wake != nil || slot.generation == math.MaxUint64 {
			continue
		}
		ref, err := n.reservation.Borrow()
		if err != nil {
			return namespaceSubscription{}, err
		}
		slot.generation++
		slot.wake = wake
		slot.reservation = ref
		return namespaceSubscription{owner: n, index: i, generation: slot.generation}, nil
	}
	return namespaceSubscription{}, CBORFailure("revocation_subscription_capacity")
}

func (s namespaceSubscription) release() {
	if s.owner == nil {
		return
	}
	n := s.owner
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.index >= len(n.subscribers) {
		return
	}
	slot := &n.subscribers[s.index]
	if slot.generation == s.generation {
		slot.wake = nil
		slot.reservation.Release()
		slot.reservation = resourcev4.Reference{}
	}
}

// Caller holds the namespace gate. Notifications carry no authority or State
// data; every recipient must recheck the current original authorization.
func (n *LiveNamespace) notifySubscribers() {
	for _, slot := range n.subscribers {
		if slot.wake != nil {
			select {
			case slot.wake <- struct{}{}:
			default:
			}
		}
	}
}

func (n *LiveNamespace) SubscriptionCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	count := 0
	for _, slot := range n.subscribers {
		if slot.wake != nil {
			count++
		}
	}
	return count
}

// CredentialSubscriptions reserves one bounded reference per unique required
// namespace before spend. The complete namespace capacity/service reservation
// already belongs to each shared live owner; another Session does not acquire
// another copy of State. Each slot borrows that exact shared reservation; the
// subscription's own allocation is charged separately before activation.
type CredentialSubscriptions struct {
	floor         *DeliverySubscriptionFloor
	mu            sync.Mutex
	closure       *EndpointCredentials
	bindings      [5]CredentialValidation
	refs          [5]namespaceSubscription
	count         int
	hardEnd       uint64
	hard          *timev4.Deadline
	freshness     [5]credentialProjection
	wake          chan struct{}
	bound         *EndpointAuthorization
	used, closed  bool
	prepared      bool
	preparation   CredentialPreparation
	reservation   resourcev4.Reference
	authorization EndpointAuthorization
	delivery      [2]DeliveryAuthorization
}

func CredentialSubscriptionsBackingBytes() uint64 {
	return uint64(unsafe.Sizeof(CredentialSubscriptions{})) + uint64(unsafe.Sizeof(timev4.Deadline{}))
}

func CredentialSubscriptionsCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: CredentialSubscriptionsBackingBytes(), resourcev4.Items: 1}
}

// The admitted resource vector must additionally contain this one notification
// channel and its host bookkeeping. No notification creates a task or timer.
func (e *EndpointCredentials) Subscribe(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference) (*CredentialSubscriptions, error) {
	return e.subscribe(bindings, hardEnd, reservation, nil)
}

func (e *EndpointCredentials) subscribe(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference, inherited *timev4.Deadline) (*CredentialSubscriptions, error) {
	return e.subscribeWithFloor(bindings, hardEnd, reservation, inherited, nil)
}

func (e *EndpointCredentials) subscribeWithFloor(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference, inherited *timev4.Deadline, floor *DeliverySubscriptionFloor) (*CredentialSubscriptions, error) {
	if e == nil {
		return nil, CBORFailure("configuration_capacity")
	}
	if _, err := e.CheckCurrent(bindings, hardEnd); err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if err := reservation.CheckSameEnvironment(binding.Namespace.reservation); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(CredentialSubscriptionsCharge())
	if err != nil {
		return nil, err
	}
	s := &CredentialSubscriptions{closure: e, hardEnd: min(hardEnd, e.hardEnd), wake: make(chan struct{}, 1), reservation: owned}
	copy(s.bindings[:], bindings)
	if inherited == nil {
		s.hard, err = timev4.NewDeadline(bindings[0].Namespace.clock, s.hardEnd)
	} else if !inherited.BelongsTo(bindings[0].Namespace.clock) {
		err = timev4.ErrOwner
	} else {
		s.hard, err = inherited.Fork(s.hardEnd)
	}
	if err != nil {
		owned.Release()
		return nil, err
	}
	if _, err := s.checkPreparationLocked(); err != nil {
		s.closeLocked()
		return nil, err
	}
	if floor != nil {
		if err := floor.attach(s); err != nil {
			s.closeLocked()
			return nil, err
		}
	} else {
		for _, binding := range bindings {
			duplicate := false
			for _, ref := range s.refs[:s.count] {
				duplicate = duplicate || ref.owner == binding.Namespace
			}
			if duplicate {
				continue
			}
			ref, err := binding.Namespace.subscribe(s.wake)
			if err != nil {
				s.closeLocked()
				return nil, err
			}
			s.refs[s.count] = ref
			s.count++
		}
	}
	// Any change between preflight and the last registration is checked here;
	// subsequent changes wake the original owner without an event-history queue.
	if _, err := s.checkPreparationLocked(); err != nil {
		s.closeLocked()
		return nil, err
	}
	return s, nil
}

func (s *CredentialSubscriptions) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	s.hard.Cancel()
	s.closure = nil
	clear(s.bindings[:])
	if s.bound == nil {
		clear(s.authorization.bindings[:])
		s.authorization.closure, s.authorization.activation = nil, nil
	}
	if s.floor != nil {
		s.floor.release(s)
		s.floor = nil
	} else {
		for _, ref := range s.refs[:s.count] {
			ref.release()
		}
	}
	clear(s.refs[:])
	s.count = 0
	s.reservation.Seal()
	s.reservation.Release()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// CheckPreparation is still local validation, not an activation guard. It is
// available only to the original reservation before its one-time transfer.
func (s *CredentialSubscriptions) CheckPreparation() (CredentialValidity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.closed || s.prepared {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	result, err := s.checkPreparationLocked()
	if err != nil {
		s.closeLocked()
	}
	return result, err
}

func (s *CredentialSubscriptions) checkPreparationLocked() (result CredentialValidity, err error) {
	if err = s.reservation.Check(); err != nil {
		return result, err
	}
	if err = s.hard.Check(); err != nil {
		return result, err
	}
	result, err = s.closure.CheckCurrent(s.bindings[:s.closure.count], s.hardEnd)
	if err != nil {
		return result, err
	}
	for i, cap := range result.deadlines[:s.closure.count] {
		if _, err = s.freshness[i].project(s.bindings[i].Namespace.clock, cap); err != nil {
			return result, err
		}
	}
	return result, nil
}

// Close belongs to the original pre-spend reservation until its successful
// one-time transfer. A stale caller cannot release a live Session's references.
func (s *CredentialSubscriptions) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound == nil && !s.prepared {
		s.closeLocked()
	}
}

func (s *CredentialSubscriptions) closeOwned(owner *EndpointAuthorization) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound == owner {
		s.closeLocked()
	}
}

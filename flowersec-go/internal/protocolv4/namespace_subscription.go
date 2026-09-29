package protocolv4

import (
	"errors"
	"math"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
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
	return n.reserveSubscription(wake, true)
}

func (n *LiveNamespace) reserveSubscription(wake chan struct{}, sampleTime bool) (namespaceSubscription, error) {
	var sample timev4.Sample
	if sampleTime {
		var err error
		sample, err = n.sampleCurrent()
		if err != nil {
			return namespaceSubscription{}, err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if wake == nil || cap(wake) != 1 {
		return namespaceSubscription{}, CBORFailure("revocation_subscription_owner")
	}
	if err := n.checkAvailable(); err != nil {
		return namespaceSubscription{}, err
	}
	if sampleTime {
		if current, err := n.clock.RefreshSample(sample); err != nil {
			return namespaceSubscription{}, err
		} else {
			sample = current
		}
	}
	for i := range n.subscribers {
		slot := &n.subscribers[i]
		if slot.wake != nil || slot.generation == math.MaxUint64 || slot.reservation == (resourcev4.Reference{}) {
			continue
		}
		ref, err := slot.reservation.TakeBorrow()
		if err != nil {
			if errors.Is(err, resourcev4.ErrCapacity) {
				// An exhausted original generation retires this position. It
				// cannot borrow a replacement from unrelated root capacity.
				slot.reservation.Release()
				slot.reservation = resourcev4.Reference{}
				continue
			}
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
	if slot.generation == s.generation && slot.wake != nil {
		slot.wake = nil
		// The namespace owns this preadmitted slot even while it is idle or
		// closed. The next subscription advances both original generations;
		// clearing wake already fences every stale subscription handle. Only
		// namespace destruction releases the slot's physical reference.
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
// another copy of State. Each slot moves its preadmitted shared reference; the
// subscription's own allocation is charged separately before activation.
// MaxSourceCredentials covers three endpoint credentials and both role sets
// for all sixteen signed candidates, with one Grant and relay identity each.
const MaxSourceCredentials = 3 + 16*2*2

type CredentialSubscriptions struct {
	sampling                       uint32
	cleaned                        bool
	sourceSelf                     *CredentialSubscriptions
	sourceOrigin                   resourcev4.Reference
	sourceComplete, sourceAttached bool
	floor                          *DeliverySubscriptionFloor
	mu                             sync.Mutex
	closure                        *EndpointCredentials
	bindings                       [5]CredentialValidation
	refs                           [MaxSourceCredentials]namespaceSubscription
	count                          int
	hardEnd                        uint64
	hard                           *timev4.Deadline
	freshness                      [5]credentialProjection
	wake                           chan struct{}
	bound                          *EndpointAuthorization
	used, closed                   bool
	prepared                       bool
	preparation                    CredentialPreparation
	reservation                    resourcev4.Reference
	authorization                  EndpointAuthorization
	delivery                       [2]DeliveryAuthorization
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
	return e.subscribeWithPreparation(bindings, hardEnd, reservation, inherited, floor, nil)
}

func (e *EndpointCredentials) SubscribePrepared(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference, preparation *CredentialSubscriptions) (*CredentialSubscriptions, error) {
	if preparation == nil {
		return nil, resourcev4.ErrOwner
	}
	return e.subscribeWithPreparation(bindings, hardEnd, reservation, nil, nil, preparation)
}

func (e *EndpointCredentials) subscribeWithPreparation(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference, inherited *timev4.Deadline, floor *DeliverySubscriptionFloor, source *CredentialSubscriptions) (*CredentialSubscriptions, error) {
	samples, err := sampleCredentialBindings(bindings)
	if err != nil {
		return nil, err
	}
	return e.subscribeWithPreparationAt(bindings, hardEnd, reservation, inherited, floor, source, samples)
}

func (e *EndpointCredentials) subscribeWithPreparationAt(bindings []CredentialValidation, hardEnd uint64, reservation resourcev4.Reference, inherited *timev4.Deadline, floor *DeliverySubscriptionFloor, source *CredentialSubscriptions, samples credentialSamples) (*CredentialSubscriptions, error) {
	if e == nil {
		return nil, CBORFailure("configuration_capacity")
	}
	if _, err := e.checkCurrentAt(bindings, hardEnd, samples); err != nil {
		return nil, err
	}
	var s *CredentialSubscriptions
	var owned resourcev4.Reference
	var err error
	if source != nil {
		if err = source.attachSourceClosure(e, bindings, reservation); err != nil {
			return nil, err
		}
		s, owned = source, source.reservation
		s.hardEnd = min(hardEnd, e.hardEnd)
	} else {
		for _, binding := range bindings {
			if err := reservation.CheckSameEnvironment(binding.Namespace.reservation); err != nil {
				return nil, err
			}
		}
		owned, err = reservation.Take(CredentialSubscriptionsCharge())
		if err != nil {
			return nil, err
		}
		s = &CredentialSubscriptions{closure: e, hardEnd: min(hardEnd, e.hardEnd), wake: make(chan struct{}, 1), reservation: owned}
	}
	copy(s.bindings[:], bindings)
	if inherited == nil {
		s.hard, err = timev4.NewDeadlineAt(bindings[0].Namespace.clock, samples[0], s.hardEnd)
	} else if !inherited.BelongsTo(bindings[0].Namespace.clock) {
		err = timev4.ErrOwner
	} else {
		s.hard, err = inherited.ForkAt(s.hardEnd, samples[0])
	}
	if err != nil {
		s.closeLocked()
		return nil, err
	}
	if _, err := s.checkPreparationLockedAt(samples, nil); err != nil {
		s.closeLocked()
		return nil, err
	}
	if floor != nil {
		if err := floor.attach(s); err != nil {
			s.closeLocked()
			return nil, err
		}
	} else if source == nil {
		for _, binding := range bindings {
			duplicate := false
			for _, ref := range s.refs[:s.count] {
				duplicate = duplicate || ref.owner == binding.Namespace
			}
			if duplicate {
				continue
			}
			ref, err := binding.Namespace.reserveSubscription(s.wake, false)
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
	if _, err := s.checkPreparationLockedAt(samples, nil); err != nil {
		s.closeLocked()
		return nil, err
	}
	return s, nil
}

func (s *CredentialSubscriptions) closeLocked() {
	if s.sourceSelf != nil && s.sourceSelf != s {
		return
	}
	s.closed = true
	if s.hard != nil {
		s.hard.Cancel()
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	s.cleanupLocked()
}

func (s *CredentialSubscriptions) cleanupLocked() {
	if !s.closed || s.cleaned || s.sampling != 0 {
		return
	}
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
	s.cleaned = true
}

// CheckPreparation is still local validation, not an activation guard. It is
// available only to the original reservation before its one-time transfer.
func (s *CredentialSubscriptions) CheckPreparation() (CredentialValidity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.closed || s.prepared || s.closure == nil {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	result, err := s.checkPreparationLocked()
	if s.used || s.prepared {
		return CredentialValidity{}, CBORFailure("credential_authorization_owner")
	}
	if err != nil {
		s.closeLocked()
	}
	return result, err
}

func (s *CredentialSubscriptions) checkPreparationLocked() (result CredentialValidity, err error) {
	used, prepared, bound := s.used, s.prepared, s.bound
	samples, err := s.sampleLocked()
	if s.used != used || s.prepared != prepared || s.bound != bound {
		return result, CBORFailure("credential_authorization_owner")
	}
	return s.checkPreparationLockedAt(samples, err)
}

// As with endpoint sampling, mu is held both on entry and on return. Close
// can revoke this owner during a blocked adapter without returning its backing.
func (s *CredentialSubscriptions) sampleLocked() (samples credentialSamples, err error) {
	if s.closed || s.closure == nil || s.sampling == math.MaxUint32 {
		return samples, resourcev4.ErrOwner
	}
	bindings, count := s.bindings, s.closure.count
	used, prepared, bound := s.used, s.prepared, s.bound
	s.sampling++
	s.mu.Unlock()
	returned := false
	defer func() {
		s.mu.Lock()
		s.sampling--
		if !returned && s.used == used && s.prepared == prepared && s.bound == bound {
			s.closeLocked()
		} else {
			s.cleanupLocked()
		}
	}()
	samples, err = sampleCredentialBindings(bindings[:count])
	returned = true
	return samples, err
}

func (s *CredentialSubscriptions) checkPreparationLockedAt(samples credentialSamples, sampleErr error) (result CredentialValidity, err error) {
	if s.closed || s.closure == nil || s.hard == nil || s.sourceSelf != nil && s.sourceSelf != s {
		return result, resourcev4.ErrOwner
	}
	if err = s.reservation.Check(); err != nil {
		return result, err
	}
	err = s.hard.CheckAt(samples[0])
	if sampleErr != nil && !errors.Is(err, timev4.ErrExpired) {
		return result, sampleErr
	}
	if err != nil {
		return result, err
	}
	result, err = s.closure.checkCurrentAt(s.bindings[:s.closure.count], s.hardEnd, samples)
	if err != nil {
		return result, err
	}
	for i, cap := range result.deadlines[:s.closure.count] {
		if _, err = s.freshness[i].projectAt(s.bindings[i].Namespace.clock, cap, samples[i]); err != nil {
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

// PreparationWake exposes the coalesced namespace notification while the
// original preauth owner retains this subscription. It conveys no activation.
func (s *CredentialSubscriptions) PreparationWake() <-chan struct{} {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wake
}

func (s *CredentialSubscriptions) NotifyPreparation() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && !s.used && !s.prepared {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// PreparationRemainingMS preserves each independently hosted namespace's
// original monotonic projection. A watchdog must wake at freshness expiry
// even when that namespace never publishes another notification.
func (s *CredentialSubscriptions) PreparationRemainingMS() (uint64, error) {
	if s == nil {
		return 0, resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.closed || s.prepared || s.closure == nil {
		return 0, resourcev4.ErrOwner
	}
	samples, err := s.sampleLocked()
	if s.used || s.prepared {
		return 0, resourcev4.ErrOwner
	}
	if _, err = s.checkPreparationLockedAt(samples, err); err != nil {
		s.closeLocked()
		return 0, err
	}
	remaining, err := s.hard.RemainingMSAt(samples[0])
	if err != nil {
		s.closeLocked()
		return 0, err
	}
	for i := 0; i < s.closure.count; i++ {
		ms, err := s.freshness[i].projectAt(s.bindings[i].Namespace.clock, s.freshness[i].cap, samples[i])
		if err != nil {
			s.closeLocked()
			return 0, err
		}
		remaining = min(remaining, ms)
	}
	return remaining, nil
}

// CheckPreparationClock binds a protocol work deadline to the original parent
// namespace clock. Independently hosted dependencies retain their own clocks
// and freshness projections; no wire timestamp supplies the work clock.
func (s *CredentialSubscriptions) CheckPreparationClock(clock *timev4.Clock) error {
	if s == nil || clock == nil {
		return resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.used || s.prepared || s.hard == nil || !s.hard.BelongsTo(clock) {
		return resourcev4.ErrOwner
	}
	return s.reservation.Check()
}

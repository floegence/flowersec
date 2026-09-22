package protocolv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// DeliverySubscriptionFloor is the original short-result namespace promise.
// It reserves real shared-namespace references before irreversible Session
// admission. One live result uses them at a time; it grants no authorization.
// Closing the Session retires only idle ownership, leaving an attached result
// independently covered until its actual authority reference exits.
type DeliverySubscriptionFloor struct {
	self            *DeliverySubscriptionFloor
	mu              sync.Mutex
	reservation     resourcev4.Reference
	closure         *EndpointCredentials
	refs            [5]namespaceSubscription
	count           int
	wake            chan struct{}
	active          *CredentialSubscriptions
	closed, cleaned bool
}

func DeliverySubscriptionFloorCharge() resourcev4.Vector {
	return resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(DeliverySubscriptionFloor{})), resourcev4.Items: 1}
}

func (s *CredentialSubscriptions) ReserveDeliveryFloor(reservation resourcev4.Reference) (*DeliverySubscriptionFloor, error) {
	if s == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || s.closed || s.prepared {
		return nil, CBORFailure("credential_authorization_owner")
	}
	if _, err := s.checkPreparationLocked(); err != nil {
		return nil, err
	}
	return newDeliverySubscriptionFloor(s.closure, s.bindings[:s.closure.count], reservation)
}

// The authorized component constructor uses the same ownership path. Complete
// Session assembly uses CredentialSubscriptions.ReserveDeliveryFloor pre-spend.
func (a *EndpointAuthorization) ReserveDeliveryFloor(reservation resourcev4.Reference) (*DeliverySubscriptionFloor, error) {
	if a == nil {
		return nil, CBORFailure("credential_authorization_owner")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.checkLocked(false); err != nil {
		return nil, err
	}
	return newDeliverySubscriptionFloor(a.closure, a.bindings[:a.closure.count], reservation)
}

func newDeliverySubscriptionFloor(closure *EndpointCredentials, bindings []CredentialValidation, reservation resourcev4.Reference) (_ *DeliverySubscriptionFloor, err error) {
	for _, binding := range bindings {
		if err := reservation.CheckSameEnvironment(binding.Namespace.reservation); err != nil {
			return nil, err
		}
	}
	owned, err := reservation.Take(DeliverySubscriptionFloorCharge())
	if err != nil {
		return nil, err
	}
	f := &DeliverySubscriptionFloor{reservation: owned, closure: closure, wake: make(chan struct{}, 1)}
	f.self = f
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	for _, binding := range bindings {
		duplicate := false
		for _, ref := range f.refs[:f.count] {
			duplicate = duplicate || ref.owner == binding.Namespace
		}
		if duplicate {
			continue
		}
		ref, e := binding.Namespace.subscribe(f.wake)
		if e != nil {
			return nil, e
		}
		f.refs[f.count] = ref
		f.count++
	}
	return f, nil
}

// caller holds the original endpoint authorization gate; this only attaches
// already admitted namespace slots to its one freshly checked result owner.
func (f *DeliverySubscriptionFloor) attach(s *CredentialSubscriptions) error {
	if f == nil || f.self != f {
		return CBORFailure("credential_authorization_owner")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.cleaned || f.active != nil || f.closure != s.closure {
		return CBORFailure("revocation_subscription_capacity")
	}
	if err := f.reservation.CheckSameEnvironment(s.reservation); err != nil {
		return err
	}
	for _, binding := range s.bindings[:s.closure.count] {
		found := false
		for _, ref := range f.refs[:f.count] {
			found = found || ref.owner == binding.Namespace
		}
		if !found {
			return CBORFailure("credential_authorization_owner")
		}
	}
	select {
	case <-f.wake:
	default:
	}
	f.active = s
	s.floor, s.refs, s.count, s.wake = f, f.refs, f.count, f.wake
	return nil
}

func (f *DeliverySubscriptionFloor) release(s *CredentialSubscriptions) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active != s {
		return
	}
	f.active = nil
	f.cleanupLocked()
}

func (f *DeliverySubscriptionFloor) Close() {
	if f == nil || f.self != f {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	// This preexisting metadata joins the result's independent responsibility;
	// the original namespace borrows themselves never carried Session scope.
	if f.active != nil {
		_ = f.reservation.DetachSessionScope()
	}
	f.cleanupLocked()
}

func (f *DeliverySubscriptionFloor) cleanupLocked() {
	if !f.closed || f.active != nil || f.cleaned {
		return
	}
	for _, ref := range f.refs[:f.count] {
		ref.release()
	}
	clear(f.refs[:])
	f.count = 0
	f.reservation.Release()
	f.reservation = resourcev4.Reference{}
	f.closure, f.wake = nil, nil
	f.cleaned = true
}

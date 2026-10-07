package protocolv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NamespaceForPreparation identifies the already installed original owner. It
// does not check a credential, sample time, fetch State or grant authorization.
// A later namespace replacement cannot retarget a captured subscriber position.
func (t *NamespaceTrustStore) NamespaceForPreparation(clock *timev4.Clock, environment resourcev4.Reference) (*LiveNamespace, error) {
	if t == nil || clock == nil {
		return nil, resourcev4.ErrConfiguration
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.retired || t.retirementOnly || t.namespace == nil || t.count == 0 {
		return nil, resourcev4.ErrClosed
	}
	if clock != t.clock {
		return nil, resourcev4.ErrOwner
	}
	if err := t.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	return t.namespace, nil
}

// PreparationReferenceFor retains this exact installed namespace before source
// acquisition. It performs no time/provider call and grants no credential use.
func (n *LiveNamespace) PreparationReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if n == nil || clock == nil {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.clock != clock {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := n.checkAvailable(); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := n.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return n.reservation.Borrow()
}

// PrepareCredentialSubscriptions constructs the final subscription owner and
// claims actual namespace positions before source acquisition. The caller's
// primary remains untouched until its original Connect accepts ownership.
// complete fixes the entire trusted namespace set; partial component sources
// may add their remaining dependencies before any native preparation or spend.
func PrepareCredentialSubscriptions(namespaces []*LiveNamespace, complete bool, reservation resourcev4.Reference) (_ *CredentialSubscriptions, err error) {
	if len(namespaces) == 0 || len(namespaces) > MaxSourceCredentials {
		return nil, resourcev4.ErrConfiguration
	}
	if err = reservation.CheckMinimum(CredentialSubscriptionsCharge()); err != nil {
		return nil, err
	}
	s := &CredentialSubscriptions{sourceOrigin: reservation, sourceComplete: complete, wake: make(chan struct{}, 1)}
	s.sourceSelf = s
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	for _, namespace := range namespaces {
		if namespace == nil {
			return nil, resourcev4.ErrOwner
		}
		if err = s.addSourceNamespaceLocked(namespace, reservation); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *CredentialSubscriptions) addSourceNamespaceLocked(namespace *LiveNamespace, reservation resourcev4.Reference) error {
	for _, ref := range s.refs[:s.count] {
		if ref.owner == namespace {
			return ref.check()
		}
	}
	if s.count == len(s.refs) || namespace == nil {
		return resourcev4.ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(namespace.reservation); err != nil {
		return err
	}
	ref, err := namespace.reserveSubscription(s.wake, false)
	if err != nil {
		return err
	}
	s.refs[s.count] = ref
	s.count++
	return nil
}

func (s *CredentialSubscriptions) checkSourceLocked(origin resourcev4.Reference) error {
	if s.sourceSelf != s || s.closed || s.sourceOrigin == (resourcev4.Reference{}) || s.sourceOrigin != origin || s.sourceAttached {
		return resourcev4.ErrOwner
	}
	ref := s.reservation
	if ref == (resourcev4.Reference{}) {
		ref = origin
	}
	if err := ref.Check(); err != nil {
		return err
	}
	for _, sub := range s.refs[:s.count] {
		if err := sub.check(); err != nil {
			return err
		}
	}
	return nil
}

func (s *CredentialSubscriptions) CheckSourcePreparation(origin resourcev4.Reference) error {
	if s == nil {
		return resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkSourceLocked(origin)
}

func (s *CredentialSubscriptions) AdoptSourcePreparation(origin resourcev4.Reference) error {
	if s == nil {
		return resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reservation != (resourcev4.Reference{}) {
		return resourcev4.ErrOwner
	}
	if err := s.checkSourceLocked(origin); err != nil {
		return err
	}
	owned, err := origin.Take(CredentialSubscriptionsCharge())
	if err == nil {
		s.reservation = owned
	}
	return err
}

// CheckSourceNamespaces never allocates. Pool acquisition calls it before its
// durable take so a changed material cannot consume an unreserved dependency.
func (s *CredentialSubscriptions) CheckSourceNamespaces(bindings []CredentialValidation) error {
	if s == nil {
		return resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkSourceNamespacesLocked(bindings)
}

func (s *CredentialSubscriptions) checkSourceNamespacesLocked(bindings []CredentialValidation) error {
	if err := s.checkSourceLocked(s.sourceOrigin); err != nil {
		return err
	}
	if len(bindings) == 0 || len(bindings) > len(s.refs) {
		return resourcev4.ErrConfiguration
	}
	for _, binding := range bindings {
		found := false
		for _, ref := range s.refs[:s.count] {
			found = found || ref.owner == binding.Namespace
		}
		if !found {
			return resourcev4.ErrOwner
		}
	}
	return nil
}

func (s *CredentialSubscriptions) CompleteSourceNamespaces(bindings []CredentialValidation) error {
	if s == nil {
		return resourcev4.ErrOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkSourceLocked(s.sourceOrigin); err != nil {
		return err
	}
	if s.reservation == (resourcev4.Reference{}) || len(bindings) == 0 || len(bindings) > len(s.refs) {
		return resourcev4.ErrOwner
	}
	if !s.sourceComplete {
		for _, binding := range bindings {
			if err := s.addSourceNamespaceLocked(binding.Namespace, s.reservation); err != nil {
				return err
			}
		}
	}
	if err := s.checkSourceNamespacesLocked(bindings); err != nil {
		return err
	}
	s.sourceComplete = true
	return nil
}

func (s *CredentialSubscriptions) attachSourceClosure(closure *EndpointCredentials, bindings []CredentialValidation, origin resourcev4.Reference) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sourceOrigin != origin || s.reservation == (resourcev4.Reference{}) || s.closure != nil || !s.sourceComplete {
		return resourcev4.ErrOwner
	}
	if err := s.checkSourceNamespacesLocked(bindings); err != nil {
		return err
	}
	s.closure, s.sourceAttached = closure, true
	return nil
}

func (s namespaceSubscription) check() error {
	if s.owner == nil {
		return resourcev4.ErrOwner
	}
	n := s.owner
	n.mu.Lock()
	defer n.mu.Unlock()
	if s.index < 0 || s.index >= len(n.subscribers) {
		return resourcev4.ErrOwner
	}
	slot := &n.subscribers[s.index]
	if slot.generation != s.generation || slot.wake == nil {
		return resourcev4.ErrOwner
	}
	if err := n.checkAvailable(); err != nil {
		return err
	}
	return slot.reservation.Check()
}

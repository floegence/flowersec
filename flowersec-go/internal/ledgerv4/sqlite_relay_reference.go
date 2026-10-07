package ledgerv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// RelayReference retains the original claim store and reports its independently
// configured identity and fixed record geometry before any physical hop work.
// It conveys neither a claim nor evidence of original issuer publication.
func (s *SQLiteStore) RelayReference(environment resourcev4.Reference) (resourcev4.Reference, SQLiteIdentity, uint32, error) {
	ref, identity, _, limit, err := s.admissionReference(environment)
	return ref, identity, limit, err
}

// ReferenceFor binds a relay service to the same original claim authority.
// Only previously committed public registrations can satisfy ResolveRelayParent.
func (a *SQLiteRelayAuthorityTable) ReferenceFor(identity SQLiteIdentity, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if a == nil {
		return resourcev4.Reference{}, ErrConfiguration
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return resourcev4.Reference{}, ErrOwner
	}
	if identity != a.identity {
		return resourcev4.Reference{}, ErrOwner
	}
	if err := a.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := a.shared.Check(); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := a.storeRef.Check(); err != nil {
		return resourcev4.Reference{}, err
	}
	return a.reservation.Borrow()
}

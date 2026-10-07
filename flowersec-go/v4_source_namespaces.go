package flowersec

import "github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"

// PreparationNamespaceSet preserves the provider's original namespace promise
// through the public source wrapper. It never acquires material, samples time,
// issues credentials or starts control I/O. Close retains a running inspection
// until it returns, just as it retains the original AcquireLease invocation.
func (s *LiveAuthoritySource) PreparationNamespaceSet(clock *Clock, environment ResourceReference) (set MaterialNamespaceSet, err error) {
	if s == nil || clock == nil {
		return set, cryptov4.ErrConfiguration
	}
	s.mu.Lock()
	if s.closed || s.provider == nil {
		s.mu.Unlock()
		return set, cryptov4.ErrClosed
	}
	if s.active != 0 {
		s.mu.Unlock()
		return set, cryptov4.ErrTransition
	}
	s.active++
	provider := s.provider
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		if s.closed {
			set, err = MaterialNamespaceSet{}, cryptov4.ErrClosed
		}
		s.mu.Unlock()
		s.closeProviderIfReady()
	}()
	if p, ok := provider.(MaterialNamespaceSetProvider); ok {
		set, err = p.PreparationNamespaceSet(clock, environment)
		if err == nil && set.Count == 0 {
			err = cryptov4.ErrConfiguration
		}
		return set, err
	}
	if p, ok := provider.(MaterialNamespaceProvider); ok {
		owners, err := p.PreparationNamespaces(clock, environment)
		if err != nil {
			return set, err
		}
		copy(set.Owners[:], owners[:])
		set.Count = uint8(len(owners))
		return set, nil
	}
	return set, cryptov4.ErrConfiguration
}

var _ MaterialNamespaceSetProvider = (*LiveAuthoritySource)(nil)

package protocolv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ReferenceFor retains this exact issuer under its original Environment and
// Clock. It grants no issuance permission and does not revive a closed issuer.
func (s *DirectIssuer) ReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if s == nil {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.c.Clock != clock {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := s.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return s.reservation.Borrow()
}

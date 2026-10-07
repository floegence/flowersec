package protocolv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ReferenceFor retains the current independent trust owner in its original
// Environment and Clock. It grants no credential, bootstrap or signing rights.
func (t *NamespaceTrustStore) ReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if t == nil {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return resourcev4.Reference{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.clock != clock || t.retirementOnly {
		return resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return resourcev4.Reference{}, err
	}
	if err := t.reservation.CheckSameEnvironment(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	return t.reservation.Borrow()
}

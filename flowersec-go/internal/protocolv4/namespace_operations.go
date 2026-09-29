package protocolv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
	"math"
)

// NamespaceOperationsSnapshot contains aggregate health of the original trust
// and active Head owners. Current does not assert freshness for an arbitrary
// credential's staleness requirement. Reads never advance pins, retire history,
// close authorization gates, fetch content, or expose namespace identities.
type NamespaceOperationsSnapshot struct {
	Continuity                                                        string
	Capacity, Registered                                              uint32
	Current, Starting, TrustExpired, HeadExpired, Unavailable, Closed uint32
	Pins, Fetching, Refreshing                                        uint32
	TrustConfigurations, TrustConfigurationCapacity                   uint32
	RegistryClosed, RegistryRetired                                   bool
}

func (r *NamespaceRegistry) OperationsSnapshot() NamespaceOperationsSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := NamespaceOperationsSnapshot{Capacity: r.capacity, Registered: r.used, RegistryClosed: r.closed, RegistryRetired: r.retired,
		Continuity: "online_bootstrap"}
	if r.continuity == DurableRestore {
		s.Continuity = "durable_restore"
	}
	for _, entry := range r.entries[:r.used] {
		t := entry.trust
		sample, sampleErr := r.sampleOperationsLocked(t)
		t.mu.Lock()
		n := t.namespace
		t.mu.Unlock()
		// Namespace validation takes namespace before trust. Preserve that order
		// even though this read performs no protocol mutation.
		if n != nil {
			n.mu.Lock()
		}
		t.mu.Lock()
		s.TrustConfigurations += uint32(t.count)
		s.TrustConfigurationCapacity += t.limits.Configurations
		if n != nil {
			if n.pin != nil {
				s.Pins++
				if n.pin.running {
					s.Fetching++
				}
			}
			if n.refreshActive {
				s.Refreshing++
			}
		}
		switch {
		case r.closed || t.closed || t.retired || n != nil && (n.destroyed || n.terminal != nil):
			s.Closed++
		case !t.continuityReady || t.count == 0 || n == nil || n.initializing || n.active == nil:
			s.Starting++
		default:
			err := sampleErr
			if err == nil {
				err = t.checkCurrentLockedAt(sample)
			}
			if err == timev4.ErrExpired {
				s.TrustExpired++
			} else if err != nil {
				s.Unavailable++
			} else {
				// Head verification calls this trust owner itself after we release
				// its gate. It rechecks current trust for this exact original Head.
				t.mu.Unlock()
				err = n.reservation.Check()
				if err == nil {
					err = n.checkHeadAt(n.active.head, sample)
				}
				switch err {
				case nil:
					s.Current++
				case timev4.ErrExpired:
					s.HeadExpired++
				default:
					s.Unavailable++
				}
				n.mu.Unlock()
				continue
			}
		}
		t.mu.Unlock()
		if n != nil {
			n.mu.Unlock()
		}
	}
	return s
}

// The table and exact trust owner remain retained while the adapter runs.
// Close may fence either owner immediately; the caller rechecks both gates.
func (r *NamespaceRegistry) sampleOperationsLocked(t *NamespaceTrustStore) (timev4.Sample, error) {
	if r.closed || r.retired || r.sampling == math.MaxUint32 {
		return timev4.Sample{}, timev4.ErrUnavailable
	}
	r.sampling++
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.sampling-- }()
	return t.sampleCurrent()
}

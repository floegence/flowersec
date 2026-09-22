package rpcv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// Advertise selects one already registered exact contract for its immutable
// method. Execution requires a presently usable original Offer. Selecting a
// new advertisement never removes another digest or changes an old window.
// The deployment owner must complete its implementation/store readiness barrier
// before this local publication; this registry does not establish that barrier.
func (r *ContractRoutes) Advertise(digest [32]byte) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	entry, err := r.offerEntryLocked(digest)
	if err != nil {
		r.mu.Unlock()
		return err
	}
	execution := entry.policy.Semantics == 1
	r.mu.Unlock()
	var now timev4.Sample
	if execution {
		now, err = r.offerSample()
		if err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err = r.offerEntryLocked(digest)
	if err != nil {
		return err
	}
	if !entry.registered {
		return ErrMethod
	}
	if execution {
		if _, ok := usableOffer(entry, now, 0, true); !ok {
			return ErrMethod
		}
	}
	if entry.advertised {
		return nil
	}
	if r.generation == math.MaxUint64 {
		return ErrCapacity
	}
	for i := range r.entries {
		if r.entries[i].method == entry.method {
			r.entries[i].advertised = false
		}
	}
	entry.advertised = true
	r.generation++
	return nil
}

// SetRegistered changes future exact-route availability within the frozen
// method set. An execution registration cannot be withdrawn while it owns any
// unretired Offer, including future windows. Definite expiry is handled only by
// RetireOffers. Existing semantic captures and accepted input retain their body.
func (r *ContractRoutes) SetRegistered(digest [32]byte, registered bool) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.offerEntryLocked(digest)
	if err != nil {
		return err
	}
	if entry.registered == registered {
		return nil
	}
	if !registered && entry.offerCount != 0 {
		return ErrOwner
	}
	if r.generation == math.MaxUint64 {
		return ErrCapacity
	}
	entry.registered = registered
	if !registered {
		entry.advertised = false
	}
	r.generation++
	return nil
}

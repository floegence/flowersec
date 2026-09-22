package rpcv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// offerSample invokes the original bounded clock adapter outside the registry
// gate. Mutators recheck the registry under its gate before changing state.
func (r *ContractRoutes) offerSample() (timev4.Sample, error) {
	if r == nil {
		return timev4.Sample{}, ErrOwner
	}
	r.mu.Lock()
	if r.closed || r.cleaned {
		r.mu.Unlock()
		return timev4.Sample{}, ErrClosed
	}
	clock := r.clock
	err := r.reservation.Check()
	r.mu.Unlock()
	if err != nil {
		return timev4.Sample{}, err
	}
	if clock == nil {
		return timev4.Sample{}, ErrConfiguration
	}
	return clock.Sample()
}
func (r *ContractRoutes) offerEntryLocked(digest [32]byte) (*contractRouteEntry, error) {
	if r.closed || r.cleaned {
		return nil, ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return nil, err
	}
	for i := range r.entries {
		if r.entries[i].policy.Digest == digest {
			return &r.entries[i], nil
		}
	}
	return nil, ErrMethod
}

// RegisterOffer adds one distinct exact execution window to the original route.
// It cannot change stable contract bytes, extend an existing window or evict an
// unexpired commitment when the eight-window set is full. Admission/history,
// current permission and deployment publication barriers remain separate.
func (r *ContractRoutes) RegisterOffer(digest [32]byte, wire []byte) error {
	now, err := r.offerSample()
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.offerEntryLocked(digest)
	if err != nil {
		return err
	}
	if !entry.registered {
		return ErrMethod
	}
	if entry.offerWindowMS == 0 {
		return ErrConfiguration
	}
	offer, err := entry.contract.CheckOffer(r.offerDecoder, wire, entry.offerWindowMS)
	if err != nil {
		return err
	}
	if now.LowerMS >= offer.NotAfterMS {
		return ErrMethod
	}
	for _, existing := range entry.offers[:entry.offerCount] {
		if existing == offer {
			return nil
		}
	}
	if entry.offerCount == 8 || r.generation == math.MaxUint64 {
		return ErrCapacity
	}
	entry.offers[entry.offerCount] = offer
	entry.offerCount++
	r.generation++
	return nil
}

// RetireOffers removes only windows which trusted time has definitely passed.
// It does not retire an execution key, history/result record or stable route.
// Uncertain time cannot advance this collection boundary, and reading a window
// never refreshes its original bounds. No timer or background task is created.
func (r *ContractRoutes) RetireOffers() (uint32, error) {
	now, err := r.offerSample()
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleaned {
		return 0, ErrClosed
	}
	if err := r.reservation.Check(); err != nil {
		return 0, err
	}
	var count uint32
	for i := range r.entries {
		for _, offer := range r.entries[i].offers[:r.entries[i].offerCount] {
			if now.LowerMS >= offer.NotAfterMS {
				count++
			}
		}
	}
	if count == 0 {
		return 0, nil
	}
	if r.generation == math.MaxUint64 {
		return 0, ErrCapacity
	}
	for i := range r.entries {
		entry := &r.entries[i]
		next := uint8(0)
		for _, offer := range entry.offers[:entry.offerCount] {
			if now.LowerMS < offer.NotAfterMS {
				entry.offers[next] = offer
				next++
			}
		}
		clear(entry.offers[next:])
		entry.offerCount = next
	}
	r.generation++
	return count, nil
}

// OfferForAdmission selects ONE original window containing the real current
// interval and original operation cutoff. Adjacent/overlapping windows are not
// merged. This value is not a reservation or a store/dispatch capability; the
// original execution registration must recheck every admission prerequisite.
func (r *ContractRoutes) OfferForAdmission(digest [32]byte, cutoffMS uint64) (protocolv4.AdmissionOfferBounds, error) {
	return r.selectOffer(digest, cutoffMS, false)
}

// OfferForQuery returns a presently usable original window for the exact
// registered execution contract. It does not select another advertised digest,
// authenticate a query caller or install a new admission promise.
func (r *ContractRoutes) OfferForQuery(digest [32]byte) (protocolv4.AdmissionOfferBounds, error) {
	return r.selectOffer(digest, 0, true)
}
func (r *ContractRoutes) selectOffer(digest [32]byte, cutoffMS uint64, query bool) (protocolv4.AdmissionOfferBounds, error) {
	now, err := r.offerSample()
	if err != nil {
		return protocolv4.AdmissionOfferBounds{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.offerEntryLocked(digest)
	if err != nil {
		return protocolv4.AdmissionOfferBounds{}, err
	}
	if !entry.registered {
		return protocolv4.AdmissionOfferBounds{}, ErrMethod
	}
	if offer, ok := usableOffer(entry, now, cutoffMS, query); ok {
		return offer, nil
	}
	return protocolv4.AdmissionOfferBounds{}, ErrMethod
}

func usableOffer(entry *contractRouteEntry, now timev4.Sample, cutoffMS uint64, query bool) (protocolv4.AdmissionOfferBounds, bool) {
	var selected protocolv4.AdmissionOfferBounds
	found := false
	for _, offer := range entry.offers[:entry.offerCount] {
		cutoff := cutoffMS
		if query {
			cutoff = offer.NotAfterMS
		}
		if now.LowerMS >= offer.NotBeforeMS && now.UpperMS < cutoff && cutoff <= offer.NotAfterMS {
			if !query {
				return offer, true
			}
			// A renewal should obtain the longest currently usable ORIGINAL
			// window. Its own lower bound is retained; no union is synthesized.
			if !found || offer.NotAfterMS > selected.NotAfterMS {
				selected, found = offer, true
			}
		}
	}
	return selected, found
}

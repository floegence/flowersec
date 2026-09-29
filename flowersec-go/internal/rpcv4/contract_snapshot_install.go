package rpcv4

import (
	"bytes"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// WithQueryBindings checks a complete private initial selection at the one
// public handoff. Unregister cannot slip between two methods' qualification.
func (r *ContractRoutes) WithQueryBindings(digests [][32]byte, offers []protocolv4.AdmissionOfferBounds, now timev4.Sample, action func() error) error {
	if r == nil || len(digests) != len(offers) || len(digests) == 0 || len(digests) > 256 || action == nil {
		return ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for j, digest := range digests {
		entry, err := r.offerEntryLocked(digest)
		if err != nil {
			return err
		}
		if !entry.registered {
			return ErrMethod
		}
		if entry.policy.Semantics != 1 {
			if offers[j] != (protocolv4.AdmissionOfferBounds{}) {
				return ErrAssociation
			}
			continue
		}
		if !now.BelongsTo(r.clock) {
			return timev4.ErrOwner
		}
		found := false
		for _, offer := range entry.offers[:entry.offerCount] {
			if offers[j] == offer && now.UpperMS < offer.NotAfterMS {
				found = true
				break
			}
		}
		if !found {
			return ErrAdmissionOfferUnavailable
		}
	}
	return action()
}

// QueryOfferWindow reads trusted local policy for one declared method. It is
// never inferred from a response or from the peer's advertised timestamps.
func (r *ContractRoutes) QueryOfferWindow(digest [32]byte) (uint64, error) {
	if r == nil {
		return 0, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.offerEntryLocked(digest)
	if err != nil {
		return 0, err
	}
	return entry.offerWindowMS, nil
}

// WithQuerySnapshot installs only an exact, already trusted local contract.
// A response cannot add a method, replace an implementation or register an
// unknown variant. The caller holds its current endpoint/lease and binding
// gates through action. The Offer and binding are committed together, and an
// unsuccessful action restores all original windows and registration facts.
func (r *ContractRoutes) WithQuerySnapshot(info protocolv4.ContractSnapshotInfo, canonical []byte, now timev4.Sample, action func() error) error {
	if r == nil || action == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, err := r.offerEntryLocked(info.Policy.Digest)
	if err != nil {
		return err
	}
	if (info.Status != "available_full" && info.Status != "available_unchanged") || !entry.registered || entry.policy != info.Policy {
		return ErrMethod
	}
	size, err := entry.contract.CanonicalSize()
	if err != nil {
		return err
	}
	if size != len(canonical) {
		return ErrAssociation
	}
	var chunk [256]byte
	for offset := 0; offset < size; {
		n, err := entry.contract.CopyCanonicalRange(chunk[:min(len(chunk), size-offset)], offset)
		if err != nil {
			return err
		}
		if n == 0 || !bytes.Equal(chunk[:n], canonical[offset:offset+n]) {
			return ErrAssociation
		}
		offset += n
	}
	if entry.policy.Semantics != 1 {
		if info.HasOffer {
			return ErrAssociation
		}
		return action()
	}
	if !now.BelongsTo(r.clock) {
		return timev4.ErrOwner
	}
	if !info.HasOffer || info.Offer.Digest != entry.policy.Digest || info.Offer.NotBeforeMS >= info.Offer.NotAfterMS ||
		entry.offerWindowMS == 0 || info.Offer.NotAfterMS-info.Offer.NotBeforeMS > entry.offerWindowMS || now.UpperMS >= info.Offer.NotAfterMS {
		return ErrAdmissionOfferUnavailable
	}
	for _, offer := range entry.offers[:entry.offerCount] {
		if offer == info.Offer {
			return action()
		}
	}
	if r.generation == math.MaxUint64 {
		return ErrCapacity
	}
	previous, previousCount := entry.offers, entry.offerCount
	next := uint8(0)
	for _, offer := range previous[:previousCount] {
		if now.LowerMS < offer.NotAfterMS {
			entry.offers[next] = offer
			next++
		}
	}
	if next == uint8(len(entry.offers)) {
		return ErrCapacity
	}
	entry.offers[next] = info.Offer
	entry.offerCount = next + 1
	clear(entry.offers[entry.offerCount:])
	if err := action(); err != nil {
		entry.offers, entry.offerCount = previous, previousCount
		return err
	}
	r.generation++
	return nil
}

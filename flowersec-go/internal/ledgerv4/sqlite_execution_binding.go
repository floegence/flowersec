package ledgerv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Bind pins the original shared store metadata for an SDK service adapter.
// It does not keep a closed connection available for new admission. Original
// committed work has its own independently retained physical connection pins.
func (e *SQLiteExecutions) Bind(service SQLiteExecutionService, clock *timev4.Clock, metadata resourcev4.Reference) (resourcev4.Reference, error) {
	if e == nil || clock != e.config.Clock {
		return resourcev4.Reference{}, ErrOwner
	}
	if err := e.CheckBinding(service, metadata); err != nil {
		return resourcev4.Reference{}, err
	}
	return e.store.reservation.Borrow()
}

func (e *SQLiteExecutions) WorkCharge() (resourcev4.Vector, error) {
	if e == nil || e.store == nil {
		return resourcev4.Vector{}, ErrOwner
	}
	return SQLiteExecutionWorkCharge(e.config.WorkRuntimeBytes)
}

// RegistrationRevision is a current local registry observation. Register
// repeats its exact revision check in the original atomic admission boundary;
// this read is neither a reservation nor a dispatch right.
func (e *SQLiteExecutions) RegistrationRevision(ctx context.Context, digest [32]byte, guard func() error) (uint64, error) {
	r, err := e.ReadRegistration(ctx, digest, nil, guard)
	if err != nil {
		return 0, err
	}
	if !r.Enabled {
		return 0, ErrExecutionContract
	}
	return r.Revision, nil
}

// SQLiteExecutionRegistration is detached persisted configuration, not a work
// or admission capability. OfferCount selects the original windows in Offers.
// Reading or reopening never replaces their bounds with the current time.
type SQLiteExecutionRegistration struct {
	Revision      uint64
	Enabled       bool
	ContractBytes int
	OfferCount    int
	Offers        [8]protocolv4.AdmissionOfferBounds
}

// ReadRegistration copies canonical terms into caller-owned bounded storage.
// A nil destination reads only metadata. No output is copied on failure; the
// existing store workspace and one provider call own the entire read.
func (e *SQLiteExecutions) ReadRegistration(ctx context.Context, digest [32]byte, dst []byte, guard func() error) (SQLiteExecutionRegistration, error) {
	var result SQLiteExecutionRegistration
	if e == nil || e.store == nil || guard == nil || digest == ([32]byte{}) {
		return result, ErrConfiguration
	}
	if err := e.store.begin(ctx); err != nil {
		return result, err
	}
	defer e.store.end()
	if err := e.check(guard); err != nil {
		return result, err
	}
	if err := e.store.checkFence(); err != nil {
		return result, err
	}
	r, err := e.readContract(digest)
	if err != nil {
		return result, err
	}
	if dst != nil && len(dst) < r.bytes {
		return result, ErrCapacity
	}
	contract, err := e.codec.Decode(e.contract[:r.bytes])
	if err != nil {
		return result, err
	}
	defer contract.Release()
	policy, err := e.checkContract(contract)
	if err != nil || policy.Digest != digest {
		return result, ErrExecutionContract
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = e.check(guard); err != nil {
		return result, err
	}
	result.Revision, result.Enabled, result.ContractBytes, result.OfferCount = r.revision, r.enabled, r.bytes, r.count
	for i, offer := range r.offers[:r.count] {
		result.Offers[i] = protocolv4.AdmissionOfferBounds{Digest: digest, NotBeforeMS: offer.LowerMS, NotAfterMS: offer.UpperMS}
	}
	if dst != nil {
		copy(dst, e.contract[:r.bytes])
	}
	return result, nil
}

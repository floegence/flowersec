package ledgerv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
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
	if e == nil || e.store == nil || guard == nil || digest == ([32]byte{}) {
		return 0, ErrConfiguration
	}
	if err := e.store.begin(ctx); err != nil {
		return 0, err
	}
	defer e.store.end()
	if err := e.check(guard); err != nil {
		return 0, err
	}
	if err := e.store.checkFence(); err != nil {
		return 0, err
	}
	r, err := e.readContract(digest)
	if err != nil {
		return 0, err
	}
	if !r.enabled {
		return 0, ErrExecutionContract
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = e.check(guard); err != nil {
		return 0, err
	}
	return r.revision, nil
}

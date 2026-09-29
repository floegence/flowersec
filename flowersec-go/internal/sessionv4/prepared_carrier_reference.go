package sessionv4

import (
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// preparedCarrierReference is embedded in one original candidate method slot.
// Its alias remains admitted between numeric attempts. Only actual provider
// retirement returns it; a canceled method still owns its existing reference.
type preparedCarrierReference struct {
	mu                   sync.Mutex
	origin, idle, active resourcev4.Reference
	closed               bool
}

func (r *preparedCarrierReference) snapshot() resourcev4.Reference {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.idle
}

func (r *preparedCarrierReference) take(origin, expected resourcev4.Reference) (resourcev4.Reference, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.origin != origin || r.idle != expected || expected == (resourcev4.Reference{}) || r.active != (resourcev4.Reference{}) {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := r.idle.CheckBorrowedFrom(origin); err != nil {
		return resourcev4.Reference{}, err
	}
	ref, err := r.idle.TakeBorrow()
	if err != nil {
		return resourcev4.Reference{}, err
	}
	r.idle, r.active = resourcev4.Reference{}, ref
	return ref, nil
}

func (r *preparedCarrierReference) giveBack(ref resourcev4.Reference) {
	if r == nil {
		ref.Release()
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != ref || ref == (resourcev4.Reference{}) {
		return
	}
	if !r.closed {
		if moved, err := ref.TakeBorrow(); err == nil {
			r.idle, r.active = moved, resourcev4.Reference{}
			return
		}
	}
	ref.Release()
	r.active = resourcev4.Reference{}
}

func (r *preparedCarrierReference) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.idle.Release()
	r.idle = resourcev4.Reference{}
}

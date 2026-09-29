package sessionv4

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ArtifactLeaseReferences belongs to one original source position. It admits
// the future lease's dependency and first-material aliases before acquisition;
// successful construction moves those actual positions without another Borrow.
type ArtifactLeaseReferences struct {
	mu                   sync.Mutex
	self                 *ArtifactLeaseReferences
	origin, dependencies resourcev4.Reference
	shared, material     resourcev4.Reference
	closed, claimed      bool
}

func ArtifactLeaseReferencesBytes() uint64 { return uint64(unsafe.Sizeof(ArtifactLeaseReferences{})) }

func NewArtifactLeaseReferences(reservation, dependencies resourcev4.Reference) (*ArtifactLeaseReferences, error) {
	if reservation == dependencies {
		return nil, resourcev4.ErrOwner
	}
	if err := reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		return nil, err
	}
	material, err := reservation.Borrow()
	if err != nil {
		shared.Release()
		return nil, err
	}
	r := &ArtifactLeaseReferences{origin: reservation, dependencies: dependencies, shared: shared, material: material}
	r.self = r
	return r, nil
}

func (r *ArtifactLeaseReferences) checkLocked(reservation, dependencies resourcev4.Reference) error {
	if r.self != r || r.closed || r.claimed || r.origin != reservation || r.dependencies != dependencies {
		return resourcev4.ErrOwner
	}
	if err := r.shared.CheckBorrowedFrom(dependencies); err != nil {
		return err
	}
	return r.material.CheckBorrowedFrom(reservation)
}

func (r *ArtifactLeaseReferences) Check(reservation, dependencies resourcev4.Reference) error {
	if r == nil {
		return resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked(reservation, dependencies)
}

func (r *ArtifactLeaseReferences) take(reservation, dependencies resourcev4.Reference) (resourcev4.Reference, resourcev4.Reference, error) {
	if r == nil {
		return resourcev4.Reference{}, resourcev4.Reference{}, resourcev4.ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkLocked(reservation, dependencies); err != nil {
		return resourcev4.Reference{}, resourcev4.Reference{}, err
	}
	shared, err := r.shared.TakeBorrow()
	if err != nil {
		return resourcev4.Reference{}, resourcev4.Reference{}, err
	}
	r.shared = shared
	material, err := r.material.TakeBorrow()
	if err != nil {
		return resourcev4.Reference{}, resourcev4.Reference{}, err
	}
	r.shared, r.material = resourcev4.Reference{}, resourcev4.Reference{}
	r.claimed = true
	return shared, material, nil
}

func (r *ArtifactLeaseReferences) Close() {
	if r == nil || r.self != r {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.shared.Release()
	r.material.Release()
	r.shared, r.material = resourcev4.Reference{}, resourcev4.Reference{}
	r.origin, r.dependencies = resourcev4.Reference{}, resourcev4.Reference{}
}

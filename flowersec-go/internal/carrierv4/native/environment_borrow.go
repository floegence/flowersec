package native

import (
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// EnvironmentBorrow is part of an original factory preparation position. Its
// one real alias is admitted before credentials, reused only after physical
// retirement, and never replaced with a new reference during a numeric retry.
type EnvironmentBorrow struct {
	mu                   sync.Mutex
	origin, idle, active resourcev4.Reference
	closed               bool
}

func EnvironmentBorrowBytes() uint64 { return uint64(unsafe.Sizeof(EnvironmentBorrow{})) }

func NewEnvironmentBorrow(environment resourcev4.Reference) (*EnvironmentBorrow, error) {
	ref, err := environment.Borrow()
	if err != nil {
		return nil, err
	}
	return &EnvironmentBorrow{origin: environment, idle: ref}, nil
}

func (b *EnvironmentBorrow) Check(environment resourcev4.Reference) error {
	if b == nil {
		return resourcev4.ErrOwner
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return resourcev4.ErrClosed
	}
	if b.origin != environment || b.active != (resourcev4.Reference{}) {
		return resourcev4.ErrOwner
	}
	return b.idle.CheckBorrowedFrom(environment)
}

func (b *EnvironmentBorrow) take(environment resourcev4.Reference) (resourcev4.Reference, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if b.origin != environment || b.active != (resourcev4.Reference{}) {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	if err := b.idle.CheckBorrowedFrom(environment); err != nil {
		return resourcev4.Reference{}, err
	}
	ref, err := b.idle.TakeBorrow()
	if err != nil {
		return resourcev4.Reference{}, err
	}
	b.idle, b.active = resourcev4.Reference{}, ref
	return ref, nil
}

func (b *EnvironmentBorrow) giveBack(ref resourcev4.Reference) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ref == (resourcev4.Reference{}) || b.active != ref {
		return
	}
	if !b.closed {
		if next, err := ref.TakeBorrow(); err == nil {
			b.idle, b.active = next, resourcev4.Reference{}
			return
		}
	}
	ref.Release()
	b.active = resourcev4.Reference{}
}

func (b *EnvironmentBorrow) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	b.idle.Release()
	b.idle, b.origin = resourcev4.Reference{}, resourcev4.Reference{}
}

func TakeEnvironmentBorrow(environment resourcev4.Reference, admitted ...*EnvironmentBorrow) (resourcev4.Reference, *EnvironmentBorrow, error) {
	if len(admitted) > 1 {
		return resourcev4.Reference{}, nil, resourcev4.ErrConfiguration
	}
	if len(admitted) == 1 && admitted[0] != nil {
		ref, err := admitted[0].take(environment)
		return ref, admitted[0], err
	}
	ref, err := environment.Borrow()
	return ref, nil, err
}

func ReleaseEnvironmentBorrow(ref resourcev4.Reference, admitted *EnvironmentBorrow) {
	if admitted != nil {
		admitted.giveBack(ref)
	} else {
		ref.Release()
	}
}

package sessionv4

import (
	"math"
	"sync/atomic"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// CompletionFloor holds one Session's future short-result opportunity in the
// original root executor. It is idle between actual results and occupies no
// ready/running worker. A submitted decoder returns it only on physical exit.
// This protects scheduling responsibility, not result payload or wire authority.
type CompletionFloor struct {
	executor        atomic.Pointer[ApplicationExecutor]
	index           int
	backing, anchor resourcev4.Reference
	closed          bool // guarded by the original executor
}

func (e *ApplicationExecutor) CompletionFloorCharge() resourcev4.Vector {
	v, _ := e.CompletionCharge().Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(CompletionFloor{})), resourcev4.Items: 1})
	return v
}

func (e *ApplicationExecutor) NewCompletionFloor(reservation, backing resourcev4.Reference) (*CompletionFloor, error) {
	anchor, err := reservation.Borrow()
	if err != nil {
		return nil, err
	}
	p, err := e.reserveCompletion(reservation, backing, true)
	if err != nil {
		anchor.Release()
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	f := &CompletionFloor{index: p.index}
	f.executor.Store(e)
	s := &e.completions[p.index]
	f.backing, f.anchor = s.backing, anchor
	s.floor, s.reservation, s.task = f, nil, nil
	p.executor.Store(nil)
	return f, nil
}

// Checkout consumes no new quota or reference. Its order is assigned at each
// actual future-result admission, so an old idle floor cannot jump newer work.
func (f *CompletionFloor) Checkout() (*CompletionReservation, error) {
	if f == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e := f.executor.Load()
	if e == nil {
		return nil, cryptov4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.executor.Load() != e || f.closed || e.closed {
		return nil, cryptov4.ErrClosed
	}
	s := &e.completions[f.index]
	if s.floor != f || s.reservation != nil || s.task != nil || e.completionOrder == math.MaxUint64 {
		return nil, cryptov4.ErrCapacity
	}
	if err := s.backing.Check(); err != nil {
		return nil, err
	}
	if err := s.charge.Check(); err != nil {
		return nil, err
	}
	p := &CompletionReservation{index: f.index}
	p.executor.Store(e)
	e.completionOrder++
	s.order, s.reservation, s.task = e.completionOrder, p, &CompletionTask{done: make(chan struct{})}
	return p, nil
}

func (f *CompletionFloor) Close() {
	if f == nil {
		return
	}
	e := f.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.executor.Load() != e {
		return
	}
	f.closed = true
	s := &e.completions[f.index]
	if s.resultDetached {
		e.detachCompletionFloorLocked(s)
		e.cleanupLocked()
		return
	}
	// Already accepted future results keep their original completion promise,
	// including submission after Session Close. Only their owner may cancel it.
	if s.reservation == nil && !s.submitted {
		e.releaseCompletionLocked(f.index)
	}
	e.cleanupLocked()
}

func (f *CompletionFloor) CleanupComplete() bool { return f == nil || f.executor.Load() == nil }

// An independently attached result no longer belongs to Session cleanup.
// Its exact future descriptor/charge remains in the root executor, while only
// the original floor's Session anchor and Session metadata alias are retired.
func (e *ApplicationExecutor) detachCompletionFloorLocked(s *completionSlot) {
	f := s.floor
	if f == nil || !f.closed || !s.resultDetached {
		return
	}
	f.backing.Release()
	f.anchor.Release()
	f.backing, f.anchor = resourcev4.Reference{}, resourcev4.Reference{}
	f.executor.Store(nil)
	s.floor = nil
}

// DetachSessionScope is a mechanical move after the stream's physical I/O has
// retired. The same future position and any running callback keep their full
// root/Environment responsibility; neither a callback nor a quota is created.
func (f *CompletionFloor) DetachSessionScope() error {
	if f == nil {
		return cryptov4.ErrConfiguration
	}
	e := f.executor.Load()
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.executor.Load() != e || e.completions[f.index].floor != f {
		return cryptov4.ErrClosed
	}
	s := &e.completions[f.index]
	for _, ref := range [...]resourcev4.Reference{s.charge, s.backing, f.anchor, f.backing} {
		if ref != (resourcev4.Reference{}) {
			if err := ref.DetachSessionScope(); err != nil {
				return err
			}
		}
	}
	return nil
}

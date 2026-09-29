package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// A stream owns one original future descriptor for its entire accepted use,
// including the gaps between items. Each item assigns its own scheduling order
// only when checked out. No dormant stream claims a running decoder worker.
type completionFloorUse struct {
	floor  *CompletionFloor
	closed bool // guarded by the original executor
}

func (f *CompletionFloor) borrowStream(backing resourcev4.Reference) (*completionFloorUse, error) {
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
	if s.floor != f || f.use != nil || s.reservation != nil || s.task != nil {
		return nil, cryptov4.ErrCapacity
	}
	if err := s.backing.CheckSameEnvironment(backing); err != nil {
		return nil, err
	}
	if err := s.charge.Check(); err != nil {
		return nil, err
	}
	borrow, err := backing.Borrow()
	if err != nil {
		return nil, err
	}
	u := &completionFloorUse{floor: f}
	f.use, s.backing, s.resultBound = u, borrow, true
	return u, nil
}

func (u *completionFloorUse) checkout() (*CompletionReservation, error) {
	if u == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return u.floor.checkout(u)
}

// Physical transport retirement removes only this result's Session scopes.
// An open workload's original anchor still protects its next promised use.
func (u *completionFloorUse) detachSession() error {
	if u == nil {
		return cryptov4.ErrConfiguration
	}
	f := u.floor
	e := f.executor.Load()
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.executor.Load() != e || f.use != u || u.closed {
		return cryptov4.ErrClosed
	}
	s := &e.completions[f.index]
	if err := s.charge.DetachSessionScope(); err != nil {
		return err
	}
	if err := s.backing.DetachSessionScope(); err != nil {
		return err
	}
	s.resultDetached = true
	e.detachCompletionFloorLocked(s)
	return nil
}

func (u *completionFloorUse) close() {
	if u == nil {
		return
	}
	f := u.floor
	e := f.executor.Load()
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f.executor.Load() != e || f.use != u || u.closed {
		return
	}
	u.closed, f.use = true, nil
	s := &e.completions[f.index]
	// A caller can abandon while the actual decoder is still running. That
	// invocation continues to own the slot and result alias through its exit.
	if s.reservation == nil && s.task == nil {
		e.releaseCompletionLocked(f.index)
	}
	e.cleanupLocked()
}

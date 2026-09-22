package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// rebindResultBacking runs before request publication. The original future
// descriptor then pins its independent result owner, never a retired Session
// invocation. Failure leaves the old complete reservation unchanged.
func (p *CompletionReservation) rebindResultBacking(backing resourcev4.Reference) error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return cryptov4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) {
		return cryptov4.ErrClosed
	}
	s := &e.completions[p.index]
	if s.reservation != p || s.submitted || s.resultBound {
		return cryptov4.ErrTransition
	}
	if err := s.backing.CheckSameEnvironment(backing); err != nil {
		return err
	}
	borrow, err := backing.Borrow()
	if err != nil {
		return err
	}
	if s.floor == nil {
		s.backing.Release()
	}
	s.backing = borrow
	s.resultBound = true
	return nil
}

func (p *CompletionReservation) detachResultSession() error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	e := p.executor.Load()
	if e == nil {
		return cryptov4.ErrClosed
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if p.executor.Load() != e || p.index >= len(e.completions) {
		return cryptov4.ErrClosed
	}
	s := &e.completions[p.index]
	if s.reservation != p || s.submitted || !s.resultBound {
		return cryptov4.ErrTransition
	}
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

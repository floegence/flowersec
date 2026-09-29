package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// CheckOriginalAdmission validates a future Session's actual unused history
// position and all four original owners, without checking out or replacing any
// of them. The immutable service binding is checked by the enclosing batch.
func (a *ExecutionAdmission) CheckOriginalAdmission(history *VolatileExecutions, maxResponse uint32, requests [4]resourcev4.Request) error {
	if a == nil || a.self != a {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.history != history || a.maxResponse != maxResponse {
		return ErrOwner
	}
	if err := a.checkOriginalLocked(); err != nil {
		return err
	}
	if err := a.metadata.CheckRequest(requests[0]); err != nil {
		return err
	}
	for i, floor := range a.floors {
		if err := floor.CheckAdmissionRequest(requests[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func (a *ExecutionAdmission) checkOriginalLocked() error {
	if a.closed || a.cleaned || !a.reusable || a.started || a.authorityAdopted || a.using.Load() || a.tails.Load() != 0 || !a.claimed.Load() {
		return ErrOwner
	}
	s := a.history
	s.mu.Lock()
	valid := !s.closed && a.floorIndex >= 0 && a.floorIndex < len(s.floors) && s.floors[a.floorIndex] == a
	s.mu.Unlock()
	if !valid {
		return ErrClosed
	}
	for _, ref := range [...]resourcev4.Reference{a.metadata, a.historyPin, a.workAuthority, a.joinAuthority} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	for _, floor := range a.floors {
		if err := floor.CheckAvailable(); err != nil {
			return err
		}
	}
	return nil
}

// AdoptOriginalAuthority fixes the final primary handle after the same
// dispatch allocation has passed through Take. Both original aliases must
// still name that exact backing and scope; a different owner is never adopted.
func (a *ExecutionAdmission) AdoptOriginalAuthority(authority resourcev4.Reference) error {
	if a == nil || a.self != a {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkOriginalLocked(); err != nil {
		return err
	}
	if err := a.workAuthority.CheckBorrowedFrom(authority); err != nil {
		return err
	}
	if err := a.joinAuthority.CheckBorrowedFrom(authority); err != nil {
		return err
	}
	a.authority, a.authorityAdopted = authority, true
	return nil
}

func (a *DurableExecutionAdmission) CheckOriginalAdmission(history *DurableExecutions, maxResponse uint32, requests [4]resourcev4.Request) error {
	if a == nil || a.durableExecutionAdmission == nil {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.history != history || a.maxResponse != maxResponse {
		return ErrOwner
	}
	if err := a.checkOriginalLocked(); err != nil {
		return err
	}
	if err := a.capacity.CheckOriginalAdmission(requests[0]); err != nil {
		return err
	}
	for i, floor := range a.floors {
		if err := floor.CheckAdmissionRequest(requests[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func (a *DurableExecutionAdmission) checkOriginalLocked() error {
	if a.closed.Load() || a.cleaned || a.started || a.authorityAdopted || a.using.Load() || a.tails.Load() != 0 || !a.claimed.Load() {
		return ErrOwner
	}
	s := a.history
	s.mu.Lock()
	valid := !s.closed && a.index >= 0 && a.index < len(s.floors) && s.floors[a.index] == a
	s.mu.Unlock()
	if !valid {
		return ErrClosed
	}
	// No work has started, so the original SQLite promise is still claimed.
	// Check its independent store lifetime as well as the history owner.
	if err := a.capacity.CheckReady(); err != nil {
		return err
	}
	for _, ref := range [...]resourcev4.Reference{a.historyPin, a.workAuthority, a.joinAuthority} {
		if err := ref.Check(); err != nil {
			return err
		}
	}
	for _, floor := range a.floors {
		if err := floor.CheckAvailable(); err != nil {
			return err
		}
	}
	return nil
}

func (a *DurableExecutionAdmission) AdoptOriginalAuthority(authority resourcev4.Reference) error {
	if a == nil || a.durableExecutionAdmission == nil {
		return ErrOwner
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkOriginalLocked(); err != nil {
		return err
	}
	if err := a.workAuthority.CheckBorrowedFrom(authority); err != nil {
		return err
	}
	if err := a.joinAuthority.CheckBorrowedFrom(authority); err != nil {
		return err
	}
	a.authority, a.authorityAdopted = authority, true
	return nil
}

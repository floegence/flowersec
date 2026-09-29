package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"

// ExecutorOperationsSnapshot describes the existing root service. A read does
// not reserve another lane, enqueue work, or expose callbacks and owner IDs.
type ExecutorOperationsSnapshot struct {
	Counts ApplicationExecutorSnapshot `json:"counts"`
	Limits ApplicationExecutorSnapshot `json:"limits"`
}

func (e *ApplicationExecutor) BorrowOperations(ref resourcev4.Reference) (resourcev4.Reference, error) {
	if e == nil {
		return resourcev4.Reference{}, resourcev4.ErrOwner
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	if err := e.reservation.CheckSameRoot(ref); err != nil {
		return resourcev4.Reference{}, err
	}
	return e.reservation.Borrow()
}

func (e *ApplicationExecutor) OperationsSnapshot() ExecutorOperationsSnapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.config
	limits := ApplicationExecutorSnapshot{Running: c.Running, ResidentRunning: c.ResidentRunning,
		Ready: c.Ready, ResidentReady: c.ResidentReady, CompletionReserved: c.CompletionReserved,
		CompletionRunning: c.CompletionRunning, CompletionClaims: c.CompletionRunning, QueryOwners: c.QueryOwners}
	if c.Diagnostics {
		limits.DiagnosticReady, limits.DiagnosticRunning = diagnosticReady, diagnosticRunning
	}
	if c.QueryOwners != 0 {
		limits.QueryReady, limits.QueryRunning = 4, 1
	}
	return ExecutorOperationsSnapshot{Counts: e.snapshotLocked(), Limits: limits}
}

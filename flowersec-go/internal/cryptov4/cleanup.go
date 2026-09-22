package cryptov4

import "context"

// finishCleanupLocked observes the actual owners of record/key backing. A
// workspace remains borrowed through KDF, authentication and Packet ownership,
// including both datagram directions. Staging and rekey have separate bounded
// work positions. None of these owners can be replaced by a logical Done fact.
func (e *Engine) finishCleanupLocked() {
	if !e.closed || e.cleanupComplete || e.borrowedWork != 0 || e.flight != 0 || e.staging || e.rekey != nil {
		return
	}
	for i := range e.used {
		clear(e.used[i])
		e.used[i] = nil
	}
	e.staged = nil
	e.stageJobs = nil
	e.pause = nil
	e.cleanupComplete = true
	close(e.cleanup)
}

// WaitCleanup waits for Engine-owned record, scope KDF, staging and rekey
// backing to reach its real release boundary after Close. It does not wait for
// the separate handshake signer/root owner or retire Session/provider budgets.
// Cancellation detaches only this waiter and never releases a live borrow.
func (e *Engine) WaitCleanup(ctx context.Context) error {
	if e == nil || ctx == nil {
		return ErrConfiguration
	}
	select {
	case <-e.cleanup:
		return nil
	default:
	}
	select {
	case <-e.cleanup:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

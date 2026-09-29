package sessionv4

import (
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Each original method position keeps its first cancellation window. Completion
// is the worker's physical exit signal, including provider retirement. A later
// winner or another address cannot restart an unfinished loser's allowance.
func (r *candidateRace) loserCleanupRemaining() (bool, uint64, error) {
	var windows [2]*timev4.Window
	r.mu.Lock()
	for i := range r.slots {
		slot := &r.slots[i]
		if slot.cleanupWindow == nil || slot.done == nil || slot == r.winnerSlot {
			continue
		}
		select {
		case <-slot.done:
			if slot.cleanupError != nil {
				err := slot.cleanupError
				r.mu.Unlock()
				return false, 0, err
			}
		default:
			windows[i] = slot.cleanupWindow
		}
	}
	r.mu.Unlock()
	pending, remaining := false, uint64(candidateCleanupMS)
	for _, window := range windows {
		if window == nil {
			continue
		}
		pending = true
		left, err := window.RemainingMS()
		if err == timev4.ErrExpired {
			return true, 0, ErrSessionCleanupIncomplete
		}
		if err != nil {
			return true, 0, err
		}
		remaining = min(remaining, left)
	}
	return pending, remaining, nil
}

// The source's original worker joins canceled candidates before spending the
// selected lease. The race may choose a winner immediately, but no irreversible
// work depends on an unbounded loser cleanup. Timeout ends this Connect while
// its existing worker and position still retain every unfinished physical tail.
func (r *candidateRace) waitLosers() error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if err := r.source.check(r.session); err != nil {
			return err
		}
		pending, remaining, err := r.loserCleanupRemaining()
		if err != nil {
			return err
		}
		preparation, err := r.preparationWindow.RemainingMS()
		if err != nil {
			return err
		}
		if !pending {
			return nil
		}
		timer.Reset(time.Duration(min(remaining, preparation, 100)) * time.Millisecond)
		select {
		case <-r.session.context.Done():
			return r.session.context.Err()
		case <-r.wake:
		case <-timer.C:
		}
	}
}

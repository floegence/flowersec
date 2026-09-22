package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"

// ordinaryMaintenanceReady admits one ordinary publication quantum only when
// no original critical/normal owner is ready. The original admission gate is
// held through the shared writer claim; a later critical arrival can therefore be delayed by at most
// that single already-admitted ordinary record, never by a queued PONG batch.
// No application callback, waiter allocation or I/O occurs in this gate.
func (a *OpenAdmission) ordinaryMaintenanceReadyLocked() (bool, error) {
	if a.closed {
		return false, cryptov4.ErrClosed
	}
	if l := a.lifecycle; l != nil && l.boundary.set && (!l.goAwaySent || !l.closeSent && a.communicationDrainedLocked()) {
		return false, nil
	}
	if p := a.termination; p != nil {
		if s, _, _ := p.nextLocked(); s != nil {
			return false, nil
		}
	}
	if r := a.retirement; r != nil && r.ackReadyLocked() {
		return false, nil
	}
	x := a.exchange
	if x == nil {
		return true, nil
	}
	x.mu.Lock()
	// State changes are owned by busy; it is cleared only after the complete
	// transition. Do not inspect fields concurrently with crypto/publication.
	if x.busy {
		x.mu.Unlock()
		return false, nil
	}
	state, closed := x.state, x.closed
	x.mu.Unlock()
	if closed || state == 4 {
		return true, nil
	}
	if a.direction == 0 && state == 0 {
		return false, nil // Prepared client INIT has priority over probes/replies.
	}
	if a.direction == 1 && state == 0 && a.rekeyCauses != nil {
		c := a.rekeyCauses
		c.mu.Lock()
		i := c.current
		requestReady := i != nil && i.exchange == x && !i.submitted && !i.peer && !i.cancelled && !i.completed
		c.mu.Unlock()
		if requestReady {
			return false, nil
		}
	}
	ready := a.direction == 0 && state == 2 || a.direction == 1 && (state == 1 || state == 3)
	if !ready {
		return true, nil
	}
	satisfied, err := x.barriers.satisfiedLocked()
	return !satisfied, err
}

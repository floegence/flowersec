package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// PeerControlError carries only the authenticated registered transport code.
// It is not evidence about application execution or permission to retry.
type PeerControlError struct{ Code uint64 }

func (e PeerControlError) Error() string { return "sessionv4: authenticated peer transport error" }

func (a *OpenAdmission) applyLifecycleControl(record *ReceivedRecord) (err error) {
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	f, err := record.Body()
	if err != nil {
		return err
	}
	if f.Header.Scope != 0 {
		return ErrOpenAssociation
	}
	if err := record.claimMaintenance(); err != nil {
		return err
	}
	if f.Schema == "GOAWAY" {
		ceiling, _ := f.Field("accept_ceiling").Uint()
		reason, _ := f.Field("reason").Uint()
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.closed {
			return cryptov4.ErrClosed
		}
		boundary := goAwayBoundary{true, ceiling, reason}
		if a.peerGoAway.set {
			if a.peerGoAway != boundary {
				return ErrGoAwayConflict
			}
		} else {
			if ceiling < a.highestAccepted[a.direction] {
				return ErrGoAwayConflict
			}
			a.peerGoAway = boundary
			a.openGate.close()
			a.notifyDecisionOpportunityLocked()
		}
		return record.accepted()
	}
	if f.Schema != "CLOSE" && f.Schema != "ERROR" {
		return ErrOpenAssociation
	}
	scope, _ := f.Field("target_scope").Uint()
	field := "reason"
	if f.Schema == "ERROR" {
		field = "code"
	}
	code, _ := f.Field(field).Uint()
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	if scope != 0 {
		// Even a stable bit is insufficient: CLOSE requires the same live
		// trusted association. It cannot allocate or reconstruct a Stream.
		s, lookupErr := a.slot(OpenHandle{a, scope})
		if lookupErr != nil || s.carrier == nil && !(s.bootstrap && a.bootstrap.complete) || s.phase == openFree {
			a.mu.Unlock()
			return ErrOpenAssociation
		}
		if err = record.accepted(); err == nil {
			a.cancelStreamLocked(s)
		}
		a.mu.Unlock()
		return err
	}
	if err = record.accepted(); err != nil {
		a.mu.Unlock()
		return err
	}
	var cause error = ErrPeerClosed
	if f.Schema == "ERROR" {
		cause = PeerControlError{code}
	}
	if l := a.lifecycle; l != nil && l.boundary.set && f.Schema == "CLOSE" && code == 0 && a.communicationDrainedLocked() {
		if deadlineErr := l.deadline.Check(); deadlineErr == nil {
			l.operation.finish(Drained, nil)
			cause = nil
		}
	}
	a.mu.Unlock()
	a.closeWithCause(cause)
	return nil
}

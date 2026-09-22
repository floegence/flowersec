package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// NextPending returns each authenticated application OPEN to the original
// dispatcher at most once. A dispatcher keeps the returned handle while its
// authorization or Decide call runs; ErrOpenPending does not enqueue it again.
// The fixed dispatcher position rejects concurrent observers instead of
// allocating a waiter queue. Cancellation before delivery preserves the OPEN.
func (a *OpenAdmission) NextPending(ctx context.Context) (OpenHandle, error) {
	if a == nil || ctx == nil {
		return OpenHandle{}, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return OpenHandle{}, err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return OpenHandle{}, cryptov4.ErrClosed
	}
	if a.pendingWaiting {
		a.mu.Unlock()
		return OpenHandle{}, ErrOpenWaitBusy
	}
	if !a.beginTailLocked() {
		a.mu.Unlock()
		return OpenHandle{}, cryptov4.ErrCapacity
	}
	a.pendingWaiting = true
	a.mu.Unlock()
	var selected OpenHandle
	defer func() {
		a.mu.Lock()
		a.pendingWaiting = false
		if selected.owner != nil {
			if s, err := a.slot(selected); err == nil {
				s.retirementReferences--
				a.collect(s)
			}
		}
		a.methodTails--
		a.notifyCleanup()
		a.mu.Unlock()
	}()
	for {
		if err := ctx.Err(); err != nil {
			return OpenHandle{}, err
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			return OpenHandle{}, cryptov4.ErrClosed
		}
		for i := int(a.limits.Terminal); i < len(a.slots); i++ {
			s := &a.slots[i]
			if s.phase == openPending && !s.dispatched && !s.deciding {
				if s.retirementReferences == math.MaxUint32 {
					a.mu.Unlock()
					return OpenHandle{}, cryptov4.ErrCapacity
				}
				s.dispatched = true
				s.retirementReferences++
				selected = OpenHandle{a, s.scope}
				a.mu.Unlock()
				return selected, nil
			}
		}
		a.mu.Unlock()
		select {
		case <-a.pendingWake:
		case <-ctx.Done():
			return OpenHandle{}, ctx.Err()
		}
	}
}

// WaitOutcome observes the original OPEN's accepted/rejected phase. It returns
// nil for acceptance, ErrOpenRejected for rejection, and ErrAbandoned if the
// original OPEN was cancelled. A cancelled context only ends observation: it
// cannot cancel the OPEN, invent a peer outcome, or refund submitted work.
// One observer per OPEN pins both the admission and the original slot until
// its actual return, including movement from ingress to a terminal proof slot.
func (a *OpenAdmission) WaitOutcome(ctx context.Context, h OpenHandle) error {
	if a == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return cryptov4.ErrClosed
	}
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	// Bootstrap activation has its own original READY coordinator.
	if s.bootstrap || s.phase == openReserved || s.pendingRejection() || s.local && !s.submitted {
		a.mu.Unlock()
		return ErrOpenAssociation
	}
	if s.outcomeWaiting {
		a.mu.Unlock()
		return ErrOpenWaitBusy
	}
	if s.retirementReferences == math.MaxUint32 || !a.beginTailLocked() {
		a.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	s.outcomeWaiting = true
	s.retirementReferences++
	wake := a.outcomeWake[a.find(h.scope)]
	a.mu.Unlock()
	defer a.finishOutcomeWait(h)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		err := a.openOutcomeLocked(h)
		a.mu.Unlock()
		if err != ErrOpenPending {
			return err
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// WaitDecisionOpportunity observes a capacity change for this original pending
// OPEN. It neither reserves replacement work nor selects an outcome. The
// original dispatcher retries PreparePeerOpen or Decide after a notification;
// buffered hints may be stale, so their usual admission checks remain canonical.
// It shares this OPEN's single outcome observer position with WaitOutcome.
func (a *OpenAdmission) WaitDecisionOpportunity(ctx context.Context, h OpenHandle) error {
	if a == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	s, err := a.slot(h)
	if err == nil {
		err = a.peerPreparationReadyLocked(s)
	}
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if s.outcomeWaiting {
		a.mu.Unlock()
		return ErrOpenWaitBusy
	}
	if s.retirementReferences == math.MaxUint32 || !a.beginTailLocked() {
		a.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	s.outcomeWaiting = true
	s.retirementReferences++
	wake := a.outcomeWake[a.find(h.scope)]
	a.mu.Unlock()
	defer a.finishOutcomeWait(h)
	select {
	case <-wake:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err = a.slot(h)
	if err != nil {
		return err
	}
	return a.peerPreparationReadyLocked(s)
}

func (a *OpenAdmission) finishOutcomeWait(h OpenHandle) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, err := a.slot(h); err == nil {
		s.outcomeWaiting = false
		s.retirementReferences--
		a.collect(s)
	}
	a.methodTails--
	a.notifyCleanup()
}

func (a *OpenAdmission) openOutcomeLocked(h OpenHandle) error {
	if a.closed {
		return cryptov4.ErrClosed
	}
	s, err := a.slot(h)
	if err != nil {
		return err
	}
	if s.cancelled {
		return ErrAbandoned
	}
	if s.phase == openOpening || s.phase == openPending {
		return ErrOpenPending
	}
	if !s.accepted {
		return ErrOpenRejected
	}
	return nil
}

func (a *OpenAdmission) notifyPendingLocked() { notifyOpenWait(a.pendingWake) }

// One fixed notification per original pending slot prevents separate jobs
// from consuming each other's capacity-change hint. No waiter queue is built.
func (a *OpenAdmission) notifyDecisionOpportunityLocked() {
	a.notifyPendingLocked()
	for i := int(a.limits.Terminal); i < len(a.slots); i++ {
		if a.slots[i].phase == openPending {
			notifyOpenWait(a.outcomeWake[i])
		}
	}
}

func (a *OpenAdmission) notifyOutcomeLocked(s *openSlot) {
	if i := a.find(s.scope); i >= 0 {
		notifyOpenWait(a.outcomeWake[i])
	}
}

// waitStreamCleanupReady reuses the original scope's bounded observation slot.
// It joins authenticated terminal publication before physical flow cleanup;
// neither cancellation nor a local Close manufactures a peer drain proof.
func (a *OpenAdmission) waitStreamCleanupReady(ctx context.Context, h OpenHandle) error {
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if s.outcomeWaiting || s.retirementReferences == math.MaxUint32 || !a.beginTailLocked() {
		a.mu.Unlock()
		return ErrOpenWaitBusy
	}
	s.outcomeWaiting = true
	s.retirementReferences++
	wake := a.outcomeWake[a.find(h.scope)]
	a.mu.Unlock()
	defer a.finishOutcomeWait(h)
	for {
		a.mu.Lock()
		s, err := a.slot(h)
		ready := false
		if err == nil {
			ready = !s.terminalPublishing && !s.cleanupBusy && (a.closed || s.coreCleaned || s.flow == nil)
			if !ready && !s.terminalPublishing && !s.cleanupBusy {
				s.flow.send.mu.Lock()
				ready = !s.accepted && s.phase != openOpening && s.phase != openPending && s.phase != openReserved || s.drainComplete && s.flow.send.wireDone
				s.flow.send.mu.Unlock()
			}
		}
		a.mu.Unlock()
		if err != nil || ready {
			return err
		}
		select {
		case <-wake:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func notifyOpenWait(wake chan struct{}) {
	select {
	case wake <- struct{}{}:
	default:
	}
}

package sessionv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// Method tails protect the whole admission graph. Slot references separately
// protect normal authenticated retirement. All pins leave after the original
// method's failure, provider and cleanup defers have returned.
func (a *OpenAdmission) beginTailLocked() bool {
	if a.cleaned || a.methodTails == math.MaxUint64 {
		return false
	}
	a.methodTails++
	return true
}

func (a *OpenAdmission) beginTail() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.beginTailLocked()
}

func (a *OpenAdmission) endTail() {
	a.mu.Lock()
	a.methodTails--
	a.notifyCleanup()
	a.mu.Unlock()
}

func (a *OpenAdmission) notifyCleanup() {
	select {
	case a.cleanupWake <- struct{}{}:
	default:
	}
}

// cleanupClosed runs on the original reserved Session coordinator, after its
// services and ingress have exited. It has no worker or timer of its own. A
// caller cancelling observation leaves every original ownership charge intact.
func (a *OpenAdmission) cleanupClosed(ctx context.Context) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if a.cleaned {
		a.mu.Unlock()
		return a.WaitCleanup(ctx)
	}
	if !a.closed || a.cleaning {
		a.mu.Unlock()
		return cryptov4.ErrTransition
	}
	a.cleaning = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.cleaning = false
		if a.cleaned {
			close(a.cleanupDone)
		}
		a.notifyCleanup()
		a.mu.Unlock()
	}()
	if a.sharedIngress != nil {
		if err := a.sharedIngress.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.mu.Lock()
		if a.methodTails != 0 {
			a.mu.Unlock()
			if err := a.waitCleanupChange(ctx); err != nil {
				return err
			}
			continue
		}
		if x := a.exchange; x != nil {
			a.mu.Unlock()
			x.Close()
			x.releaseOwner()
			continue
		}
		if a.barriers != nil {
			a.barriers.disposeClosedLocked()
		}
		if a.retirement != nil {
			a.retirement.disposeClosedLocked()
		}
		pending := false
		selected := -1
		for i := range a.slots {
			s := &a.slots[i]
			if s.phase == openFree {
				continue
			}
			// A callback can still own the Stream while no I/O method is
			// running. Only its original Release relinquishes that owner.
			if s.owner != nil || s.cleanupBusy || s.terminalPublishing || s.retirementReferences != 0 || s.barrierReferences != 0 {
				pending = true
				continue
			}
			if s.flow != nil && !s.coreCleaned {
				selected = i
				break
			}
			if s.carrier != nil && s.carrier.shared != nil && s.carrier.shared == a.sharedIngress {
				// The original shared reader and this flow have actually
				// exited. A logical association has no extra native handle.
				s.carrierDone = true
			}
			if s.carrier != nil && !s.carrierDone {
				pending = true
			}
		}
		if selected >= 0 {
			s := &a.slots[selected]
			flow := s.flow
			flow.send.mu.Lock()
			queue := flow.send.queueOwner
			flow.send.mu.Unlock()
			var bootstrapReader *RecordReceiver
			if s.bootstrap {
				bootstrapReader = a.bootstrap.reader
			}
			s.cleanupBusy = true
			s.retirementReferences++
			a.beginTailLocked()
			a.mu.Unlock()
			err := cleanupFlow(ctx, flow, queue, bootstrapReader, true)
			a.mu.Lock()
			s.cleanupBusy = false
			s.retirementReferences--
			s.coreCleaned = err == nil
			a.mu.Unlock()
			a.endTail()
			if err != nil {
				return err
			}
			continue
		}
		if pending {
			a.mu.Unlock()
			if err := a.waitCleanupChange(ctx); err != nil {
				return err
			}
			continue
		}
		// No protocol fact changes here: stable bits, terminal tuples and
		// retirement ACKs are never fabricated to discard a closed Session.
		for i := range a.slots {
			s := &a.slots[i]
			if s.flow != nil {
				if s.flow.nativeReceive != nil {
					if err := s.flow.nativeReceive.retire(); err != nil {
						a.mu.Unlock()
						return err
					}
				}
				if err := s.flow.send.retire(); err != nil {
					a.mu.Unlock()
					return err
				}
			}

			*s = openSlot{}
		}
		clear(a.index)
		clear(a.metadata)
		clear(a.metadataUsed)
		clear(a.encode)
		a.active, a.opening, a.pending, a.positiveProofs, a.rejectionProofs = 0, 0, 0, 0, 0
		a.byOpener = [2][3]uint32{}
		a.cleaned = true
		a.mu.Unlock()
		return nil
	}
}

func (a *OpenAdmission) waitCleanupChange(ctx context.Context) error {
	select {
	case <-a.cleanupWake:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WaitCleanup observes the original coordinator; it cannot grant new capacity
// or launch replacement cleanup on timeout.
func (a *OpenAdmission) WaitCleanup(ctx context.Context) error {
	if a == nil || ctx == nil {
		return cryptov4.ErrConfiguration
	}
	select {
	case <-a.cleanupDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Retire releases the original fixed admission charge only after physical
// cleanup. Service reservations are retired here in dependency order; a
// refusal retains this owner so the original coordinator can finish it.
func (a *OpenAdmission) Retire() error {
	if a == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	if a.retired {
		a.mu.Unlock()
		return nil
	}
	if !a.cleaned || a.cleaning {
		a.mu.Unlock()
		return cryptov4.ErrCapacity
	}
	a.cleaning = true
	a.mu.Unlock()
	retired := false
	defer func() {
		if !retired {
			a.mu.Lock()
			a.cleaning = false
			a.mu.Unlock()
		}
	}()
	if a.bootstrap != nil && a.bootstrap.reader != nil {
		if err := a.bootstrap.reader.retire(); err != nil {
			return err
		}
	}
	if a.nativeAuth != nil {
		if err := a.nativeAuth.retire(); err != nil {
			return err
		}
	}
	if a.sendService != nil {
		if err := a.sendService.retire(); err != nil {
			return err
		}
	}
	if a.termination != nil {
		if err := a.termination.retire(); err != nil {
			return err
		}
	}
	if a.liveness != nil {
		if err := a.liveness.retire(); err != nil {
			return err
		}
	}
	if a.maintenanceMessages != nil {
		if err := a.maintenanceMessages.retire(); err != nil {
			return err
		}
	}
	if a.lifecycle != nil {
		if err := a.lifecycle.retire(); err != nil {
			return err
		}
	}
	if a.rekeyService != nil {
		if err := a.rekeyService.retire(); err != nil {
			return err
		}
	}
	if a.retirementService != nil {
		if err := a.retirementService.retire(); err != nil {
			return err
		}
	}
	if a.sharedIngress != nil {
		if err := a.sharedIngress.Retire(); err != nil {
			return err
		}
	}
	if a.maintenanceIngress != nil {
		if err := a.maintenanceIngress.retire(); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.slots, a.index, a.metadata, a.metadataUsed, a.encode = nil, nil, nil, nil, nil
	a.stable = [2][]uint64{}
	a.decoder = nil
	a.outcomeWake = nil
	a.retired, a.cleaning = true, false
	retired = true
	a.reservation.Release()
	return nil
}

package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ApplyMaintenance consumes the original authenticated control record before
// its decoder is released. Stable IDs accept only the closed late-message
// whitelist; they never regain keys, credit or application ownership.
func (a *OpenAdmission) ApplyMaintenance(record *ReceivedRecord) (err error) {
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction {
		return ErrOpenAssociation
	}
	defer record.acceptOnSuccess(&err)
	f, err := record.Body()
	if err != nil {
		return err
	}
	if f.Schema == "OPEN_ACCEPT" {
		return a.ApplyOutcome(record)
	}
	switch f.Schema {
	case "STREAM_ACK_CREDIT", "STREAM_ACK_STOP", "STREAM_ACK_STOPPED", "STREAM_ACK_DRAINED":
	default:
		return ErrOpenAssociation
	}
	scope, ok := f.Field("stream_id").Uint()
	if !ok {
		return ErrOpenAssociation
	}
	a.mu.Lock()
	if a.termination != nil {
		if _, err := a.termination.checkLocked(); err != nil {
			a.mu.Unlock()
			a.closeWithCause(err)
			return err
		}
	}
	defer a.mu.Unlock()
	if a.closed {
		return cryptov4.ErrClosed
	}
	if a.isStable(scope) {
		return nil
	}
	s, err := a.slot(OpenHandle{a, scope})
	if err != nil {
		return err
	}
	if !s.accepted || s.flow == nil {
		return ErrOpenAssociation
	}
	if err := s.flow.Apply(record); err != nil {
		return err
	}
	s.owner.notify()
	if f.Schema == "STREAM_ACK_STOP" {
		s.stoppedDirty = true
	}
	if a.termination != nil {
		a.termination.notify()
	}
	a.maybeRecent(s)
	a.notifyOutcomeLocked(s)
	return nil
}

func (a *OpenAdmission) maybeRecent(s *openSlot) {
	if s.phase != openLive || !s.drainSubmitted {
		return
	}
	s.flow.send.mu.Lock()
	complete, sendProof := s.flow.send.wireDone, s.flow.send.proof
	s.flow.send.mu.Unlock()
	if !complete {
		return
	}
	receiveProof, ok := s.flow.receive.DrainProof()
	if !ok {
		return
	}
	s.terminal[a.direction], s.terminal[1-a.direction] = sendProof, receiveProof
	s.phase = openRecent
	if a.retirement != nil {
		a.retirement.notify()
	}
	a.engine.RetireScope(s.scope)
	if s.carrierDone && s.activeCharged {
		a.active--
		a.byOpener[(s.scope+1)%2][s.class]--
		s.activeCharged = false
		a.notifyDecisionOpportunityLocked()
	}
}

func (a *OpenAdmission) PublishStopped(ctx context.Context, h OpenHandle, maintenance *RecordWriter) (RecordWriteResult, error) {
	return a.publishTerminalMessage(ctx, h, maintenance, terminalStopped)
}
func (a *OpenAdmission) PublishDrained(ctx context.Context, h OpenHandle, maintenance *RecordWriter) (RecordWriteResult, error) {
	return a.publishTerminalMessage(ctx, h, maintenance, terminalDrained)
}
func (a *OpenAdmission) PublishStop(ctx context.Context, h OpenHandle, maintenance *RecordWriter) (RecordWriteResult, error) {
	return a.publishTerminalMessage(ctx, h, maintenance, terminalStop)
}

type streamTerminalTicket struct {
	direction *directionTermination
	service   *StreamTerminationService
	ctx       context.Context
}

func (g streamTerminalTicket) LockTicket() error {
	// Engine already owns its ticket gate. Never acquire admission here:
	// OPEN/cleanup/deadline owners acquire admission before Engine.
	d := g.direction
	d.mu.Lock()
	err := g.ctx.Err()
	if err == nil && g.service != nil && g.service.sealed.Load() {
		err = cryptov4.ErrClosed
	}
	if err == nil && g.service != nil {
		err = g.service.reservation.Check()
		if err == nil && !d.done {
			err = d.failure
			if err == nil && d.until != nil {
				err = d.until.Check()
				if errors.Is(err, timev4.ErrExpired) {
					err = ErrTerminationDeadline
				}
			}
		}
	}
	if err != nil {
		d.mu.Unlock()
	}
	return err
}

func (g streamTerminalTicket) UnlockTicket(bool) { g.direction.mu.Unlock() }

func (a *OpenAdmission) publishTerminalMessage(ctx context.Context, h OpenHandle, maintenance *RecordWriter, kind terminalMessage) (result RecordWriteResult, err error) {
	if maintenance == nil || maintenance.engine != a.engine || maintenance.scope != 0 {
		return result, ErrOpenAssociation
	}
	// Check readiness before spending a ticket. A not-yet-known STOPPED tuple
	// must never sit ahead of the maintenance message needed to resolve it.
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return result, err
	}
	if a.closed {
		a.mu.Unlock()
		return result, cryptov4.ErrClosed
	}
	if !s.accepted || s.flow == nil || s.phase != openLive && s.phase != openRecent {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	// Admission orders the whole publication, including pre-ticket builders
	// and provider return tails, against core cleanup. Repeated publication
	// cannot race already completed DRAINED metadata out from under itself.
	if s.terminalPublishing || s.cleanupBusy {
		a.mu.Unlock()
		return result, ErrOpenPending
	}
	if kind == terminalDrained {
		if _, ok := s.flow.receive.DrainProof(); !ok && !s.coreCleaned {
			a.mu.Unlock()
			return result, ErrOpenPending
		}
	} else if kind == terminalStopped {
		if _, ok := s.flow.send.Terminal(); !ok {
			a.mu.Unlock()
			return result, ErrOpenPending
		}
	} else if kind == terminalCredit {
		s.flow.receive.pool.mu.Lock()
		ready := s.flow.receive.creditReadyLocked()
		s.flow.receive.pool.mu.Unlock()
		if !ready {
			a.mu.Unlock()
			return result, ErrOpenPending
		}
	} else {
		s.flow.receive.pool.mu.Lock()
		abandoned := s.flow.receive.abandoned
		s.flow.receive.pool.mu.Unlock()
		if !abandoned {
			a.mu.Unlock()
			return result, ErrOpenPending
		}
	}
	// The original proof remains until this real publication callback exits,
	// even if its peer's retirement request is processed concurrently.
	a.beginTailLocked()
	defer a.endTail()
	s.retirementReferences++
	s.terminalPublishing = true
	direction := &s.flow.receive.termination
	if kind == terminalStopped {
		direction = &s.flow.send.termination
	}
	guard := streamTerminalTicket{direction, a.termination, ctx}
	a.mu.Unlock()
	result, err = maintenance.WriteBuildGuard(ctx, protocolv4.FrameStreamAck, 192, func(_ protocolv4.RecordHeader, dst []byte) (int, error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s, err := a.slot(h)
		if err != nil {
			return 0, err
		}
		if a.closed {
			return 0, cryptov4.ErrClosed
		}
		var wire []byte
		if kind == terminalDrained {
			if s.coreCleaned {
				wire, err = s.flow.encodeDrainProof(dst, s.terminal[1-a.direction])
			} else {
				wire, err = s.flow.EncodeDrained(dst)
			}
			if err == nil {
				s.drainSubmitted = true
				a.maybeRecent(s)
			}
		} else if kind == terminalStopped {
			wire, err = s.flow.EncodeStopped(dst)
			if err == nil {
				s.stoppedSubmitted, s.stoppedDirty = true, false
			}
		} else if kind == terminalCredit {
			wire, err = s.flow.receive.encodeCredit(dst)
		} else {
			wire, err = s.flow.EncodeStop(dst)
			if err == nil {
				s.stopSubmitted = true
			}
		}
		return len(wire), err
	}, nil, guard)
	a.mu.Lock()
	if s, lookupErr := a.slot(h); lookupErr == nil {
		s.terminalPublishing = false
		if a.termination != nil {
			a.termination.notify()
		}
		if kind == terminalDrained && err == nil && result.Complete {
			err = s.flow.receive.termination.complete()
			s.drainComplete = err == nil
		}
		s.owner.notify()
		a.notifyOutcomeLocked(s)
		s.retirementReferences--
		a.collect(s)
	}
	a.mu.Unlock()
	if err != nil && result.Submitted {
		a.closeWithCause(err)
	}
	return result, err
}

// CleanupStream releases storage only after the original flow/provider owners
// and application read queue have reached their real cleanup conditions. An
// accepted Stream in an open Session must first settle both terminal proofs
// and the actual DRAINED publication return. Rejected OPENs have no such wire
// obligations. ErrTerminal means those facts are not yet complete; it
// never suppresses maintenance needed to make progress. A closed Session has
// no further publication rights and only needs its actual I/O tails to exit.
// CarrierClosed remains a separate report from the original carrier owner.
func (a *OpenAdmission) CleanupStream(ctx context.Context, h OpenHandle) error {
	return a.cleanupStreamOwned(ctx, h, nil)
}

func (a *OpenAdmission) cleanupStreamOwned(ctx context.Context, h OpenHandle, owner *StreamOwnership) error {
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if s.flow == nil {
		a.mu.Unlock()
		return nil
	}
	if s.owner != owner {
		a.mu.Unlock()
		return ErrStreamOwned
	}
	if s.terminalPublishing || s.cleanupBusy {
		a.mu.Unlock()
		return ErrOpenPending
	}
	if s.coreCleaned {
		a.mu.Unlock()
		return nil
	}
	flow := s.flow
	flow.send.mu.Lock()
	wireDone, queue := flow.send.wireDone, flow.send.queueOwner
	flow.send.mu.Unlock()
	if !a.closed && s.accepted && (!s.drainComplete || !wireDone) {
		a.mu.Unlock()
		return ErrTerminal
	}
	if !a.closed {
		a.maybeRecent(s)
	}
	var bootstrapReader *RecordReceiver
	if s.bootstrap {
		bootstrapReader = a.bootstrap.reader
	}
	a.beginTailLocked()
	defer a.endTail()
	s.retirementReferences++
	s.cleanupBusy = true
	closed := a.closed
	a.mu.Unlock()
	err = cleanupFlow(ctx, flow, queue, bootstrapReader, closed)
	a.mu.Lock()
	if s, lookupErr := a.slot(h); lookupErr == nil {
		s.cleanupBusy = false
		s.coreCleaned = err == nil
		if a.termination != nil {
			a.termination.notify()
		}
		s.retirementReferences--
		a.collect(s)
	}
	a.mu.Unlock()
	return err
}

func cleanupFlow(ctx context.Context, flow *StreamFlow, queue *SendQueue, bootstrapReader *RecordReceiver, closed bool) error {
	err := flow.send.WaitCleanup(ctx)
	if err == nil && queue != nil {
		err = queue.WaitCleanup(ctx)
	}
	if err == nil && flow.nativeReceive != nil {
		flow.nativeReceive.Close()
		err = flow.nativeReceive.WaitCleanup(ctx)
	}
	if err == nil && bootstrapReader != nil {
		bootstrapReader.Close()
		err = bootstrapReader.WaitCleanup(ctx)
	}
	if err == nil {
		if closed {
			flow.receive.Abandon()
			err = flow.receive.waitCleanup(ctx)
		} else {
			err = flow.receive.Cleanup()
		}
	}
	return err
}

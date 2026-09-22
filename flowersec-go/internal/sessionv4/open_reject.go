package sessionv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// HoldRejection transfers an authenticated OPEN into its protected rejection
// proof position when ordinary ingress staging is full. It retains only the
// original fixed association/digest/deadline, never peer metadata or the decoder.
// The caller releases the record before publishing or processing more input.
// Failure closes Session: a valid unresolved OPEN cannot simply be dropped.
func (a *OpenAdmission) HoldRejection(record *ReceivedRecord, carrier *CarrierAssociation, deadline *timev4.Deadline) (h OpenHandle, err error) {
	defer func() {
		if err != nil {
			a.closeWithCause(err)
		}
	}()
	if record == nil || record.receiver.engine != a.engine || record.receiver.direction != 1-a.direction || record.incoming == nil || carrier == nil {
		return h, ErrOpenAssociation
	}
	f, err := record.Body()
	if err != nil {
		return h, err
	}
	if f.Type != protocolv4.FrameOpenStream || f.Header != record.incoming.Header() {
		return h, ErrOpenAssociation
	}
	digest, _ := f.Field("open_digest").ByteString()
	if len(digest) != 32 {
		return h, ErrOpenAssociation
	}
	reason, err := protocolv4.EnumValue("OPEN_ACCEPT", "reason", "resource_exhausted")
	if err != nil {
		return h, err
	}
	a.mu.Lock()
	if err := a.checkDeadline(deadline); err != nil {
		a.mu.Unlock()
		return h, err
	}
	carrier.mu.Lock()
	if a.closed || carrier.bound != nil || a.find(f.Header.Scope) >= 0 {
		carrier.mu.Unlock()
		a.mu.Unlock()
		return h, ErrOpenAssociation
	}
	i := a.freeSlot(false, true)
	if i < 0 {
		carrier.mu.Unlock()
		a.mu.Unlock()
		return h, cryptov4.ErrCapacity
	}
	s := &a.slots[i]
	*s = openSlot{scope: f.Header.Scope, phase: openReserved, carrier: carrier, incoming: record.incoming, header: f.Header, deadline: deadline, reason: reason, rejectionToken: true}
	copy(s.digest[:], digest)
	carrier.bound, carrier.scope = a, s.scope
	carrier.mu.Unlock()
	a.insert(s.scope, i)
	a.rejectionProofs++
	if a.barriers != nil {
		a.barriers.bind(s)
	}
	h = OpenHandle{a, s.scope}
	if a.termination != nil {
		a.termination.notify()
	}
	a.mu.Unlock()
	return h, record.accepted()
}

func (s *openSlot) pendingRejection() bool {
	return s.phase == openReserved && s.rejectionToken && s.incoming != nil
}

type rejectionTicket struct {
	ctx      context.Context
	deadline *timev4.Deadline
	service  *StreamTerminationService
}

func (g rejectionTicket) LockTicket() error {
	// Engine owns its gate here. The deadline is the immutable original
	// reference; do not acquire admission in the opposite lock order.
	if err := g.ctx.Err(); err != nil {
		return err
	}
	if g.service != nil {
		if g.service.sealed.Load() {
			return cryptov4.ErrClosed
		}
		if err := g.service.reservation.Check(); err != nil {
			return err
		}
	}
	return rekeyTimeError(g.deadline.Check())
}

func (g rejectionTicket) UnlockTicket(bool) {}

// PublishRejection publishes the one original protected rejection. A definite
// before-ticket refusal preserves the same proof position and deadline. Its
// actual provider tail holds a retirement reference even after peer retirement.
func (a *OpenAdmission) PublishRejection(ctx context.Context, h OpenHandle, maintenance *RecordWriter) (result RecordWriteResult, err error) {
	if ctx == nil || maintenance == nil || maintenance.engine != a.engine || maintenance.scope != 0 {
		return result, cryptov4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	a.mu.Lock()
	s, err := a.slot(h)
	if err != nil || a.closed {
		a.mu.Unlock()
		if err == nil {
			err = cryptov4.ErrClosed
		}
		return result, err
	}
	if !s.pendingRejection() {
		a.mu.Unlock()
		return result, ErrOpenAssociation
	}
	if s.deciding {
		a.mu.Unlock()
		return result, cryptov4.ErrCapacity
	}
	if err := a.checkDeadline(s.deadline); err != nil {
		a.mu.Unlock()
		a.closeWithCause(err)
		return result, err
	}
	if err := a.engine.ApplicationInputReady(s.header.Epoch); err != nil {
		a.mu.Unlock()
		return result, err
	}
	a.beginTailLocked()
	defer a.endTail()
	s.deciding = true
	s.retirementReferences++
	if a.termination != nil {
		a.termination.notify()
	}
	guard := rejectionTicket{ctx, s.deadline, a.termination}
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
		if err := a.checkDeadline(s.deadline); err != nil {
			return 0, err
		}
		wire, err := encodeOpenOutcome(dst, s.header, s.digest, false, 0, s.reason)
		if err != nil {
			return 0, err
		}
		if err := s.incoming.Resolve(false); err != nil {
			return 0, err
		}
		s.phase, s.incoming = openRecent, nil
		s.rejectProof()
		if a.retirement != nil {
			a.retirement.notify()
		}
		return len(wire), nil
	}, nil, guard)
	a.mu.Lock()
	if err == nil {
		err = a.checkDeadline(guard.deadline)
	}
	s.deciding = false
	s.retirementReferences--
	a.collect(s)
	a.mu.Unlock()
	if err != nil && (result.Submitted || !retryRejection(err)) {
		a.closeWithCause(err)
	}
	return result, err
}

func retryRejection(err error) bool {
	return errors.Is(err, cryptov4.ErrCapacity) || errors.Is(err, cryptov4.ErrTransition) || errors.Is(err, cryptov4.ErrNotReady) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

package rpcv4

import (
	"context"
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// QueueResultRead transfers one charged reader to the original ReplySlot.
// Its pin owns the complete immutable result backing; the publisher copies at
// most 4096 bytes per turn and retains that pin through actual publication.
// Success consumes the reader, so later Close/CopyChunk calls cannot reclaim
// or borrow the publisher's source. Failure leaves cleanup with the caller.
func (p *Publisher) QueueResultRead(t Ticket, read *ExecutionResultRead, deadline *timev4.Deadline) (*Publication, error) {
	if p == nil || read == nil || deadline == nil {
		return nil, ErrConfiguration
	}
	var publication *Publication
	err := read.withAccess(func(authority resourcev4.Reference) error {
		n := p.network
		n.mu.Lock()
		defer n.mu.Unlock()
		if err := p.liveLocked(); err != nil {
			return err
		}
		s, err := n.slotLocked(t)
		if err != nil {
			return err
		}
		if t.direction != incoming || s.path.Channel != p.channel || s.inputState != InputComplete || s.message.publisher != nil || !n.resultReadMatches(s.header) {
			return ErrOwner
		}
		return read.withResult(authority, func(result *executionResult) error {
			if read.publicationOwned || !deadline.BelongsTo(read.clock) || deadline.Cap() > s.header.Fields().DeadlineAtMS {
				return ErrOwner
			}
			if err := deadline.Check(); err != nil {
				return err
			}
			if err := read.reservation.CheckSameEnvironment(n.reservation); err != nil {
				return err
			}
			values := s.header.Fields()
			values.Kind, values.DeadlineAtMS = 0, 0
			values.PayloadBytes = result.length
			m := sendMessage{publisher: p, readSource: read, readDeadline: deadline, prev: -1, nextReady: -1}
			length, header, err := p.codec.Encode(m.headerWire[:], "read_result_response", values)
			if err != nil {
				return err
			}
			if err := s.header.MatchResponse(header); err != nil {
				return err
			}
			publication = &Publication{}
			m.header, m.headerBytes, m.publication = header, uint16(length), publication
			read.publicationOwned = true
			s.message = m
			p.enqueueLocked(t, p.lane(s, t.direction))
			return nil
		})
	})
	return publication, err
}

// stepResultRead acquires authority outside the Network lock, then rechecks
// the original source/slot before touching bytes. No result lock is held
// while acquiring authority; cancellation and stale publisher turns can
// neither deadlock this gate nor publish for a reused ReplySlot.
func (p *Publisher) stepResultRead(ctx context.Context, t Ticket, read *ExecutionResultRead) (progressed bool, err error) {
	checked := false
	err = read.withAccess(func(authority resourcev4.Reference) error {
		n := p.network
		n.mu.Lock()
		defer n.mu.Unlock()
		if err := p.liveLocked(); err != nil {
			checked = true
			return err
		}
		s, e := n.slotLocked(t)
		if e != nil || s.message.readSource != read || p.batchPending || !s.message.queued {
			checked = true
			return nil
		}
		m := &s.message
		chunkLen := 0
		if m.begun {
			err = read.withResult(authority, func(result *executionResult) error {
				if err := m.readDeadline.Check(); err != nil {
					return err
				}
				if m.next >= result.length {
					return ErrOwner
				}
				end := min(result.length, m.next+uint32(len(p.readBuffer)))
				chunkLen = copy(p.readBuffer[:], result.payload[m.next:end])
				return nil
			})
			if err != nil {
				return err
			}
		} else {
			err = read.withResult(authority, func(*executionResult) error {
				return m.readDeadline.Check()
			})
			if err != nil {
				return err
			}
		}
		progressed, err = p.stepLocked(ctx, t, s, int(m.lane), p.readBuffer[:chunkLen])
		checked = true
		return err
	})
	if checked || err == nil {
		return progressed, err
	}
	// Before BEGIN the original fixed refusal can replace the response. After
	// BEGIN only ABORT is legal, with the exact already accepted prefix offset.
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	s, e := n.slotLocked(t)
	if e != nil || s.message.readSource != read {
		return false, nil
	}
	code := "service_unavailable"
	switch {
	case errors.Is(err, ErrExecutionUnauthorized):
		code = "permission_denied"
	case errors.Is(err, ErrResultExpired):
		code = "result_expired"
	case errors.Is(err, timev4.ErrExpired):
		code = "deadline_exceeded"
	}
	m := &s.message
	p.unlinkLocked(t)
	m.publication.update(false, false, false, true, code)
	m.releaseSource()
	if !m.begun {
		return false, p.smallReplyLocked(t, s, code)
	}
	m.abort = true
	p.enqueueLocked(t, p.lane(s, t.direction))
	return false, nil
}

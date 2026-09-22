package rpcv4

import (
	"errors"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func queryTimeRefusal(err error) string {
	if errors.Is(err, timev4.ErrExpired) {
		return "deadline_exceeded"
	}
	return "service_unavailable"
}

// RefuseExpired services at most the original Q2 complete pending requests.
// It needs no free full response position and never treats a partial input as
// complete. The original bounded clock adapter runs outside all reader gates;
// the active check holds the real service lifetime through its actual exit.
func (q *ContractQueryService) RefuseExpired() (int, error) {
	if q == nil {
		return 0, ErrOwner
	}
	q.mu.Lock()
	if q.closed || q.cleaned {
		q.mu.Unlock()
		return 0, ErrClosed
	}
	if q.checking {
		q.mu.Unlock()
		return 0, ErrCapacity
	}
	if err := q.reservation.Check(); err != nil {
		q.mu.Unlock()
		return 0, err
	}
	q.checking = true
	clock, n := q.clock, q.network
	q.mu.Unlock()
	defer func() { q.mu.Lock(); q.checking = false; q.cleanupLocked(); q.mu.Unlock() }()
	now, clockErr := clock.Sample()
	n.mu.Lock()
	defer n.mu.Unlock()
	q.mu.Lock()
	closed := q.closed
	q.mu.Unlock()
	if closed {
		return 0, ErrClosed
	}
	count := 0
	start, end, _ := n.bounds(contractQuery)
	for i := start; i < end; i++ {
		s := &n.slots[incoming][i]
		m := &s.received
		if s.state == networkFree || !m.ready || m.input == nil || m.input.query != q || s.message.publisher != nil {
			continue
		}
		code := ""
		if clockErr != nil {
			code = "service_unavailable"
		} else if now.UpperMS >= s.header.Fields().DeadlineAtMS {
			code = "deadline_exceeded"
		}
		if code == "" {
			continue
		}
		p := n.queryPublisherLocked(s.path.Channel)
		if p == nil {
			return count, ErrOwner
		}
		if err := p.smallReplyLocked(Ticket{n, s.generation, uint16(i), incoming}, s, code); err != nil {
			return count, err
		}
		m.input.Close()
		m.input = nil
		m.ready = false
		m.receiver = nil
		count++
	}
	return count, nil
}
func (n *Network) queryPublisherLocked(channel [16]byte) *Publisher {
	for _, p := range n.publishers {
		if p != nil && p.channel == channel {
			return p
		}
	}
	return nil
}

// Refuse uses only this complete query's original small ReplySlot output. The
// fixed worker uses it for expiry or source failure while retaining independent
// old output tails. An already selected STOP or begun response is not replaced.
func (j ContractQueryJob) Refuse(code string) error {
	if _, err := protocolv4.ApplicationRefusalCode(code); err != nil {
		return err
	}
	q := j.service
	if q == nil {
		return ErrOwner
	}
	q.mu.Lock()
	n := q.network
	q.mu.Unlock()
	if n == nil {
		return ErrClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	q.mu.Lock()
	defer q.mu.Unlock()
	s, err := j.slotLocked()
	if err != nil {
		return err
	}
	if s.stepping || s.queued {
		return ErrOwner
	}
	slot, err := n.slotLocked(s.ticket)
	if err != nil {
		return err
	}
	if slot.inputState != InputComplete || slot.class != contractQuery || slot.message.publisher != nil {
		return ErrOwner
	}
	p := n.queryPublisherLocked(slot.path.Channel)
	if p == nil {
		return ErrOwner
	}
	if err := p.smallReplyLocked(s.ticket, slot, code); err != nil {
		return err
	}
	q.releaseOutputLocked(j.index, j.generation)
	return nil
}

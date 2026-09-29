package rpcv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// NotifyProtection owns an existing publisher queue position. It confers no
// authority, does not open a channel, and supplies no payload or status backing.
// Its use remains occupied until the workload returns all real source/status
// tails, even when local publication has already finished.
type NotifyProtection struct {
	publisher  *NotifyPublisher
	generation uint64
	index      uint16
}

func (p *NotifyPublisher) Protect(output []NotifyProtection) error {
	if p == nil || len(output) == 0 {
		return ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.retired {
		return ErrClosed
	}
	for _, out := range output {
		if out != (NotifyProtection{}) {
			return ErrOwner
		}
	}
	available := 0
	for i := range p.slots {
		s := &p.slots[i]
		if s.source == nil && !s.protected && s.generation != math.MaxUint64 {
			available++
		}
	}
	if available < len(output) {
		return ErrCapacity
	}
	count := 0
	for i := range p.slots {
		s := &p.slots[i]
		if s.source != nil || s.protected || s.generation == math.MaxUint64 {
			continue
		}
		s.generation++
		s.protected, s.inUse, s.closed = true, false, false
		output[count] = NotifyProtection{p, s.generation, uint16(i)}
		count++
		if count == len(output) {
			break
		}
	}
	return nil
}

func (p NotifyProtection) slotLocked() (*notifyPublisherSlot, error) {
	if p.publisher == nil || int(p.index) >= len(p.publisher.slots) {
		return nil, ErrOwner
	}
	s := &p.publisher.slots[p.index]
	if !s.protected || s.generation != p.generation {
		return nil, ErrOwner
	}
	return s, nil
}

func (p *NotifyPublisher) admitPositionLocked(protection NotifyProtection) (int, error) {
	if protection != (NotifyProtection{}) {
		if protection.publisher != p {
			return 0, ErrOwner
		}
		s, err := protection.slotLocked()
		if err != nil {
			return 0, err
		}
		if s.closed {
			return 0, ErrClosed
		}
		if s.source != nil || s.inUse {
			return 0, ErrCapacity
		}
		return int(protection.index), nil
	}
	for i := range p.slots {
		if s := &p.slots[i]; s.source == nil && !s.protected {
			return i, nil
		}
	}
	return 0, ErrCapacity
}

func (p NotifyProtection) Submit(ctx context.Context, header, payload []byte, deadline *timev4.Deadline, guard NotifyPublicationGuard, source, status resourcev4.Reference, runtimeBytes uint64) (*NotifySubmission, error) {
	if p.publisher == nil {
		return nil, ErrOwner
	}
	return p.publisher.submit(ctx, header, payload, deadline, guard, source, status, runtimeBytes, p)
}

// The composing workload calls ReleaseUse only after its owned references and
// aliases are available. A retired publisher cannot acquire any further use.
func (p NotifyProtection) ReleaseUse() error {
	if p.publisher == nil {
		return nil
	}
	p.publisher.mu.Lock()
	defer p.publisher.mu.Unlock()
	if p.publisher.retired {
		return nil
	}
	s, err := p.slotLocked()
	if err != nil {
		return err
	}
	if s.source != nil {
		return ErrCapacity
	}
	s.inUse = false
	if s.closed {
		s.protected = false
	}
	return nil
}

func (p NotifyProtection) Close() {
	if p.publisher == nil {
		return
	}
	p.publisher.mu.Lock()
	defer p.publisher.mu.Unlock()
	s, err := p.slotLocked()
	if err != nil {
		return
	}
	s.closed = true
	if s.source == nil {
		s.protected, s.inUse = false, false
	}
}

// Queue order follows successful admission, independent of which protected or
// ordinary position supplied it. A live message cannot be interleaved.
func (p *NotifyPublisher) headLocked() *notifySource {
	var head *notifySource
	for i := range p.slots {
		s := p.slots[i].source
		if s != nil && (head == nil || s.serial < head.serial) {
			head = s
		}
	}
	return head
}

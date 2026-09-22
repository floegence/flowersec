package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
	"sync/atomic"
)

// CheckEnvironment validates the actual original owner, not an equal network
// configuration or Session identifier. It creates no extra borrow or allowance.
func (n *Network) CheckEnvironment(ref resourcev4.Reference) error {
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	return n.reservation.CheckSameEnvironment(ref)
}
func (r *Receiver) CheckAssociation(n *Network, p *Publisher) error {
	if r == nil || n == nil || p == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.failure != nil {
		return ErrClosed
	}
	if r.network != n || r.publisher != p {
		return ErrAssociation
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return p.liveLocked()
}

// ServiceConsumer is issued once for the original Session dispatcher. Manual
// receiver reads are fenced after capture, including after this token stops.
// Stopping never creates replacement dispatch or withdraws a live ReplySlot.
type ServiceConsumer struct{ network atomic.Pointer[Network] }

func (n *Network) ClaimServiceConsumer(owner resourcev4.Reference) (*ServiceConsumer, error) {
	if n == nil {
		return nil, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, err
	}
	if n.serviceConsumer != nil || n.inputs == nil {
		return nil, ErrOwner
	}
	if err := owner.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	c := &ServiceConsumer{}
	c.network.Store(n)
	n.serviceConsumer = c
	return c, nil
}
func (c *ServiceConsumer) NextRequest(r *Receiver, p *Publisher) (Ticket, *RequestInput, error) {
	if c == nil {
		return Ticket{}, nil, ErrOwner
	}
	n := c.network.Load()
	if n == nil {
		return Ticket{}, nil, ErrClosed
	}
	if err := r.CheckAssociation(n, p); err != nil {
		return Ticket{}, nil, err
	}
	return r.nextRequest(c)
}
func (c *ServiceConsumer) Stop() {
	if c != nil {
		c.network.Store(nil)
	}
}
func (n *Network) CheckQueryService(q *ContractQueryService) error {
	if n == nil || q == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	if n.queries != q {
		return ErrAssociation
	}
	return nil
}

func (n *Network) CheckServiceClock(clock *timev4.Clock) error {
	if n == nil || clock == nil {
		return ErrConfiguration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	if n.inputs == nil {
		return ErrOwner
	}
	n.inputs.mu.Lock()
	defer n.inputs.mu.Unlock()
	if n.inputs.closed || n.inputs.config.Clock != clock {
		return ErrOwner
	}
	return nil
}

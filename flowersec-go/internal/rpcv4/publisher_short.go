package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"

// ReserveShortRequest binds the trusted local short call to this original
// channel. It grants no publication or payload/result reservation by itself.
func (p *Publisher) ReserveShortRequest(h protocolv4.ApplicationHeader) (Ticket, error) {
	return p.reserveRequest(h, true)
}

// ReserveRequest uses the same Session-wide K and original channel while
// preserving any unused local short-call opportunity.
func (p *Publisher) ReserveRequest(h protocolv4.ApplicationHeader) (Ticket, error) {
	return p.reserveRequest(h, false)
}

func (p *Publisher) reserveRequest(h protocolv4.ApplicationHeader, short bool) (Ticket, error) {
	if p == nil {
		return Ticket{}, ErrOwner
	}
	n := p.network
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := p.liveLocked(); err != nil {
		return Ticket{}, err
	}
	return n.acquireClassLocked(outgoing, h, Association{Channel: p.channel}, short)
}

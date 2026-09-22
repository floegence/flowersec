package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// NewIncomingInput binds the byte/hash owner to the actual original ReplySlot.
// A separately constructed input with coincidentally equal header fields cannot
// certify this serial's input boundary. All needed backing is already reserved.
func (n *Network) NewIncomingInput(t Ticket, contract *protocolv4.ServiceContract, c InputConfig, reservation resourcev4.Reference) (*RequestInput, error) {
	if n == nil {
		return nil, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := n.slotLocked(t)
	if err != nil {
		return nil, err
	}
	if t.direction != incoming || s.inputAttached {
		return nil, ErrOwner
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	p, err := NewRequestInput(s.header, contract, c, reservation)
	if err != nil {
		return nil, err
	}
	p.ticket = t
	// This state also prevents constructing a competing input owner before
	// the first byte arrives. It is not a complete-input or dispatch fact.
	s.inputAttached = true
	return p, nil
}

// ObserveInput transfers only an actual complete/aborted byte-owner boundary
// into the original slot. The reader does this before Take or Close detaches
// the input. It does not execute or register the operation.
func (n *Network) ObserveInput(p *RequestInput) error {
	if n == nil || p == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != InputComplete && p.state != InputAborted {
		return ErrOwner
	}
	s, err := n.slotLocked(p.ticket)
	if err != nil {
		return err
	}
	if p.ticket.direction != incoming || s.header != p.header || !s.inputAttached || s.inputState != InputCollecting {
		return ErrOwner
	}
	s.inputState = p.state
	return nil
}

package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

func StreamInputEnvelopeCharge(policy protocolv4.ServiceContractPolicy, config InputConfig) (resourcev4.Vector, error) {
	if policy.Shape != 1 || !config.Capture || policy.RequestMaxBytes > 1048576 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return requestInputEnvelopeCharge(policy.RequestMaxBytes, policy.Semantics == 1, config)
}

func ResumeInputEnvelopeCharge(policy protocolv4.ServiceContractPolicy, config InputConfig) (resourcev4.Vector, error) {
	if policy.Shape != 0 || policy.Semantics != 1 || policy.ExecutionMode != 1 || !config.Capture || policy.RequestMaxBytes > 1048576 {
		return resourcev4.Vector{}, ErrConfiguration
	}
	return requestInputEnvelopeCharge(policy.RequestMaxBytes, true, config)
}

// StreamContract lends the already retained trusted body to SDK framing. The
// original capture must outlive that borrow; this does not install a handler.
func (c ContractRoute) StreamContract() (*protocolv4.ServiceContract, error) {
	return c.applicationStreamContract(false)
}

func (c ContractRoute) ResumeContract() (*protocolv4.ServiceContract, error) {
	return c.applicationStreamContract(true)
}

func (c ContractRoute) applicationStreamContract(resume bool) (*protocolv4.ServiceContract, error) {
	if c.capture == nil {
		return nil, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil || !resume && s.entry.policy.Shape != 1 || resume && (s.entry.policy.Shape != 0 || s.entry.policy.Semantics != 1 || s.entry.policy.ExecutionMode != 1) {
		return nil, ErrMethod
	}
	if err := s.reservation.Check(); err != nil {
		return nil, err
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if s.registry.closed || !s.entry.registered {
		return nil, ErrMethod
	}
	return s.entry.contract, nil
}

// NewStreamInput moves a preaccepted complete input backing into the same
// original RequestInput/VerifiedInput engine used by execution admission. No
// second payload buffer or parallel digest engine is constructed by framing.
func (c ContractRoute) NewStreamInput(ticket Ticket, h protocolv4.ApplicationHeader, config InputConfig, reservation resourcev4.Reference, storage []byte, deadline *timev4.Deadline) (*RequestInput, error) {
	return c.newApplicationStreamInput(ticket, h, config, reservation, storage, deadline, false)
}

func (c ContractRoute) NewResumeInput(ticket Ticket, h protocolv4.ApplicationHeader, config InputConfig, reservation resourcev4.Reference, storage []byte, deadline *timev4.Deadline) (*RequestInput, error) {
	return c.newApplicationStreamInput(ticket, h, config, reservation, storage, deadline, true)
}

func (c ContractRoute) newApplicationStreamInput(ticket Ticket, h protocolv4.ApplicationHeader, config InputConfig, reservation resourcev4.Reference, storage []byte, deadline *timev4.Deadline, resume bool) (*RequestInput, error) {
	if c.capture == nil || ticket.network == nil || !resume && !h.StreamRequest() || resume && h.Kind() != "resume_request" || config.Clock == nil || deadline == nil {
		return nil, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return nil, ErrOwner
	}
	if err := s.reservation.CheckSameEnvironment(reservation); err != nil {
		return nil, err
	}
	s.registry.mu.Lock()
	valid := !s.registry.closed && s.entry.registered && config.Clock == s.registry.clock
	s.registry.mu.Unlock()
	if !valid {
		return nil, ErrMethod
	}
	n := ticket.network
	n.mu.Lock()
	defer n.mu.Unlock()
	slot, err := n.slotLocked(ticket)
	if err != nil {
		return nil, err
	}
	if ticket.direction != incoming || slot.class != generalStreaming || slot.inputAttached || slot.header != h {
		return nil, ErrOwner
	}
	if err := reservation.CheckSameEnvironment(n.reservation); err != nil {
		return nil, err
	}
	p, err := newRequestInput(h, s.entry.contract, config, reservation, storage, deadline)
	if err != nil {
		return nil, err
	}
	p.ticket = ticket
	p.method, p.methodBound, p.policy = s.entry.method, true, s.entry.policy
	slot.inputAttached = true
	return p, nil
}

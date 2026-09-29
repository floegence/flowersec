package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"

// BindingIdentity captures the complete immutable method definition and the
// fields excluded from a bounded acceptance policy. It is local metadata, not
// permission to call a peer or install a remote advertisement.
func (c ContractRoute) BindingIdentity(acceptance protocolv4.ContractAcceptance) (shape, policy [32]byte, err error) {
	if c.capture == nil {
		return shape, policy, ErrOwner
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return shape, policy, ErrOwner
	}
	if err = s.reservation.Check(); err != nil {
		return
	}
	shape, err = s.entry.contract.MethodShapeDigest()
	if err == nil {
		policy, err = s.entry.contract.AcceptanceIdentity(acceptance)
	}
	return
}

// BindingPolicy inspects a trusted static definition, including a declared
// method not currently registered for dispatch. It grants no readiness.
func (r *ContractRoutes) BindingPolicy(digest [32]byte, acceptance protocolv4.ContractAcceptance) (protocolv4.ServiceContractPolicy, error) {
	if r == nil {
		return protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return protocolv4.ServiceContractPolicy{}, ErrClosed
	}
	for j := range r.entries {
		e := &r.entries[j]
		if e.policy.Digest == digest {
			_, err := e.contract.AcceptanceIdentity(acceptance)
			return e.policy, err
		}
	}
	return protocolv4.ServiceContractPolicy{}, ErrMethod
}

// CheckBindingUpdate serializes against registration and registry destruction.
// Both exact explicit updates and bounded updates retain the original method
// definition. Bounded updates additionally compare every unlisted field.
func (r *ContractRoutes) CheckBindingUpdate(current, candidate [32]byte, acceptance protocolv4.ContractAcceptance) error {
	if r == nil {
		return ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	var old, next *contractRouteEntry
	for j := range r.entries {
		e := &r.entries[j]
		if e.policy.Digest == current {
			old = e
		}
		if e.policy.Digest == candidate {
			next = e
		}
	}
	if old == nil || next == nil || !next.registered {
		return ErrMethod
	}
	if old.method != next.method {
		return protocolv4.ErrContractPolicyRejected
	}
	b, err := next.contract.AcceptanceIdentity(acceptance)
	if err != nil {
		return err
	}
	if acceptance.Mode == protocolv4.ContractBounded {
		a, err := old.contract.AcceptanceIdentity(acceptance)
		if err != nil {
			return err
		}
		if a != b {
			return protocolv4.ErrContractPolicyRejected
		}
	}
	return nil
}

package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"

// Exactly one history owns a logical service. Backend selection comes only
// from trusted registration, never from a wire request or a failed lookup.
func (b ServiceBinding) valid() bool {
	return (b.History != nil) != (b.DurableHistory != nil)
}

func (b ServiceBinding) borrow(ref resourcev4.Reference) (resourcev4.Reference, error) {
	expected := ExecutionService{Tenant: b.Authority.Tenant, Audience: b.Authority.Audience, Namespace: b.Authority.Namespace}
	if b.History != nil {
		h := b.History
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.closed {
			return resourcev4.Reference{}, ErrClosed
		}
		if h.service != expected {
			return resourcev4.Reference{}, ErrAssociation
		}
		if err := ref.CheckSameEnvironment(h.reservation); err != nil {
			return resourcev4.Reference{}, err
		}
		return h.reservation.Borrow()
	}
	if b.DurableHistory == nil || b.DurableHistory.durableExecutions == nil {
		return resourcev4.Reference{}, ErrOwner
	}
	h := b.DurableHistory
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return resourcev4.Reference{}, ErrClosed
	}
	if h.config.Service != expected {
		return resourcev4.Reference{}, ErrAssociation
	}
	if err := ref.CheckSameEnvironment(h.reservation); err != nil {
		return resourcev4.Reference{}, err
	}
	return h.reservation.Borrow()
}

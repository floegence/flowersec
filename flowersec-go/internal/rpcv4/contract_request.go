package rpcv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// Clone acquires an independent, charged lifetime for the same exact contract.
// Releasing the binding's capture cannot revoke or free a live call's capture.
// Registration and authorization remain separate current publication gates.
func (c ContractRoute) Clone(reservation resourcev4.Reference, runtimeBytes uint64) (ContractRoute, error) {
	if c.capture == nil {
		return ContractRoute{}, ErrOwner
	}
	charge, err := ContractRouteCharge(runtimeBytes)
	if err != nil {
		return ContractRoute{}, err
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.registry
	if r == nil {
		return ContractRoute{}, ErrOwner
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cleaned {
		return ContractRoute{}, ErrClosed
	}
	if r.captures == math.MaxUint32 {
		return ContractRoute{}, ErrCapacity
	}
	if err := reservation.CheckSameEnvironment(s.reservation); err != nil {
		return ContractRoute{}, err
	}
	owned, err := reservation.Take(charge)
	if err != nil {
		return ContractRoute{}, err
	}
	r.captures++
	return ContractRoute{&routeCapture{registry: r, entry: s.entry, reservation: owned}}, nil
}

// CheckPayload verifies prepared execution bytes before any network position
// is acquired. Its hash working set belongs to the original caller reservation.
func (c ContractRoute) CheckPayload(h protocolv4.ApplicationHeader, payload []byte) error {
	if c.capture == nil || uint64(len(payload)) != uint64(h.Fields().PayloadBytes) {
		return ErrConfiguration
	}
	s := c.capture
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry == nil {
		return ErrOwner
	}
	if err := s.reservation.Check(); err != nil {
		return err
	}
	if err := s.entry.contract.CheckRequest(h); err != nil {
		return err
	}
	if !h.HasExecutionIdentity() {
		return nil
	}
	v, err := protocolv4.NewExecutionRequestVerifier(h, s.entry.contract)
	if err != nil {
		return err
	}
	defer v.Close()
	if len(payload) != 0 {
		if err := v.WriteAt(0, payload); err != nil {
			return err
		}
	}
	return v.Finish()
}

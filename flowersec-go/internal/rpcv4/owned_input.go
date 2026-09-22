package rpcv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"

// ApplicationInput is the original result allocation after irrevocable input
// delivery. Application code owns the bytes and may retain them. The SDK keeps
// the original charge through its actual callback/transfer tail; Close never
// wipes an application-owned alias or claims to constrain its object graph.
type ApplicationInput struct {
	reservation resourcev4.Reference
	payload     []byte
}

func (v *VerifiedInput) DetachSessionScope() error {
	if v == nil {
		return ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.borrowed || v.cleaned {
		return ErrOwner
	}
	return v.reservation.DetachSessionScope()
}

// Deliver runs only inside the caller's original authorization/consumption
// gate. It moves the complete backing without allocation or application code.
func (v *VerifiedInput) Deliver() (ApplicationInput, error) {
	if v == nil {
		return ApplicationInput{}, ErrOwner
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.borrowed || v.cleaned {
		return ApplicationInput{}, ErrOwner
	}
	if err := v.reservation.Check(); err != nil {
		return ApplicationInput{}, err
	}
	result := ApplicationInput{reservation: v.reservation, payload: v.payload[:len(v.payload):len(v.payload)]}
	v.reservation, v.payload = resourcev4.Reference{}, nil
	v.deadline, v.ticket = nil, Ticket{}
	v.closed, v.cleaned = true, true
	return result, nil
}

func (v *ApplicationInput) Bytes() []byte { return v.payload }
func (v *ApplicationInput) Close() {
	v.payload = nil
	v.reservation.Release()
	v.reservation = resourcev4.Reference{}
}

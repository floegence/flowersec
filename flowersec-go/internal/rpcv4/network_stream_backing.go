package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ProtectStreamBacking admits the original aggregate alias together with the
// declared dedicated-stream opportunity, before a full root slab can prevent
// Start from retaining its Network. No payload or additional K is reserved.
func (p OutgoingProtection) ProtectStreamBacking() error {
	n := p.network
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	s, err := p.slotLocked()
	if err != nil {
		return err
	}
	if s.protectionClosed {
		return ErrClosed
	}
	if s.protectionInUse || s.state != networkFree || s.streamBacking != (resourcev4.Reference{}) {
		return ErrOwner
	}
	s.streamBacking, err = n.reservation.Borrow()
	return err
}

func (n *Network) RetainProtectedStream(session protocolv4.SessionContract, reservation resourcev4.Reference, p OutgoingProtection) (resourcev4.Reference, error) {
	if n == nil || p.network != n {
		return resourcev4.Reference{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return resourcev4.Reference{}, err
	}
	if n.config.Session != session {
		return resourcev4.Reference{}, ErrOwner
	}
	if err := n.reservation.CheckSameEnvironment(reservation); err != nil {
		return resourcev4.Reference{}, err
	}
	s, err := p.slotLocked()
	if err != nil {
		return resourcev4.Reference{}, err
	}
	if s.protectionClosed {
		return resourcev4.Reference{}, ErrClosed
	}
	if s.protectionInUse || s.state != networkFree || s.streamBorrowed {
		return resourcev4.Reference{}, ErrCapacity
	}
	ref, err := s.streamBacking.TakeBorrow()
	if err != nil {
		return resourcev4.Reference{}, err
	}
	s.streamBacking, s.streamBorrowed = ref, true
	return ref, nil
}

// Only the same original alias returns. The physical Stream has already left
// Network use; result/decoder cleanup separately retains the original K token.
// Closing that Network retires this alias instead of creating a replacement.
func (p OutgoingProtection) ReturnStreamBacking(ref resourcev4.Reference) {
	n := p.network
	if n == nil {
		ref.Release()
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := p.slotLocked()
	if err != nil || !s.streamBorrowed || s.streamBacking != ref {
		ref.Release()
		return
	}
	s.streamBorrowed = false
	if !n.closed && !s.protectionClosed {
		if moved, err := ref.TakeBorrow(); err == nil {
			s.streamBacking = moved
			return
		}
		// Exhausted generations or closed scopes cannot fulfill another use.
		s.protectionClosed = true
	}
	s.streamBacking = resourcev4.Reference{}
	ref.Release()
}

package rpcv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"math"
)

// RetainStream pins the original Session's aggregate table before dedicated
// Stream acceptance. It grants no new slot, input, handler or publication right.
func (n *Network) RetainStream(session protocolv4.SessionContract, reservation resourcev4.Reference) (resourcev4.Reference, error) {
	if n == nil {
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
	return n.reservation.Borrow()
}

// ReserveIncomingStream occupies one real general ReplySlot before the
// dedicated OPEN is accepted. Its immutable request is bound only after the
// canonical initial header arrives; no headerless slot can dispatch a method.
func (n *Network) ReserveIncomingStream(path Association) (Ticket, error) {
	if n == nil {
		return Ticket{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return Ticket{}, err
	}
	if path.Channel == ([16]byte{}) || path.Serial != 0 || n.conflictLocked(incoming, path, generalStreaming, -1) {
		return Ticket{}, ErrAssociation
	}
	start, end, bucket := n.bounds(generalStreaming)
	for i := start; i < end; i++ {
		s := &n.slots[incoming][i]
		if s.state != networkFree || s.generation == math.MaxUint64 {
			continue
		}
		*s = networkSlot{generation: s.generation + 1, state: networkReply, class: generalStreaming, path: path}
		n.count[incoming][bucket]++
		return Ticket{n, s.generation, uint16(i), incoming}, nil
	}
	return Ticket{}, ErrCapacity
}

func (n *Network) BindIncomingStream(t Ticket, header protocolv4.ApplicationHeader) error {
	if n == nil || !header.StreamRequest() && header.Kind() != "resume_request" {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	s, err := n.slotLocked(t)
	if err != nil {
		return err
	}
	if t.direction != incoming || s.class != generalStreaming || s.state != networkReply || s.header.Kind() != "" {
		return ErrOwner
	}
	s.header = header
	return nil
}

// StreamBinding validates an exact trusted local registration against this
// Network's original immutable route set. Its contract is borrowed only while
// the caller holds the Network owner; preparation captures its own route.
func (n *Network) StreamBinding(method uint32, namespace string, typeID uint32, digest [32]byte) (*protocolv4.ServiceContract, protocolv4.ServiceContractPolicy, error) {
	return n.applicationStreamBinding(method, namespace, typeID, digest, false)
}

func (n *Network) ResumeBinding(method uint32, namespace string, typeID uint32, digest [32]byte) (*protocolv4.ServiceContract, protocolv4.ServiceContractPolicy, error) {
	return n.applicationStreamBinding(method, namespace, typeID, digest, true)
}

func (n *Network) applicationStreamBinding(method uint32, namespace string, typeID uint32, digest [32]byte, resume bool) (*protocolv4.ServiceContract, protocolv4.ServiceContractPolicy, error) {
	if n == nil {
		return nil, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return nil, protocolv4.ServiceContractPolicy{}, err
	}
	if n.inputs == nil {
		return nil, protocolv4.ServiceContractPolicy{}, ErrOwner
	}
	a := n.inputs
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.routes == nil {
		return nil, protocolv4.ServiceContractPolicy{}, ErrClosed
	}
	r := a.routes
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, protocolv4.ServiceContractPolicy{}, ErrClosed
	}
	for _, entry := range r.entries {
		p := entry.policy
		shape := !resume && p.Shape == 1 || resume && p.Shape == 0 && p.Semantics == 1 && p.ExecutionMode == 1
		if entry.registered && entry.method == method && p.Namespace == namespace && p.Type == typeID && p.Digest == digest && shape && (p.Semantics == 0 || p.Semantics == 1 && n.config.Session.Limits().ApplicationProfile == "execution") {
			return entry.contract, p, nil
		}
	}
	return nil, protocolv4.ServiceContractPolicy{}, ErrMethod
}

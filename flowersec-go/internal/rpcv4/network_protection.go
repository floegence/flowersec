package rpcv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// OutgoingProtection identifies one future call's original general K position.
// Its state lives in the admitted Network slab. It allocates no extra table,
// ReplySlot, query capacity or worker, and confers no publication authority.
// The composing workload owns payload, preparation, result and execution
// reservations separately and returns a use only after all of their tails exit.
type OutgoingProtection struct {
	network    *Network
	generation uint64
	index      uint16
}

// CheckOriginal validates the exact unpublished table position and, for a
// dedicated Stream, its preadmitted Network alias. It creates no new capacity.
func (p OutgoingProtection) CheckOriginal(n *Network, stream bool) error {
	if n == nil || p.network != n {
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
	if s.protectionClosed || s.protectionInUse || s.state != networkFree || s.streamBorrowed || stream != (s.streamBacking != (resourcev4.Reference{})) {
		return ErrOwner
	}
	if stream {
		return s.streamBacking.Check()
	}
	return nil
}

// ProtectOutgoing takes a finite batch of actual general positions atomically.
// Existing full/late/streaming calls and protected uses all retain their cost.
// The separate short floor remains available under its original local policy.
func (n *Network) ProtectOutgoing(output []OutgoingProtection) error {
	if n == nil || len(output) == 0 {
		return ErrConfiguration
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.liveLocked(); err != nil {
		return err
	}
	for _, p := range output {
		if p != (OutgoingProtection{}) {
			return ErrOwner
		}
	}
	if !n.spareOutgoingLocked(len(output)) {
		return ErrCapacity
	}
	end := int(n.config.Session.Limits().RPCMaxGeneralOutstanding)
	available := 0
	for i := 0; i < end; i++ {
		s := &n.slots[outgoing][i]
		if s.state == networkFree && !s.protected && s.generation != math.MaxUint64 && s.protectionGeneration != math.MaxUint64 {
			available++
		}
	}
	if available < len(output) {
		return ErrCapacity
	}
	count := 0
	for i := 0; i < end && count < len(output); i++ {
		s := &n.slots[outgoing][i]
		if s.state != networkFree || s.protected || s.generation == math.MaxUint64 || s.protectionGeneration == math.MaxUint64 {
			continue
		}
		s.protected = true
		s.protectionGeneration++
		output[count] = OutgoingProtection{n, s.protectionGeneration, uint16(i)}
		count++
	}
	return nil
}

// Protected active calls are already included in the general count. Only idle
// positions and positions retaining post-network tails add to that count.
func (n *Network) spareOutgoingLocked(want int) bool {
	if want < 0 || want > int(n.config.Session.Limits().RPCMaxGeneralOutstanding) {
		return false
	}
	used := int(n.count[outgoing][0])
	for i := 0; i < int(n.config.Session.Limits().RPCMaxGeneralOutstanding); i++ {
		s := &n.slots[outgoing][i]
		if s.protected && s.state == networkFree {
			used++
		}
	}
	if n.config.ProtectShortCall && n.shortOutgoing == 0 {
		used++
	}
	return used+want <= int(n.config.Session.Limits().RPCMaxGeneralOutstanding)
}

func (p OutgoingProtection) slotLocked() (*networkSlot, error) {
	n := p.network
	if n == nil || int(p.index) >= len(n.slots[outgoing]) {
		return nil, ErrOwner
	}
	s := &n.slots[outgoing][p.index]
	if !s.protected || s.protectionGeneration != p.generation {
		return nil, ErrOwner
	}
	return s, nil
}

// Reserve starts one protected use on a trusted channel or dedicated Stream.
// General publication still validates its original publisher, exact header,
// authorization, complete source and continuous reader/result responsibilities.
func (p OutgoingProtection) Reserve(h protocolv4.ApplicationHeader, path Association, short bool) (Ticket, error) {
	if p.network == nil {
		return Ticket{}, ErrOwner
	}
	p.network.mu.Lock()
	defer p.network.mu.Unlock()
	return p.reserveLocked(h, path, short)
}

func (p OutgoingProtection) reserveLocked(h protocolv4.ApplicationHeader, path Association, short bool) (Ticket, error) {
	n := p.network
	if err := n.liveLocked(); err != nil {
		return Ticket{}, err
	}
	s, err := p.slotLocked()
	if err != nil {
		return Ticket{}, err
	}
	if s.protectionClosed {
		return Ticket{}, ErrClosed
	}
	if s.protectionInUse || s.state != networkFree || s.generation == math.MaxUint64 {
		return Ticket{}, ErrCapacity
	}
	class, err := n.classify(h, outgoing)
	if err != nil {
		return Ticket{}, err
	}
	if class == contractQuery || short && class != generalUnary {
		return Ticket{}, ErrMethod
	}
	if path.Channel == ([16]byte{}) || path.Serial != 0 || n.conflictLocked(outgoing, path, class, int(p.index)) {
		return Ticket{}, ErrAssociation
	}
	*s = networkSlot{streamBacking: s.streamBacking, streamBorrowed: s.streamBorrowed, generation: s.generation + 1, protectionGeneration: s.protectionGeneration, protected: true, protectionInUse: true,
		state: networkReserved, class: class, header: h, path: path, short: short}
	n.count[outgoing][0]++
	return Ticket{n, s.generation, p.index, outgoing}, nil
}

// ReleaseUse follows both physical network release and the original workload's
// final result/provider/decoder alias release. Network Release alone cannot
// reproduce a declared target while its previous use still retains resources.
func (p OutgoingProtection) ReleaseUse(t Ticket) error {
	n := p.network
	if n == nil {
		return ErrOwner
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if t.network != n || t.direction != outgoing || t.index != p.index {
		return ErrOwner
	}
	s, err := p.slotLocked()
	if err != nil {
		return err
	}
	if !s.protectionInUse || s.generation != t.generation || s.state != networkFree || s.streamBorrowed {
		return ErrOwner
	}
	s.protectionInUse = false
	if s.protectionClosed {
		n.dropProtectionLocked(s)
	}
	return nil
}

// Close seals future use. A live use keeps its original position until its
// network and workload tails return; closing the Network revokes idle positions
// because that Session can no longer admit replacement calls.
func (p OutgoingProtection) Close() {
	n := p.network
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	s, err := p.slotLocked()
	if err != nil {
		return
	}
	s.protectionClosed = true
	if !s.streamBorrowed {
		s.streamBacking.Release()
		s.streamBacking = resourcev4.Reference{}
	}
	if !s.protectionInUse && s.state == networkFree {
		n.dropProtectionLocked(s)
	}
}

func (n *Network) dropProtectionLocked(s *networkSlot) {
	if !s.streamBorrowed {
		s.streamBacking.Release()
	}
	s.streamBacking, s.streamBorrowed = resourcev4.Reference{}, false
	s.protected, s.protectionInUse, s.protectionClosed = false, false, false
}

func (n *Network) resetSlotLocked(s *networkSlot) {
	if s.protected && n.closed {
		n.dropProtectionLocked(s)
	}
	*s = networkSlot{streamBacking: s.streamBacking, streamBorrowed: s.streamBorrowed, generation: s.generation, protectionGeneration: s.protectionGeneration,
		protected: s.protected, protectionInUse: s.protectionInUse, protectionClosed: s.protectionClosed}
}

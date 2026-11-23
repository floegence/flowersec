package resourcev4

import (
	"math"
	"unsafe"
)

// ProtectedReservation keeps one already admitted responsibility unavailable
// to unrelated work between uses. Checkout reuses its original reference slot;
// it never reserves a new root, account, vector, or reference position. Each use
// has a fresh generation and may pass through ordinary Take/Borrow/Transfer.
// A use returns only when its owner and every actual alias have released it.
// The original trusted composition closes this reservation after its services.
type ProtectedReservation struct {
	root          *Root
	index, charge uint32
	generation    uint64
	borrowIndex   uint32
	hasBorrow     bool
	anchorIndex   uint32
	hasAnchor     bool
}

func ProtectedCharge(minimum Vector) (Vector, error) {
	if minimum == (Vector{}) {
		return Vector{}, ErrConfiguration
	}
	return minimum.Add(Vector{SDKBytes: uint64(unsafe.Sizeof(ProtectedReservation{})), Items: 1})
}

// An optional already admitted Borrow protects one actual execution reference
// as well as the backing. Both positions stay in the original root slab.
func NewProtectedReservation(ref Reference, minimum Vector, borrows ...Reference) (*ProtectedReservation, error) {
	return newProtectedReservation(ref, minimum, Reference{}, borrows...)
}

// NewProtectedResultReservation preadmits an additional original scope anchor.
// Live result references may shed Session scope while that anchor keeps the
// Session's one reusable floor charged. CloseAfterUse retires the anchor and
// transfers actual result tails to their existing independent budget scopes.
func NewProtectedResultReservation(ref Reference, minimum Vector, anchor Reference, borrows ...Reference) (*ProtectedReservation, error) {
	if anchor == (Reference{}) {
		return nil, ErrOwner
	}
	return newProtectedReservation(ref, minimum, anchor, borrows...)
}

func newProtectedReservation(ref Reference, minimum Vector, anchor Reference, borrows ...Reference) (*ProtectedReservation, error) {
	charge, err := ProtectedCharge(minimum)
	if err != nil {
		return nil, err
	}
	if ref.root == nil || len(borrows) > 1 {
		return nil, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	anchors := 0
	if anchor != (Reference{}) {
		anchors = 1
	}
	if s == nil || !s.primary || c.refs != uint32(1+len(borrows)+anchors) || c.protected != nil || s.transferID != ([16]byte{}) {
		return nil, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return nil, err
	}
	if !c.value.Contains(charge) || s.generation == math.MaxUint64 {
		return nil, ErrCapacity
	}
	if anchors != 0 {
		if anchor.root != r {
			return nil, ErrOwner
		}
		a, ac := anchor.slotsLocked()
		if a == nil || ac != c || a.primary || a.owner != s.owner || a.transferID != ([16]byte{}) || !sameProtectedScopes(s, a) || a.generation == math.MaxUint64 {
			return nil, ErrOwner
		}
		if len(borrows) != 0 && borrows[0] == anchor {
			return nil, ErrOwner
		}
	}
	p := &ProtectedReservation{root: r, index: ref.index, charge: s.charge, generation: c.generation}
	if len(borrows) != 0 {
		alias := borrows[0]
		if alias.root != r {
			return nil, ErrOwner
		}
		b, bc := alias.slotsLocked()
		if b == nil || bc != c || b.primary || b.owner != s.owner || b.transferID != ([16]byte{}) || !sameProtectedScopes(s, b) {
			return nil, ErrOwner
		}
		if b.generation == math.MaxUint64 {
			return nil, ErrCapacity
		}
		p.borrowIndex, p.hasBorrow = alias.index, true
		b.generation++
		b.protectedIdle = true
	}
	if anchors != 0 {
		a, _ := anchor.slotsLocked()
		a.generation++
		a.protectedIdle = true
		p.hasAnchor, p.anchorIndex = true, anchor.index
	}
	s.generation++
	s.protectedIdle = true
	c.protected = p
	return p, nil
}

func (p *ProtectedReservation) slotsLocked() (*referenceSlot, *chargeSlot) {
	r := p.root
	if uint64(p.index) >= uint64(len(r.refs)) || uint64(p.charge) >= uint64(len(r.charges)) {
		return nil, nil
	}
	s, c := &r.refs[p.index], &r.charges[p.charge]
	if !s.active || !c.active || c.generation != p.generation || c.protected != p || s.charge != p.charge || s.chargeGeneration != c.generation {
		return nil, nil
	}
	return s, c
}

func (p *ProtectedReservation) Checkout() (Reference, error) {
	if p == nil || p.root == nil {
		return Reference{}, ErrOwner
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	return p.checkoutLocked()
}

// CheckAvailable observes whether the original responsibility and every real
// alias have returned. It reserves nothing; callers still use Checkout for
// their actual transfer under the same root gate.
func (p *ProtectedReservation) CheckAvailable() error {
	if p == nil || p.root == nil {
		return ErrOwner
	}
	p.root.mu.Lock()
	defer p.root.mu.Unlock()
	return p.checkoutReadyLocked()
}

func (p *ProtectedReservation) checkoutReadyLocked() error {
	r := p.root
	s, c := p.slotsLocked()
	if s == nil {
		return ErrClosed
	}
	if r.closed || c.protectedClosed {
		return ErrClosed
	}
	for _, a := range s.accounts[:s.count] {
		if slot := a.slotLocked(r); slot == nil || slot.closed {
			return ErrClosed
		}
	}
	if !p.idleLocked(s, c) || s.generation == math.MaxUint64 || p.hasBorrow && r.refs[p.borrowIndex].generation == math.MaxUint64 {
		return ErrCapacity
	}
	return nil
}

func sameProtectedScopes(a, b *referenceSlot) bool {
	if a.count != b.count {
		return false
	}
	for _, scope := range a.accounts[:a.count] {
		if accountIndex(b.accounts[:b.count], scope) < 0 {
			return false
		}
	}
	return true
}

func (p *ProtectedReservation) owns(index uint32) bool {
	return index == p.index || p.hasBorrow && index == p.borrowIndex || p.hasAnchor && index == p.anchorIndex
}

func (p *ProtectedReservation) idleLocked(s *referenceSlot, c *chargeSlot) bool {
	if !s.protectedIdle {
		return false
	}
	refs := uint32(1)
	if p.hasAnchor {
		refs++
	}
	if p.hasBorrow {
		return c.refs == refs+1 && p.root.refs[p.borrowIndex].protectedIdle
	}
	return c.refs == refs
}

// Reusing the preadmitted alias does not attach another account reference. A
// transferred owner with other scopes must obtain its own ordinary reference.
func (p *ProtectedReservation) borrowLocked(source *referenceSlot) (Reference, bool) {
	if !p.hasBorrow {
		return Reference{}, false
	}
	r := p.root
	b := &r.refs[p.borrowIndex]
	if !b.protectedIdle || b.generation == math.MaxUint64 || !sameProtectedScopes(source, b) {
		return Reference{}, false
	}
	b.protectedIdle = false
	b.owner = source.owner
	b.generation++
	return Reference{r, p.borrowIndex, b.generation}, true
}

func (p *ProtectedReservation) checkoutLocked() (Reference, error) {
	if err := p.checkoutReadyLocked(); err != nil {
		return Reference{}, err
	}
	r := p.root
	s, c := p.slotsLocked()
	// The former use may have sealed its own aliases. All of them have now
	// actually exited; only the original protected responsibility remains.
	c.sealed = false
	s.protectedIdle = false
	s.primary = true
	s.transferID = [16]byte{}
	s.transferredTo = Reference{}
	s.generation++
	return Reference{r, p.index, s.generation}, nil
}

// CheckoutProtectedBatch acquires a complete original protected vector under
// the same root gate. A live tail in any component leaves all components idle.
func CheckoutProtectedBatch(input []*ProtectedReservation, output []Reference) error {
	if len(input) == 0 || len(input) != len(output) || input[0] == nil || input[0].root == nil {
		return ErrConfiguration
	}
	r := input[0].root
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range input {
		if p == nil || p.root != r || output[i] != (Reference{}) {
			return ErrOwner
		}
		for _, earlier := range input[:i] {
			if earlier == p {
				return ErrOwner
			}
		}
		if err := p.checkoutReadyLocked(); err != nil {
			return err
		}
	}
	for i, p := range input {
		output[i], _ = p.checkoutLocked()
	}
	return nil
}

func (p *ProtectedReservation) Close() {
	p.close(true)
}

// CloseAfterUse stops future checkouts while preserving an already accepted
// completion's original backing access through its physical callback exit.
// Original root/account closure still applies; no closed scope is reopened.
func (p *ProtectedReservation) CloseAfterUse() {
	p.close(false)
}

func (p *ProtectedReservation) close(seal bool) {
	if p == nil || p.root == nil {
		return
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.drainWaitersLocked()
	s, c := p.slotsLocked()
	if s == nil {
		return
	}
	c.protectedClosed = true
	if seal {
		c.sealed = true
	}
	if p.hasAnchor {
		r.retireResultProtectionLocked(c)
		return
	}
	r.finishProtectedLocked(c)
}

func (p *ProtectedReservation) CleanupComplete() bool {
	if p == nil || p.root == nil {
		return true
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, _ := p.slotsLocked()
	return s == nil
}

// The dormant original reference still holds all original account charges.
// Final close removes it only after the last real use/transfer/borrow exits.
func (r *Root) finishProtectedLocked(c *chargeSlot) {
	p := c.protected
	if p == nil || !c.protectedClosed {
		return
	}
	s, _ := p.slotsLocked()
	if s == nil || !p.idleLocked(s, c) {
		return
	}
	s.protectedIdle = false
	c.protected = nil
	if p.hasBorrow {
		b := &r.refs[p.borrowIndex]
		b.protectedIdle = false
		Reference{r, p.borrowIndex, b.generation}.releaseLocked()
	}
	Reference{r, p.index, s.generation}.releaseLocked()
}

func (*ProtectedReservation) String() string               { return "Flowersec.ProtectedReservation" }
func (*ProtectedReservation) GoString() string             { return "Flowersec.ProtectedReservation" }
func (*ProtectedReservation) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Only original result protection has an anchor. On Session retirement, live
// result generations remain ordinary references; idle implementation slots
// disappear. No live input is released, no new root position is allocated.
func (r *Root) retireResultProtectionLocked(c *chargeSlot) {
	p := c.protected
	if p == nil || !p.hasAnchor {
		return
	}
	c.protected = nil
	indices := [3]uint32{p.index, p.anchorIndex, p.borrowIndex}
	n := 2
	if p.hasBorrow {
		n++
	}
	for _, index := range indices[:n] {
		s := &r.refs[index]
		if s.protectedIdle {
			s.protectedIdle = false
			Reference{r, index, s.generation}.releaseLocked()
		}
	}
}

// Returning to an active floor restores only already charged anchor scopes.
// It cannot acquire capacity or reopen a closed root/account for new work.
func (p *ProtectedReservation) restoreScopesLocked(s *referenceSlot, c *chargeSlot) {
	if !p.hasAnchor {
		return
	}
	p.root.restoreScopesLocked(s, c, &p.root.refs[p.anchorIndex])
}

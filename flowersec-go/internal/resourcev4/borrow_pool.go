package resourcev4

import (
	"math"
	"unsafe"
)

// BorrowPool reserves actual alias positions in the original root slab. Each
// checkout uses one of those positions with a fresh generation, never another
// reservation, scope or free-reference search. It grants no primary rights.
// Its separate metadata remains charged until Close and the last actual use.
type BorrowPool struct {
	self             *BorrowPool
	root             *Root
	source, metadata Reference
	indices          []uint32
	remaining        int
	closed           bool
	flexible         bool
	shared           bool
	metadataOwned    bool
}

func BorrowPoolCharge(capacity uint32) (Vector, error) {
	if capacity == 0 || uint64(capacity) > uint64(math.MaxInt)/uint64(unsafe.Sizeof(uint32(0))) {
		return Vector{}, ErrConfiguration
	}
	return Vector{SDKBytes: uint64(unsafe.Sizeof(BorrowPool{})) + uint64(capacity)*uint64(unsafe.Sizeof(uint32(0))), Items: 1}, nil
}

// NewBorrowPool takes only its metadata owner and borrows the existing source.
// Admission is local and complete: a failure releases every unpublished alias.
// The source must remain the same primary while future checkouts are permitted.
func NewBorrowPool(source, metadata Reference, capacity uint32) (_ *BorrowPool, err error) {
	return newBorrowPool(source, metadata, capacity, false, false)
}

// NewBorrowPoolForSources reserves dependency positions before the future
// application's actual parents are known. Idle positions belong to this
// metadata; checkout attaches one position to the supplied original primary.
// It never copies a source, renews its authority, or allocates a reference at
// runtime. The metadata and every borrowed source must share one Environment.
func NewBorrowPoolForSources(metadata Reference, capacity uint32) (*BorrowPool, error) {
	return newBorrowPool(metadata, metadata, capacity, true, false)
}

// Metadata returns the pool-owned primary responsibility. Independent pools
// consume the constructor's metadata handle, so callers that retain the
// backing charge must replace their stale pre-admission handle with this one.
func (p *BorrowPool) Metadata() Reference {
	if p == nil || p.self != p {
		return Reference{}
	}
	return p.metadata
}

// NewBorrowPoolInBacking admits aliases for a component whose metadata is
// already included in a larger SDK aggregate. It borrows that aggregate; it
// does not Take, partition or refund any part of the shared primary. The
// aggregate's charge must include every component's BorrowPoolCharge. Unlike
// detached result pools, this pool retains all original admission fences.
func NewBorrowPoolInBacking(backing Reference, capacity uint32) (*BorrowPool, error) {
	return newBorrowPool(backing, backing, capacity, true, true)
}

func newBorrowPool(source, metadata Reference, capacity uint32, flexible, shared bool) (_ *BorrowPool, err error) {
	charge, err := BorrowPoolCharge(capacity)
	if err != nil {
		return nil, err
	}
	if err = metadata.CheckSameEnvironment(source); err != nil {
		return nil, err
	}
	r := source.root
	r.mu.Lock()
	s, c := source.slotsLocked()
	m, mc := metadata.slotsLocked()
	valid := s != nil && s.primary && m != nil && m.primary && (c != mc || flexible && source == metadata) && uint64(capacity) <= uint64(len(r.refs))
	r.mu.Unlock()
	if !valid {
		return nil, ErrOwner
	}
	var owned Reference
	metadataOwned := true
	if shared {
		if err = metadata.CheckMinimum(charge); err == nil {
			owned, err = metadata.Borrow()
		}
	} else {
		owned, err = metadata.Take(charge)
	}
	if err != nil {
		return nil, err
	}
	if flexible {
		source = owned
	}
	p := &BorrowPool{root: r, source: source, metadata: owned, flexible: flexible, shared: shared, metadataOwned: metadataOwned, indices: make([]uint32, 0, int(capacity))}
	p.self = p
	adopted := false
	defer func() {
		if !adopted {
			p.Close()
		}
	}()
	err = func() error {
		r.mu.Lock()
		defer r.mu.Unlock()
		s, c := source.slotsLocked()
		if s == nil || !s.primary && !shared {
			return ErrOwner
		}
		if err := r.checkCharge(s, c); err != nil {
			return err
		}
		if m, mc := owned.slotsLocked(); m == nil {
			return ErrOwner
		} else if err := r.checkCharge(m, mc); err != nil {
			return err
		}
		nextIndex := 0
		for range capacity {
			index := -1
			for nextIndex < len(r.refs) {
				i := nextIndex
				nextIndex++
				// Admission and the first checkout each invalidate the former
				// handle. A slot with no checkout generation is not capacity.
				if !r.refs[i].active && r.refs[i].generation < math.MaxUint64-1 {
					index = i
					break
				}
			}
			if index < 0 || c.refs == math.MaxUint32 {
				return ErrCapacity
			}
			ref := &r.refs[index]
			*ref = referenceSlot{borrowPool: p, protectedIdle: true, generation: ref.generation + 1, charge: s.charge, chargeGeneration: c.generation, owner: s.owner, accounts: s.accounts, count: s.count, active: true}
			r.referenceExtent = max(r.referenceExtent, index+1)
			r.attachScopes(c, s.accounts[:s.count])
			c.refs++
			r.referenceCount++
			p.indices = append(p.indices, uint32(index))
			p.remaining++
		}
		return nil
	}()
	if err != nil {
		// Admission is transactional. Close must run while the constructor's
		// metadata handle is still available so every published idle position
		// and the metadata charge are returned on partial failure.
		r.mu.Lock()
		p.closed = true
		for _, index := range p.indices {
			s := &r.refs[index]
			if s.active && s.borrowPool == p && s.protectedIdle {
				p.releaseIdleLocked(index, s)
			}
		}
		p.cleanupLocked()
		r.mu.Unlock()
		return nil, err
	}
	adopted = true
	return p, nil
}

func (p *BorrowPool) checkLocked(source Reference) (*referenceSlot, *chargeSlot, error) {
	if p.closed || !p.flexible && source != p.source {
		return nil, nil, ErrOwner
	}
	s, c := source.slotsLocked()
	if s == nil || !s.primary {
		return nil, nil, ErrOwner
	}
	if err := p.root.checkCharge(s, c); err != nil {
		return nil, nil, err
	}
	m, mc := p.metadata.slotsLocked()
	if m == nil {
		return nil, nil, ErrOwner
	}
	if p.flexible && s.owner.Environment != m.owner.Environment {
		return nil, nil, ErrOwner
	}
	if err := p.checkMetadataLocked(m, mc); err != nil {
		return nil, nil, err
	}
	return s, c, nil
}

func (p *BorrowPool) checkMetadataLocked(m *referenceSlot, mc *chargeSlot) error {
	if !p.flexible || p.shared {
		return p.root.checkCharge(m, mc)
	}
	if p.root.closed || mc.sealed {
		return ErrClosed
	}
	for _, a := range m.accounts[:m.count] {
		s := a.slotLocked(p.root)
		// A completed result can retain these original positions after its
		// transport closes. The selected parent still passes its own full
		// authority check; this metadata grants capacity, not Session access.
		if s == nil || s.closed && s.key.Kind != SessionAccount && s.key.Kind != DirectionAccount {
			return ErrClosed
		}
	}
	return nil
}

func (p *BorrowPool) CheckSource(source Reference) error {
	if p == nil || p.self != p || source.root != p.root {
		return ErrOwner
	}
	p.root.mu.Lock()
	defer p.root.mu.Unlock()
	_, _, err := p.checkLocked(source)
	return err
}

func (p *BorrowPool) Borrow(source Reference) (Reference, error) {
	if p == nil || p.self != p || source.root != p.root {
		return Reference{}, ErrOwner
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c, err := p.checkLocked(source)
	if err != nil {
		return Reference{}, err
	}
	for _, index := range p.indices {
		alias := &r.refs[index]
		if p.flexible {
			if !alias.active || alias.borrowPool != p || !alias.protectedIdle || alias.generation == math.MaxUint64 {
				continue
			}
			if c.refs == math.MaxUint32 {
				return Reference{}, ErrCapacity
			}
			// The metadata primary stays live while any position is lent. Its
			// own charge therefore cannot disappear during this exact relink.
			_, parked := p.metadata.slotsLocked()
			r.releaseScopes(parked, alias.accounts[:alias.count])
			parked.refs--
			*alias = referenceSlot{borrowPool: p, generation: alias.generation + 1, charge: s.charge, chargeGeneration: c.generation, owner: s.owner, accounts: s.accounts, count: s.count, active: true}
			r.attachScopes(c, s.accounts[:s.count])
			c.refs++
			return Reference{r, index, alias.generation}, nil
		}
		if alias.active && alias.borrowPool == p && alias.protectedIdle && alias.generation < math.MaxUint64 && alias.chargeGeneration == c.generation && alias.charge == s.charge && sameProtectedScopes(alias, s) {
			alias.generation++
			alias.protectedIdle = false
			return Reference{r, index, alias.generation}, nil
		}
	}
	return Reference{}, ErrCapacity
}

// The root Release gate calls this for the same live alias. Returning a use
// neither refunds the source nor permits stale copies to release a later use.
func (p *BorrowPool) releaseLocked(ref Reference, slot *referenceSlot, _ *chargeSlot) {
	if !p.closed {
		if p.flexible {
			// Settle the source's actual scopes and physical tail first. Reuse
			// only this reserved slot; no free-reference search is permitted.
			slot.borrowPool = nil
			ref.releaseLocked()
			m, mc := p.metadata.slotsLocked()
			*slot = referenceSlot{borrowPool: p, protectedIdle: true, generation: slot.generation, charge: m.charge, chargeGeneration: mc.generation, owner: m.owner, accounts: m.accounts, count: m.count, active: true}
			p.root.attachScopes(mc, m.accounts[:m.count])
			mc.refs++
			p.root.referenceCount++
			return
		}
		// Keep the alias's actual original scopes. A source or alias whose
		// scopes changed cannot use this slot for a later checkout.
		slot.protectedIdle = true
		return
	}
	slot.borrowPool = nil
	p.remaining--
	// The pool owns this idle slot; release it directly after detaching the
	// pool marker so slots protected by the pool's idle state can be retired.
	ref.releaseLocked()
	p.cleanupLocked()
}

func (p *BorrowPool) releaseIdleLocked(index uint32, slot *referenceSlot) {
	if slot == nil || !slot.active || slot.borrowPool != p || !slot.protectedIdle {
		return
	}
	generation := slot.generation
	slot.protectedIdle = false
	slot.borrowPool = nil
	p.remaining--
	Reference{p.root, index, generation}.releaseLocked()
	p.cleanupLocked()
}

// CheckAvailable prevents a workload from recycling its dependency allowance
// while an older preparation, result waiter or decoder still retains a parent.
func (p *BorrowPool) CheckAvailable() error {
	if p == nil || p.self != p {
		return ErrOwner
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	m, mc := p.metadata.slotsLocked()
	if m == nil {
		return ErrOwner
	}
	if err := r.checkCharge(m, mc); err != nil {
		return err
	}
	for _, index := range p.indices {
		s := &r.refs[index]
		if !s.active || s.borrowPool != p || !s.protectedIdle || s.generation == math.MaxUint64 {
			return ErrCapacity
		}
	}
	return nil
}

func (p *BorrowPool) Close() {
	if p == nil || p.self != p {
		return
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.drainWaitersLocked()
	if p.closed {
		return
	}
	p.closed = true
	for _, index := range p.indices {
		s := &r.refs[index]
		if s.active && s.borrowPool == p && s.protectedIdle {
			p.releaseIdleLocked(index, s)
		}
	}
	p.cleanupLocked()
}

func (p *BorrowPool) cleanupLocked() {
	if !p.closed || p.remaining != 0 {
		return
	}
	p.indices = nil
	p.source = Reference{}
	if p.metadataOwned && p.metadata != (Reference{}) {
		p.metadata.releaseLocked()
	}
	p.metadata = Reference{}
}

func (p *BorrowPool) CleanupComplete() bool {
	if p == nil || p.self != p {
		return true
	}
	p.root.mu.Lock()
	defer p.root.mu.Unlock()
	return p.closed && p.remaining == 0
}

func (*BorrowPool) String() string               { return "Flowersec.BorrowPool" }
func (*BorrowPool) GoString() string             { return "Flowersec.BorrowPool" }
func (*BorrowPool) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

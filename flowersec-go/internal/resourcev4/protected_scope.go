package resourcev4

// BorrowScope retains this same physical protected backing in the exact
// accounting scopes of another already admitted owner. No bytes are allocated
// or charged twice at the root; each additional Session still admits the full
// vector before sharing it. Tenant and Environment generations must agree.
// The caller retains the returned borrow through every use in those scopes.
func (p *ProtectedReservation) BorrowScope(owner Reference) (Reference, error) {
	if p == nil || p.root == nil || owner.root != p.root {
		return Reference{}, ErrOwner
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if int(p.charge) >= len(r.charges) || int(p.index) >= len(r.refs) {
		return Reference{}, ErrOwner
	}
	c, s := &r.charges[p.charge], &r.refs[p.index]
	o, oc := owner.slotsLocked()
	if o == nil || !c.active || c.generation != p.generation || c.protected != p || c.protectedClosed || p.hasAnchor || !s.active || s.owner.Environment != o.owner.Environment {
		return Reference{}, ErrOwner
	}
	if err := r.checkCharge(o, oc); err != nil {
		return Reference{}, err
	}
	if !s.protectedIdle {
		if err := r.checkCharge(s, c); err != nil {
			return Reference{}, err
		}
	}
	for _, a := range s.accounts[:s.count] {
		if a.slotLocked(r) == nil || a.slotLocked(r).closed {
			return Reference{}, ErrClosed
		}
	}
	for _, a := range s.accounts[:s.count] {
		kind := a.slotLocked(r).key.Kind
		if (kind == TenantAccount || kind == EnvironmentAccount) && accountIndex(o.accounts[:o.count], a) < 0 {
			return Reference{}, ErrOwner
		}
	}
	for _, a := range o.accounts[:o.count] {
		kind := a.slotLocked(r).key.Kind
		if (kind == TenantAccount || kind == EnvironmentAccount) && accountIndex(s.accounts[:s.count], a) < 0 {
			return Reference{}, ErrOwner
		}
	}
	// Scope anchors use their already charged root reference slots as a
	// bounded linked index. Many actual Sessions do not widen every charge's
	// ordinary eight-account metadata or allocate an unaccounted map.
	for _, a := range o.accounts[:o.count] {
		if accountIndex(c.accounts[:c.count], a) < 0 && !r.protectedScopeHeld(c, a, nil) {
			scope := a.slotLocked(r)
			if !fits(scope.used, scope.limit, c.value) {
				return Reference{}, ErrCapacity
			}
		}
	}
	index := r.freeReference()
	if index < 0 {
		return Reference{}, ErrCapacity
	}
	ref := &r.refs[index]
	*ref = referenceSlot{generation: ref.generation + 1, charge: s.charge, chargeGeneration: c.generation, owner: s.owner, accounts: o.accounts, count: o.count, active: true, protectedScope: true, protectedNext: p.scopeFirst}
	r.activateReference(uint32(index))
	for _, a := range ref.accounts[:ref.count] {
		if accountIndex(c.accounts[:c.count], a) < 0 && !r.protectedScopeHeld(c, a, nil) {
			scope := a.slotLocked(r)
			scope.used, _ = scope.used.Add(c.value)
			scope.charges++
		}
	}
	p.scopeFirst = uint32(index) + 1
	c.refs++
	r.referenceCount++
	p.scopeCount++
	return Reference{r, uint32(index), ref.generation}, nil
}

func (r *Root) protectedScopeHeld(c *chargeSlot, a accountSlotKey, except *referenceSlot) bool {
	if c.protected == nil {
		return false
	}
	for next := c.protected.scopeFirst; next != 0; {
		s := &r.refs[next-1]
		if s != except && accountIndex(s.accounts[:s.count], a) >= 0 {
			return true
		}
		next = s.protectedNext
	}
	return false
}

func (r *Root) releaseProtectedScopeLocked(s *referenceSlot, c *chargeSlot) {
	p := c.protected
	for _, a := range s.accounts[:s.count] {
		if accountIndex(c.accounts[:c.count], a) < 0 && !r.protectedScopeHeld(c, a, s) {
			scope := a.slotLocked(r)
			scope.used = scope.used.subtract(c.value)
			scope.charges--
			if scope.closed && scope.charges == 0 {
				scope.active = false
			}
		}
	}
	next := &p.scopeFirst
	for *next != 0 {
		entry := &r.refs[*next-1]
		if entry == s {
			*next = s.protectedNext
			break
		}
		next = &entry.protectedNext
	}
	p.scopeCount--
	s.protectedScope, s.protectedNext = false, 0
}

// UseComplete distinguishes actual output/alias exit from idle scope anchors.
// Anchors can retire only after this predicate, including after future Close.
func (p *ProtectedReservation) UseComplete() bool {
	if p == nil || p.root == nil {
		return true
	}
	p.root.mu.Lock()
	defer p.root.mu.Unlock()
	s, c := p.slotsLocked()
	return s == nil || p.idleLocked(s, c)
}

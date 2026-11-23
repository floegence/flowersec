package resourcev4

// DetachSessionScope belongs to an original completed-input ownership transfer.
// It removes only this reference's Session/direction accounting; any other
// physical alias keeps its own original scopes charged. Tenant, Environment,
// root, bytes, result position and reference identity remain unchanged. No new
// slot or resource is acquired at completion. Reusable backing accepts this only when its original result anchor already
// preserves the complete Session floor; ordinary protected work cannot detach.
func (ref Reference) DetachSessionScope() error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || c.protected != nil && (!c.protected.hasAnchor || ref.index == c.protected.anchorIndex) {
		return ErrOwner
	}
	// A completed input or an actual physical retirement may race Session
	// close. Removing only those scopes must remain possible; this cannot
	// reopen a closed root, Environment, tenant or sealed backing owner.
	if r.closed || c.sealed {
		return ErrClosed
	}
	for _, account := range s.accounts[:s.count] {
		scope := account.slotLocked(r)
		if scope == nil || scope.closed && scope.key.Kind != SessionAccount && scope.key.Kind != DirectionAccount {
			return ErrClosed
		}
	}
	var removed [MaxAccountsPerCharge]Account
	n, kept := 0, 0
	for _, account := range s.accounts[:s.count] {
		kind := account.slotLocked(r).key.Kind
		if kind == SessionAccount || kind == DirectionAccount {
			removed[n] = account
			n++
		} else {
			s.accounts[kept] = account
			kept++
		}
	}
	clear(s.accounts[kept:])
	s.count = kept
	r.releaseScopes(c, removed[:n])
	r.drainWaitersLocked()
	return nil
}

// RestoreOriginalScopes is a mechanical return to an existing protected
// responsibility. anchor must be an actual reference to the same backing and
// already hold every restored scope. It creates neither a new alias nor budget.
func (ref Reference) RestoreOriginalScopes(anchor Reference) error {
	if ref.root == nil || ref.root != anchor.root {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	a, ac := anchor.slotsLocked()
	if s == nil || a == nil || ac != c {
		return ErrOwner
	}
	for _, scope := range s.accounts[:s.count] {
		if accountIndex(a.accounts[:a.count], scope) < 0 {
			return ErrOwner
		}
	}
	r.restoreScopesLocked(s, c, a)
	return nil
}

func (r *Root) restoreScopesLocked(s *referenceSlot, c *chargeSlot, a *referenceSlot) {
	var added [MaxAccountsPerCharge]Account
	n := 0
	for _, scope := range a.accounts[:a.count] {
		if accountIndex(s.accounts[:s.count], scope) < 0 {
			added[n] = scope
			n++
		}
	}
	r.attachScopes(c, added[:n])
	s.accounts, s.count = a.accounts, a.count
}

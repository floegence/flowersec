package resourcev4

// ClaimVerificationRegistry binds one retained registry to the physical
// Environment budget. Its original charge must stay held until that budget is
// permanently closed. Equal IDs in a second registry cannot split history.
func (ref Reference) ClaimVerificationRegistry() error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !s.primary || s.owner.Environment == ([16]byte{}) {
		return ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return err
	}
	for _, a := range s.accounts[:s.count] {
		kind := a.slotLocked(r).key.Kind
		if kind == SessionAccount || kind == DirectionAccount {
			return ErrOwner
		}
	}
	for _, charge := range r.charges {
		if charge.active && charge.verificationEnvironment == s.owner.Environment {
			return ErrOwner
		}
	}
	c.verificationEnvironment = s.owner.Environment
	return nil
}

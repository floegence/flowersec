package resourcev4

// CopyResultAccounts projects the exact remaining scope generations of an
// original completed result. It does not infer an Environment from labels or
// permit a caller to omit a surviving tenant/account from its next vector.
func (ref Reference) CopyResultAccounts(dst []Account) (int, error) {
	if ref.root == nil {
		return 0, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !c.resultOwner || !s.primary {
		return 0, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return 0, err
	}
	if len(dst) < s.count {
		return 0, ErrCapacity
	}
	return copy(dst, s.accounts[:s.count]), nil
}

// CheckAllocationScope fixes dynamic children to the exact original root,
// Environment and account generations of their already admitted parent. A
// factory cannot substitute another root or omit a tenant/Session account when
// it creates payload, result or callback backing later in the same lifecycle.
func (ref Reference) CheckAllocationScope(root *Root, owner OwnerKey, accounts []Account) error {
	if root == nil || ref.root != root {
		return ErrOwner
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil {
		return ErrOwner
	}
	if err := root.checkCharge(s, c); err != nil {
		return err
	}
	if !root.validOwner(owner) || owner.ProfileRevision != s.owner.ProfileRevision || owner.Environment != s.owner.Environment || len(accounts) != s.count {
		return ErrOwner
	}
	for index, account := range accounts {
		if account.slotLocked(root) == nil || accountIndex(s.accounts[:s.count], account) < 0 {
			return ErrOwner
		}
		for _, earlier := range accounts[:index] {
			if earlier == account {
				return ErrOwner
			}
		}
	}
	return nil
}

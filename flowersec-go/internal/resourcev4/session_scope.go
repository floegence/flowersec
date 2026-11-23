package resourcev4

// CheckSessionScope verifies one already charged Session position against the
// exact trusted tenant and Session accounts. Account identity includes its root
// and original generation; matching IDs in another root or a reused slot do not
// establish the same scope. Only this reference's accounts count, not accounts
// held by another owner of the same backing during a Transfer.
//
// The check changes no ownership or charge and grants no protocol authority.
// Borrowed references keep their original scopes. Callers acquiring the primary
// reservation must still use Take; later submission gates must still check the
// original reference because this observation does not keep an account open.
func (ref Reference) CheckSessionScope(tenant, session Account) error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil {
		return ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return err
	}
	for _, required := range [...]struct {
		account Account
		kind    AccountKind
	}{{tenant, TenantAccount}, {session, SessionAccount}} {
		account := required.account.slotLocked(r)
		if account == nil || account.key.Kind != required.kind || accountIndex(s.accounts[:s.count], required.account) < 0 {
			return ErrOwner
		}
		if account.closed {
			return ErrClosed
		}
	}
	if c.value[Sessions] != 1 {
		return ErrCapacity
	}
	return nil
}

package resourcev4

import "math"

// CheckBorrowedFrom proves that this original alias still belongs to the
// supplied primary's exact backing, owner and account set. Equal Environment
// IDs or matching charges alone do not establish this relationship. Take may
// advance the primary handle without changing the alias's original backing.
func (ref Reference) CheckBorrowedFrom(primary Reference) error {
	if ref.root == nil || ref.root != primary.root {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	p, pc := primary.slotsLocked()
	if s == nil || p == nil || s.primary || !p.primary || c != pc || s.owner != p.owner || s.transferID != ([16]byte{}) || p.transferID != ([16]byte{}) || !sameProtectedScopes(s, p) {
		return ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return err
	}
	return r.checkCharge(p, pc)
}

// TakeBorrow moves one already admitted Borrow reference into its final owner
// without acquiring another reference slot or changing any charge/account.
// Only ordinary non-primary borrows can move: primary owners and predecessors
// of a named Transfer keep their separate ownership/replay rules. A successful
// move invalidates every copy of the supplied handle; failure leaves it intact.
// The moved handle remains a borrow and cannot mint further aliases or owners.
func (ref Reference) TakeBorrow() (Reference, error) {
	if ref.root == nil {
		return Reference{}, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || s.primary || s.transferID != ([16]byte{}) {
		return Reference{}, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return Reference{}, err
	}
	if s.generation == math.MaxUint64 {
		return Reference{}, ErrCapacity
	}
	s.generation++
	return Reference{r, ref.index, s.generation}, nil
}

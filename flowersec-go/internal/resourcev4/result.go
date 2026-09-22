package resourcev4

// MaxResultOwners is the local result-owner bound shared by every Environment
// and Session in this actual root. It counts preadmitted future short results,
// completed results and old physical tails, independently of network K/Q2.
const MaxResultOwners = 4096

// ReserveResult admits one result position and its complete backing atomically.
// The position follows this same charge through Take, Borrow, Transfer and
// protected reuse. Only final physical release makes it generally available.
func (r *Root) ReserveResult(owner OwnerKey, value Vector, accounts ...Account) (Reference, error) {
	if r == nil {
		return Reference{}, ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainWaitersLocked()
	return r.reserveResultLocked(owner, value, accounts)
}

func (r *Root) reserveResultLocked(owner OwnerKey, value Vector, accounts []Account) (Reference, error) {
	if r.closed {
		return Reference{}, ErrClosed
	}
	if r.resultCount == MaxResultOwners {
		return Reference{}, ErrCapacity
	}
	ref, err := r.reserveLocked(owner, value, accounts)
	if err != nil {
		return Reference{}, err
	}
	_, c := ref.slotsLocked()
	c.resultOwner = true
	r.resultCount++
	return ref, nil
}

func (ref Reference) CheckResultOwner() error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !s.primary || !c.resultOwner {
		return ErrOwner
	}
	return r.checkCharge(s, c)
}

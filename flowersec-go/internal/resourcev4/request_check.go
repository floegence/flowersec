package resourcev4

// CheckMinimum validates an unconsumed primary without changing its generation.
// Trusted preparation uses this before promising a future use of caller-owned
// backing. It does not grant an owner, scope, borrow or additional capacity.
func (ref Reference) CheckMinimum(minimum Vector) error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !s.primary {
		return ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return err
	}
	if !c.value.Contains(minimum) {
		return ErrCapacity
	}
	return nil
}

// CheckRequest validates a preadmitted allocation against its actual concrete
// use. It grants no additional quota and does not mutate the reservation. The
// exact owner, all account generations and result-owner class must match;
// a smaller concrete vector may retain its original conservative charge.
func (ref Reference) CheckRequest(request Request) error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	return r.checkRequestLocked(s, c, request)
}

// CheckAdmissionRequest validates the original unpublished protected backing.
// A previous checkout cannot become an original admission again. This neither
// checks out backing nor revives stale constructor handles.
func (p *ProtectedReservation) CheckAdmissionRequest(request Request) error {
	if p == nil || p.root == nil {
		return ErrOwner
	}
	r := p.root
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := p.checkoutReadyLocked(); err != nil {
		return err
	}
	s, c := p.slotsLocked()
	return r.checkRequestLocked(s, c, request)
}

func (r *Root) checkRequestLocked(s *referenceSlot, c *chargeSlot, request Request) error {
	if s == nil || !s.primary || s.owner != request.Owner || c.resultOwner != request.ResultOwner || s.count != len(request.Accounts) {
		return ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return err
	}
	if !c.value.Contains(request.Charge) {
		return ErrCapacity
	}
	for i, a := range request.Accounts {
		if accountIndex(s.accounts[:s.count], a) < 0 {
			return ErrOwner
		}
		for _, prior := range request.Accounts[:i] {
			if prior == a {
				return ErrOwner
			}
		}
	}
	return nil
}

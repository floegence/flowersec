package resourcev4

// RetainsCleanupScope attributes a live callback reference to its original
// Session account or original plan backing. Sealed accounts remain observable;
// this grants no admission, borrow, transfer, or release capability. Detached
// result references no longer carry the Session scope and therefore do not
// become Session callbacks merely because their Environment is shared.
func (ref Reference) RetainsCleanupScope(session Account, backing Reference) bool {
	if ref.root == nil {
		return false
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, charge := ref.slotsLocked()
	if s == nil {
		return false
	}
	if backing.root == r {
		_, original := backing.slotsLocked()
		if original != nil && original == charge {
			return true
		}
	}
	account := session.slotLocked(r)
	return account != nil && account.key.Kind == SessionAccount && accountIndex(s.accounts[:s.count], session.slotKey()) >= 0
}

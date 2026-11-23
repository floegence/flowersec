package resourcev4

import "math"

// OwnerKey is the local resource registry's exact owner/backing identity.
// Different keys never deduplicate implicitly. A backing shared by multiple
// users is acquired with Borrow or an explicit Transfer of this same charge.
type OwnerKey struct {
	ProfileRevision                [32]byte
	Environment, Instance, Backing [16]byte
	Kind                           uint16
	Direction                      uint8
}

type referenceSlot struct {
	protectedIdle    bool
	generation       uint64
	charge           uint32
	chargeGeneration uint64
	owner            OwnerKey
	accounts         [MaxAccountsPerCharge]Account
	count            int
	active, primary  bool
	transferID       [16]byte
	transferredTo    Reference
}

type Reference struct {
	root       *Root
	index      uint32
	generation uint64
}

func (r *Root) validOwner(key OwnerKey) bool {
	return key.ProfileRevision == r.profile && key.Environment != [16]byte{} && key.Instance != [16]byte{} && key.Backing != [16]byte{} && key.Kind != 0 && key.Direction <= 2
}

func (r *Root) freeReference() int {
	for i := range r.refs {
		if !r.refs[i].active && r.refs[i].generation < math.MaxUint64 {
			return i
		}
	}
	return -1
}

func (r *Root) ownerExists(owner OwnerKey) bool {
	for i := range r.refs {
		if r.refs[i].active && r.refs[i].owner == owner {
			return true
		}
	}
	return false
}

func accountIndex(accounts []Account, a Account) int {
	for i, existing := range accounts {
		if existing == a {
			return i
		}
	}
	return -1
}

func (r *Root) scopeSet(owner OwnerKey, value Vector, input []Account, existing *chargeSlot) (scopes [MaxAccountsPerCharge]Account, count int, err error) {
	if len(input) > MaxAccountsPerCharge {
		return scopes, 0, ErrConfiguration
	}
	additions := 0
	for _, a := range input {
		s := a.slotLocked(r)
		if s == nil || s.key.Kind == EnvironmentAccount && s.key.ID != owner.Environment {
			return scopes, 0, ErrOwner
		}
		if s.closed {
			return scopes, 0, ErrClosed
		}
		if accountIndex(scopes[:count], a) >= 0 {
			continue
		}
		alreadyCharged := existing != nil && accountIndex(existing.accounts[:existing.count], a) >= 0
		if !alreadyCharged {
			if !fits(s.used, s.limit, value) {
				return scopes, 0, ErrCapacity
			}
			additions++
		}
		scopes[count] = a
		count++
	}
	if existing != nil && existing.count+additions > MaxAccountsPerCharge {
		return scopes, 0, ErrCapacity
	}
	return scopes, count, nil
}

// Same backing is charged once per actual scope, even while old and new
// owners overlap. Each scope retains the charge until its own final ref exits.
func (r *Root) attachScopes(c *chargeSlot, scopes []Account) {
	for _, a := range scopes {
		i := accountIndex(c.accounts[:c.count], a)
		if i < 0 {
			i = c.count
			c.accounts[i] = a
			c.count++
			account := a.slotLocked(r)
			account.used, _ = account.used.Add(c.value)
			account.charges++
		}
		c.accountRefs[i]++
	}
}

func (r *Root) releaseScopes(c *chargeSlot, scopes []Account) {
	for _, a := range scopes {
		i := accountIndex(c.accounts[:c.count], a)
		c.accountRefs[i]--
		if c.accountRefs[i] != 0 {
			continue
		}
		account := a.slotLocked(r)
		account.used = account.used.subtract(c.value)
		account.charges--
		if account.closed && account.charges == 0 {
			account.active = false
		}
		c.count--
		c.accounts[i], c.accountRefs[i] = c.accounts[c.count], c.accountRefs[c.count]
		c.accounts[c.count], c.accountRefs[c.count] = Account{}, 0
	}
}

// Reserve atomically charges the root and every supplied account. Accounts
// may overlap (tenant/Environment/Session/direction/pool); the root and each
// exact account are charged only once. A foreign root is rejected before any
// mutation, never partly acquired while waiting for another budget authority.
func (r *Root) Reserve(owner OwnerKey, value Vector, accounts ...Account) (Reference, error) {
	if r == nil {
		return Reference{}, ErrConfiguration
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drainWaitersLocked()
	return r.reserveLocked(owner, value, accounts)
}

func (r *Root) reserveLocked(owner OwnerKey, value Vector, accounts []Account) (Reference, error) {
	if !r.validOwner(owner) || value == (Vector{}) || len(accounts) > MaxAccountsPerCharge {
		return Reference{}, ErrConfiguration
	}
	if r.closed {
		return Reference{}, ErrClosed
	}
	if r.ownerExists(owner) {
		return Reference{}, ErrOwner
	}
	scopes, count, err := r.scopeSet(owner, value, accounts, nil)
	if err != nil {
		return Reference{}, err
	}
	if !fits(r.used, r.limit, value) {
		return Reference{}, ErrCapacity
	}
	chargeIndex := -1
	for i := range r.charges {
		if !r.charges[i].active && r.charges[i].generation < math.MaxUint64 {
			chargeIndex = i
			break
		}
	}
	refIndex := r.freeReference()
	if chargeIndex < 0 || refIndex < 0 {
		return Reference{}, ErrCapacity
	}
	c := &r.charges[chargeIndex]
	*c = chargeSlot{generation: c.generation + 1, value: value, refs: 1, active: true}
	s := &r.refs[refIndex]
	*s = referenceSlot{generation: s.generation + 1, charge: uint32(chargeIndex), chargeGeneration: c.generation, owner: owner, accounts: scopes, count: count, active: true, primary: true}
	r.used, _ = r.used.Add(value)
	r.attachScopes(c, scopes[:count])
	r.chargeCount++
	r.referenceCount++
	return Reference{r, uint32(refIndex), s.generation}, nil
}

func (ref Reference) slotsLocked() (*referenceSlot, *chargeSlot) {
	r := ref.root
	if ref.generation == 0 || uint64(ref.index) >= uint64(len(r.refs)) {
		return nil, nil
	}
	s := &r.refs[ref.index]
	if !s.active || s.protectedIdle || s.generation != ref.generation {
		return nil, nil
	}
	c := &r.charges[s.charge]
	if !c.active || c.generation != s.chargeGeneration {
		return nil, nil
	}
	return s, c
}

func (r *Root) checkCharge(ref *referenceSlot, c *chargeSlot) error {
	if r.closed || c.sealed {
		return ErrClosed
	}
	for _, a := range ref.accounts[:ref.count] {
		if s := a.slotLocked(r); s == nil || s.closed {
			return ErrClosed
		}
	}
	return nil
}

func (ref Reference) Check() error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if c == nil {
		return ErrOwner
	}
	return r.checkCharge(s, c)
}

// CheckRetained proves only that an original responsibility remains charged.
// Root/account Close seals new admission, not the physical cleanup of work
// already accepted. This grants no Borrow, Take, transfer or publication right;
// those operations still require the ordinary open-owner checks.
func (ref Reference) CheckRetained() error {
	if ref.root == nil {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	_, c := ref.slotsLocked()
	if c == nil {
		return ErrOwner
	}
	return nil
}

// CheckSameEnvironment rejects private budget roots and cross-Environment
// composition before any ownership changes. Equal IDs/configuration in two
// roots do not establish a shared aggregate bound.
func (ref Reference) CheckSameEnvironment(other Reference) error {
	if ref.root == nil || ref.root != other.root {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ac := ref.slotsLocked()
	b, bc := other.slotsLocked()
	if a == nil || b == nil || a.owner.Environment != b.owner.Environment {
		return ErrOwner
	}
	if err := r.checkCharge(a, ac); err != nil {
		return err
	}
	return r.checkCharge(b, bc)
}

// CheckSameRoot is only for components intentionally shared across real
// Environments, such as the root's application executor. It does not prove
// that protocol, trust, payload or per-Environment owners may be interchanged.
func (ref Reference) CheckSameRoot(other Reference) error {
	if ref.root == nil || ref.root != other.root {
		return ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ac := ref.slotsLocked()
	b, bc := other.slotsLocked()
	if a == nil || b == nil {
		return ErrOwner
	}
	if err := r.checkCharge(a, ac); err != nil {
		return err
	}
	return r.checkCharge(b, bc)
}

// ClaimApplicationExecutor fixes the one physical executor for this root's
// lifetime. This registers local backing, not invocation/dispatch authority.
// Environments borrow that executor; closing a borrower or creating another
// Environment cannot install fresh ordinary/resident capacity. The trusted
// root factory closes the original executor before releasing the root itself.
func (ref Reference) ClaimApplicationExecutor() error {
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
	// The shared executor cannot inherit a borrower's tenant/Environment or
	// Session close fence. Each invocation carries those original scopes.
	for _, account := range s.accounts[:s.count] {
		if account.slotLocked(r).key.Kind != PoolAccount {
			return ErrOwner
		}
	}
	if r.applicationExecutorClaimed {
		return ErrOwner
	}
	r.applicationExecutorClaimed = true
	return nil
}

// EnvironmentClosed proves that this original budget authority cannot admit
// further work in the owning Environment. Sealing an individual reservation
// is deliberately insufficient to discard shared verification history.
func (ref Reference) EnvironmentClosed() bool {
	if ref.root == nil {
		return false
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, _ := ref.slotsLocked()
	if s == nil {
		return false
	}
	if r.closed {
		return true
	}
	for _, a := range s.accounts[:s.count] {
		account := a.slotLocked(r)
		if account != nil && account.key.Kind == EnvironmentAccount && account.key.ID == s.owner.Environment && account.closed {
			return true
		}
	}
	return false
}

// Take attaches an original reservation to a concrete owner without acquiring
// another quota. It invalidates the supplied handle, so a stale constructor
// caller cannot attach twice or release the new owner's reservation.
func (ref Reference) Take(minimum Vector) (Reference, error) {
	if ref.root == nil {
		return Reference{}, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !s.primary {
		return Reference{}, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return Reference{}, err
	}
	if !c.value.Contains(minimum) || s.generation == math.MaxUint64 {
		return Reference{}, ErrCapacity
	}
	s.generation++
	return Reference{r, ref.index, s.generation}, nil
}

// Borrow admits one real alias/task reference to this same backing. Only the
// current owner may create borrows; neither copies nor old transferred owners
// can manufacture new uses. Reference metadata comes from the fixed root slab.
func (ref Reference) Borrow() (Reference, error) {
	if ref.root == nil {
		return Reference{}, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil || !s.primary {
		return Reference{}, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return Reference{}, err
	}
	if c.protected != nil {
		if alias, ok := c.protected.borrowLocked(s); ok {
			return alias, nil
		}
	}
	index := r.freeReference()
	if index < 0 {
		return Reference{}, ErrCapacity
	}
	borrow := &r.refs[index]
	*borrow = referenceSlot{generation: borrow.generation + 1, charge: s.charge, chargeGeneration: c.generation, owner: s.owner, accounts: s.accounts, count: s.count, active: true}
	r.attachScopes(c, s.accounts[:s.count])
	c.refs++
	r.referenceCount++
	return Reference{r, uint32(index), borrow.generation}, nil
}

// Transfer registers one exact same-backing owner transition. The old handle
// and all existing borrows remain charged until their real release. A repeat
// of the same event returns only its original still-held target; a different
// event cannot transfer this old owner again. Optional replacement accounts
// move local preauth/pool/Session ownership atomically, retaining original
// tenant and Environment scopes. Omitting accounts keeps the original scopes.
// Real distinct allocations still require their own full reservation.
func (ref Reference) Transfer(owner OwnerKey, id [16]byte, accounts ...Account) (Reference, error) {
	if ref.root == nil || id == [16]byte{} || !ref.root.validOwner(owner) {
		return Reference{}, ErrOwner
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	s, c := ref.slotsLocked()
	if s == nil {
		return Reference{}, ErrOwner
	}
	if err := r.checkCharge(s, c); err != nil {
		return Reference{}, err
	}
	if len(accounts) == 0 {
		accounts = s.accounts[:s.count]
	}
	scopes, count, err := r.scopeSet(owner, c.value, accounts, c)
	if err != nil {
		return Reference{}, err
	}
	for _, a := range s.accounts[:s.count] {
		kind := a.slotLocked(r).key.Kind
		if (kind == TenantAccount || kind == EnvironmentAccount) && accountIndex(scopes[:count], a) < 0 {
			return Reference{}, ErrOwner
		}
	}
	if s.transferID != [16]byte{} {
		target, _ := s.transferredTo.slotsLocked()
		if s.transferID == id && target != nil && target.owner == owner {
			if count != target.count {
				return Reference{}, ErrOwner
			}
			for _, a := range scopes[:count] {
				if accountIndex(target.accounts[:target.count], a) < 0 {
					return Reference{}, ErrOwner
				}
			}
			return s.transferredTo, nil
		}
		return Reference{}, ErrOwner
	}
	if !s.primary || s.owner == owner || s.owner.ProfileRevision != owner.ProfileRevision || s.owner.Environment != owner.Environment || s.owner.Backing != owner.Backing || s.owner.Direction != owner.Direction || r.ownerExists(owner) {
		return Reference{}, ErrOwner
	}
	index := r.freeReference()
	if index < 0 {
		return Reference{}, ErrCapacity
	}
	target := &r.refs[index]
	*target = referenceSlot{generation: target.generation + 1, charge: s.charge, chargeGeneration: c.generation, owner: owner, accounts: scopes, count: count, active: true, primary: true}
	r.attachScopes(c, scopes[:count])
	s.primary = false
	s.transferID, s.transferredTo = id, Reference{r, uint32(index), target.generation}
	c.refs++
	r.referenceCount++
	return s.transferredTo, nil
}

// Seal revokes new use while retaining every byte/work/item charge. Closing
// a Session or timing out cleanup must not call Release for a still-live task.
func (ref Reference) Seal() {
	if ref.root == nil {
		return
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.drainWaitersLocked()
	if s, c := ref.slotsLocked(); s != nil && s.primary {
		c.sealed = true
	}
}

func (ref Reference) Release() {
	if ref.root == nil {
		return
	}
	r := ref.root
	r.mu.Lock()
	defer r.mu.Unlock()
	ref.releaseLocked()
	r.drainWaitersLocked()
}

func (ref Reference) releaseLocked() {
	r := ref.root
	s, c := ref.slotsLocked()
	if s == nil {
		return
	}
	if s.primary {
		c.sealed = true
	}
	if c.protected != nil && c.protected.owns(ref.index) {
		// Keep the original protected reference and its complete scope vector.
		// No generation may be checked out until all transferred/borrowed tails
		// have released their separate references to this same responsibility.
		c.protected.restoreScopesLocked(s, c)
		s.protectedIdle = true
		s.primary = false
		s.owner = r.refs[c.protected.index].owner
		r.finishProtectedLocked(c)
		return
	}
	s.active = false
	s.owner = OwnerKey{}
	s.transferredTo = Reference{}
	r.releaseScopes(c, s.accounts[:s.count])
	s.accounts, s.count = [MaxAccountsPerCharge]Account{}, 0
	c.refs--
	r.referenceCount--
	if c.refs != 0 {
		r.finishProtectedLocked(c)
		return
	}
	r.used = r.used.subtract(c.value)
	if c.resultOwner {
		r.resultCount--
	}
	*c = chargeSlot{generation: c.generation}
	r.chargeCount--
}

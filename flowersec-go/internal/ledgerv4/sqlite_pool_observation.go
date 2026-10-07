package ledgerv4

import "sync"

// PoolSpendObservation is caller-owned compact status. Only the original
// admitted SQLitePoolSpend can publish transitions. It retains no proof,
// credential, database, authority reference or dispatch/activation capability.
// It is not a durable receipt and cannot authorize a subsequent connection.
type PoolSpendObservation struct {
	mu                                 sync.Mutex
	owner                              *sqlitePoolSpend
	bound, started, committed, retired bool
}
type PoolSpendStatus struct{ Bound, Started, CommitKnown, Retired bool }

func (o *PoolSpendObservation) Snapshot() PoolSpendStatus {
	if o == nil {
		return PoolSpendStatus{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return PoolSpendStatus{o.bound, o.started, o.committed, o.retired}
}
func (o *PoolSpendObservation) bind(owner *sqlitePoolSpend) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if owner == nil || o.bound {
		return ErrOwner
	}
	o.owner = owner
	o.bound = true
	return nil
}
func (o *PoolSpendObservation) startedOriginal(owner *sqlitePoolSpend) {
	o.mu.Lock()
	if o.owner == owner && !o.retired {
		o.started = true
	}
	o.mu.Unlock()
}
func (o *PoolSpendObservation) committedOriginal(owner *sqlitePoolSpend) {
	o.mu.Lock()
	if o.owner == owner && o.started && !o.retired {
		o.committed = true
	}
	o.mu.Unlock()
}
func (o *PoolSpendObservation) retiredOriginal(owner *sqlitePoolSpend) {
	o.mu.Lock()
	if o.owner == owner {
		o.retired = true
		o.owner = nil
	}
	o.mu.Unlock()
}

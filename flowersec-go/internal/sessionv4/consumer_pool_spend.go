package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// ConsumePoolSQLite binds issuance-time pool material to the original local
// winner, verifies current activation trust before the write, and performs one
// TxA-P. Only its definite original commit may activate that same carrier. The
// complete graph and store workspace must have been admitted before this call.
func (a *SessionAdmissionReservation) ConsumePoolSQLite(store *ledgerv4.SQLiteStore, authority ledgerv4.SQLitePoolAuthority, activation *protocolv4.ActivationAuthority, proof []byte, reservation resourcev4.Reference) (x *InitialExchange, err error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	facts, err := activation.PoolSpendFacts(proof)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	if a.accepted != nil || a.config.Initial.ActivationSourceProfile != "preauthorized_pool" || a.binding.Role != protocolv4.ClientToServer || a.claimed || a.busy || a.authorization != nil {
		a.mu.Unlock()
		return nil, cryptov4.ErrTransition
	}
	err = a.checkLocked()
	if err == nil {
		err = activation.MatchOriginal(a.binding.Session, a.binding.Attempt, a.binding.Candidate)
	}
	if err == nil {
		a.authorization, err = a.subscriptions.Authorize(activation)
	}
	if err == nil {
		err = a.authorization.ConstrainHandshakeDeadline(a.config.Initial.Deadline)
	}
	if err == nil {
		_, err = a.authorization.CheckAdmission()
	}
	a.mu.Unlock()
	if err != nil {
		a.Close()
		return nil, err
	}
	claim, err := a.beginClaim()
	if err != nil {
		a.Close()
		return nil, err
	}
	defer func() {
		a.mu.Lock()
		a.claimActive = false
		a.signalLocked()
		a.mu.Unlock()
		if err != nil {
			a.Close()
			x = nil
		}
	}()
	guard := func() error { a.mu.Lock(); defer a.mu.Unlock(); return a.checkLocked() }
	durable, err := ledgerv4.NewSQLitePoolSpend(a.ctx, store, authority, facts, proof, a.poolOwner, a.config.Core.Clock, a.config.Initial.Deadline, guard, reservation, a.environment)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.poolSpend = durable
	err = a.checkLocked()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	err = durable.Consume(func() error {
		a.mu.Lock()
		check := a.checkLocked()
		if check == nil && (!a.claimActive || claim != &a.claim || a.committed || a.activated) {
			check = cryptov4.ErrTransition
		}
		if check == nil {
			a.committed = true
		}
		a.mu.Unlock()
		if check != nil {
			return check
		}
		var activateErr error
		x, activateErr = a.activateOriginal(activation, claim)
		return activateErr
	})
	return x, err
}

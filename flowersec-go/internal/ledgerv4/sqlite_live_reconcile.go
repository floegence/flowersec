package ledgerv4

import (
	"context"
	"errors"
)

// LiveAuthorizationFact is an independently verified external authorization
// observation, bound to the whole original request. It is not a receipt from
// the caller and does not contain, authorize, or synthesize activation material.
type LiveAuthorizationFact struct {
	Target  LiveSpendReadTarget
	Outcome AuthorizationOutcome
}

// LiveAuthorizationQuery is the trusted authority's optional read-only adapter.
// Query must not dispatch the original authorization callback. It uses the
// original stable request identity at the external system and verifies the
// returned fact before returning. Its admitted dependencies and actual I/O
// remain retained until this synchronous call exits, even after cancellation.
type LiveAuthorizationQuery interface {
	QueryAuthorization(context.Context, SQLiteIdentity, LiveSpendReadTarget) (LiveAuthorizationFact, error)
}

// ReconcileAuthorization monotonically resolves consumed/unknown using a
// verified external fact. Existing definite results are read without querying.
// A spending row must first finish its own original expiry/recovery boundary;
// this operation never competes with a live callback or fabricates not_started.
func (r *SQLiteLiveSpendRead) ReconcileAuthorization(query LiveAuthorizationQuery) (SpendReceipt, error) {
	if query == nil {
		return SpendReceipt{}, ErrConfiguration
	}
	if err := r.begin(); err != nil {
		return SpendReceipt{}, err
	}
	defer r.finish()
	v, err := r.read()
	if err != nil {
		return SpendReceipt{}, err
	}
	if !v.consumed || v.outcome != 0 {
		return liveSpendReceipt(v), nil
	}
	if v.version != 2 || len(v.proof) != 0 {
		return SpendReceipt{}, ErrStorageFormat
	}
	fact, err := query.QueryAuthorization(r.ctx, r.identity, r.target)
	if err != nil {
		return SpendReceipt{}, err
	}
	if err = r.check(); err != nil {
		return SpendReceipt{}, err
	}
	if fact.Target != r.target {
		return SpendReceipt{}, ErrConflict
	}
	var outcome uint64
	switch fact.Outcome {
	case AuthorizationUnknown:
		return liveSpendReceipt(v), nil
	case AuthorizationDenied:
		outcome = 1
	case AuthorizationAuthorized:
		outcome = 2
	default:
		return SpendReceipt{}, ErrConfiguration
	}
	now, err := r.clock.Sample()
	if err != nil {
		return SpendReceipt{}, err
	}
	// Preserve the full original TxA and material deadline. Updated history can
	// lengthen retention, but cannot create a new material-delivery deadline.
	n, err := encodeLiveConsumedVersion(r.output, v.spending, nil, r.store.epoch, outcome, max(now.UpperMS, v.terminalAt), 3)
	if err != nil {
		return SpendReceipt{}, err
	}
	s := r.store
	if err = s.begin(r.ctx); err != nil {
		return SpendReceipt{}, err
	}
	err = s.writeTransaction(r.ctx, r.check, func() error {
		if err := s.exec("UPDATE spend SET version=?1,fence=?2,projection=?3 WHERE lease=?4 AND source=0 AND state=1 AND version=?5 AND fence=?6 AND projection=?7", named(1, sqliteUint(3)), named(2, sqliteUint(s.epoch)), named(3, r.output[:n]), named(4, r.key[:r.keySize]), named(5, sqliteUint(2)), named(6, sqliteUint(v.fence)), named(7, v.projection)); err != nil {
			return err
		}
		return s.changedOne()
	})
	s.end()
	if errors.Is(err, ErrConflict) {
		current, readErr := r.read()
		if readErr != nil {
			return SpendReceipt{}, readErr
		}
		if !current.consumed || current.outcome == 0 || current.outcome != outcome {
			return SpendReceipt{}, ErrConflict
		}
		return liveSpendReceipt(current), nil
	}
	if err != nil {
		return SpendReceipt{}, err
	}
	v.outcome, v.terminalAt = outcome, max(now.UpperMS, v.terminalAt)
	return liveSpendReceipt(v), nil
}

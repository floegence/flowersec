package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// A batch occupies its original Environment position before claiming method
// candidates. Transfer to the query worker preserves that same position; a
// blocked authorization adapter cannot create an uncounted fifth acquisition.
type contractQueryClaim struct {
	environment *Environment
	index       int
	acquisition *ContractQueryAcquisition
	protection  *contractQueryProtection
	destination resourcev4.Reference
}

func (e *Environment) reserveContractQuery() (*contractQueryClaim, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return nil, cryptov4.ErrClosed
	}
	if e.queryActive+uint32(e.staticContractWork) >= e.ordinaryContractWorkLimitLocked() {
		return nil, cryptov4.ErrCapacity
	}
	for j := range e.queries {
		if e.ordinaryContractQuerySlotLocked(j) {
			claim := &contractQueryClaim{environment: e, index: j}
			e.queryClaims[j] = claim
			e.queryActive++
			return claim, nil
		}
	}
	return nil, cryptov4.ErrCapacity
}

func (claim *contractQueryClaim) release() {
	if claim == nil {
		return
	}
	e := claim.environment
	e.mu.Lock()
	if e.queryClaims[claim.index] == claim {
		e.queryClaims[claim.index] = nil
		e.queryActive--
		e.completeLocked()
	} else if q := claim.acquisition; q != nil && e.queries[claim.index] == q {
		// The query may have finished decoding before its consumer installs
		// the candidate. Retain the same original position through both the
		// consumer's output cleanup and the worker's actual physical exit.
		q.mu.Lock()
		q.consumerHeld = false
		if q.workerExited {
			q.call.ReleaseConsumer()
		}
		q.mu.Unlock()
	}
	claim.acquisition = nil
	claim.destination.Release()
	claim.destination = resourcev4.Reference{}
	e.mu.Unlock()
	e.signalMaterials()
}

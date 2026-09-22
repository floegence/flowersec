package sessionv4

import "github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"

func (e *Environment) admitResult(c *UnaryCall) error {
	if e == nil || c == nil || c.deferred == nil {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	if err := e.reservation.CheckSameEnvironment(c.deferred.metadata); err != nil {
		return err
	}
	for j, existing := range e.results {
		if existing == nil {
			e.results[j] = c
			e.resultActive++
			c.deferred.environment, c.deferred.environmentIndex = e, j
			e.signalMaterials()
			return nil
		}
	}
	return cryptov4.ErrCapacity
}

// Results share the Environment's existing coordinator and bounded owner
// index. They never retain the closed Session or create a watcher per result.
// At most 64 owners are visited per turn; actual disclosure rechecks its gate.
func (e *Environment) advanceResults() bool {
	e.mu.Lock()
	visits := min(64, len(e.results))
	e.mu.Unlock()
	for range visits {
		e.mu.Lock()
		if len(e.results) == 0 || e.resultActive == 0 {
			e.mu.Unlock()
			return false
		}
		index := e.resultCursor % len(e.results)
		e.resultCursor = (index + 1) % len(e.results)
		c := e.results[index]
		e.mu.Unlock()
		if c != nil && c.advanceResult() {
			e.mu.Lock()
			if e.results[index] == c {
				e.results[index] = nil
				e.resultActive--
				e.completeLocked()
			}
			e.mu.Unlock()
		}
	}
	e.mu.Lock()
	active := e.resultActive != 0
	e.mu.Unlock()
	return active
}

// All independent payload handoffs share the Environment close fence before
// taking their original delivery-authorization and result gates.
func (e *Environment) withResultDelivery(transfer func() error) error {
	if e == nil || transfer == nil {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	return transfer()
}

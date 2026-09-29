package sessionv4

import (
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type environmentResultSlot struct {
	call               *UnaryCall
	stream             *StreamMessages
	pin                resourcev4.Reference
	generation         uint64
	protected, closing bool
}

// The original Environment result table contains both active results and
// admitted future positions. A token refers to that table's existing storage;
// it creates no independent result pool or root result-owner allowance.
type environmentResultProtection struct {
	environment *Environment
	index       int
	generation  uint64
}

func (e *Environment) protectResult(owner resourcev4.Reference) (environmentResultProtection, error) {
	var output [1]environmentResultProtection
	err := e.protectResults(owner, output[:])
	return output[0], err
}

func (e *Environment) protectResults(owner resourcev4.Reference, output []environmentResultProtection) error {
	if e == nil || len(output) == 0 {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	if err := e.reservation.CheckSameEnvironment(owner); err != nil {
		return err
	}
	for _, position := range output {
		if position != (environmentResultProtection{}) {
			return resourcev4.ErrOwner
		}
	}
	available := 0
	for i := range e.results {
		slot := &e.results[i]
		if slot.call == nil && slot.stream == nil && !slot.protected && slot.generation != math.MaxUint64 {
			available++
		}
	}
	if available < len(output) {
		return cryptov4.ErrCapacity
	}
	count := 0
	for i := range e.results {
		slot := &e.results[i]
		if slot.call == nil && slot.stream == nil && !slot.protected && slot.generation != math.MaxUint64 {
			slot.generation++
			slot.protected = true
			output[count] = environmentResultProtection{e, i, slot.generation}
			count++
			if count == len(output) {
				return nil
			}
		}
	}
	return cryptov4.ErrCapacity
}

func (p environmentResultProtection) slotLocked() (*environmentResultSlot, error) {
	e := p.environment
	if e == nil || p.index < 0 || p.index >= len(e.results) {
		return nil, resourcev4.ErrOwner
	}
	slot := &e.results[p.index]
	if !slot.protected || slot.generation != p.generation {
		return nil, resourcev4.ErrOwner
	}
	return slot, nil
}

func (p environmentResultProtection) close() {
	if p.environment == nil {
		return
	}
	p.environment.mu.Lock()
	defer p.environment.mu.Unlock()
	slot, err := p.slotLocked()
	if err != nil {
		return
	}
	slot.closing = true
	if slot.call == nil && slot.stream == nil {
		slot.protected, slot.closing = false, false
	}
}

func (e *Environment) admitResult(c *UnaryCall, protection environmentResultProtection) error {
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
	if c.deferred.environment != nil {
		return resourcev4.ErrOwner
	}
	if protection != (environmentResultProtection{}) {
		if protection.environment != e {
			return resourcev4.ErrOwner
		}
		slot, err := protection.slotLocked()
		if err != nil {
			return err
		}
		if slot.closing {
			return cryptov4.ErrClosed
		}
		if slot.call != nil || slot.stream != nil {
			return cryptov4.ErrCapacity
		}
		// The preadmitted result alias keeps its reusable backing unavailable
		// until this original table entry has also retired. It has independent
		// result scopes, so a completed result does not pin Session cleanup.
		pin, err := c.deferred.metadata.Borrow()
		if err == nil {
			err = pin.DetachSessionScope()
		}
		if err != nil {
			pin.Release()
			return err
		}
		slot.pin = pin
		slot.call = c
		e.resultActive++
		c.deferred.environment, c.deferred.environmentIndex = e, protection.index
		e.signalMaterials()
		return nil
	}
	for j := range e.results {
		if slot := &e.results[j]; slot.call == nil && slot.stream == nil && !slot.protected {
			slot.call = c
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
		c, m, closed := e.results[index].call, e.results[index].stream, e.closed
		e.mu.Unlock()
		if c != nil && c.advanceResult() || m != nil && m.advanceEnvironmentResult(closed) {
			e.mu.Lock()
			if slot := &e.results[index]; slot.call == c && slot.stream == m {
				slot.call = nil
				slot.stream = nil
				if m != nil {
					m.mu.Lock()
					m.environment = nil
					m.mu.Unlock()
				}
				slot.pin.Release()
				slot.pin = resourcev4.Reference{}
				if slot.closing {
					slot.protected, slot.closing = false, false
				}
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

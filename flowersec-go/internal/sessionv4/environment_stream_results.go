package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// Dedicated streaming and unary results consume the same finite Environment
// owner table. The stream keeps its one existing lifetime task; this table only
// joins actual cleanup and orders Environment closure with local handoff.
func (e *Environment) admitStreamResult(m *StreamMessages, protection environmentResultProtection) error {
	if e == nil || m == nil || m.server || m.environment != nil {
		return cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.retired {
		return cryptov4.ErrClosed
	}
	if err := e.reservation.CheckSameEnvironment(m.reservation); err != nil {
		return err
	}
	if err := m.reservation.CheckResultOwner(); err != nil {
		return err
	}
	index := -1
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
		pin, err := m.reservation.Borrow()
		if err == nil {
			err = pin.DetachSessionScope()
		}
		if err != nil {
			pin.Release()
			return err
		}
		slot.pin, index = pin, protection.index
	} else {
		for j := range e.results {
			slot := &e.results[j]
			if slot.call == nil && slot.stream == nil && !slot.protected {
				index = j
				break
			}
		}
	}
	if index < 0 {
		return cryptov4.ErrCapacity
	}
	e.results[index].stream = m
	m.environment = e
	e.resultActive++
	e.signalMaterials()
	return nil
}

// Registration precedes Start. Until the original constructor exits, only it
// may access the unpublished object. Close seals the delivery gate immediately;
// the coordinator joins any construction failure after this final publication.
func (m *StreamMessages) finishEnvironmentPreparation() {
	m.mu.Lock()
	if m.environmentReady.Load() {
		m.mu.Unlock()
		return
	}
	e := m.environment
	m.environmentReady.Store(true)
	m.mu.Unlock()
	if e != nil {
		e.signalMaterials()
	}
}

func (m *StreamMessages) advanceEnvironmentResult(closed bool) bool {
	if !m.environmentReady.Load() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cleaned {
		return true
	}
	m.advanceStreamResultLocked()
	if closed {
		m.closeLocked()
	} else {
		m.cleanupLocked()
	}
	return m.cleaned
}

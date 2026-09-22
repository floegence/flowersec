package cryptov4

import (
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

// ApplicationFreeze is the unique original application ticket fence. The
// Session owns cause/credit admission and holds its live/proof references; this
// capability orders only the real crypto ticket frontier and freeze itself.
type ApplicationFreeze struct {
	engine    *Engine
	epoch     uint32
	committed bool
}

// FreezeApplication captures every admitted scope's exact send-ticket frontier
// in the same gate that prevents new OPEN/DATA/FIN tickets. A builder/provider
// still running after its ticket is included. Temporary incoming OPEN and local
// candidates without a ticket are excluded. dst is a preadmitted reservation.
func (e *Engine) FreezeApplication(dst []protocolv4.RecordHeader) (*ApplicationFreeze, int, error) {
	e.mu.Lock()
	if err := e.live(); err != nil {
		e.mu.Unlock()
		return nil, 0, err
	}
	if e.freeze != nil || e.staged != nil {
		e.mu.Unlock()
		return nil, 0, ErrTransition
	}
	count := 0
	for scope, keys := range e.current.keys.all() {
		if scope == 0 || scope == protocolv4.DatagramScope() || keys.incoming != nil || keys.deriving[0] || keys.deriving[1] || keys.opening && !keys.openSubmitted {
			continue
		}
		count++
	}
	if len(dst) < count {
		e.mu.Unlock()
		return nil, 0, ErrCapacity
	}
	f := &ApplicationFreeze{engine: e, epoch: e.current.number}
	e.freeze = f
	i := 0
	for scope, keys := range e.current.keys.all() {
		if scope == 0 || scope == protocolv4.DatagramScope() || keys.incoming != nil || keys.deriving[0] || keys.deriving[1] || keys.opening && !keys.openSubmitted {
			continue
		}
		dst[i] = protocolv4.RecordHeader{Epoch: e.current.number, Scope: scope, Sequence: keys.keys[e.config.SendDirection].next}
		i++
	}
	e.mu.Unlock()
	slices.SortFunc(dst[:count], func(a, b protocolv4.RecordHeader) int {
		if a.Scope < b.Scope {
			return -1
		}
		if a.Scope > b.Scope {
			return 1
		}
		return 0
	})
	return f, count, nil
}

func (f *ApplicationFreeze) Epoch() uint32 { return f.epoch }

// Commit is called by the original coordinator at client INIT ticket or
// authenticated server INIT. It removes rollback authority and seals queued
// datagram publication. It does not itself authenticate a rekey phase.
func (f *ApplicationFreeze) Commit() error {
	e := f.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.freeze != f || e.current.number != f.epoch {
		return ErrTransition
	}
	f.committed = true
	return nil
}

// Cancel is available only to the Session's still-cancellable client owner.
// The caller must first exclude original peer REQUEST and security obligations.
// Used IDs, closed scopes and crypto charges are never rolled back.
func (f *ApplicationFreeze) Cancel() error {
	e := f.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.freeze != f || f.committed || e.staged != nil {
		return ErrTransition
	}
	e.freeze = nil
	e.signalSend()
	return nil
}

// Resume follows the coordinator's actual ACK completion and epoch install.
// Clearing this fence cannot restore retired scope keys or an old epoch.
func (f *ApplicationFreeze) Resume() error {
	e := f.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.freeze != f || !f.committed || e.current.number != f.epoch+1 || e.current.number == 0 {
		return ErrTransition
	}
	e.freeze = nil
	e.signalSend()
	return nil
}

func (e *Engine) ApplicationReady() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.live(); err != nil {
		return err
	}
	if e.freeze != nil {
		return ErrTransition
	}
	return nil
}

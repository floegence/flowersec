package sessionv4

import (
	"context"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

type environmentMaterial struct {
	occupied, constructing bool
	ctx                    context.Context
	cancel                 context.CancelCauseFunc
	window                 *timev4.Window
	expiry                 *timev4.Deadline
	material               *ConnectionMaterial
}

// CreateMaterial hosts one trusted static factory before it calls key or
// provider code. The factory transfers sole ownership of an unused material;
// its complete lease/identity allocations are separately preadmitted. This is
// not a durable pool or an issuer call, and supplies no once-consumption fact.
// The original method joins actual factory exit, including its deferred work.
func (e *Environment) CreateMaterial(ctx context.Context, factory func(context.Context) (*ConnectionMaterial, error)) (result *ConnectionMaterial, err error) {
	if e == nil || ctx == nil || factory == nil {
		return nil, cryptov4.ErrConfiguration
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	if err = ctx.Err(); err == nil {
		err = e.reservation.Check()
	}
	if err == nil {
		err = e.shared.Check()
	}
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	var p *environmentMaterial
	for i := range e.materials {
		if !e.materials[i].occupied {
			p = &e.materials[i]
			break
		}
	}
	if p == nil {
		e.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	p.occupied, p.constructing = true, true
	p.ctx, p.cancel = context.WithCancelCause(ctx)
	e.materialActive++
	e.mu.Unlock()
	e.signalMaterials()
	returned, adopted := false, false
	defer func() {
		if recover() != nil || !returned {
			err = ErrEnvironmentTaskExit
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if adopted {
			p.material.mu.Lock()
			p.material.building = false
			if err != nil {
				p.material.closed = true
			}
			p.material.cleanupLocked()
			p.material.mu.Unlock()
		}
		if err != nil {
			result = nil
		}
		p.constructing = false
		if p.cancel != nil {
			p.cancel(err)
		}
		p.ctx, p.cancel, p.window = nil, nil, nil
		if p.material == nil {
			*p = environmentMaterial{}
			e.materialActive--
		}
		e.signalMaterials()
	}()
	window, err := timev4.NewWindow(e.materialClock, e.materialCreateMS)
	if err != nil {
		returned = true
		return nil, err
	}
	e.mu.Lock()
	p.window = window
	call := p.ctx
	e.mu.Unlock()
	if err = context.Cause(call); err == nil {
		err = window.Check()
	}
	if err != nil {
		returned = true
		return nil, err
	}
	result, err = factory(call)
	if result == nil {
		if err == nil {
			err = ErrSourceContractInvalid
		}
		returned = true
		return nil, err
	}
	// Only a genuinely transferred, unused owner is adopted. Returning a
	// material already hosted by another factory cannot close that owner.
	result.mu.Lock()
	if result.environment != nil || result.used || result.building || result.attached || result.closed {
		result.mu.Unlock()
		returned = true
		return nil, cryptov4.ErrTransition
	}
	result.environment, result.building = e, true
	result.mu.Unlock()
	e.mu.Lock()
	p.material = result
	adopted = true
	e.mu.Unlock()
	if err != nil {
		returned = true
		return nil, err
	}
	if err = result.reservation.CheckSameEnvironment(e.reservation); err != nil {
		returned = true
		return nil, err
	}
	if err = result.check(); err != nil {
		returned = true
		return nil, err
	}
	end := result.materialEnd()
	expiry, err := timev4.NewDeadline(e.materialClock, end)
	if err == nil {
		err = expiry.Check()
	}
	if err == nil {
		err = window.Check()
	}
	if err != nil {
		returned = true
		return nil, err
	}
	e.mu.Lock()
	result.mu.Lock()
	if e.closed {
		err = cryptov4.ErrClosed
	} else if result.closed {
		err = cryptov4.ErrClosed
	} else if err = context.Cause(call); err == nil {
		err = e.reservation.Check()
	}
	if err == nil {
		err = e.shared.Check()
	}
	if err == nil {
		p.expiry = expiry
		// Only original successful delivery detaches creation cancellation.
		p.cancel(nil)
		p.ctx, p.cancel, p.window = nil, nil, nil
	}
	result.mu.Unlock()
	e.mu.Unlock()
	returned = true
	return result, err
}

// materialEnd applies original nonrenewable bounds only. A temporary freshness
// interruption cannot discard an otherwise usable unused credential snapshot;
// every eventual use still checks current trust/freshness independently.
func (m *ConnectionMaterial) materialEnd() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.lease.lease
	if l == nil || m.closed {
		return 0
	}
	end, _ := l.maps[0].Field("initiation_not_after_ms").Uint()
	for _, credential := range l.credentials {
		end = min(end, credential.Scope().ExpiresMS)
	}
	if l.maps[1] != nil {
		activationEnd, _ := l.maps[1].Field("activation_not_after_ms").Uint()
		end = min(end, activationEnd)
	}
	return end
}

func (e *Environment) signalMaterials() {
	select {
	case e.materialWake <- struct{}{}:
	default:
	}
}

func (e *Environment) watchMaterials() {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer func() {
		timer.Stop()
		e.mu.Lock()
		e.materialExited = true
		e.completeLocked()
		e.mu.Unlock()
	}()
	for {
		serviceActive := e.advanceServiceDispatches()
		if e.advanceResults() {
			serviceActive = true
		}
		e.mu.Lock()
		registry := e.serviceRegistry
		e.mu.Unlock()
		if registry != nil && registry.Collect() {
			serviceActive = true
		}
		e.mu.Lock()
		var wakeAfter uint64
		if serviceActive {
			wakeAfter = 25
		}
		for i := range e.materials {
			p := &e.materials[i]
			if !p.occupied {
				continue
			}
			if p.constructing {
				wakeAfter = 100
				if p.ctx != nil {
					cause := context.Cause(p.ctx)
					if cause == nil && p.window != nil {
						cause = p.window.Check()
					}
					if cause == nil {
						cause = e.reservation.Check()
					}
					if cause == nil {
						cause = e.shared.Check()
					}
					if cause != nil {
						p.cancel(cause)
					}
				}
				continue
			}
			m := p.material
			select {
			case <-m.done:
				m.mu.Lock()
				m.environment = nil
				m.mu.Unlock()
				*p = environmentMaterial{}
				e.materialActive--
				continue
			default:
			}
			if p.expiry != nil {
				remaining, err := p.expiry.RemainingMS()
				if err == nil {
					err = e.reservation.Check()
				}
				if err == nil {
					err = e.shared.Check()
				}
				if err != nil {
					m.Close()
					p.expiry = nil
				} else if wakeAfter == 0 || remaining < wakeAfter {
					wakeAfter = max(1, min(remaining, 1000))
				}
			}
		}
		if e.watchContractQueriesLocked() && (wakeAfter == 0 || wakeAfter > 100) {
			wakeAfter = 100
		}
		if e.closed && e.materialActive == 0 && e.queryActive == 0 && e.resultActive == 0 && (!e.services || e.active == 0) {
			e.mu.Unlock()
			return
		}
		e.mu.Unlock()
		var tick <-chan time.Time
		if wakeAfter != 0 {
			timer.Reset(time.Duration(wakeAfter) * time.Millisecond)
			tick = timer.C
		}
		select {
		case <-e.materialWake:
			timer.Stop()
		case <-tick:
		}
	}
}

// The original Environment coordinator drives all attached Session method
// owners without a per-request watcher or a new application executor lane.
// No Environment or Session lock spans clock checks or dispatch admission.
func (e *Environment) advanceServiceDispatches() bool {
	if !e.services {
		return false
	}
	active := false
	for index := 0; ; index++ {
		e.mu.Lock()
		if index >= len(e.positions) {
			e.mu.Unlock()
			break
		}
		s := e.positions[index]
		e.mu.Unlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		p, delivered := s.application, s.delivered
		s.mu.Unlock()
		if p == nil {
			continue
		}
		p.mu.Lock()
		d, rpc, notifications := p.services, p.rpc, p.notifications
		p.mu.Unlock()
		if rpc != nil {
			active = true
			rpc.AdvanceCalls()
		}
		if notifications != nil {
			active = true
			if delivered {
				notifications.activate()
			}
			notifications.Advance()
		}
		if d == nil {
			continue
		}
		active = true
		if delivered {
			d.activate()
		}
		d.Advance()
	}
	return active
}

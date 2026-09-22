package sessionv4

import (
	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// checkAdmissionPreparation rechecks the original frozen graph at the local
// pre-claim and activation gates. It grants no store/credential permission and
// does not reserve missing resources after consumption.
func (p *SessionCorePlan) checkAdmissionPreparation(environment resourcev4.Reference) error {
	if p == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	if p.claimed || p.preparing || p.installing {
		return cryptov4.ErrTransition
	}
	if p.config.applicationServices && p.rpc == nil {
		return cryptov4.ErrConfiguration
	}
	if err := p.refs[corePlanOwner].CheckSameEnvironment(environment); err != nil {
		return err
	}
	for _, ref := range p.refs {
		if ref != (resourcev4.Reference{}) {
			if err := ref.Check(); err != nil {
				return err
			}
		}
	}
	if p.receivePool != nil {
		if err := p.receivePool.reservation.Check(); err != nil {
			return err
		}
	}
	handlers := p.config.Handlers.Plan
	if handlers == nil {
		return nil
	}
	if err := handlers.CheckEnvironment(environment); err != nil {
		return err
	}
	executor := handlers.Executor()
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.closed {
		return resourcev4.ErrClosed
	}
	return executor.reservation.Check()
}

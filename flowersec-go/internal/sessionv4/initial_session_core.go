package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
)

// Install the sole close owner while the original Initial carrier is still
// private. Holding both gates prevents a watchdog from capturing the previous
// provider or a concurrent plan close from losing a newly constructed owner.
func (p *SessionCorePlan) attachCarrier(x *InitialExchange) (sessionCoreCarrier, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.checkLocked(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, cryptov4.ErrClosed
	}
	if p.initial != x || x.corePlan != p || p.input != nil || x.sending || x.receiving || x.authenticating {
		return nil, cryptov4.ErrTransition
	}
	if p.config.MessageCarrier {
		input, err := NewSessionMessageInputWithEnvironmentBorrow(context.Background(), x.messages, p.config.messageOptions(), p.refs[coreCarrierOwner], p.carrierEnvironment)
		if err != nil {
			return nil, err
		}
		p.input, x.messages = input, input
		return input, nil
	}
	input, err := newSessionStreamInput(x.stream, p.config.WorkSlots+2, p.refs[coreCarrierOwner])
	if err != nil {
		return nil, err
	}
	p.input, x.stream = input, input
	return input, nil
}

// AuthenticateCore consumes the original preadmitted transport plan, installs
// its mandatory services before READY, and transfers this exact carrier
// after both READY flights. The caller drives the core's reserved runtime.
// Admission/trust and application handler plans remain separate obligations.
// On failure the original plan retains cleanup ownership; cancellation cannot
// make its unfinished provider or crypto work available to another attempt.
func (x *InitialExchange) AuthenticateCore(config cryptov4.HandshakeConfig, plan *SessionCorePlan) (core *SessionCore, err error) {
	defer clear(config.PSK[:])
	if x == nil || plan == nil {
		return nil, cryptov4.ErrConfiguration
	}
	x.mu.Lock()
	if err = x.checkLocked(); err != nil {
		x.mu.Unlock()
		return nil, err
	}
	messages := x.messages != nil
	if x.stream == nil && !messages || config.Role != x.config.Role {
		x.mu.Unlock()
		return nil, cryptov4.ErrConfiguration
	}
	reservation := x.config.Reservation
	x.mu.Unlock()
	plan.mu.Lock()
	matching := messages == plan.config.MessageCarrier
	plan.mu.Unlock()
	if !matching {
		return nil, cryptov4.ErrConfiguration
	}
	if err = plan.CheckEnvironment(reservation); err != nil {
		return nil, err
	}
	records := plan.records()
	if config.Clock != records.Clock || config.LocalIdleDurationMS != records.LocalIdleDurationMS {
		return nil, cryptov4.ErrConfiguration
	}
	if err = plan.claimInitial(config.Session, config.Role, x); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			plan.Close()
			core = nil
		}
	}()
	input, err := plan.attachCarrier(x)
	if err != nil {
		return nil, err
	}
	_, err = x.authenticate(config, plan.records(), plan, plan.PrepareRecords, func(engine *cryptov4.Engine) error {
		core, err = plan.Install(engine, input, input)
		return err
	})
	if err == nil && plan.rpc != nil {
		err = plan.rpc.completeBootstrap()
	}
	return core, err
}

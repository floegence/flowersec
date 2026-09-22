package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// AcceptedIngressFactory is the trusted original listener/upgrade adapter.
// PrepareAccepted runs only after the Environment has acquired its position,
// watcher and all intake workspaces. It uses the supplied original deadline;
// returning an entrance transfers its sole cleanup ownership even with an
// error. A failure without an entrance must first join its own provider tails.
// Shared provider policy/backing is covered by Dependencies. This is neither
// a material resolver nor an application authorization callback.
type AcceptedIngressFactory interface {
	PrepareAccepted(context.Context, *timev4.Deadline) (*AcceptedEntrance, error)
}

type AcceptedIngressConfig struct {
	Factory                   AcceptedIngressFactory
	Intake                    AcceptedIntakeConfig
	Reservation, Dependencies resourcev4.Reference
	RuntimeBytes              uint64
}

type acceptedIngress struct {
	config              AcceptedIngressConfig
	reservation, shared resourcev4.Reference
	entrance            *AcceptedEntrance
	adopted             bool
}

func AcceptedIngressCharge(c AcceptedIngressConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	if _, err := AcceptedIntakeCharge(c.Intake); err != nil {
		return resourcev4.Vector{}, err
	}
	snapshot, err := rpcServicesSnapshotCharge(c.Intake.Input.Config.RPC)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(acceptedIngress{})), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(snapshot)
}

// AcceptIngress owns physical preparation before ClientHello intake. The same
// two original Environment tasks continue through admission, READY and runtime;
// this layer creates no extra provider worker or replacement cleanup position.
func (e *Environment) AcceptIngress(ctx context.Context, c AcceptedIngressConfig) (*EnvironmentSession, error) {
	return e.acceptIngress(ctx, c, ServeIngress{})
}

func (e *Environment) acceptIngress(ctx context.Context, c AcceptedIngressConfig, ingress ServeIngress) (*EnvironmentSession, error) {
	return e.acceptIngressOwned(ctx, c, ingress, nil)
}
func (e *Environment) acceptIngressOwned(ctx context.Context, c AcceptedIngressConfig, ingress ServeIngress, adopted *bool) (*EnvironmentSession, error) {
	var err error
	c.Intake.Input.Config, err = c.Intake.Input.Config.CaptureRequirements()
	if err != nil {
		return nil, err
	}
	i := c.Intake.Input
	if e == nil || ctx == nil || c.Factory == nil || c.Intake.Resolver == nil || i.Entrance != nil || i.Establishment != nil || i.Subscriptions != nil || i.Store == nil || i.Authority == nil || i.Root == nil || i.Config.Initial.Deadline == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := AcceptedIngressCharge(c)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	slot := -1
	for n, current := range e.positions {
		if current == nil {
			slot = n
			break
		}
	}
	if slot < 0 {
		e.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	err = ctx.Err()
	if err == nil {
		err = i.Config.Initial.Deadline.Check()
	}
	if err == nil {
		err = e.shared.Check()
	}
	input := environmentEstablishment{kind: 3, accepted: i}
	if err == nil {
		err = input.check(e.reservation)
	}
	for _, ref := range [...]resourcev4.Reference{c.Reservation, c.Dependencies, c.Intake.Reservation, c.Intake.Dependencies, c.Intake.Establishment, c.Intake.Subscriptions} {
		if err == nil {
			err = e.reservation.CheckSameEnvironment(ref)
		}
	}
	s := newEnvironmentSession(e, slot, ctx)
	application := i.Config.Application
	if err == nil {
		err = application.claimPreparation(s)
	}
	var shared, owned resourcev4.Reference
	if err == nil {
		shared, err = c.Dependencies.Borrow()
	}
	if err == nil {
		owned, err = c.Reservation.Take(charge)
	}
	if err != nil {
		application.undoPreparation(s)
		shared.Release()
		e.mu.Unlock()
		return nil, err
	}
	c.Intake.Input.Config.RPC = captureRPCServicesConfig(c.Intake.Input.Config.RPC)
	c.Intake.Input.Config.applicationHost = s
	s.application = application
	p := &acceptedIngress{config: c, reservation: owned, shared: shared}
	s.ingress = p
	s.preparationOwner, s.preparationDependencies = owned, shared
	s.preparationDeadline = i.Config.Initial.Deadline
	e.positions[slot], e.active = s, e.active+1
	if ingress.group != nil {
		attached, attachErr := ingress.attach(s)
		if attached {
			s.serve = ingress
		}
		if attachErr != nil {
			s.closeWith(attachErr)
		}
	}
	e.mu.Unlock()
	if adopted != nil {
		*adopted = true
	}
	go s.watch(ctx)
	go s.run(environmentEstablishment{ingress: p})
	return s.deliver(ctx)
}

func (p *acceptedIngress) check(s *EnvironmentSession) error {
	if err := s.context.Err(); err != nil {
		return err
	}
	if err := s.preparationDeadline.Check(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

func (p *acceptedIngress) prepare(s *EnvironmentSession) (input environmentEstablishment, err error) {
	if err = p.check(s); err != nil {
		return input, err
	}
	p.entrance, err = p.config.Factory.PrepareAccepted(&s.context, s.preparationDeadline)
	if err != nil {
		return input, err
	}
	if err = p.check(s); err != nil {
		return input, err
	}
	if p.entrance == nil {
		return input, cryptov4.ErrConfiguration
	}
	c := p.config.Intake
	c.Input.Entrance = p.entrance
	if _, err = s.environment.admitIntakeAt(&s.context, c, s); err != nil {
		return input, err
	}
	p.adopted = true
	input.intake = s.intake
	return input, nil
}

func (p *acceptedIngress) cleanup() error {
	if !p.adopted {
		if e := p.entrance; e != nil {
			e.Close()
			if err := e.WaitCleanup(context.Background()); err != nil {
				return err
			}
			if err := e.Retire(); err != nil {
				return err
			}
		}
		c := p.config.Intake
		c.Reservation.Release()
		c.Establishment.Release()
		c.Subscriptions.Release()
		c.Input.Buffers.Release()
		c.Input.Invocation.Release()
	}
	p.shared.Release()
	p.reservation.Release()
	*p = acceptedIngress{}
	return nil
}

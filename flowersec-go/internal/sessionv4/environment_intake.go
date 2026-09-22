package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// AcceptedMaterialResolver is the trusted, bounded material lookup provider.
// ClientHello is an UNAUTHENTICATED routing hint, borrowed for this call only.
// The resolver may select a verified material snapshot from its fixed trust
// scope, but this result confers no application permission or durable admission.
// Business handler/application authorization occurs only after FSB validation.
// A nonnil material transfers sole cleanup ownership even with an error; the
// original method returns only after its provider work no longer uses the hint.
type AcceptedMaterialResolver interface {
	ResolveAcceptedMaterial(context.Context, []byte) (*ConnectionMaterial, InitialHello, error)
}

// AcceptedIntakeConfig captures one already accepted original carrier before
// ClientHello or material lookup. Its fixed provider/listener owns the transport
// observations and entrance capacity. The received material supplies Session
// parameters, while the local runtime policy and original deadline stay fixed.
// Listener/HTTP upgrade dispatch and Serve aggregation are outer composition.
type AcceptedIntakeConfig struct {
	Input                           AcceptedSessionInput
	Resolver                        AcceptedMaterialResolver
	Limits                          EstablishmentLimits
	LocalCapabilities, RuntimeBytes uint64
	Reservation, Dependencies       resourcev4.Reference
	Establishment, Subscriptions    resourcev4.Reference
}

type acceptedIntake struct {
	config              AcceptedIntakeConfig
	reservation, shared resourcev4.Reference
	hello               []byte
	material            *ConnectionMaterial
	establishment       *SessionEstablishment
}

func AcceptedIntakeCharge(c AcceptedIntakeConfig) (resourcev4.Vector, error) {
	if _, err := EstablishmentCharge(c.Limits); err != nil {
		return resourcev4.Vector{}, err
	}
	if c.RuntimeBytes == 0 || c.Limits.Hello.HelloBytes <= 0 || c.Limits.Hello.HelloBytes > 1<<20 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	snapshot, err := rpcServicesSnapshotCharge(c.Input.Config.RPC)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(acceptedIntake{})) + uint64(c.Limits.Hello.HelloBytes), resourcev4.Items: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(snapshot)
}

func (e *Environment) AcceptIntake(ctx context.Context, c AcceptedIntakeConfig) (*EnvironmentSession, error) {
	s, err := e.admitIntakeAt(ctx, c, nil)
	if err != nil {
		return nil, err
	}
	go s.watch(ctx)
	go s.run(environmentEstablishment{intake: s.intake})
	return s.deliver(ctx)
}

func (e *Environment) admitIntakeAt(ctx context.Context, c AcceptedIntakeConfig, existing *EnvironmentSession) (*EnvironmentSession, error) {
	var err error
	c.Input.Config, err = c.Input.Config.CaptureRequirements()
	if err != nil {
		return nil, err
	}
	i := c.Input
	if e == nil || ctx == nil || c.Resolver == nil || i.Entrance == nil || i.Root == nil || i.Store == nil || i.Authority == nil || i.Establishment != nil || i.Subscriptions != nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := AcceptedIntakeCharge(c)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if existing != nil {
		existing.mu.Lock()
		defer existing.mu.Unlock()
		if existing.environment != e || existing.closed || existing.entrance != nil || existing.intake != nil {
			e.mu.Unlock()
			return nil, cryptov4.ErrClosed
		}
	}
	if e.closed {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	slot := -1
	if existing != nil {
		slot = existing.position
	} else {
		for n, position := range e.positions {
			if position == nil {
				slot = n
				break
			}
		}
	}
	if slot < 0 {
		e.mu.Unlock()
		return nil, cryptov4.ErrCapacity
	}
	err = ctx.Err()
	if err == nil {
		err = e.shared.Check()
	}
	input := environmentEstablishment{kind: 3, accepted: i}
	if err == nil {
		err = input.check(e.reservation)
	}
	for _, ref := range [...]resourcev4.Reference{c.Reservation, c.Dependencies, c.Establishment, c.Subscriptions} {
		if err == nil {
			err = e.reservation.CheckSameEnvironment(ref)
		}
	}
	entrance := i.Entrance
	entrance.mu.Lock()
	if err == nil && (entrance.closed || entrance.busy || entrance.admission != nil || entrance.host != nil) {
		err = cryptov4.ErrTransition
	}
	if err == nil {
		err = entrance.owner.CheckSameEnvironment(e.reservation)
	}
	if err == nil && (entrance.environment != i.Environment || i.Config.Initial.Deadline != entrance.config.Initial.Deadline) {
		err = cryptov4.ErrConfiguration
	}
	if err == nil && existing != nil && existing.preparationDeadline != entrance.config.Initial.Deadline {
		err = cryptov4.ErrConfiguration
	}
	if err == nil {
		entrance.initial.mu.Lock()
		if entrance.initial.phase != 0 || entrance.initial.sending || entrance.initial.receiving {
			err = cryptov4.ErrTransition
		}
		entrance.initial.mu.Unlock()
	}
	s := existing
	if s == nil {
		s = newEnvironmentSession(e, slot, ctx)
	}
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
		if existing == nil {
			application.undoPreparation(s)
		}
		shared.Release()
		entrance.mu.Unlock()
		e.mu.Unlock()
		return nil, err
	}
	c.Input.Config.RPC = captureRPCServicesConfig(c.Input.Config.RPC)
	if c.Input.Config.RPC != nil {
		c.Input.Config.RPC.Root, c.Input.Config.RPC.Owner = i.Root, i.ResourceOwner
	}
	c.Input.Config.applicationHost = s
	s.application = application
	intake := &acceptedIntake{config: c, reservation: owned, shared: shared}
	if existing == nil {
		e.positions[slot], e.active = s, e.active+1
	}
	s.intake, s.entrance = intake, entrance
	s.preparationDeadline = entrance.config.Initial.Deadline
	s.preparationOwner, s.preparationDependencies = owned, shared
	entrance.host = s
	entrance.mu.Unlock()
	e.mu.Unlock()
	return s, nil
}

func (p *acceptedIntake) check(s *EnvironmentSession) error {
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

func (p *acceptedIntake) prepare(s *EnvironmentSession) (input environmentEstablishment, err error) {
	c := p.config
	i := c.Input
	input = environmentEstablishment{kind: 3, accepted: i}
	if err = p.check(s); err != nil {
		return input, err
	}
	p.hello = make([]byte, c.Limits.Hello.HelloBytes)
	n, err := i.Entrance.readClientHello(p.hello, s)
	if err != nil {
		return input, err
	}
	if err = p.check(s); err != nil {
		return input, err
	}
	var hello InitialHello
	p.material, hello, err = c.Resolver.ResolveAcceptedMaterial(&s.context, p.hello[:n:n])
	if err != nil {
		return input, err
	}
	if err = p.check(s); err != nil {
		return input, err
	}
	if p.material == nil || hello.Artifact != nil || hello.Workspace != nil {
		return input, cryptov4.ErrConfiguration
	}
	p.material.mu.Lock()
	valid := !p.material.closed && p.material.identity.identity != nil && p.material.identity.identity.role == protocolv4.ServerToClient
	generation := p.material.generation
	p.material.mu.Unlock()
	if !valid {
		return input, cryptov4.ErrConfiguration
	}
	p.establishment, i.Subscriptions, err = p.material.Establishment(hello, c.Limits, generation, c.Establishment, c.Subscriptions)
	if err != nil {
		return input, err
	}
	i.Establishment = p.establishment
	if p.establishment.material.Source != i.Entrance.config.Initial.ActivationSourceProfile || p.establishment.session.Profile != i.Entrance.config.Initial.Profile {
		return input, ErrSourceContractInvalid
	}
	i.Config.Core.Session = p.establishment.session
	if i.Config.RPC != nil {
		i.Config.RPC.Session = p.establishment.session.Contract
		i.Config.RPC.CryptoProfile = p.establishment.session.Profile
	}
	i.Config.Initial.Profile = p.establishment.session.Profile
	i.Config.Initial.Role = protocolv4.ServerToClient
	i.Config.Initial.ActivationSourceProfile = p.establishment.material.Source
	i.Config.Features, err = p.establishment.material.Artifact.FeatureEnvelope(hello.Index, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: c.LocalCapabilities, ProposedOffer: hello.Offered, RouteAllowedFeatures: hello.Policy.RouteAllowedFeatures})
	if err != nil {
		return input, err
	}
	if _, _, err = SessionAdmissionRequirements(i.Config); err != nil {
		return input, err
	}
	input.accepted = i
	_, err = s.environment.admitAt(&s.context, input, s)
	return input, err
}

func (p *acceptedIntake) cleanup() error {
	if p.establishment != nil {
		if err := p.establishment.Retire(); err != nil {
			return err
		}
	}
	if p.material != nil {
		p.material.Close()
		if err := p.material.WaitCleanup(context.Background()); err != nil {
			return err
		}
	}
	c := p.config
	c.Establishment.Release()
	c.Subscriptions.Release()
	c.Input.Buffers.Release()
	c.Input.Invocation.Release()
	clear(p.hello)
	p.shared.Release()
	p.reservation.Release()
	*p = acceptedIntake{}
	return nil
}

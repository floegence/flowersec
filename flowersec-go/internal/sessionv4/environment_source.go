package sessionv4

import (
	"bytes"
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

var ErrConnectionRequirementUnavailable = protocolv4.ErrConnectionRequirementUnavailable

// CarrierPreparationRequest borrows only the selected public route, without
// the Artifact, PSK, activation proof, certificate or private identity handles.
// Route and Config describe one original attempt and cannot be retained past
// PrepareCarrier. The trusted factory validates the complete signed route
// against its actual endpoint/TLS policy before any credential-free dialing.
type CarrierPreparationRequest struct {
	Config         PreparedCarrierConfig
	Scope          SessionResourceScope
	Route          []byte
	AddressAttempt uint8
	Budget         CarrierAttemptBudget
}

// CarrierAttemptBudget reserves a qualified maximum for one numeric attempt,
// including TLS and HTTP preparation. Unused allowance is not reissued within
// the same Connect. Provider runtime/resource qualification remains mandatory.
type CarrierAttemptBudget struct{ PreauthBytes, WorkUnits uint64 }

// SourceLiveIssuance belongs to the in-process reference authority. It fixes
// delegated signing capability and original times before acquisition; only the
// actual selected candidate is filled after preparation. No signing runs here.
type SourceLiveIssuance struct {
	Tunnel *protocolv4.LiveTunnelActivationConfig
	// Tunnels binds independent relay/Grant policy by original signed candidate
	// index. Use Tunnel for a common policy, or Tunnels for distinct relays.
	// Direct candidates always use the direct original projection.
	Tunnels                             [16]*protocolv4.LiveTunnelActivationConfig
	Signer                              protocolv4.MapSigner
	IssuedAt, ActivationEnd, SessionEnd uint64
	Reservation                         resourcev4.Reference
}

// ConsumerCarrierFactory is a bounded SDK provider, not an application callback.
// The factory has no retry queue and returns only after its original method's
// work exits. A nonnil result transfers cleanup ownership even alongside an
// error. Failure without a result must retire all physical preparation tails
// before returning. Shared configuration/backing belongs to Dependencies below.
type ConsumerCarrierFactory interface {
	PrepareCarrier(context.Context, CarrierPreparationRequest) (*PreparedCarrier, error)
}

// SourceConnectConfig is private trusted assembly for original direct routes.
// Both source variants run the same acquisition/preparation/admission path.
// Admission is a frozen local template: signed Session fields and the feature
// envelope are derived from the acquired material, never a previous lease.
// Candidate and address ceilings may be more conservative than signed limits.
// CarrierReservation uses SourceCarrierCharge for its reusable method position.
type SourceConnectConfig struct {
	staticMaterial                                          *ConnectionMaterial
	controller                                              *controllerAttempt
	controllerOwner                                         *ConnectionController
	poolSource                                              *PreauthorizedPoolSource
	Identity                                                *ApplicationIdentity
	Generation                                              MaterialGeneration
	Requirements                                            MaterialRequirements
	Provider                                                MaterialLeaseProvider
	Carrier                                                 ConsumerCarrierFactory
	Hello                                                   InitialHello
	Limits                                                  EstablishmentLimits
	Admission                                               SessionAdmissionConfig
	LocalCapabilities                                       uint64
	Root                                                    *resourcev4.Root
	Owner                                                   resourcev4.OwnerKey
	Environment, Preauth, Dependencies                      resourcev4.Reference
	Scope                                                   SessionResourceScope
	Preparation, Acquisition, Material, Establishment       resourcev4.Reference
	Subscriptions, CarrierReservation                       resourcev4.Reference
	RuntimeBytes, MaterialRuntimeBytes, CarrierRuntimeBytes uint64
	ParallelCandidates, AddressAttempts                     uint8
	CandidateStartIntervalMS                                uint64
	CandidateStartIntervalConfigured                        bool
	AttemptBudget                                           CarrierAttemptBudget
	LiveIssuance                                            SourceLiveIssuance
}

type sourcePreparation struct {
	references    sourceReferences
	config        SourceConnectConfig
	input         environmentEstablishment
	reservation   resourcev4.Reference
	shared        resourcev4.Reference
	acquisition   *MaterialAcquisition
	material      *ConnectionMaterial
	establishment *SessionEstablishment
	prepared      *PreparedCarrier
	admission     *SessionAdmissionReservation
	selection     materialPreparation
	race          candidateRace
	issuance      *protocolv4.LiveActivationPlan
}

func SourcePreparationCharge(c SourceConnectConfig) (resourcev4.Vector, error) {
	if _, err := EstablishmentCharge(c.Limits); err != nil {
		return resourcev4.Vector{}, err
	}
	if c.RuntimeBytes == 0 || c.Limits.Hello.RouteBytes <= 0 || c.Limits.Hello.RouteBytes > 1<<20 ||
		len(c.Hello.IdentityHint) > c.Limits.Hello.HelloBytes || len(c.Hello.Policy.Exporter) != 0 ||
		c.Hello.Policy.BindingMode > 1 || c.Hello.BindingModes == 0 || c.Hello.BindingModes & ^uint64(3) != 0 || c.Hello.BindingModes&(1<<c.Hello.Policy.BindingMode) == 0 ||
		c.ParallelCandidates > 2 || c.CandidateStartIntervalMS > 30000 || !c.CandidateStartIntervalConfigured && c.CandidateStartIntervalMS != 0 || c.AddressAttempts > 8 || c.AttemptBudget.PreauthBytes == 0 || c.AttemptBudget.PreauthBytes > 262144 || c.AttemptBudget.WorkUnits == 0 || c.AttemptBudget.WorkUnits > 256 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	a := c.LiveIssuance
	perCandidate := a.Tunnels != ([16]*protocolv4.LiveTunnelActivationConfig{})
	if a.Tunnel != nil && perCandidate || a.Signer == nil && (perCandidate || a.Tunnel != nil || a.Reservation != (resourcev4.Reference{}) || a.IssuedAt != 0 || a.ActivationEnd != 0 || a.SessionEnd != 0) || a.Signer != nil && (a.IssuedAt >= a.ActivationEnd || a.ActivationEnd > a.SessionEnd) {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	// Admission scratch and the retained future graph belong to this source
	// preparation in both fixed-Session and Controller connections. Charging
	// them on the Controller would leave ordinary Connect unaccounted for.
	n := uint64(unsafe.Sizeof(sourcePreparation{})) + uint64(unsafe.Sizeof(sessionHeadroom{})) +
		uint64(unsafe.Sizeof(sessionAdmissionBatch{})) + uint64(unsafe.Sizeof([sessionAdmissionOwnerCapacity + 2]resourcev4.Request{})) +
		// Total preparation, two retained cancellation windows and two
		// concurrent prospective winners before the winner gate.
		5*uint64(unsafe.Sizeof(timev4.Window{})) +
		2*uint64(c.Limits.Hello.RouteBytes) + uint64(len(c.Hello.IdentityHint)) + uint64(len(c.Hello.Policy.Exporter))
	snapshot, err := rpcServicesSnapshotCharge(c.Admission.RPC)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge, err := (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 11, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(snapshot)
}

// Local capacity refusal preserves all caller inputs. Once admitted, this
// position owns the supplied workspace references through actual cleanup.
// The variants are explicit; failures never choose a different authority.
func (e *Environment) ConnectSourcePool(ctx context.Context, c SourceConnectConfig, spend PoolSessionInput) (*EnvironmentSession, error) {
	if spend.Store == nil || spend.Authority == nil || spend.Establishment != nil || spend.Admission != nil || c.LiveIssuance.Signer != nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.startSource(ctx, c, environmentEstablishment{kind: 1, pool: spend}, nil)
}

func (e *Environment) ConnectSourceLiveSQLite(ctx context.Context, c SourceConnectConfig, spend LiveSessionInput) (*EnvironmentSession, error) {
	if !spend.validAuthority(c.LiveIssuance.Signer != nil) || spend.Control.Provider != nil || spend.Establishment != nil || spend.Admission != nil {
		return nil, cryptov4.ErrConfiguration
	}
	return e.startSource(ctx, c, environmentEstablishment{kind: 2, live: spend}, nil)
}

func (e *Environment) startSourcePrepared(ctx context.Context, c SourceConnectConfig, input environmentEstablishment, static *ConnectionMaterial) (*EnvironmentSession, bool, error) {
	if e == nil || ctx == nil || c.Carrier == nil || c.Root == nil ||
		c.Admission.Initial.Deadline == nil || !c.Requirements.valid() ||
		c.Hello.Artifact != nil || c.Hello.Workspace != nil || c.RuntimeBytes == 0 {
		return nil, false, cryptov4.ErrConfiguration
	}
	if c.poolSource != nil {
		if static != nil || input.kind != 1 || c.Identity != nil || c.Provider != nil || c.Acquisition != (resourcev4.Reference{}) || c.Material != (resourcev4.Reference{}) || c.MaterialRuntimeBytes != 0 {
			return nil, false, cryptov4.ErrConfiguration
		}
		if err := c.poolSource.access(); err != nil {
			return nil, false, err
		}
		c.poolSource.mu.Lock()
		pool := c.poolSource.pool
		closed := c.poolSource.closed
		c.poolSource.mu.Unlock()
		if pool == nil || closed {
			return nil, false, cryptov4.ErrConfiguration
		}
		pool.mu.Lock()
		belongs := !pool.closed && pool.environment == e
		pool.mu.Unlock()
		if !belongs {
			return nil, false, cryptov4.ErrConfiguration
		}
	} else if static == nil {
		if c.Identity == nil || c.Provider == nil || c.Identity.role != protocolv4.ClientToServer {
			return nil, false, cryptov4.ErrConfiguration
		}
	} else if c.Identity != nil || c.Provider != nil || c.Acquisition != (resourcev4.Reference{}) || c.Material != (resourcev4.Reference{}) || c.MaterialRuntimeBytes != 0 {
		return nil, false, cryptov4.ErrConfiguration
	}
	c.staticMaterial = static
	var err error
	if c.Requirements, err = c.Requirements.capture(); err != nil {
		return nil, false, err
	}
	// One captured requirement set follows acquisition, every original
	// candidate, final admission and READY publication. No second template
	// may silently override or weaken it.
	if c.Admission.Requirements != (protocolv4.V4ConnectionRequirements{}) {
		return nil, false, cryptov4.ErrConfiguration
	}
	c.Admission.Requirements = c.Requirements.Connection
	// The source's exact profile is fixed before issuer work. Material later
	// supplies its signed parameters to this same aggregate admission recipe.
	profile := c.Requirements.ApplicationProfile
	if profile == "transport" {
		if c.Admission.RPC != nil {
			return nil, false, ErrConnectionRequirementUnavailable
		}
	} else if (profile != "services" && profile != "execution") || !e.services || c.Admission.RPC == nil || c.Admission.Application == nil {
		return nil, false, ErrConnectionRequirementUnavailable
	}
	if c.Requirements.Connection.Datagram && !c.Admission.Core.Datagrams ||
		(c.Requirements.Connection.IndependentReliableReadProgress || c.Requirements.Connection.BoundStreamInputIsolation) && !c.Admission.Core.Native && !c.Admission.Core.MixedCarrier {
		return nil, false, protocolv4.ErrRequiredGuaranteeUnavailable
	}
	charge, err := SourcePreparationCharge(c)
	if err != nil {
		return nil, false, err
	}
	if err = c.Admission.Initial.Deadline.Check(); err != nil {
		return nil, false, err
	}
	adopted := false
	if c.Admission.headroom == nil {
		// This is only an early local refusal, not a promise of a position.
		// The publication gate below checks again after constructing the
		// original resource vector. Result/dependency admission may take the
		// Environment gate, so it must run outside that gate.
		if err = e.checkSourcePosition(ctx); err != nil {
			return nil, false, err
		}
		c.Admission.headroom, err = reserveSessionHeadroom(c, e)
		if err != nil {
			return nil, false, err
		}
		defer func() {
			if !adopted {
				c.Admission.headroom.close()
			}
		}()
	}
	// Only finite local gates execute under this lock. Issuer, provider, crypto
	// and store work begin after the original position and watcher are installed.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, false, cryptov4.ErrClosed
	}
	slot := -1
	for i, current := range e.positions {
		if current == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		e.observePositionRejection()
		e.mu.Unlock()
		return nil, false, cryptov4.ErrCapacity
	}
	err = ctx.Err()
	if err == nil {
		err = e.shared.Check()
	}
	if err == nil {
		err = input.check(e.reservation)
	}
	refs := [...]resourcev4.Reference{c.Environment, c.Preauth, c.Dependencies, c.Preparation, c.Establishment, c.Subscriptions, c.CarrierReservation}
	for _, ref := range refs {
		if err == nil {
			err = e.reservation.CheckSameEnvironment(ref)
		}
	}
	if static == nil && c.poolSource == nil {
		for _, ref := range [...]resourcev4.Reference{c.Acquisition, c.Material} {
			if err == nil {
				err = e.reservation.CheckSameEnvironment(ref)
			}
		}
	}
	if err == nil && c.LiveIssuance.Signer != nil {
		err = e.reservation.CheckSameEnvironment(c.LiveIssuance.Reservation)
	}
	s := newEnvironmentSession(e, slot, ctx)
	application := c.Admission.Application
	if err == nil {
		err = application.claimPreparation(s)
	}
	var shared, owned resourcev4.Reference
	var references sourceReferences
	var selection materialPreparation
	if err == nil {
		references, err = c.Admission.headroom.takeSource(c)
		shared = references.shared
	}
	if err == nil && static != nil {
		source := "preauthorized_pool"
		if input.kind == 2 {
			source = "live_authority"
		}
		err = selection.claim(static, c.Generation, c.Hello.Attempt, e, source, c.Requirements)
	}
	if err == nil {
		if references.workloadSnapshotBytes > charge[resourcev4.SDKBytes] {
			err = resourcev4.ErrOwner
		} else {
			charge[resourcev4.SDKBytes] -= references.workloadSnapshotBytes
			owned, err = c.Preparation.Take(charge)
		}
	}
	if err != nil {
		selection.close()
		application.undoPreparation(s)
		references.close()
		e.mu.Unlock()
		return nil, false, err
	}
	c.Admission.RPC = captureRPCServicesConfig(c.Admission.RPC)
	if c.Admission.RPC != nil {
		c.Admission.RPC.Root, c.Admission.RPC.Owner = c.Root, c.Owner
	}
	c.Hello.IdentityHint = bytes.Clone(c.Hello.IdentityHint)
	c.Hello.Policy.Exporter = bytes.Clone(c.Hello.Policy.Exporter)
	c.Admission.applicationHost = s
	s.application = application
	source := &sourcePreparation{config: c, input: input, reservation: owned, shared: shared, references: references, material: static, selection: selection}
	source.references.shared = resourcev4.Reference{}
	s.source = source
	if c.controllerOwner != nil {
		s.notificationController = c.controllerOwner
		// This original candidate is not yet exposed to Controller observers.
		// Session delivery enables its initializer; only the later atomic
		// current-switch gate proves application publication by the Controller.
		s.controllerManaged = true
		s.controllerDiagnosticAttempt = c.controller.serial
		if err = c.controllerOwner.attach(c.controller, s); err != nil {
			source.selection.close()
			application.undoPreparation(s)
			owned.Release()
			shared.Release()
			source.references.close()
			e.mu.Unlock()
			return nil, false, err
		}
	}
	source.config.controller, source.config.controllerOwner = nil, nil
	s.preparationOwner, s.preparationDependencies = owned, shared
	s.preparationDeadline = c.Admission.Initial.Deadline
	s.staticMaterial = static
	e.positions[slot], e.active = s, e.active+1
	adopted = true
	s.beginDiagnostics()
	e.mu.Unlock()
	go s.watch(ctx)
	go s.run(environmentEstablishment{source: source})
	result, err := s.deliver(ctx)
	return result, true, err
}

func (e *Environment) checkSourcePosition(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return cryptov4.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.shared.Check(); err != nil {
		return err
	}
	for _, current := range e.positions {
		if current == nil {
			return nil
		}
	}
	e.observePositionRejection()
	return cryptov4.ErrCapacity
}

func (e *Environment) startSource(ctx context.Context, c SourceConnectConfig, input environmentEstablishment, static *ConnectionMaterial) (*EnvironmentSession, error) {
	s, _, err := e.startSourcePrepared(ctx, c, input, static)
	return s, err
}

func (p *sourcePreparation) prepare(s *EnvironmentSession) (input environmentEstablishment, err error) {
	c := p.config
	input = p.input
	if err = p.check(s); err != nil {
		return input, err
	}
	if err = p.references.subscriptions.AdoptSourcePreparation(c.Subscriptions); err != nil {
		return input, err
	}
	if err = p.references.adoptCarriers(c); err != nil {
		return input, err
	}
	source := "preauthorized_pool"
	if input.kind == 2 {
		source = "live_authority"
	}
	if p.material == nil && c.poolSource != nil {
		if err = c.Admission.headroom.checkWorkloadRevision(); err != nil {
			return input, err
		}
		p.material, err = c.poolSource.acquirePrepared(&s.context, c.Requirements, p.references.subscriptions)
		if err != nil {
			return input, err
		}
		p.references.verification.release()
		// The installed item's generation belongs to that immutable material.
		// A newer pool owner never rewrites an earlier item's captured identity.
		c.Generation = p.material.generation
		p.config.Generation = c.Generation
		err = p.selection.claim(p.material, c.Generation, c.Hello.Attempt, s.environment, source, c.Requirements)
		if err == nil {
			err = p.selection.validate()
		}
	} else if p.material == nil {
		p.acquisition, err = newMaterialAcquisition(&s.context, c.Identity, c.Generation, source, c.Requirements, c.Admission.Initial.Deadline, c.RuntimeBytes, c.MaterialRuntimeBytes, c.Acquisition, c.Material, &p.references)
		if err != nil {
			return input, err
		}
		provider := c.Provider
		if p.references.materialProvider != nil {
			provider = p.references.materialProvider
		}
		if err = c.Admission.headroom.checkWorkloadRevision(); err != nil {
			return input, err
		}
		p.material, err = p.acquisition.Acquire(provider)
		if err != nil {
			s.mu.Lock()
			s.controllerSourceFailure = controllerSourceFailure(err)
			s.mu.Unlock()
			return input, err
		}
		err = p.selection.begin(p.material, c.Generation, c.Hello.Attempt)
	} else {
		err = p.selection.validate()
	}
	if err != nil {
		return input, err
	}
	if err = p.references.subscriptions.CompleteSourceNamespaces(p.material.lease.lease.allCredentialBindings()); err != nil {
		return input, err
	}
	p.references.verification.release()
	if err = s.environment.checkMaterialVerification(p.material); err != nil {
		return input, err
	}
	config := c.Admission
	config.Core.Session = p.material.lease.lease.session
	if config.RPC != nil {
		// Mutate only our original private snapshot before candidate workers
		// start. No stale material's contract or crypto profile is retained.
		config.RPC.Session = config.Core.Session.Contract
		config.RPC.CryptoProfile = config.Core.Session.Profile
	}
	config.Initial.Profile = config.Core.Session.Profile
	config.Initial.Role = protocolv4.ClientToServer
	config.Initial.ActivationSourceProfile = source
	if err = p.race.init(p, s, config); err != nil {
		return input, err
	}
	for {
		p.prepared, config, err = p.race.prepare()
		if err != nil {
			return input, err
		}
		if err = p.check(s); err != nil {
			return input, err
		}
		if err = p.material.check(); err != nil {
			return input, err
		}
		if err = p.prepared.Check(); err == nil {
			break
		}
		if err = p.race.rejectWinner(p.prepared); err != nil {
			return input, err
		}
		p.prepared = nil
	}
	if err = p.race.waitLosers(); err != nil {
		return input, err
	}
	// Winner replacement is over. Return idle provider positions now, while
	// the winner retains its actual backing through physical retirement.
	for i := range p.race.slots {
		if preparation := p.race.slots[i].providerPreparation; preparation != nil {
			preparation.Close()
		}
	}
	c.Hello.Index = p.prepared.AdmissionBinding().Candidate.Index
	if input.kind == 2 && c.LiveIssuance.Signer != nil {
		l, authority := p.material.lease.lease, c.LiveIssuance
		tunnel, selectErr := authority.tunnelFor(l, c.Hello.Index)
		if selectErr != nil {
			return input, selectErr
		}
		p.issuance, err = protocolv4.NewLiveActivationPlan(l.maps[0], l.verification.Rules, l.verification.Delegation, l.verification.Once, authority.Signer,
			protocolv4.LiveActivationConfig{Tunnel: tunnel, Index: c.Hello.Index, Attempt: c.Hello.Attempt, IssuedAt: authority.IssuedAt, ActivationEnd: authority.ActivationEnd, SessionEnd: authority.SessionEnd}, authority.Reservation, c.Environment, p.material.reservation)
		if err != nil {
			return input, err
		}
		if tunnel != nil {
			local := l.tunnelMaterial(c.Hello.Index, protocolv4.ClientToServer)
			if local == nil || !local.pendingGrant {
				return input, cryptov4.ErrConfiguration
			}
			if err = p.issuance.MatchGrantPreparation(protocolv4.ClientToServer, local.liveGrant); err != nil {
				return input, err
			}
		}
		input.live.Issuance = p.issuance
		guard := input.live.Guard
		input.live.Guard = func() error {
			if err := p.material.check(); err != nil {
				return err
			}
			now, err := c.Admission.Core.Clock.Sample()
			if err != nil {
				return err
			}
			requirement := l.validation[0].Policy.Requirements()
			if checkErr := p.issuance.CheckTrust(l.validation[0].Namespace, l.credentials[0], l.validation[0].Issuer, requirement.StalenessMS, requirement.SignerLifetimeMS, l.session.SessionNotAfterMS, now.Interval); checkErr != nil {
				return checkErr
			}
			return guard()
		}
	}
	var subscriptions *protocolv4.CredentialSubscriptions
	p.establishment, subscriptions, err = p.material.establishment(c.Hello, c.Limits, c.Generation, c.Establishment, c.Subscriptions, true, p.references.subscriptions)
	if err != nil {
		return input, err
	}
	establishment := p.establishment
	p.admission, err = NewSessionAdmissionReservation(&s.context, config, p.prepared, subscriptions, c.Root, c.Owner, c.Environment, c.Preauth, c.Scope, nil, nil)
	if err != nil {
		return input, err
	}
	p.config.Admission.headroom.close()
	p.config.Admission.headroom = nil
	if input.kind == 1 {
		input.pool.Establishment, input.pool.Admission = establishment, p.admission
	} else {
		input.live.Establishment, input.live.Admission = establishment, p.admission
	}
	_, err = s.environment.admitAt(&s.context, input, s)
	return input, err
}

func (c SourceLiveIssuance) tunnelFor(lease *ArtifactLease, index uint64) (*protocolv4.LiveTunnelActivationConfig, error) {
	if lease == nil || index >= uint64(len(c.Tunnels)) {
		return nil, cryptov4.ErrConfiguration
	}
	candidate := lease.maps[0].Field("candidates").Index(int(index))
	kind, ok := candidate.Named("Candidate", "path_kind").Uint()
	if !ok {
		return nil, cryptov4.ErrConfiguration
	}
	if kind == 0 {
		if c.Tunnels[index] != nil {
			return nil, cryptov4.ErrConfiguration
		}
		return nil, nil
	}
	selected := c.Tunnel
	if selected == nil {
		selected = c.Tunnels[index]
	}
	if kind != 1 || selected == nil {
		return nil, cryptov4.ErrConfiguration
	}
	return selected, nil
}

func (p *sourcePreparation) check(s *EnvironmentSession) error {
	if err := s.context.Err(); err != nil {
		return err
	}
	if err := p.config.Admission.Initial.Deadline.Check(); err != nil {
		return err
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

// Called only after the original worker returns and its watcher exits. Partial
// construction and canceled late provider results have the same physical
// obligations as a fully adopted admission; no new cleanup task is scheduled.
func (p *sourcePreparation) cleanup() error {
	if err := p.race.cleanup(); err != nil {
		return err
	}
	p.selection.close()
	if p.issuance != nil {
		if err := p.issuance.Close(); err != nil {
			return err
		}
	}
	if p.acquisition != nil {
		p.acquisition.Close()
		if err := p.acquisition.WaitCleanup(context.Background()); err != nil {
			return err
		}
	}
	if p.admission != nil {
		p.admission.Close()
		if err := p.admission.WaitCleanup(context.Background()); err != nil {
			return err
		}
		if err := p.admission.Retire(); err != nil {
			return err
		}
	} else if p.prepared != nil {
		p.prepared.Close()
		if err := p.prepared.WaitCleanup(context.Background()); err != nil {
			return err
		}
		if err := p.prepared.Retire(); err != nil {
			return err
		}
	}
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
	c.Admission.headroom.close()
	p.references.close()
	for i := range p.race.slots {
		p.race.slots[i].parent.close()
		p.race.slots[i].floor.Close()
		if preparation := p.race.slots[i].providerPreparation; preparation != nil {
			preparation.Close()
		}
	}
	c.LiveIssuance.Reservation.Release()
	for _, ref := range [...]resourcev4.Reference{c.Acquisition, c.Material, c.Establishment, c.Subscriptions, c.CarrierReservation} {
		ref.Release()
	}
	// Durable input workspaces move to the ordinary establishment on adoption.
	// Stale handles are harmless; unadopted workspaces still leave this owner.
	p.input.pool.Consume.Release()
	p.input.live.Buffers.Release()
	p.input.live.Invocation.Release()
	if relay := p.input.live.ServerPublication.Relay; relay != nil {
		relay.Reservation.Release()
	}
	clear(c.Hello.IdentityHint)
	clear(c.Hello.Policy.Exporter)
	p.shared.Release()
	p.reservation.Release()
	*p = sourcePreparation{}
	return nil
}

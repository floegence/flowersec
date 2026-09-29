package sessionv4

import (
	"bytes"
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// TunnelAcceptedEntranceRequirements excludes the already owned prepared
// carrier. The metadata owns the endpoint HOP work and its bounded scratch.
func TunnelAcceptedEntranceRequirements(c AcceptedEntranceConfig) (resourcev4.Vector, error) {
	metadata, initial, _, err := acceptedEntranceCharges(c)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	scratch, err := hopAuthenticationScratchBytes()
	if err == nil {
		metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: scratch})
	}
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return metadata.Add(initial)
}

// NewTunnelAcceptedEntrance transfers the original allowed server carrier to
// preauth. No consumer spend, admission receipt, or replacement connection is
// involved. ReadClientHello performs HOP_AUTH before exposing NEGOTIATE bytes.
// A nonnil entrance owns cleanup even when construction returns an error.
func NewTunnelAcceptedEntrance(ctx context.Context, c AcceptedEntranceConfig, recipient *TunnelServerAllowRecipient, root *resourcev4.Root, owner resourcev4.OwnerKey, environment resourcev4.Reference, accounts ...resourcev4.Account) (_ *AcceptedEntrance, err error) {
	if ctx == nil || recipient == nil || root == nil {
		return nil, cryptov4.ErrConfiguration
	}
	metadata, initial, _, err := acceptedEntranceCharges(c)
	if err != nil {
		return nil, err
	}
	scratch, err := hopAuthenticationScratchBytes()
	if err == nil {
		metadata, err = metadata.Add(resourcev4.Vector{resourcev4.SDKBytes: scratch})
	}
	if err != nil {
		return nil, err
	}
	r := recipient
	r.mu.Lock()
	if r.closed || r.busy || !r.allowed || r.entranceActive {
		r.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	r.busy = true
	prepared, lease, identity := r.prepared, r.lease.lease, r.identity.identity
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.busy = false; r.cleanupLocked(); r.mu.Unlock() }()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = r.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if c.Initial.Deadline != r.deadline || c.Initial.Profile != lease.session.Profile || c.Initial.ActivationSourceProfile != lease.source {
		return nil, cryptov4.ErrConfiguration
	}
	if err = r.checkPreauth(); err != nil {
		return nil, err
	}
	if err = prepared.Check(); err != nil {
		return nil, err
	}
	if err = lease.maps[0].CheckConnectionGuarantees(r.expected.Candidate.Index, protocolv4.ServerToClient, prepared.guarantees); err != nil {
		return nil, err
	}
	var refs [2]resourcev4.Reference
	requests := [2]resourcev4.Request{{Owner: admissionResourceKey(owner, 0), Charge: metadata, Accounts: accounts}, {Owner: admissionResourceKey(owner, 1), Charge: initial, Accounts: accounts}}
	if err = root.ReserveBatch(requests[:], refs[:]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs {
			ref.Release()
		}
	}()
	if err = refs[0].CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	backing, err := refs[1].Borrow()
	if err != nil {
		return nil, err
	}
	owned, err := refs[0].Take(metadata)
	if err != nil {
		backing.Release()
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			owned.Release()
			backing.Release()
		}
	}()
	e := &AcceptedEntrance{owner: owned, environment: environment, initialBacking: backing, carrier: prepared, tunnel: r, config: c, wake: make(chan struct{}, 1), done: make(chan struct{})}
	e.guard = acceptedAuthorization{reservation: owned, environment: environment, deadline: c.Initial.Deadline, tunnel: r, wake: make(chan struct{}, 1)}
	grant, relay, _, err := lease.endpointCredentialMaps(r.expected.Candidate.Index, protocolv4.ServerToClient)
	if err != nil {
		return nil, err
	}
	if r.live {
		grant = r.grantMap
	}
	material := EstablishmentMaterial{Role: protocolv4.ServerToClient, Artifact: lease.maps[0], ClientCertificate: lease.maps[2], ServerCertificate: lease.maps[3], Grant: grant, RelayCertificate: relay, Signer: identity.signer}
	if err = e.hop.prepare(&material, r.expected.Candidate, prepared, c.Initial.Limits); err != nil {
		return nil, err
	}
	// No network, signer, clock adapter or store call runs under this gate.
	r.mu.Lock()
	prepared.mu.Lock()
	if r.closed || prepared.closed || prepared.allowRecipient != r || !prepared.allowGranted || prepared.activated || prepared.admission != nil {
		prepared.mu.Unlock()
		r.mu.Unlock()
		return nil, resourcev4.ErrOwner
	}
	r.entranceActive = true
	prepared.activated = true
	prepared.parent, prepared.deadline = nil, nil
	prepared.mu.Unlock()
	r.mu.Unlock()
	adopted = true
	config := c.Initial
	config.Authorization, config.Reservation, config.accepted, config.hop = &e.guard, refs[1], &e.guard, &e.hop
	if prepared.binding.MessageCarrier {
		e.initial, err = NewInitialMessages(ctx, config, &prepared.messageAdapter)
	} else {
		e.initial, err = NewInitialStream(ctx, config, &prepared.streamAdapter)
	}
	if err != nil {
		e.Close()
	}
	return e, err
}

// checkPreauth retains the original material through the entrance's physical
// retirement. Subscriptions bound every namespace freshness interval and wake
// the same Initial watchdog; an allow never renews those intervals.
func (r *TunnelServerAllowRecipient) checkPreauth() error {
	r.mu.Lock()
	if r.closed || !r.allowed {
		r.mu.Unlock()
		return resourcev4.ErrClosed
	}
	subscriptions, deadline, cap := r.subscriptions, r.deadline, r.delivered.NotAfterMS
	r.mu.Unlock()
	_, err := subscriptions.CheckPreparation()
	if err != nil {
		return err
	}
	if err = deadline.Tighten(cap); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return resourcev4.ErrClosed
	}
	return r.reservation.Check()
}

func (r *TunnelServerAllowRecipient) preparationWake() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.subscriptions.PreparationWake()
}

func (r *TunnelServerAllowRecipient) notifyPreparation() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.subscriptions.NotifyPreparation()
}

func (r *TunnelServerAllowRecipient) retireEntrance() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed, r.entranceActive = true, false
	if r.prepared != nil {
		r.prepared.mu.Lock()
		if r.prepared.allowRecipient == r {
			r.prepared.allowRecipient = nil
		}
		r.prepared.mu.Unlock()
	}
	r.cleanupLocked()
}

func (e *AcceptedEntrance) checkTunnelHello(hello InitialHello) error {
	r := e.tunnel
	if r == nil || hello.Artifact == nil || len(hello.Policy.Exporter) != 0 {
		return protocolv4.ErrHopAuthContext
	}
	session, err := hello.Artifact.SessionParameters()
	if err != nil {
		return err
	}
	if session != e.carrier.binding.Session || hello.Index != r.expected.Candidate.Index || hello.Attempt != r.expected.Attempt {
		return protocolv4.ErrHopAuthContext
	}
	if err = hello.Artifact.CheckBindingMode(hello.Index, hello.Policy.BindingMode); err != nil {
		return err
	}
	if err = r.checkPreauth(); err != nil {
		return err
	}
	return hello.Artifact.CheckConnectionGuarantees(hello.Index, protocolv4.ServerToClient, e.carrier.guarantees)
}

// Adoption must match the exact original grant and relay certificate whose
// possession completed on this entrance. FSB then supplies independent e2e
// activation authority; neither proof can substitute for the other.
func (e *AcceptedEntrance) matchTunnelMaterial(m *EstablishmentMaterial, selected protocolv4.PoolMember) error {
	if e.tunnel == nil || m.Grant == nil || m.RelayCertificate == nil || selected != e.tunnel.expected.Candidate || m.Hello.Attempt != e.tunnel.expected.Attempt {
		return protocolv4.ErrHopAuthContext
	}
	e.initial.mu.Lock()
	complete := e.initial.hopPhase == 4 && e.initial.config.hop == &e.hop
	e.initial.mu.Unlock()
	if !complete {
		return protocolv4.ErrHopAuthStage
	}
	for _, pair := range [][2]*protocolv4.SignedMap{{m.Grant, e.hop.grant}, {m.RelayCertificate, e.hop.relayCertificate}, {m.ServerCertificate, e.hop.localCertificate}} {
		got, err := pair[0].Bytes()
		if err != nil {
			return err
		}
		want, err := pair[1].Bytes()
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return protocolv4.ErrHopAuthContext
		}
	}
	return nil
}

func (r *TunnelServerAllowRecipient) remainingPreauth() (uint64, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, resourcev4.ErrClosed
	}
	s := r.subscriptions
	r.mu.Unlock()
	return s.PreparationRemainingMS()
}

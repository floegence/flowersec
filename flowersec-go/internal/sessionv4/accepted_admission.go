package sessionv4

import (
	"context"
	"crypto/sha256"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// AcceptedAdmissionMaterial is independently verified local material. The
// constructor still compares its actual signed FSB bytes with the same entrance
// and checks the original hello/activation/credential closure under current
// trust. None of these immutable values is a durable admitted receipt.
type AcceptedAdmissionMaterial struct {
	Activation             *protocolv4.ActivationBinding
	Authority              *protocolv4.ActivationAuthority
	FSB, ClientCertificate *protocolv4.SignedMap
	Subscriptions          *protocolv4.CredentialSubscriptions
	Attempt                [16]byte
}

// NewAcceptedSessionAdmissionReservation reserves the core and metadata only
// after this entrance has received and verified its original FSB. The existing
// Initial/preauth backing is borrowed without a duplicate charge. Success owns
// the entrance and subscriptions. Failure before adoption leaves them with the
// caller; a later authorization failure returns the owned reservation together
// with the error so the caller can join and retire its actual cleanup.
func NewAcceptedSessionAdmissionReservation(ctx context.Context, c SessionAdmissionConfig, e *AcceptedEntrance, material AcceptedAdmissionMaterial, root *resourcev4.Root, owner resourcev4.OwnerKey, environment, preauth resourcev4.Reference, scope SessionResourceScope, accounts ...resourcev4.Account) (a *SessionAdmissionReservation, err error) {
	return newAcceptedSessionAdmissionReservation(ctx, c, e, material, root, owner, environment, preauth, scope, nil, accounts...)
}

func newAcceptedSessionAdmissionReservation(ctx context.Context, c SessionAdmissionConfig, e *AcceptedEntrance, material AcceptedAdmissionMaterial, root *resourcev4.Root, owner resourcev4.OwnerKey, environment, preauth resourcev4.Reference, scope SessionResourceScope, host *EnvironmentSession, accounts ...resourcev4.Account) (a *SessionAdmissionReservation, err error) {
	if ctx == nil || e == nil || material.Activation == nil || material.Authority == nil || material.Subscriptions == nil || material.FSB == nil || material.ClientCertificate == nil {
		return nil, cryptov4.ErrConfiguration
	}
	meta, _, err := sessionAdmissionCharges(c)
	if err != nil {
		return nil, err
	}
	c.Requirements.ApplicationProfile = nil
	if err = c.Requirements.Check(e.carrier.guarantees); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	x, err := e.beginHosted(host)
	if err != nil {
		return nil, err
	}
	defer e.end()
	if environment != e.environment || c.Initial.Role != protocolv4.ServerToClient || c.Initial.Profile != e.config.Initial.Profile || c.Initial.Deadline != e.config.Initial.Deadline || c.Initial.ActivationSourceProfile != e.config.Initial.ActivationSourceProfile {
		return nil, cryptov4.ErrConfiguration
	}
	if err = preauth.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	binding := PreparedCarrierBinding{Session: c.Core.Session, Role: protocolv4.ServerToClient, Candidate: material.Activation.Winner(), Attempt: material.Attempt, MessageCarrier: e.carrier.binding.MessageCarrier}
	if c.Core.MessageCarrier != binding.MessageCarrier {
		return nil, cryptov4.ErrConfiguration
	}
	if err = material.Authority.MatchOriginal(binding.Session, binding.Attempt, binding.Candidate); err != nil {
		return nil, err
	}
	if err = material.Authority.MatchBinding(material.Activation); err != nil {
		return nil, err
	}
	wire, err := material.FSB.Bytes()
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(wire)
	x.mu.Lock()
	err = x.checkLocked()
	if err == nil && (x.phase != 3 || x.sending || x.receiving || x.authenticating || x.fsbDigest != actual || x.hello == nil || x.config.Limits.MaxFrame != c.Initial.Limits.MaxFrame) {
		err = ErrInitialPhase
	}
	hello := x.hello
	x.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err = hello.MatchOriginal(binding.Session, binding.Attempt, binding.Candidate); err != nil {
		return nil, err
	}
	if err = c.Features.MatchHello(hello, binding.Role); err != nil {
		return nil, err
	}
	admissionBinding, err := hello.MatchFSB(material.Activation, material.FSB, material.ClientCertificate)
	if err != nil {
		return nil, err
	}
	facts, err := hello.AdmissionFacts(material.Activation, material.FSB, material.ClientCertificate)
	if err != nil {
		return nil, err
	}
	if _, err = material.Subscriptions.CheckOriginalFor(environment, binding.Session, binding.Role, binding.Candidate); err != nil {
		return nil, err
	}
	held, err := preauth.Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if a == nil {
			held.Release()
		}
	}()
	x.mu.Lock()
	initial, err := x.config.Reservation.Borrow()
	x.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		if a == nil {
			initial.Release()
		}
	}()
	var batch sessionAdmissionBatch
	if err = batch.prepare(c, root, owner, environment, scope, accounts...); err != nil {
		return nil, err
	}
	defer batch.release()
	var requests [sessionAdmissionOwnerCapacity + 1]resourcev4.Request
	var refs [sessionAdmissionOwnerCapacity + 1]resourcev4.Reference
	for i := 0; i < batch.count; i++ {
		requests[i], err = batch.request(i)
		if err != nil {
			return nil, err
		}
	}
	n := batch.count
	requests[n] = resourcev4.Request{Owner: admissionResourceKey(owner, coreOwnerCapacity), Charge: meta, Accounts: batch.core.accounts[:batch.core.accountCount]}
	if err = root.ReserveBatch(requests[:n+1], refs[:n+1]); err != nil {
		return nil, err
	}
	defer func() {
		for _, ref := range refs[:n+1] {
			ref.Release()
		}
	}()
	metadata, err := refs[n].Take(meta)
	if err != nil {
		return nil, err
	}
	defer func() {
		if a == nil {
			metadata.Release()
		}
	}()
	slot, err := refs[0].Borrow()
	if err != nil {
		return nil, err
	}
	defer func() {
		if a == nil {
			slot.Release()
		}
	}()
	if err = batch.reserveDeliveryFloor(material.Subscriptions, refs[:n]); err != nil {
		return nil, err
	}
	p := &SessionAdmissionReservation{ctx: ctx, prepared: e.carrier, guarantees: e.carrier.guarantees, accepted: e, initial: x, config: c, binding: binding, scope: scope, owner: metadata, initialReservation: initial, preauth: held, environment: environment, sessionSlot: slot, wake: make(chan struct{}, 1), done: make(chan struct{}), acceptedBinding: admissionBinding, acceptedFacts: facts, acceptedFSB: append([]byte(nil), wire...)}
	p.claim.owner = p
	e.mu.Lock()
	if e.closed || e.admission != nil {
		e.mu.Unlock()
		return nil, cryptov4.ErrClosed
	}
	p.subscriptions, err = material.Subscriptions.AdoptPreparation(environment, binding.Session, binding.Role, binding.Candidate, func() error {
		var adoptErr error
		adoptErr = batch.adopt(p, refs[:n])
		if adoptErr == nil {
			e.admission = p
		}
		return adoptErr
	})
	e.mu.Unlock()
	if err != nil {
		return nil, err
	}
	a = p // This original aggregate owns every real tail after adoption.
	authorization, err := p.subscriptions.Authorize(material.Authority)
	if err == nil {
		_, err = authorization.CheckAdmission()
	}
	if err == nil {
		err = authorization.ConstrainHandshakeDeadline(c.Initial.Deadline)
	}
	if authorization != nil {
		p.authorization = authorization
	}
	if err == nil {
		e.guard.mu.Lock()
		err = e.guard.checkLocked()
		if err == nil && e.guard.owner != nil {
			err = cryptov4.ErrTransition
		}
		if err == nil {
			e.guard.owner, e.guard.authorization = p, authorization
			e.guard.admissionBinding = admissionBinding
		}
		e.guard.mu.Unlock()
		e.guard.Notify()
	}
	if err != nil {
		p.Close()
		return p, err
	}
	return p, nil
}

// AdmitSQLite assembles the concrete durable adapter from the trusted service
// mapping and preadmitted same-Environment workspaces. It never accepts a
// receipt or query row as a substitute for this entrance's original FSB.
func (a *SessionAdmissionReservation) AdmitSQLite(store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteAdmissionAuthority, owner ledgerv4.AdmissionOwner, buffers, invocation resourcev4.Reference) (x *InitialExchange, response protocolv4.AdmissionResponse, err error) {
	if a == nil {
		return nil, response, cryptov4.ErrConfiguration
	}
	a.mu.Lock()
	accepted := a.accepted != nil
	a.mu.Unlock()
	if !accepted {
		return nil, response, cryptov4.ErrConfiguration
	}
	claim, err := a.beginClaim()
	if err != nil {
		return nil, response, err
	}
	defer func() {
		a.mu.Lock()
		a.claimActive = false
		a.signalLocked()
		a.mu.Unlock()
		if err != nil {
			a.Close()
			x = nil
			response = protocolv4.AdmissionResponse{}
		}
	}()
	guard := func() error { a.mu.Lock(); defer a.mu.Unlock(); return a.checkLocked() }
	durable, err := ledgerv4.NewSQLiteAdmission(a.ctx, store, authority, a.acceptedFacts, owner, a.config.Core.Clock, a.config.Initial.Deadline, guard, buffers, invocation, a.environment)
	if err != nil {
		return nil, response, err
	}
	a.mu.Lock()
	a.ledger = durable
	err = a.checkLocked()
	a.mu.Unlock()
	if err != nil {
		return nil, response, err
	}
	err = durable.Admit(func(_ context.Context, result protocolv4.AdmissionResponse) error {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.checkLocked(); err != nil {
			return err
		}
		if claim != &a.claim || !a.claimActive || a.committed || a.activated || a.acceptedBinding != result.AdmissionBinding {
			return cryptov4.ErrTransition
		}
		g := &a.accepted.guard
		g.mu.Lock()
		defer g.mu.Unlock()
		if err := g.checkLocked(); err != nil {
			return err
		}
		if g.owner != a || g.authorization != a.authorization || g.admitted {
			return cryptov4.ErrTransition
		}
		if _, err := g.authorization.CheckAdmission(); err != nil {
			return err
		}
		g.serverEpoch, g.reservationKey = result.ServerEpoch, result.ReservationKey
		g.admitted, a.committed, a.activated = true, true, true
		x, response = a.initial, result
		return nil
	})
	return
}

func (e *AcceptedEntrance) checkAdmission(a *SessionAdmissionReservation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.admission != a {
		return cryptov4.ErrClosed
	}
	if err := e.owner.Check(); err != nil {
		return err
	}
	if !a.activated {
		if err := e.initialBacking.Check(); err != nil {
			return err
		}
	}
	p := e.carrier.preparedCarrier
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return p.cause
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	return p.shared.Check()
}

package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

func (p *SessionEstablishment) bindLiveProof(wire []byte) error {
	m := &p.material
	if m.Source != "live_authority" || m.Proof != nil || m.Live.Rules == nil || p.selection == nil {
		return cryptov4.ErrTransition
	}
	proof, err := p.codecs[1].Verify(wire, m.Live.Key, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}})
	if err != nil {
		return err
	}
	m.Proof = proof
	m.Activation, err = p.selection.BindActivation(m.Artifact, proof, "live_authority", m.Hello.Index)
	if err != nil {
		return err
	}
	if err = m.Activation.MatchOriginal(p.session, m.Hello.Attempt, p.expected); err != nil {
		return err
	}
	if err = m.Activation.MatchCertificates(m.ClientCertificate, m.ServerCertificate); err != nil {
		return err
	}
	m.Authority, err = m.Live.Rules.BindActivationAuthority(m.Activation, m.Artifact, m.Live.Delegation, m.Live.Once)
	return err
}

// ConnectLiveSQLite is the in-process trusted authority composition. The
// authority owns its own original TxA/TxB and policy guard. A distributed
// control adapter must preserve those separate original owners; it cannot
// reconstruct this path from QuerySpendReceipt or a restored consumed row.
func (p *SessionEstablishment) ConnectLiveSQLite(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteLiveAuthority, issuance *protocolv4.LiveActivationPlan, owner ledgerv4.LiveSpendOwner, authorityGuard func() error, policy func(context.Context) (bool, error), buffers, invocation resourcev4.Reference) (core *SessionCore, err error) {
	return p.connectLiveSQLite(a, store, authority, issuance, owner, authorityGuard, policy, buffers, invocation, nil)
}

func (p *SessionEstablishment) connectLiveSQLite(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteLiveAuthority, issuance *protocolv4.LiveActivationPlan, owner ledgerv4.LiveSpendOwner, authorityGuard func() error, policy func(context.Context) (bool, error), buffers, invocation resourcev4.Reference, host *EnvironmentSession) (core *SessionCore, err error) {
	if a == nil || authorityGuard == nil || policy == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = p.beginHosted(protocolv4.ClientToServer, host); err != nil {
		return nil, err
	}
	defer func() { p.finish(err) }()
	if p.material.Source != "live_authority" || p.material.Proof != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = issuance.MatchOriginal(p.session, p.material.Hello.Attempt, p.expected); err != nil {
		return nil, err
	}
	if err = p.attach(a); err != nil {
		return nil, err
	}
	if err = p.authorizeApplication(a); err != nil {
		return nil, err
	}
	claim, err := a.beginClaim()
	if err != nil {
		return nil, err
	}
	// Hold the original Session claim through actual store, policy, signing
	// and local activation returns. The establishment pin then spans READY.
	claimFinished := false
	finishClaim := func() {
		if claimFinished {
			return
		}
		a.mu.Lock()
		a.claimActive = false
		a.signalLocked()
		a.mu.Unlock()
		claimFinished = true
	}
	defer finishClaim()
	guard := func() error {
		if err := p.guard(); err != nil {
			return err
		}
		return authorityGuard()
	}
	durable, err := ledgerv4.NewSQLiteLiveSpend(a.ctx, store, authority, issuance, owner, a.config.Core.Clock, a.config.Initial.Deadline, guard, buffers, invocation, a.environment)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.liveSpend = durable
	err = a.checkLocked()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var initial *InitialExchange
	err = durable.Authorize(policy, func(_ context.Context, wire []byte) error {
		if err := p.guard(); err != nil {
			return err
		}
		if err := p.bindLiveProof(wire); err != nil {
			return err
		}
		a.mu.Lock()
		check := a.checkLocked()
		if check == nil && (!a.claimActive || claim != &a.claim || a.committed || a.activated || a.authorization != nil) {
			check = cryptov4.ErrTransition
		}
		if check == nil {
			a.authorization, check = a.subscriptions.Authorize(p.material.Authority)
		}
		if check == nil {
			check = a.authorization.ConstrainHandshakeDeadline(a.config.Initial.Deadline)
		}
		if check == nil {
			_, check = a.authorization.CheckAdmission()
		}
		if check == nil {
			a.committed = true
		}
		a.mu.Unlock()
		if check != nil {
			return check
		}
		var err error
		initial, err = a.activateOriginal(p.material.Authority, claim)
		return err
	})
	finishClaim()
	if err != nil {
		return nil, err
	}
	return p.connectActivated(a, initial)
}

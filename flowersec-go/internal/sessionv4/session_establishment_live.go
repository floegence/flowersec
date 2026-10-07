package sessionv4

import (
	"context"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
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
func (p *SessionEstablishment) ConnectLiveSQLite(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteLiveAuthority, issuance *protocolv4.LiveActivationPlan, owner ledgerv4.LiveSpendOwner, authorityGuard func() error, policy func(context.Context) (bool, error), buffers, invocation resourcev4.Reference, allow ...LiveServerAllowConfig) (core *SessionCore, err error) {
	return p.connectLiveSQLite(a, store, authority, issuance, owner, authorityGuard, policy, buffers, invocation, nil, allow...)
}

func (p *SessionEstablishment) connectLiveSQLite(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteLiveAuthority, issuance *protocolv4.LiveActivationPlan, owner ledgerv4.LiveSpendOwner, authorityGuard func() error, policy func(context.Context) (bool, error), buffers, invocation resourcev4.Reference, host *EnvironmentSession, allow ...LiveServerAllowConfig) (core *SessionCore, err error) {
	if a == nil || authorityGuard == nil || policy == nil || len(allow) > 1 {
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
	var publication LiveServerAllowConfig
	var serverRequest TunnelServerAllowRequest
	if issuance.IsTunnel() {
		if len(allow) != 1 || p.material.RelayCertificate == nil {
			return nil, cryptov4.ErrConfiguration
		}
		publication = allow[0]
		fields, _, err := issuance.CopyProjection(p.fsbCopy)
		if err != nil {
			return nil, err
		}
		serverRequest, err = publication.Request(issuance, fields, a.config.Initial.Deadline.Cap())
		if err != nil {
			return nil, err
		}
	} else if p.material.RelayCertificate != nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = p.attach(a); err != nil {
		return nil, err
	}
	if err = p.authorizeApplication(a); err != nil {
		return nil, err
	}
	var relay *ledgerv4.SQLiteLiveRelayPublication
	if publication.Relay != nil {
		relay, err = ledgerv4.NewSQLiteLiveRelayPublication(a.ctx, store, issuance, *publication.Relay)
		if err != nil {
			return nil, err
		}
		defer relay.Close()
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
	if relay != nil {
		if err = durable.AttachRelayPublication(relay); err != nil {
			_ = durable.Cleanup()
			return nil, err
		}
	}
	a.mu.Lock()
	a.liveSpend = durable
	err = a.checkLocked()
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var initial *InitialExchange
	if issuance.IsTunnel() {
		err = durable.AuthorizeMaterial(policy, func(ctx context.Context, material [3][]byte) error {
			if err := p.publishLiveServerAllow(ctx, issuance, publication, serverRequest, [2][]byte{material[0], material[2]}, guard); err != nil {
				return err
			}
			var err error
			initial, err = p.activateLiveProof(a, claim, material[0], material[1])
			return err
		})
	} else {
		err = durable.Authorize(policy, func(_ context.Context, wire []byte) error {
			var err error
			initial, err = p.activateLiveProof(a, claim, wire)
			return err
		})
	}
	finishClaim()
	if err != nil {
		return nil, err
	}
	return p.connectActivated(a, initial)
}

// activateLiveProof is the shared local gate for in-process and authenticated
// remote control results. Neither an authority success nor a valid signature
// proves that this original Connect, carrier, application or namespace is live.
func (p *SessionEstablishment) activateLiveProof(a *SessionAdmissionReservation, claim *sessionAdmissionClaim, wire []byte, grant ...[]byte) (*InitialExchange, error) {
	if err := p.guard(); err != nil {
		return nil, err
	}
	tunnel := p.material.RelayCertificate != nil
	if tunnel && (len(grant) != 1 || len(grant[0]) == 0) || !tunnel && len(grant) != 0 {
		return nil, cryptov4.ErrConfiguration
	}
	if err := p.bindLiveProof(wire); err != nil {
		return nil, err
	}
	if tunnel {
		if err := p.bindLiveGrant(a, grant[0]); err != nil {
			return nil, err
		}
	}
	a.mu.Lock()
	err := a.checkLocked()
	if err == nil && (!a.claimActive || claim != &a.claim || a.committed || a.activated || a.authorization != nil) {
		err = cryptov4.ErrTransition
	}
	if err == nil && tunnel {
		err = p.prepareHop(a)
	}
	if err == nil {
		a.authorization, err = a.subscriptions.Authorize(p.material.Authority)
	}
	if err == nil {
		err = a.authorization.ConstrainHandshakeDeadline(a.config.Initial.Deadline)
	}
	if err == nil {
		_, err = a.authorization.CheckAdmission()
	}
	if err == nil {
		a.committed = true
	}
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return a.activateOriginal(p.material.Authority, claim)
}

func (p *SessionEstablishment) bindLiveGrant(a *SessionAdmissionReservation, wire []byte) error {
	closure, err := p.bindLiveGrantClosure(wire)
	if err != nil {
		return err
	}
	return a.subscriptions.CompleteLiveGrant(closure)
}

func (p *SessionEstablishment) bindLiveGrantClosure(wire []byte) (*protocolv4.EndpointCredentials, error) {
	m := &p.material
	if m.Grant != nil || m.Authority == nil || m.LiveGrant.Validation.Namespace == nil {
		return nil, cryptov4.ErrTransition
	}
	grant, err := p.codecs[6].Verify(wire, m.LiveGrant.Validation.Issuer.Key, protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	m.Grant = grant
	closure, err := protocolv4.BindEndpointCredentials(m.Role, m.Artifact, p.expected.Index, m.ClientCertificate, m.ServerCertificate, grant, m.RelayCertificate)
	if err != nil {
		return nil, err
	}
	if err = closure.MatchActivation(m.Authority); err != nil {
		return nil, err
	}
	grantIssued, _ := grant.Field("issued_at_ms").Uint()
	proofIssued, _ := m.Proof.Field("issued_at_ms").Uint()
	if grantIssued != proofIssued {
		return nil, cryptov4.ErrConfiguration
	}
	return closure, nil
}

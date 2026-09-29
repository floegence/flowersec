package sessionv4

import (
	"bytes"
	"context"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// LiveAuthorizationRequest is the frozen public projection of one original
// prepared direct/local connection. The authenticated control adapter binds it
// to its independently configured authority and original retry key. It sends
// neither PSK nor identity private keys. The authority resolves the original
// verified Artifact and derives its own proof projection, not one supplied by
// this request. AttemptNo is transport metadata, never part of the spend key.
type LiveAuthorizationRequest struct {
	Tenant, Audience, CryptoProfile          string
	Issuer, Lease, Attempt                   [16]byte
	Artifact, ClientIdentity, ServerIdentity [32]byte
	Winner                                   protocolv4.PoolMember
	ActivationNotAfterMS                     uint64
	AttemptNo                                uint8
}

// TunnelServerAllowRequest is the fixed public projection used by the
// coordinator to deliver one already-issued server-leg Grant to its original
// recipient. It carries no Artifact, PSK, activation proof or private key.
// Recipient and Incarnation are supplied by the independently authenticated
// control adapter; they are never inferred from a URL or a peer message.
type TunnelServerAllowRequest struct {
	Tenant, Audience               string
	Artifact, Grant, RelayIdentity [32]byte
	Attempt, Pairing, Leg          [16]byte
	Recipient, Incarnation         [16]byte
	Candidate                      protocolv4.PoolMember
	NotAfterMS                     uint64
}

func (r TunnelServerAllowRequest) Check() error {
	for _, scope := range []string{r.Tenant, r.Audience} {
		if len(scope) == 0 || len(scope) > 128 {
			return cryptov4.ErrConfiguration
		}
		for i, c := range scope {
			alpha := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
			if !alpha && (i == 0 || c != '.' && c != '_' && c != ':' && c != '/' && c != '@' && c != '-') {
				return cryptov4.ErrConfiguration
			}
		}
	}
	if r.Artifact == ([32]byte{}) || r.Grant == ([32]byte{}) || r.RelayIdentity == ([32]byte{}) ||
		r.Attempt == ([16]byte{}) || r.Pairing == ([16]byte{}) || r.Leg == ([16]byte{}) || r.Recipient == ([16]byte{}) || r.Incarnation == ([16]byte{}) ||
		r.Candidate.Index >= 16 || r.Candidate.CandidateID == ([16]byte{}) || r.Candidate.RouteDigest == ([32]byte{}) || r.NotAfterMS == 0 {
		return cryptov4.ErrConfiguration
	}
	return nil
}

// TunnelServerAllowProvider owns the authenticated control transport and the
// recipient's unique registration/incarnation index. A successful call means
// only that the original allow bytes were handed to that provider; the
// recipient still verifies Grant, route, attempt, fencing and expiry.
// The provider calls the bounded original guard immediately before publishing
// bytes, including after a slow TLS callback. It retains all actual work and
// borrowed arguments until return; it never queues or detaches publication.
type TunnelServerAllowProvider interface {
	PublishServerAllow(context.Context, TunnelServerAllowRequest, []byte, func() error) error
}

type TunnelServerAllowConfig struct {
	Provider               TunnelServerAllowProvider
	Recipient, Incarnation [16]byte
	// Grant is the separately issued server-leg projection, never the client's
	// role_mask=5 grant. Validation comes from independent issuer trust.
	Grant      *protocolv4.SignedMap
	Validation protocolv4.CredentialValidation
}

type tunnelServerPublication struct {
	provider   TunnelServerAllowProvider
	request    TunnelServerAllowRequest
	grant      *protocolv4.SignedMap
	credential *protocolv4.Credential
	validation protocolv4.CredentialValidation
	started    bool
}

// LiveAuthorizationProvider is the trusted control-transport adapter. One call
// performs one physical request to the original independently authenticated
// authority. It has no retry, credential fallback, or internal queue. The
// original control request may create or join the authority's unique invocation;
// a query receipt alone must never be translated into a proof response.
//
// A successful call returns complete canonical activation proof bytes in dst.
// It retains no borrowed output after return and does not detach canceled I/O.
// HTTP response authentication, request binding and any authority-side body/join
// work window belong to this adapter; Session independently verifies the proof
// against its current namespace and original winner before using Activate.
// Provider backing belongs to the connection's original Dependencies reservation.
type LiveAuthorizationProvider interface {
	RequestAuthorization(context.Context, LiveAuthorizationRequest, []byte) (int, error)
}

// LiveControlConfig selects the consumer-only live control path. RuntimeBytes
// includes the qualified control provider's actual buffers, task, TLS and work
// allowance. This explicit conservative L1 uses one physical attempt and never
// creates a signing key or SQLite authority in the consumer.
// LiveTunnelAuthorizationProvider returns proof and this client's original
// Grant together. The authority owns server publication; the consumer never
// obtains the remote Grant or an allow dispatch guard from this response.
type LiveTunnelAuthorizationProvider interface {
	LiveAuthorizationProvider
	RequestTunnelAuthorization(context.Context, LiveAuthorizationRequest, [2][]byte) ([2]int, error)
}

type LiveControlConfig struct {
	Provider     LiveAuthorizationProvider
	ServerAllow  TunnelServerAllowConfig
	RuntimeBytes uint64
	Tunnel       bool
}

func LiveControlCharge(c LiveControlConfig) (resourcev4.Vector, error) {
	if c.Provider == nil || c.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	limit, err := protocolv4.SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if c.Tunnel {
		if _, ok := c.Provider.(LiveTunnelAuthorizationProvider); !ok {
			return resourcev4.Vector{}, cryptov4.ErrConfiguration
		}
		grant, err := protocolv4.SchemaByteLimit("Grant")
		if err != nil {
			return resourcev4.Vector{}, err
		}
		limit += grant
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: uint64(limit) + uint64(unsafe.Sizeof(LiveAuthorizationRequest{})) + 1024, resourcev4.Items: 1, resourcev4.WorkSlots: 1, resourcev4.Tasks: 1, resourcev4.Timers: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

func (p *SessionEstablishment) liveControlRequest() (LiveAuthorizationRequest, error) {
	m := &p.material
	if m.Source != "live_authority" || m.Proof != nil || m.Live.Rules == nil || p.selection == nil {
		return LiveAuthorizationRequest{}, cryptov4.ErrConfiguration
	}
	if m.RelayCertificate != nil {
		if m.Grant != nil || m.LiveGrant.Validation.Namespace == nil {
			return LiveAuthorizationRequest{}, cryptov4.ErrConfiguration
		}
		if err := m.Artifact.CheckTunnelCandidate(p.expected.Index); err != nil {
			return LiveAuthorizationRequest{}, err
		}
	} else if err := m.Artifact.CheckDirectListenerCandidate(p.expected.Index); err != nil {
		return LiveAuthorizationRequest{}, err
	}
	r := LiveAuthorizationRequest{Artifact: p.session.ArtifactDigest, Attempt: m.Hello.Attempt, Winner: p.expected, AttemptNo: 1}
	for _, field := range []struct {
		name string
		dst  *string
	}{{"tenant_id", &r.Tenant}, {"audience", &r.Audience}, {"crypto_profile_id", &r.CryptoProfile}} {
		text, ok := m.Artifact.Field(field.name).Text()
		if !ok {
			return LiveAuthorizationRequest{}, cryptov4.ErrConfiguration
		}
		*field.dst = strings.Clone(text)
	}
	for _, field := range []struct {
		name string
		dst  []byte
	}{{"issuer_key_id", r.Issuer[:]}, {"lease_id", r.Lease[:]}, {"client_identity_digest", r.ClientIdentity[:]}, {"server_identity_digest", r.ServerIdentity[:]}} {
		bytes, ok := m.Artifact.Field(field.name).ByteString()
		if !ok || len(bytes) != len(field.dst) {
			return LiveAuthorizationRequest{}, cryptov4.ErrConfiguration
		}
		copy(field.dst, bytes)
	}
	r.ActivationNotAfterMS, _ = m.Artifact.Field("initiation_not_after_ms").Uint()
	return r, nil
}

func (p *SessionEstablishment) tunnelServerAllowRequest(c TunnelServerAllowConfig) (TunnelServerAllowRequest, []byte, error) {
	if p == nil || c.Provider == nil || c.Grant == nil || p.material.Grant == nil || p.material.RelayCertificate == nil {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	if err := p.material.Artifact.CheckTunnelCandidate(p.expected.Index); err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	artifactDigest := p.session.ArtifactDigest
	closure, err := protocolv4.BindEndpointCredentials(protocolv4.ServerToClient, p.material.Artifact, p.expected.Index, p.material.ClientCertificate, p.material.ServerCertificate, c.Grant, p.material.RelayCertificate)
	if err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	if err = closure.MatchActivation(p.material.Authority); err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	for _, name := range []string{"pairing_id", "service", "audience", "relay_identity_digest"} {
		if !bytes.Equal(p.material.Grant.Field(name).Encoded(), c.Grant.Field(name).Encoded()) {
			return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
		}
	}
	grantDigest, err := c.Grant.Digest("grant_digest")
	if err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	relayDigest, err := p.material.RelayCertificate.Digest("certificate_digest")
	if err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	candidate := p.material.Artifact.Field("candidates").Index(int(p.expected.Index))
	serverLeg, ok := candidate.Named("Candidate", "server_leg").Named("Leg", "leg_id").ByteString()
	if !ok || len(serverLeg) != 16 {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	grantAttempt, ok := c.Grant.Field("attempt_id").ByteString()
	if !ok || len(grantAttempt) != 16 || !bytes.Equal(grantAttempt, p.material.Hello.Attempt[:]) {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	grantPairing, ok := c.Grant.Field("pairing_id").ByteString()
	if !ok || len(grantPairing) != 16 {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	grantRoute, ok := c.Grant.Field("route_digest").ByteString()
	if !ok || !bytes.Equal(grantRoute, p.expected.RouteDigest[:]) {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	notAfter, ok := c.Grant.Field("not_after_ms").Uint()
	if !ok || notAfter == 0 {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	activationEnd, _ := p.material.Activation.Deadlines()
	notAfter = min(notAfter, p.session.SessionNotAfterMS, activationEnd, p.admission.config.Initial.Deadline.Cap())
	tenant, tenantOK := p.material.Artifact.Field("tenant_id").Text()
	audience, audienceOK := p.material.Artifact.Field("audience").Text()
	if !tenantOK || !audienceOK {
		return TunnelServerAllowRequest{}, nil, cryptov4.ErrConfiguration
	}
	grant, err := c.Grant.Bytes()
	if err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	r := TunnelServerAllowRequest{Tenant: tenant, Audience: audience, Artifact: artifactDigest, Grant: grantDigest, RelayIdentity: relayDigest,
		Attempt: p.material.Hello.Attempt, Pairing: [16]byte(grantPairing), Leg: [16]byte(serverLeg), Recipient: c.Recipient, Incarnation: c.Incarnation,
		Candidate: p.expected, NotAfterMS: notAfter}
	if err = r.Check(); err != nil {
		return TunnelServerAllowRequest{}, nil, err
	}
	return r, grant, nil
}

// prepareTunnelServerAllow fixes the recipient, exact server material and
// one publication slot before TxA-P. Missing configuration cannot burn a lease.
func (p *SessionEstablishment) prepareTunnelServerAllow(c TunnelServerAllowConfig) error {
	if p.material.Grant == nil {
		return nil
	}
	if c.Provider == nil || c.Grant == nil || p.serverAllow.grant != nil {
		return cryptov4.ErrConfiguration
	}
	wire, err := c.Grant.Bytes()
	if err != nil {
		return err
	}
	grant, err := p.codecs[8].Verify(wire, c.Grant.Key(), protocolv4.DecodeContext{})
	if err != nil {
		return err
	}
	p.serverAllow.grant = grant // Retained even when a later preparation fails.
	c.Grant = grant
	credential, err := grant.DetachCredential()
	if err != nil {
		return err
	}
	if _, err = c.Validation.CheckMaterialCredential(credential, p.session.SessionNotAfterMS, p.reservation); err != nil {
		return err
	}
	request, _, err := p.tunnelServerAllowRequest(c)
	if err != nil {
		return err
	}
	p.serverAllow = tunnelServerPublication{provider: c.Provider, request: request, grant: grant, credential: credential, validation: c.Validation}
	return nil
}

func (p *SessionEstablishment) publishTunnelServerAllow(ctx context.Context) error {
	if p.material.Grant == nil {
		return nil
	}
	if ctx == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	publication := &p.serverAllow
	if publication.provider == nil || publication.grant == nil || publication.started {
		p.mu.Unlock()
		return cryptov4.ErrTransition
	}
	publication.started = true
	p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	grant, err := publication.grant.Bytes()
	if err != nil {
		return err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := p.guard(); err != nil {
			return err
		}
		p.admission.mu.Lock()
		committed := p.admission.committed
		p.admission.mu.Unlock()
		if !committed {
			return cryptov4.ErrTransition
		}
		_, err := publication.validation.CheckMaterialCredential(publication.credential, publication.request.NotAfterMS, p.reservation)
		return err
	}
	if err = guard(); err != nil {
		return err
	}
	if err = publication.provider.PublishServerAllow(ctx, publication.request, grant, guard); err != nil {
		return err
	}
	return guard()
}

func (p *SessionEstablishment) connectLiveControl(a *SessionAdmissionReservation, c LiveControlConfig, buffers resourcev4.Reference, host *EnvironmentSession) (core *SessionCore, err error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := LiveControlCharge(c)
	if err != nil {
		return nil, err
	}
	if err = buffers.CheckSameEnvironment(a.environment); err != nil {
		return nil, err
	}
	if err = p.beginHosted(protocolv4.ClientToServer, host); err != nil {
		return nil, err
	}
	defer func() { p.finish(err) }()
	held, err := buffers.Take(charge)
	if err != nil {
		return nil, err
	}
	defer held.Release()
	request, err := p.liveControlRequest()
	if err != nil {
		return nil, err
	}
	tunnel := p.material.RelayCertificate != nil
	if tunnel && !c.Tunnel {
		return nil, cryptov4.ErrConfiguration
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
	limit, _ := protocolv4.SchemaByteLimit("ActivationAuthorization")
	proof := make([]byte, limit)
	defer clear(proof)
	var grant []byte
	if tunnel {
		grantLimit, _ := protocolv4.SchemaByteLimit("Grant")
		grant = make([]byte, grantLimit)
		defer clear(grant)
	}
	request.ActivationNotAfterMS = min(request.ActivationNotAfterMS, a.config.Initial.Deadline.Cap())
	if err = p.guard(); err != nil {
		return nil, err
	}
	// The synchronous call pins the same claim and reservations until actual
	// provider exit, including cancellation or abnormal provider return.
	var n, grantN int
	if tunnel {
		var sizes [2]int
		sizes, err = c.Provider.(LiveTunnelAuthorizationProvider).RequestTunnelAuthorization(a.ctx, request, [2][]byte{proof, grant})
		n, grantN = sizes[0], sizes[1]
	} else {
		n, err = c.Provider.RequestAuthorization(a.ctx, request, proof)
	}
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > len(proof) || tunnel && (grantN <= 0 || grantN > len(grant)) {
		return nil, cryptov4.ErrConfiguration
	}
	if err = held.Check(); err != nil {
		return nil, err
	}
	var initial *InitialExchange
	if tunnel {
		initial, err = p.activateLiveProof(a, claim, proof[:n:n], grant[:grantN:grantN])
	} else {
		initial, err = p.activateLiveProof(a, claim, proof[:n:n])
	}
	finishClaim()
	if err != nil {
		return nil, err
	}
	return p.connectActivated(a, initial)
}

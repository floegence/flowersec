package sessionv4

import (
	"bytes"
	"context"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
)

// EstablishmentLimits fixes all initial map/Hello/workspace capacity before
// spend. RuntimeBytes covers the qualified runtime and key-call overhead.
type EstablishmentLimits struct {
	MapBytes, MapNodes int
	Hello              protocolv4.HelloLimits
	RuntimeBytes       uint64
}

// LiveProofVerification is the independently configured original signer and
// authority mapping, captured before the original live result can arrive.
type LiveProofVerification struct {
	Rules            *protocolv4.NamespaceRules
	Delegation, Once []byte
	Key              [32]byte
}

// EstablishmentMaterial captures one original material and local key handles.
// The constructor copies canonical maps and public Hello inputs; independently
// authenticated trust/authority and key lifetimes remain shared original owners.
type EstablishmentMaterial struct {
	Artifact, Proof, ClientCertificate, ServerCertificate *protocolv4.SignedMap
	Activation                                            *protocolv4.ActivationBinding
	Authority                                             *protocolv4.ActivationAuthority
	LocalDH                                               cryptov4.StaticDH
	Signer                                                cryptov4.IdentitySigner
	Hello                                                 InitialHello
	Source                                                string
	Role                                                  protocolv4.Direction
	Live                                                  LiveProofVerification
}

// SessionEstablishment assembles original FSB/FSA, Noise and dual READY. It is
// a once-consumed transport component of the immutable application SessionPlan.
// Its backing remains attached to admission until Initial and provider work
// actually exit, including failed constructors and late signer completions.
type SessionEstablishment struct{ *sessionEstablishment }
type sessionEstablishment struct {
	mu                                sync.Mutex
	material                          EstablishmentMaterial
	hello                             *protocolv4.HelloWorkspace
	selection                         *protocolv4.PoolSelectionWorkspace
	expected                          protocolv4.PoolMember
	session                           protocolv4.ArtifactSessionParameters
	codecs                            [6]*protocolv4.SignedMapCodec
	fsb, fsa                          *protocolv4.SignedMap
	fsbCopy, fsaCopy                  []byte
	reservation, shared               resourcev4.Reference
	admission                         *SessionAdmissionReservation
	entrance                          *AcceptedEntrance
	host                              *EnvironmentSession
	connectionMaterial                *ConnectionMaterial
	materialSubscriptions             *protocolv4.CredentialSubscriptions
	started, running, closed, cleaned bool
}

var establishmentSchemas = [...]string{"Artifact", "ActivationAuthorization", "IdentityCertificate", "IdentityCertificate", "FSB4", "FSA4"}

func EstablishmentCharge(l EstablishmentLimits) (resourcev4.Vector, error) {
	if l.MapBytes < 1024 || l.MapBytes > 1<<20 || l.MapNodes < 1 || l.MapNodes > 1<<20 || l.RuntimeBytes == 0 {
		return resourcev4.Vector{}, cryptov4.ErrConfiguration
	}
	n, err := protocolv4.HelloBackingBytes(l.Hello)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	charge := resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1}
	add := func(n uint64) error {
		var e error
		charge, e = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: n})
		return e
	}
	for _, schema := range establishmentSchemas {
		limit, err := protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		n, err := protocolv4.SignedMapBackingBytes(schema, min(limit, l.MapBytes), l.MapNodes)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(n); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	for _, cost := range []func() (uint64, error){protocolv4.ActivationAuthorityBackingBytes, protocolv4.ActivationBindingBackingBytes, func() (uint64, error) { return protocolv4.PoolSelectionBackingBytes(l.Hello.RouteBytes, l.MapBytes) }} {
		extra, err := cost()
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(extra); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	for _, schema := range []string{"ConnectionActivationDelegation", "OnceAuthorityRef"} {
		size, err := protocolv4.SchemaByteLimit(schema)
		if err != nil {
			return resourcev4.Vector{}, err
		}
		if err = add(uint64(size)); err != nil {
			return resourcev4.Vector{}, err
		}
	}
	n, err = protocolv4.HandshakeMaterialBackingBytes()
	if err != nil {
		return resourcev4.Vector{}, err
	}
	if err = add(n); err != nil {
		return resourcev4.Vector{}, err
	}
	if err = add(uint64(unsafe.Sizeof(SessionEstablishment{})) + uint64(unsafe.Sizeof(sessionEstablishment{})) + uint64(2*l.MapBytes) + 512); err != nil {
		return resourcev4.Vector{}, err
	}
	if err = add(l.RuntimeBytes); err != nil {
		return resourcev4.Vector{}, err
	}
	return charge, nil
}

func NewSessionEstablishment(m EstablishmentMaterial, limits EstablishmentLimits, reservation, environment, materialOwner resourcev4.Reference) (_ *SessionEstablishment, err error) {
	if m.Role > protocolv4.ServerToClient || m.Source != "live_authority" && m.Source != "preauthorized_pool" || m.Artifact == nil || m.ClientCertificate == nil || m.ServerCertificate == nil || m.LocalDH == nil || m.Signer == nil || len(m.Hello.Policy.Exporter) > 256 || len(m.Hello.IdentityHint) > 256 {
		return nil, cryptov4.ErrConfiguration
	}
	pendingLive := m.Source == "live_authority" && m.Proof == nil
	if pendingLive {
		if m.Activation != nil || m.Authority != nil || m.Live.Rules == nil || m.Live.Key == ([32]byte{}) {
			return nil, cryptov4.ErrConfiguration
		}
		for _, part := range []struct {
			schema string
			wire   []byte
		}{{"ConnectionActivationDelegation", m.Live.Delegation}, {"OnceAuthorityRef", m.Live.Once}} {
			size, e := protocolv4.SchemaByteLimit(part.schema)
			if e != nil || len(part.wire) == 0 || len(part.wire) > size {
				return nil, cryptov4.ErrConfiguration
			}
		}
	} else if m.Proof == nil || m.Activation == nil || m.Authority == nil {
		return nil, cryptov4.ErrConfiguration
	}
	charge, err := EstablishmentCharge(limits)
	if err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	if err = materialOwner.CheckSameEnvironment(environment); err != nil {
		return nil, err
	}
	shared, err := materialOwner.Borrow()
	if err != nil {
		return nil, err
	}
	adopted := false
	defer func() {
		if !adopted {
			shared.Release()
		}
	}()
	held, err := reservation.Take(charge)
	if err != nil {
		return nil, err
	}
	p := &sessionEstablishment{material: m, reservation: held, shared: shared}
	p.material.Artifact, p.material.Proof, p.material.ClientCertificate, p.material.ServerCertificate = nil, nil, nil, nil
	p.material.Hello.Policy.Exporter, p.material.Hello.IdentityHint = nil, nil
	p.material.Live.Delegation, p.material.Live.Once = nil, nil
	result := &SessionEstablishment{p}
	defer func() {
		if !adopted {
			_ = result.cleanup()
		}
	}()
	p.hello, err = protocolv4.NewHelloWorkspace(limits.Hello)
	if err != nil {
		return nil, err
	}
	decode := protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": m.Source}}
	originals := [...]*protocolv4.SignedMap{m.Artifact, m.Proof, m.ClientCertificate, m.ServerCertificate}
	// Clear caller map pointers before the error cleanup can release anything.
	p.material.Artifact, p.material.Proof, p.material.ClientCertificate, p.material.ServerCertificate = nil, nil, nil, nil
	targets := [...]**protocolv4.SignedMap{&p.material.Artifact, &p.material.Proof, &p.material.ClientCertificate, &p.material.ServerCertificate}
	for i, schema := range establishmentSchemas {
		limit, e := protocolv4.SchemaByteLimit(schema)
		if e != nil {
			return nil, e
		}
		p.codecs[i], err = protocolv4.NewSignedMapCodec(schema, min(limit, limits.MapBytes), limits.MapNodes)
		if err != nil {
			return nil, err
		}
		if i < len(originals) && originals[i] != nil {
			wire, e := originals[i].Bytes()
			if e != nil {
				return nil, e
			}
			*targets[i], err = p.codecs[i].Verify(wire, originals[i].Key(), decode)
			if err != nil {
				return nil, err
			}
		}
	}
	session, err := p.material.Artifact.SessionParameters()
	if err != nil {
		return nil, err
	}
	p.session = session
	if pendingLive {
		p.material.Live.Delegation, p.material.Live.Once = bytes.Clone(m.Live.Delegation), bytes.Clone(m.Live.Once)
		p.selection, err = protocolv4.NewPoolSelectionWorkspace(limits.Hello.RouteBytes, limits.MapBytes)
		if err != nil {
			return nil, err
		}
		selection, e := p.selection.Derive(p.material.Artifact, []uint64{m.Hello.Index})
		if e != nil {
			return nil, e
		}
		p.expected, err = selection.MemberAt(0)
		selection.Release()
		if err != nil {
			return nil, err
		}
		for i, cert := range []*protocolv4.SignedMap{p.material.ClientCertificate, p.material.ServerCertificate} {
			digest, e := cert.Digest("certificate_digest")
			if e != nil {
				return nil, e
			}
			name := "client_identity_digest"
			if i == 1 {
				name = "server_identity_digest"
			}
			expected, ok := p.material.Artifact.Field(name).ByteString()
			if !ok || !bytes.Equal(digest[:], expected) {
				return nil, protocolv4.CBORFailure("admission_identity_binding")
			}
		}
	} else {
		if err = m.Activation.MatchOriginal(session, m.Hello.Attempt, m.Activation.Winner()); err != nil {
			return nil, err
		}
		if m.Hello.Index != m.Activation.Winner().Index {
			return nil, cryptov4.ErrConfiguration
		}
		if err = m.Authority.MatchBinding(m.Activation); err != nil {
			return nil, err
		}
		if err = m.Activation.MatchCertificates(p.material.ClientCertificate, p.material.ServerCertificate); err != nil {
			return nil, err
		}
		p.expected = m.Activation.Winner()
	}
	local := p.material.ClientCertificate
	if m.Role == protocolv4.ServerToClient {
		local = p.material.ServerCertificate
	}
	ed, ok := local.Field("ed25519_public_key").ByteString()
	dh, dhOK := local.Field("noise_static_public_key").Named("NoiseStaticPublicKey", "public_key_bytes").ByteString()
	if !ok || !dhOK || !bytes.Equal(ed, m.Signer.PublicKey()) || !bytes.Equal(dh, m.LocalDH.PublicKey()) {
		return nil, cryptov4.ErrConfiguration
	}
	if !pendingLive {
		proof, err := p.material.Proof.Bytes()
		if err != nil {
			return nil, err
		}
		if err = m.Authority.MatchProofBytes(proof); err != nil {
			return nil, err
		}
	}
	p.material.Hello.Artifact, p.material.Hello.Workspace = p.material.Artifact, p.hello
	p.material.Hello.Policy.Exporter = bytes.Clone(m.Hello.Policy.Exporter)
	p.material.Hello.IdentityHint = bytes.Clone(m.Hello.IdentityHint)
	p.fsbCopy, p.fsaCopy = make([]byte, limits.MapBytes), make([]byte, limits.MapBytes)
	adopted = true
	return result, nil
}

func (p *SessionEstablishment) begin(role protocolv4.Direction) error {
	return p.beginHosted(role, nil)
}

func (p *SessionEstablishment) beginHosted(role protocolv4.Direction, host *EnvironmentSession) error {
	if p == nil || p.sessionEstablishment == nil {
		return cryptov4.ErrConfiguration
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started || p.closed || p.material.Role != role || p.host != host {
		return cryptov4.ErrTransition
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	p.started, p.running = true, true
	return nil
}

func (p *SessionEstablishment) attach(a *SessionAdmissionReservation) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.checkLocked(); err != nil {
		return err
	}
	if a.establishment != nil || a.config.Initial.ActivationSourceProfile != p.material.Source || a.binding.Role != p.material.Role {
		return cryptov4.ErrTransition
	}
	if err := p.reservation.CheckSameEnvironment(a.environment); err != nil {
		return err
	}
	if p.session != a.binding.Session || p.expected != a.binding.Candidate || p.material.Hello.Attempt != a.binding.Attempt {
		return cryptov4.ErrConfiguration
	}
	if err := p.material.Artifact.CheckDirectConnectionGuarantees(a.binding.Candidate.Index, a.binding.Role, a.guarantees); err != nil {
		return err
	}
	if p.material.Activation != nil {
		if err := p.material.Activation.MatchOriginal(a.binding.Session, a.binding.Attempt, a.binding.Candidate); err != nil {
			return err
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return cryptov4.ErrClosed
	}
	p.admission, a.establishment = a, p
	a.establishActive = true
	return nil
}

func (p *SessionEstablishment) finish(err error) {
	if err != nil {
		p.Close()
	}
	p.mu.Lock()
	p.running = false
	a := p.admission
	p.mu.Unlock()
	if a != nil {
		a.mu.Lock()
		a.establishActive = false
		a.signalLocked()
		a.mu.Unlock()
	}
}

func (p *SessionEstablishment) guard() error {
	p.mu.Lock()
	closed, a := p.closed, p.admission
	p.mu.Unlock()
	if closed {
		return cryptov4.ErrClosed
	}
	if err := p.reservation.Check(); err != nil {
		return err
	}
	if err := p.shared.Check(); err != nil {
		return err
	}
	if a == nil {
		return cryptov4.ErrTransition
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkLocked()
}

// ConnectPool runs the complete original consumer path. It returns only after
// both READY flights authenticate; no intermediate transport escapes to users.
func (p *SessionEstablishment) ConnectPool(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLitePoolAuthority, consume resourcev4.Reference) (core *SessionCore, err error) {
	return p.connectPool(a, store, authority, consume, nil)
}

func (p *SessionEstablishment) connectPool(a *SessionAdmissionReservation, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLitePoolAuthority, consume resourcev4.Reference, host *EnvironmentSession) (core *SessionCore, err error) {
	if a == nil {
		return nil, cryptov4.ErrConfiguration
	}
	if err = p.beginHosted(protocolv4.ClientToServer, host); err != nil {
		return nil, err
	}
	defer func() { p.finish(err) }()
	if p.material.Source != "preauthorized_pool" {
		return nil, cryptov4.ErrConfiguration
	}
	if err = p.attach(a); err != nil {
		return nil, err
	}
	if err = p.authorizeApplication(a); err != nil {
		return nil, err
	}
	proof, err := p.material.Proof.Bytes()
	if err != nil {
		return nil, err
	}
	x, err := a.ConsumePoolSQLite(store, authority, p.material.Authority, proof, consume)
	if err != nil {
		return nil, err
	}
	return p.connectActivated(a, x)
}

func (p *SessionEstablishment) connectActivated(a *SessionAdmissionReservation, x *InitialExchange) (*SessionCore, error) {
	hello, err := x.NegotiateClient(p.material.Hello)
	if err != nil {
		return nil, err
	}
	p.fsb, _, err = x.SendAdmission(p.material.Activation, p.material.Proof, p.material.ClientCertificate, p.codecs[4], p.material.Signer, p.guard)
	if err != nil {
		return nil, err
	}
	err = x.Receive(protocolv4.FrameAdmissionResult, func(wire []byte) error {
		var e error
		key, ok := p.material.ServerCertificate.Field("ed25519_public_key").ByteString()
		if !ok || len(key) != 32 {
			return cryptov4.ErrConfiguration
		}
		p.fsa, e = p.codecs[5].Verify(wire, [32]byte(key), protocolv4.DecodeContext{})
		if e != nil {
			return e
		}
		_, e = hello.MatchFSA(p.fsa, p.material.ServerCertificate, p.material.Activation, p.fsb, p.material.ClientCertificate)
		return e
	})
	if err != nil {
		return nil, err
	}
	return p.authenticate(a, hello)
}

// Accept continues the original entrance after material lookup has consumed
// ReadClientHello exactly once. Session resources are admitted after verified
// FSB; the original durable CAS is the only path to FSA and Noise.
func (p *SessionEstablishment) Accept(ctx context.Context, e *AcceptedEntrance, config SessionAdmissionConfig, subscriptions *protocolv4.CredentialSubscriptions, root *resourcev4.Root, owner resourcev4.OwnerKey, environment, preauth resourcev4.Reference, scope SessionResourceScope, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteAdmissionAuthority, admissionOwner ledgerv4.AdmissionOwner, buffers, invocation resourcev4.Reference) (a *SessionAdmissionReservation, core *SessionCore, err error) {
	return p.accept(ctx, e, config, subscriptions, root, owner, environment, preauth, scope, store, authority, admissionOwner, buffers, invocation, nil)
}

func (p *SessionEstablishment) accept(ctx context.Context, e *AcceptedEntrance, config SessionAdmissionConfig, subscriptions *protocolv4.CredentialSubscriptions, root *resourcev4.Root, owner resourcev4.OwnerKey, environment, preauth resourcev4.Reference, scope SessionResourceScope, store *ledgerv4.SQLiteStore, authority ledgerv4.SQLiteAdmissionAuthority, admissionOwner ledgerv4.AdmissionOwner, buffers, invocation resourcev4.Reference, host *EnvironmentSession) (a *SessionAdmissionReservation, core *SessionCore, err error) {
	if ctx == nil || e == nil {
		return nil, nil, cryptov4.ErrConfiguration
	}
	if err = p.beginHosted(protocolv4.ServerToClient, host); err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			e.Close()
		}
		p.finish(err)
	}()
	if err = p.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	p.entrance = e
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return nil, nil, cryptov4.ErrClosed
	}
	hello, err := e.negotiate(p.material.Hello, host)
	if err != nil {
		return nil, nil, err
	}
	err = e.receiveAdmission(func(wire []byte) error {
		key, ok := p.material.ClientCertificate.Field("ed25519_public_key").ByteString()
		if !ok || len(key) != 32 {
			return cryptov4.ErrConfiguration
		}
		var verify error
		p.fsb, verify = p.codecs[4].Verify(wire, [32]byte(key), protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": p.material.Source}})
		return verify
	}, host)
	if err != nil {
		return nil, nil, err
	}
	if p.material.Proof == nil {
		wire, ok := p.fsb.Field("activation_authorization").ByteString()
		if !ok {
			return nil, nil, cryptov4.ErrConfiguration
		}
		if err = p.bindLiveProof(wire); err != nil {
			return nil, nil, err
		}
	}
	config.applicationHost = host
	a, err = newAcceptedSessionAdmissionReservation(ctx, config, e, AcceptedAdmissionMaterial{Activation: p.material.Activation, Authority: p.material.Authority, FSB: p.fsb, ClientCertificate: p.material.ClientCertificate, Subscriptions: subscriptions, Attempt: p.material.Hello.Attempt}, root, owner, environment, preauth, scope, host)
	if err != nil {
		return a, nil, err
	}
	if err = p.attach(a); err != nil {
		a.Close()
		return a, nil, err
	}
	if err = p.authorizeApplication(a); err != nil {
		return a, nil, err
	}
	x, response, err := a.AdmitSQLite(store, authority, admissionOwner, buffers, invocation)
	if err != nil {
		return a, nil, err
	}
	p.fsa, _, err = x.SendAdmissionResponse(p.codecs[5], p.material.ServerCertificate, response, p.material.Signer, p.guard)
	if err != nil {
		return a, nil, err
	}
	core, err = p.authenticate(a, hello)
	return a, core, err
}

func (p *SessionEstablishment) authenticate(a *SessionAdmissionReservation, hello *protocolv4.HelloBinding) (*SessionCore, error) {
	material, err := hello.BindHandshakeMaterial(p.material.Artifact, p.material.Activation, p.material.ClientCertificate, p.material.ServerCertificate, p.fsb, p.fsa)
	if err != nil {
		return nil, err
	}
	defer material.Close()
	_, end := p.material.Activation.Deadlines()
	c := a.config
	keys := cryptov4.AdmissionKeyConfig{Role: p.material.Role, LocalDH: p.material.LocalDH, Signer: p.material.Signer, Deadline: c.Initial.Deadline, Clock: c.Core.Clock, SessionDeadlineMS: end, LocalIdleDurationMS: c.Core.LocalIdleDurationMS, Authorization: a.authorization}
	config, err := cryptov4.AdmissionHandshakeConfig(material, keys, p.fsbCopy, p.fsaCopy)
	if err != nil {
		return nil, err
	}
	defer clear(config.PSK[:])
	return a.Authenticate(config)
}

func (p *SessionEstablishment) Close() {
	if p == nil || p.sessionEstablishment == nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.reservation.Seal()
	a, e := p.admission, p.entrance
	p.mu.Unlock()
	if a != nil {
		a.Close()
	}
	if e != nil {
		e.Close()
	}
}

func (p *SessionEstablishment) cleanup() error {
	if p == nil || p.sessionEstablishment == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cleaned {
		return nil
	}
	if p.running {
		return cryptov4.ErrCapacity
	}
	for _, m := range []*protocolv4.SignedMap{p.material.Artifact, p.material.Proof, p.material.ClientCertificate, p.material.ServerCertificate, p.fsb, p.fsa} {
		if m != nil {
			m.Release()
		}
	}
	clear(p.fsbCopy)
	clear(p.fsaCopy)
	clear(p.material.Hello.Policy.Exporter)
	clear(p.material.Hello.IdentityHint)
	clear(p.material.Live.Delegation)
	clear(p.material.Live.Once)
	p.material, p.codecs = EstablishmentMaterial{}, [6]*protocolv4.SignedMapCodec{}
	p.fsb, p.fsa, p.hello, p.selection = nil, nil, nil, nil
	p.fsbCopy, p.fsaCopy, p.admission, p.entrance = nil, nil, nil, nil
	p.host = nil
	p.reservation.Release()
	p.shared.Release()
	if p.materialSubscriptions != nil {
		p.materialSubscriptions.Close()
		p.materialSubscriptions = nil
	}
	if p.connectionMaterial != nil {
		p.connectionMaterial.finishSession()
		p.connectionMaterial = nil
	}
	p.cleaned = true
	return nil
}

// Retire is for an unadopted or already physically cleaned establishment.
// Attached ownership is retired by SessionAdmissionReservation itself.
func (p *SessionEstablishment) Retire() error {
	if p == nil || p.sessionEstablishment == nil {
		return nil
	}
	p.Close()
	p.mu.Lock()
	attached, e := p.admission != nil, p.entrance
	p.mu.Unlock()
	if attached {
		return cryptov4.ErrTransition
	}
	if e != nil {
		e.mu.Lock()
		cleaned := e.cleaned
		e.mu.Unlock()
		if !cleaned {
			return cryptov4.ErrCapacity
		}
	}
	return p.cleanup()
}

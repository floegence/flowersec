package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// directRuntime installs complete original V4 material and a stable admission
// authority. Its ingress resolver never accepts a decision, reconstructed lease
// or peer-selected store. Each accepted position creates a fresh application
// plan, then the public Acceptor owns FSB, AdmissionLedger CAS, Noise and READY.
type directRuntime struct {
	mu                sync.Mutex
	host              *deploymentRuntime
	config            *directRuntimeSpec
	environment       *fs.Environment
	role              protocolv4.Direction
	serviceRegistry   *rpcv4.ServiceRegistry
	durableHistories  []*directDurableHistory
	executionBindings []rpcv4.ServiceBinding
	methods           []directRuntimeMethod
	clientIngress     []*directClientIngress
	executor          *fs.ApplicationExecutor
	materials         []*directRuntimeMaterial
	listeners         []*directRuntimeListener
	authority         directRuntimeAuthority
	sessions          []*fs.Session
	acceptors         []*fs.ServeHandle
	admissions        []*directRuntimeInput
	context           context.Context
	cancel            context.CancelFunc
	active            uint32
	callbacksDone     chan struct{}
	callbacksClosed   bool
	inputs            resourcev4.Reference
	closed, cleaned   bool
	positions         chan struct{}
	cleanupDone       chan struct{}
}
type directRuntimeInput struct {
	runtime       *directRuntime
	scope         resourcev4.Account
	plan          *fs.SessionPlan
	handlers      *fs.StreamHandlerPlan
	rpc           *fs.RPCServicesConfig
	subscriptions []*fs.NotificationSubscription
}
type directRuntimeMaterial struct {
	spec     directMaterialSpec
	artifact *protocolv4.SignedMap
	lease    *fs.ArtifactLease
	identity *fs.ApplicationIdentity
	material *fs.ConnectionMaterial
	route    []byte
	session  protocolv4.ArtifactSessionParameters
	hello    fs.InitialHello
	features protocolv4.FeatureEnvelope
	binding  sessionv4.ApplicationBinding
	claimed  bool
	dh       runtimeStaticDH
}
type runtimeStaticDH struct{ key *ecdh.PrivateKey }

func (k runtimeStaticDH) PublicKey() []byte { return k.key.PublicKey().Bytes() }
func (k runtimeStaticDH) SharedSecret(peer []byte) ([]byte, error) {
	public, err := k.key.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return k.key.ECDH(public)
}

type directRuntimeAuthority struct {
	identity ledgerv4.SQLiteIdentity
	mapping  []directAdmissionSpec
}

func (a directRuntimeAuthority) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	if identity != a.identity {
		return ledgerv4.ErrOwner
	}
	fields, err := facts.Fields()
	if err != nil {
		return err
	}
	for _, record := range a.mapping {
		if record.Tenant == fields.Tenant && record.Audience == fields.Audience && record.Profile == fields.Profile && record.Source == fields.Source && record.Issuer == fields.Issuer && record.ServerIdentity == fields.ServerIdentity && record.SpendAuthority == fields.SpendAuthority && record.SigningKey == fields.SigningKey {
			return nil
		}
	}
	return ledgerv4.ErrDenied
}

type directRuntimeSource struct {
	runtime         *directRuntime
	profile, source string
	routes          map[[32]byte]bool
}

func (s directRuntimeSource) ResolveAcceptedMaterial(ctx context.Context, hello []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	if err := ctx.Err(); err != nil {
		return nil, fs.InitialHello{}, err
	}
	decoder, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	document, err := decoder.DecodeShape(hello, "ClientHello", protocolv4.DecodeContext{})
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	defer document.Release()
	hint := document.Root()
	digest, ok := hint.Named("ClientHello", "artifact_digest").ByteString()
	if !ok || len(digest) != 32 {
		return nil, fs.InitialHello{}, ledgerv4.ErrDenied
	}
	route, routeOK := hint.Named("ClientHello", "route_digest").ByteString()
	candidate, candidateOK := hint.Named("ClientHello", "candidate_id").ByteString()
	attempt, attemptOK := hint.Named("ClientHello", "attempt_id").ByteString()
	if !routeOK || len(route) != 32 || !candidateOK || len(candidate) != 16 || !attemptOK || len(attempt) != 16 || !s.routes[[32]byte(route)] {
		return nil, fs.InitialHello{}, ledgerv4.ErrDenied
	}
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	if s.runtime.closed {
		return nil, fs.InitialHello{}, resourcev4.ErrClosed
	}
	for _, material := range s.runtime.materials {
		if !material.claimed && material.session.Profile == s.profile && material.spec.Source == s.source && material.session.ArtifactDigest == [32]byte(digest) && material.binding.Route == [32]byte(route) && material.binding.Candidate == [16]byte(candidate) && material.binding.Attempt == [16]byte(attempt) {
			material.claimed = true
			return material.material, material.hello, nil
		}
	}
	return nil, fs.InitialHello{}, ledgerv4.ErrDenied
}

type directListenerAddress struct {
	address netip.AddrPort
	tcp     bool
}
type directRuntimeListener struct {
	runtime   *directRuntime
	spec      directListenerSpec
	material  *directRuntimeMaterial
	carrier   uint64
	quic      *fs.QUICServer
	transport *fs.WebTransportServer
	websocket *fs.WebSocketServer
	tcp       *net.TCPListener
	routes    map[[32]byte]bool
}

func newDirectRuntime(ctx context.Context, c deploymentConfig) (_ *directRuntime, err error) {
	host, err := newDeploymentInfrastructure(ctx, c, c.Direct.Tenant, 1)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	role := protocolv4.ServerToClient
	if c.Role == "direct-client" {
		role = protocolv4.ClientToServer
	}
	r := &directRuntime{role: role, host: host, config: c.Direct, context: lifetime, cancel: cancel, callbacksDone: make(chan struct{}), positions: make(chan struct{}, len(c.Direct.Materials)), admissions: make([]*directRuntimeInput, 0, len(c.Direct.Materials)), sessions: make([]*fs.Session, 0, len(c.Direct.Materials)), acceptors: make([]*fs.ServeHandle, 0, len(c.Direct.Materials)), authority: directRuntimeAuthority{identity: c.Stores[0].Identity, mapping: append([]directAdmissionSpec(nil), c.Direct.Admission...)}}
	success := false
	defer func() {
		if !success {
			r.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(c.ShutdownMS)*time.Millisecond)
			defer cancel()
			err = errors.Join(err, r.WaitCleanup(cleanup))
		}
	}()
	cost, err := fs.ApplicationExecutorCharge(c.Direct.Executor)
	if err != nil {
		return nil, err
	}
	ref, err := host.reserveApplicationExecutor(cost)
	if err != nil {
		return nil, err
	}
	r.executor, err = fs.NewApplicationExecutor(c.Direct.Executor, ref)
	ref.Release()
	if err != nil {
		return nil, err
	}
	if err = r.installServices(); err != nil {
		return nil, err
	}
	environmentConfig := fs.EnvironmentConfig{Services: true, ServiceRegistry: r.serviceRegistry, Positions: uint32(len(c.Direct.Materials)), Materials: uint32(len(c.Direct.Materials)), MaterialCreateMS: c.Direct.HandshakeMS, Clock: host.clock, Verification: host.registry, RuntimeBytes: 131072}
	cost, err = fs.EnvironmentCharge(environmentConfig)
	if err != nil {
		return nil, err
	}
	ref, _, err = host.reserve(cost)
	if err != nil {
		return nil, err
	}
	r.environment, err = fs.NewTransportEnvironment(fs.EnvironmentOptions{Config: environmentConfig, Reservation: ref, Dependencies: host.environment})
	ref.Release()
	if err != nil {
		return nil, err
	}
	inputCost := resourcev4.Vector{resourcev4.SDKBytes: uint64(len(c.Direct.Materials))*262144 + uint64(len(c.Direct.Listeners))*131072, resourcev4.Items: uint64(len(c.Direct.Materials)) + uint64(len(c.Direct.Listeners))}
	r.inputs, _, err = host.reserve(inputCost)
	if err != nil {
		return nil, err
	}
	for _, spec := range c.Direct.Materials {
		if err = r.installMaterial(spec); err != nil {
			return nil, err
		}
	}
	// Qualify the complete frozen graph and its same-root capacity before any
	// native endpoint is exposed. This creates no spend or reusable admission.
	for _, material := range r.materials {
		decoder, e := protocolv4.NewDecoder(16384, 1024)
		if e != nil {
			return nil, e
		}
		route, e := decoder.DecodeMap(material.route, "Route", protocolv4.DecodeContext{})
		if e != nil {
			return nil, e
		}
		carrier, _ := route.Root().Named("Route", "direct_leg").Named("Leg", "carrier").Uint()
		route.Release()
		input, _, e := r.newInput(material, carrier != 1)
		if e != nil {
			return nil, e
		}
		required, _, e := fs.SessionAdmissionRequirements(input.Config)
		if e == nil {
			reservation, _, reserveErr := r.reserveSession(required, input.Scope.Session)
			reservation.Release()
			e = reserveErr
		}
		retireErr := r.retireInput(input, nil)
		if e != nil || retireErr != nil {
			return nil, errors.Join(e, retireErr)
		}
	}
	if r.role == protocolv4.ClientToServer {
		if err = r.installClientIngress(); err != nil {
			return nil, err
		}
		success = true
		return r, nil
	}
	seen := map[directListenerAddress]bool{}
	for _, spec := range c.Direct.Listeners {
		material := r.materials[spec.Material]
		decoder, e := protocolv4.NewDecoder(16384, 1024)
		if e != nil {
			return nil, e
		}
		route, e := decoder.DecodeMap(material.route, "Route", protocolv4.DecodeContext{})
		if e != nil {
			return nil, e
		}
		path, _ := route.Root().Named("Route", "path_kind").Uint()
		carrier, _ := route.Root().Named("Route", "direct_leg").Named("Leg", "carrier").Uint()
		route.Release()
		if path != 0 || carrier > 2 {
			return nil, errors.New("direct-server listener requires a complete signed direct candidate")
		}
		address, e := netip.ParseAddrPort(spec.Address)
		if e != nil || !address.IsValid() || address.Port() == 0 {
			return nil, errors.New("direct listener requires its exact numeric address")
		}
		key := directListenerAddress{address: address, tcp: carrier == 1}
		if seen[key] {
			return nil, errors.New("direct listeners collide on the same native address")
		}
		seen[key] = true
		listener := &directRuntimeListener{runtime: r, spec: spec, material: material, carrier: carrier, routes: map[[32]byte]bool{material.binding.Route: true}}
		r.listeners = append(r.listeners, listener)
		if err = listener.install(address); err != nil {
			return nil, err
		}
	}
	success = true
	return r, nil
}
func (r *directRuntime) installMaterial(spec directMaterialSpec) error {
	h := r.host
	var wires [4][]byte
	for i, path := range []string{spec.ArtifactFile, spec.ActivationFile, spec.ClientCertificateFile, spec.ServerCertificateFile} {
		if i == 1 && spec.Source == "live_authority" {
			if path != "" {
				return errors.New("live lease must remain unactivated before its original invocation")
			}
			continue
		}
		wire, err := readRuntimeFile(path, 65536)
		if err != nil {
			return err
		}
		wires[i] = wire
		defer clear(wire)
	}
	codec, err := protocolv4.NewSignedMapCodec("Artifact", 65536, 4096)
	if err != nil {
		return err
	}
	artifact, err := codec.VerifyCredential(wires[0], h.trust[spec.Trust[0]])
	if err != nil {
		return err
	}
	material := &directRuntimeMaterial{spec: spec}
	r.materials = append(r.materials, material)
	defer artifact.Release()
	if err = artifact.CheckDirectListenerCandidate(spec.CandidateIndex); err != nil {
		return err
	}
	material.session, err = artifact.SessionParameters()
	if err != nil {
		return err
	}
	// The deployment registers raw upstream streams. Service and execution
	// profiles require their own complete RPC/application aggregate.
	if material.session.Contract.Limits().ApplicationProfile != "transport" && r.config.Services == nil {
		return errors.New("signed service or execution profile requires its complete original service aggregate")
	}
	if material.session.Contract.Limits().ApplicationProfile == "transport" && r.config.Services != nil {
		return errors.New("service registration requires its signed application profile")
	}
	route, digest, err := artifact.CopyCandidateRoute(spec.CandidateIndex, make([]byte, 16384))
	if err != nil {
		return err
	}
	material.route = append([]byte(nil), route...)
	var trust [3]*protocolv4.NamespaceTrustStore
	for i, index := range spec.Trust {
		trust[i] = h.trust[index]
	}
	leaseConfig := fs.ArtifactLeaseBytesConfig{Artifact: wires[0], Proof: wires[1], ClientCertificate: wires[2], ServerCertificate: wires[3], Source: spec.Source, ActivationSigningKeyID: spec.ActivationSigningKeyID, Trust: trust, MapBytes: 65536, MapNodes: 4096, RuntimeBytes: 65536}
	cost, err := fs.ArtifactLeaseCharge(65536, 4096, 65536)
	if err != nil {
		return err
	}
	ref, _, err := h.reserve(cost)
	if err != nil {
		return err
	}
	material.lease, err = fs.NewArtifactLeaseFromBytes(leaseConfig, ref, h.environment)
	ref.Release()
	if err != nil {
		return err
	}
	signer, err := h.signer(spec.IdentitySigner)
	if err != nil {
		return err
	}
	seed, err := readRuntimeFile(spec.DHSeedFile, 32)
	if err != nil {
		return err
	}
	defer clear(seed)
	if len(seed) != 32 {
		return errors.New("local static DH seed requires exactly 32 bytes")
	}
	curve := ecdh.X25519()
	if material.session.Profile == protocolv4.DHProfileP256 {
		curve = ecdh.P256()
	}
	private, err := curve.NewPrivateKey(seed)
	if err != nil {
		return err
	}
	material.dh = runtimeStaticDH{private}
	localCertificate, localTrust := wires[3], trust[2]
	if r.role == protocolv4.ClientToServer {
		localCertificate, localTrust = wires[2], trust[1]
	}
	identityConfig := fs.ApplicationIdentityBytesConfig{Certificate: localCertificate, Trust: localTrust, Signer: signer, StaticDH: material.dh, Role: r.role, MapNodes: 4096, RuntimeBytes: 65536}
	cost, err = fs.ApplicationIdentityCharge(4096, 65536)
	if err != nil {
		return err
	}
	ref, _, err = h.reserve(cost)
	if err != nil {
		return err
	}
	material.identity, err = fs.NewApplicationIdentityFromBytes(identityConfig, ref, h.environment)
	ref.Release()
	if err != nil {
		return err
	}
	if r.role == protocolv4.ServerToClient {
		cost, err = fs.ConnectionMaterialCharge(65536)
		if err != nil {
			return err
		}
		ref, _, err = h.reserve(cost)
		if err != nil {
			return err
		}
		material.material, err = fs.NewConnectionMaterial(material.lease, material.identity, fs.MaterialGeneration{Source: spec.Generation.Source, Generation: spec.Generation.Generation}, 65536, ref)
		ref.Release()
		if err != nil {
			return err
		}
	}
	attempt := spec.Attempt
	if spec.Source == "preauthorized_pool" {
		proofDecoder, err := protocolv4.NewDecoder(65536, 4096)
		if err != nil {
			return err
		}
		proof, err := proofDecoder.DecodeMap(wires[1], "ActivationAuthorization", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		defer proof.Release()
		value, ok := proof.Root().Named("ActivationAuthorization", "attempt_id").ByteString()
		if !ok || len(value) != 16 {
			return errors.New("original direct activation lacks attempt identity")
		}
		attempt = [16]byte(value)
	} else if attempt == ([16]byte{}) {
		return errors.New("live deployment requires the original invocation attempt")
	}
	allowed, _ := artifact.Field("allowed_features").Uint()
	offer := allowed & r.config.LocalCapabilities
	material.hello = fs.InitialHello{Index: spec.CandidateIndex, Attempt: attempt, Offered: offer, BindingModes: 1 << r.config.BindingMode, Policy: protocolv4.HelloPolicy{RouteAllowedFeatures: offer, BindingMode: r.config.BindingMode}}
	material.features, err = artifact.FeatureEnvelope(spec.CandidateIndex, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: r.config.LocalCapabilities, ProposedOffer: offer, RouteAllowedFeatures: offer})
	if err != nil {
		return err
	}
	clientDigest, serverDigest := [32]byte{}, [32]byte{}
	for i, schemaWire := range wires[2:] {
		certCodec, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, 4096)
		if err != nil {
			return err
		}
		certificate, err := certCodec.VerifyCredential(schemaWire, trust[i+1])
		if err != nil {
			return err
		}
		value, err := certificate.Digest("certificate_digest")
		certificate.Release()
		if err != nil {
			return err
		}
		if i == 0 {
			clientDigest = value
		} else {
			serverDigest = value
		}
	}
	id, ok := artifact.Field("candidates").Index(int(spec.CandidateIndex)).Named("Candidate", "candidate_id").ByteString()
	if !ok || len(id) != 16 {
		return errors.New("original direct candidate ID is missing")
	}
	material.binding = sessionv4.ApplicationBinding{Artifact: material.session.ArtifactDigest, ClientIdentity: clientDigest, ServerIdentity: serverDigest, Route: digest, Attempt: attempt, Candidate: [16]byte(id), CandidateIndex: spec.CandidateIndex, Role: r.role, Source: spec.Source, ApplicationProfile: material.session.Contract.Limits().ApplicationProfile}
	return nil
}
func (r *directRuntime) installHandlers(position *directRuntimeInput) (*fs.StreamHandlerPlan, error) {
	if len(r.config.Streams) == 0 {
		return nil, nil
	}
	config := fs.StreamHandlerPlanConfig{RuntimeBytes: 65536}
	for _, spec := range r.config.Streams {
		stream := spec
		config.Handlers = append(config.Handlers, fs.RawStreamHandlerConfig{Kind: stream.Kind, Slots: stream.Slots, WorkClass: fs.WorkResident, AuthorizeOpen: func(ctx context.Context, binding any, _ []byte) error {
			if binding != position {
				return ledgerv4.ErrDenied
			}
			return ctx.Err()
		}, Handler: func(ctx context.Context, binding any, _ []byte, owner *fs.StreamOwnership) error {
			if binding != position {
				return ledgerv4.ErrDenied
			}
			return r.bridge(ctx, owner, stream, position.scope)
		}})
	}
	cost, err := fs.StreamHandlerPlanCharge(config)
	if err != nil {
		return nil, err
	}
	ref, _, err := r.reserveSession(cost, position.scope)
	if err != nil {
		return nil, err
	}
	dependencies, err := r.host.environment.Borrow()
	if err != nil {
		ref.Release()
		return nil, err
	}
	handlers, err := fs.NewStreamHandlerPlan(config, r.executor, ref, dependencies)
	ref.Release()
	if err != nil {
		dependencies.Release()
	}
	return handlers, err
}
func (r *directRuntime) reserveSession(cost resourcev4.Vector, scope resourcev4.Account) (resourcev4.Reference, resourcev4.OwnerKey, error) {
	owner := r.host.owner
	if _, err := rand.Read(owner.Instance[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	if _, err := rand.Read(owner.Backing[:]); err != nil {
		return resourcev4.Reference{}, owner, err
	}
	ref, err := r.host.root.Reserve(owner, cost, r.host.accounts[0], r.host.accounts[1], scope)
	return ref, owner, err
}
func (r *directRuntime) newInput(material *directRuntimeMaterial, native bool) (fs.AcceptedSessionInput, fs.AcceptedEntranceConfig, error) {
	if native {
		select {
		case r.positions <- struct{}{}:
		case <-r.context.Done():
			return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, r.context.Err()
		}
	} else {
		select {
		case r.positions <- struct{}{}:
		default:
			return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, resourcev4.ErrCapacity
		}
	}
	success := false
	var position *directRuntimeInput
	defer func() {
		if !success {
			if position != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
				defer cancel()
				if err := r.retirePosition(cleanup, position); err != nil {
					log.Printf("flowersec-runtime direct input cleanup: %v", err)
				}
			} else {
				<-r.positions
			}
		}
	}()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, resourcev4.ErrClosed
	}
	r.mu.Unlock()
	h := r.host
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	scopeAccount, err := h.root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: id}, h.config.Resources.Limit)
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	position = &directRuntimeInput{runtime: r, scope: scopeAccount}
	r.mu.Lock()
	r.admissions = append(r.admissions, position)
	r.mu.Unlock()
	scope := sessionv4.SessionResourceScope{Tenant: h.accounts[0], Session: scopeAccount}
	sessionOwner := h.owner
	sessionOwner.Backing = id
	position.handlers, err = r.installHandlers(position)
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	position.rpc, err = r.serviceConfig(position, material, native, sessionOwner)
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	queryMethods, historyNamespaces := r.servicePlanGeometry()
	plan, err := (fs.SessionPlanFactory{Executor: r.executor, Root: h.root, Dependencies: h.environment}).Create(fs.SessionPlanConfig{RuntimeBytes: 65536, Handlers: position.handlers, Services: position.rpc != nil, ContractQueries: position.rpc != nil, ContractQueryMethods: queryMethods, ExecutionHistoryNamespaces: historyNamespaces, AuthorizeApplication: func(ctx context.Context, request fs.AuthenticatedRequestContext) (fs.AuthorizeApplicationResult, error) {
		binding := request.Binding()
		matched := false
		for _, original := range r.materials {
			if original.binding == binding {
				matched = true
				break
			}
		}
		if !matched {
			return fs.AuthorizeApplicationResult{}, ledgerv4.ErrDenied
		}
		lease, err := request.ReserveLease(binding, position, func(context.Context) error { return nil })
		if err == nil {
			err = r.authorizeServiceLease(lease)
		}
		return fs.AuthorizeApplicationResult{Handlers: position.handlers, Lease: lease}, err
	}}, sessionOwner, scope.Tenant, scope.Session)
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	position.plan = plan
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		plan.Close()
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, resourcev4.ErrClosed
	}
	now, err := h.clock.Sample()
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	deadline, err := timev4.NewDeadline(h.clock, now.LowerMS+r.config.HandshakeMS)
	if err != nil {
		return fs.AcceptedSessionInput{}, fs.AcceptedEntranceConfig{}, err
	}
	core := r.config.Core
	core.Clock = h.clock
	core.Session = material.session
	core.Native = native
	core.MessageCarrier = !native
	slots := uint32(0)
	timeout := uint64(0)
	for _, stream := range r.config.Streams {
		slots += stream.Slots
		timeout = max(timeout, stream.TimeoutMS)
	}
	core.Handlers = fs.SessionStreamHandlerConfig{}
	if position.handlers != nil {
		core.Handlers = fs.SessionStreamHandlerConfig{Plan: position.handlers, Concurrency: slots, TimeoutMS: timeout, RuntimeBytes: 65536, RuntimeBytesPerInvocation: 131072}
	}
	initial := fs.InitialConfig{Role: r.role, Profile: material.session.Profile, ActivationSourceProfile: material.spec.Source, Limits: sessionv4.InitialLimits{MaxFrame: int(material.session.Contract.Limits().MaxFrame), Nodes: r.config.Limits.MapNodes}, Deadline: deadline}
	admission := fs.SessionAdmissionConfig{Core: core, Application: plan, RPC: position.rpc, Features: material.features, Initial: initial, RuntimeBytes: 65536, InitialRuntimeBytes: 65536}
	entrance := fs.AcceptedEntranceConfig{Initial: initial, RuntimeBytes: 65536, InitialRuntimeBytes: 65536, CarrierRuntimeBytes: 65536}
	success = true
	return fs.AcceptedSessionInput{Config: admission, Root: h.root, ResourceOwner: sessionOwner, Environment: h.environment, Preauth: h.environment, Scope: scope, Store: h.stores[0], Authority: r.authority}, entrance, nil
}

func (l *directRuntimeListener) install(address netip.AddrPort) error {
	r, h := l.runtime, l.runtime.host
	certificate, err := loadRuntimeTLS(l.spec.CertificateFile, l.spec.PrivateKeyFile)
	if err != nil {
		return err
	}
	roots, err := runtimeTLSRoots(l.spec.TLSRootsFile)
	if err != nil {
		return err
	}
	count := uint16(min(len(r.materials), 1024))
	switch l.carrier {
	case 0:
		config := fs.QUICServerConfig{AcceptedRouteCapacity: count, Root: h.root, Owner: h.owner, Clock: h.clock, Accounts: h.accounts, Address: address, Route: l.material.route, Certificate: certificate, Roots: roots, Connection: l.spec.QUIC, Connections: count, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: l.spec.QUIC.ProviderBytes, ListenerProviderTasks: l.spec.QUIC.ProviderTasks}
		cost, err := fs.QUICServerCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := h.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		l.quic, err = fs.NewQUICServer(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
	case 2:
		config := fs.WebTransportServerConfig{AcceptedRouteCapacity: count, Root: h.root, Owner: h.owner, Clock: h.clock, Accounts: h.accounts, Address: address, Route: l.material.route, Certificate: certificate, Roots: roots, Connection: l.spec.WebTransport, Connections: count, RuntimeBytes: 65536, ListenerRuntimeBytes: 65536, ListenerProviderBytes: l.spec.WebTransport.ProviderBytes, ListenerProviderTasks: l.spec.WebTransport.ProviderTasks}
		cost, err := fs.WebTransportServerCharge(config)
		if err != nil {
			return err
		}
		ref, owner, err := h.reserve(cost)
		if err != nil {
			return err
		}
		config.Owner = owner
		l.transport, err = fs.NewWebTransportServer(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
	case 1:
		config := fs.WebSocketServerConfig{AcceptedRouteCapacity: count, Root: h.root, Clock: h.clock, Route: l.material.route, Certificate: certificate, Roots: roots, Connections: count, HeaderBytes: l.spec.WebSocket.HandshakeBytes, HeaderTimeout: l.spec.WebSocket.HandshakeTimeout, IdleTimeout: l.spec.WebSocket.MessageTimeout, RuntimeBytes: 65536, ProviderBytesPerConnection: l.spec.WebSocket.ProviderRuntimeBytes, Handler: http.HandlerFunc(l.serveHTTP)}
		cost, err := fs.WebSocketServerCharge(config)
		if err != nil {
			return err
		}
		ref, _, err := h.reserve(cost)
		if err != nil {
			return err
		}
		l.websocket, err = fs.NewWebSocketServer(config, ref, h.environment)
		ref.Release()
		if err != nil {
			return err
		}
		l.tcp, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(address))
		if err != nil {
			return err
		}
	}
	// All original descriptors are installed before exposing this listener.
	// A foreign descriptor or mismatched native endpoint is rejected by the SDK;
	// compatibility here never derives listener authority from a peer request.
	for _, material := range r.materials {
		if material == l.material || material.session.Profile != l.material.session.Profile || material.spec.Source != l.material.spec.Source {
			continue
		}
		decoder, err := protocolv4.NewDecoder(16384, 1024)
		if err != nil {
			return err
		}
		document, err := decoder.DecodeMap(material.route, "Route", protocolv4.DecodeContext{})
		if err != nil {
			return err
		}
		leg := document.Root().Named("Route", "direct_leg")
		carrier, _ := leg.Named("Leg", "carrier").Uint()
		host, _ := leg.Named("Leg", "host").Text()
		port, _ := leg.Named("Leg", "port").Uint()
		document.Release()
		if carrier != l.carrier || host != address.Addr().String() || port != uint64(address.Port()) {
			continue
		}
		if material.session.Contract.Limits().MaxFrame != l.material.session.Contract.Limits().MaxFrame {
			return errors.New("direct materials on one native listener require the same signed Initial frame geometry")
		}
		switch l.carrier {
		case 0:
			err = l.quic.InstallAcceptedRoute(material.route)
		case 2:
			err = l.transport.InstallAcceptedRoute(material.route)
		case 1:
			err = l.websocket.InstallAcceptedRoute(material.route)
		}
		if err != nil {
			return err
		}
		l.routes[material.binding.Route] = true
	}
	return nil
}
func (l *directRuntimeListener) newAcceptor(ctx context.Context) (*fs.ServeHandle, error) {
	r, h := l.runtime, l.runtime.host
	config := fs.ServeConfig{Positions: 1, RuntimeBytes: 65536, DrainTimeoutMS: r.config.Core.DrainTimeoutMS, Clock: h.clock}
	cost, err := fs.ServeCharge(config)
	if err != nil {
		return nil, err
	}
	ref, _, err := h.reserve(cost)
	if err != nil {
		return nil, err
	}
	acceptor, err := fs.NewAcceptor(ctx, fs.AcceptorOptions{Environment: r.environment, ServeOptions: fs.ServeOptions{Config: config, Reservation: ref}})
	ref.Release()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.acceptors = append(r.acceptors, acceptor)
	closed := r.closed
	r.mu.Unlock()
	if closed {
		r.retireAcceptor(acceptor)
		return nil, resourcev4.ErrClosed
	}
	return acceptor, nil
}
func (l *directRuntimeListener) source() directRuntimeSource {
	return directRuntimeSource{runtime: l.runtime, profile: l.material.session.Profile, source: l.material.spec.Source, routes: l.routes}
}
func (l *directRuntimeListener) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	r := l.runtime
	if !r.enterCallback() {
		http.Error(writer, "runtime is shutting down", http.StatusServiceUnavailable)
		return
	}
	defer r.leaveCallback()
	input, entrance, err := r.newInput(l.material, false)
	if err != nil {
		http.Error(writer, "runtime admission capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	var session *fs.Session
	defer func() { r.retireInput(input, session) }()
	acceptor, err := l.newAcceptor(r.context)
	if err != nil {
		http.Error(writer, "runtime admission unavailable", http.StatusServiceUnavailable)
		return
	}
	defer r.retireAcceptor(acceptor)
	session, hijacked, err := acceptor.AcceptWebSocket(r.context, writer, request, fs.WebSocketAcceptOptions{Input: input, Source: l.source(), Limits: r.config.Limits, Entrance: entrance, Server: l.websocket, Upgrade: l.websocket.UpgradePolicy(), Provider: l.spec.WebSocket, Dependencies: r.host.environment, Accounts: r.host.accounts, LocalCapabilities: r.config.LocalCapabilities, RuntimeBytes: 65536, IngressRuntimeBytes: 65536, IntakeRuntimeBytes: 65536, MaxAdmissionRecordBytes: r.config.MaxRecordBytes})
	if err != nil {
		if !hijacked {
			http.Error(writer, "runtime admission rejected", http.StatusForbidden)
		}
		log.Printf("flowersec-runtime direct admission: %v", err)
		return
	}
	if err := r.subscribeServices(session, input.Config.Application); err != nil {
		log.Printf("flowersec-runtime service subscription: %v", err)
		return
	}
	r.waitSession(session)
}
func (l *directRuntimeListener) acceptNative() error {
	r := l.runtime
	for {
		input, entrance, err := r.newInput(l.material, true)
		if err != nil {
			return err
		}
		acceptor, err := l.newAcceptor(r.context)
		if err != nil {
			r.retireInput(input, nil)
			return err
		}
		switch l.carrier {
		case 0:
			ingress, err := l.quic.Accept(r.context, entrance)
			if err != nil {
				r.retireAcceptor(acceptor)
				r.retireInput(input, nil)
				return err
			}
			if !r.enterCallback() {
				ingress.Close()
				r.retireAcceptor(acceptor)
				r.retireInput(input, nil)
				return resourcev4.ErrClosed
			}
			go func() {
				defer r.leaveCallback()
				defer r.retireAcceptor(acceptor)
				session, err := acceptor.AcceptQUIC(r.context, ingress, fs.QUICAcceptOptions{Input: input, Source: l.source(), Limits: r.config.Limits, Entrance: entrance, Dependencies: r.host.environment, Accounts: r.host.accounts, LocalCapabilities: r.config.LocalCapabilities, IngressRuntimeBytes: 65536, IntakeRuntimeBytes: 65536, MaxAdmissionRecordBytes: r.config.MaxRecordBytes})
				defer r.retireInput(input, session)
				if err != nil {
					log.Printf("flowersec-runtime direct admission: %v", err)
					return
				}
				r.waitSession(session)
			}()
		case 2:
			ingress, err := l.transport.Accept(r.context, entrance)
			if err != nil {
				r.retireAcceptor(acceptor)
				r.retireInput(input, nil)
				return err
			}
			if !r.enterCallback() {
				ingress.Close()
				r.retireAcceptor(acceptor)
				r.retireInput(input, nil)
				return resourcev4.ErrClosed
			}
			go func() {
				defer r.leaveCallback()
				defer r.retireAcceptor(acceptor)
				session, err := acceptor.AcceptWebTransport(r.context, ingress, fs.WebTransportAcceptOptions{Input: input, Source: l.source(), Limits: r.config.Limits, Entrance: entrance, Dependencies: r.host.environment, Accounts: r.host.accounts, LocalCapabilities: r.config.LocalCapabilities, IngressRuntimeBytes: 65536, IntakeRuntimeBytes: 65536, MaxAdmissionRecordBytes: r.config.MaxRecordBytes})
				defer r.retireInput(input, session)
				if err != nil {
					log.Printf("flowersec-runtime direct admission: %v", err)
					return
				}
				r.waitSession(session)
			}()
		default:
			r.retireAcceptor(acceptor)
			r.retireInput(input, nil)
			return resourcev4.ErrConfiguration
		}
	}
}
func (r *directRuntime) enterCallback() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.active++
	return true
}
func (r *directRuntime) leaveCallback() {
	r.mu.Lock()
	r.active--
	r.settleCallbacksLocked()
	r.mu.Unlock()
}
func (r *directRuntime) settleCallbacksLocked() {
	if r.closed && r.active == 0 && !r.callbacksClosed {
		r.callbacksClosed = true
		close(r.callbacksDone)
	}
}
func (r *directRuntime) waitSession(session *fs.Session) {
	r.retainSession(session)
	_ = session.WaitTermination(r.context)
}
func (r *directRuntime) retainSession(session *fs.Session) {
	r.mu.Lock()
	found := false
	for _, original := range r.sessions {
		if original == session {
			found = true
			break
		}
	}
	if !found {
		r.sessions = append(r.sessions, session)
	}
	closed := r.closed
	r.mu.Unlock()
	if closed {
		_ = session.Close()
	}
}
func (r *directRuntime) retireAcceptor(acceptor *fs.ServeHandle) {
	acceptor.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
	defer cancel()
	if err := acceptor.WaitCleanup(cleanup); err != nil {
		log.Printf("flowersec-runtime direct acceptor cleanup: %v", err)
		return
	}
	r.mu.Lock()
	for i, original := range r.acceptors {
		if original == acceptor {
			r.acceptors = append(r.acceptors[:i], r.acceptors[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
}
func (r *directRuntime) retireInput(input fs.AcceptedSessionInput, session *fs.Session) error {
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
	defer cancel()
	if session != nil {
		r.retainSession(session)
		_ = session.Close()
		if err := session.WaitCleanup(cleanup); err != nil {
			log.Printf("flowersec-runtime direct session cleanup: %v", err)
			return err
		}
	}
	r.mu.Lock()
	var position *directRuntimeInput
	for _, original := range r.admissions {
		if original.plan == input.Config.Application {
			position = original
			break
		}
	}
	r.mu.Unlock()
	if position == nil {
		return nil
	}
	if err := r.retirePosition(cleanup, position); err != nil {
		log.Printf("flowersec-runtime direct input retirement: %v", err)
		return err
	}
	r.mu.Lock()
	for i, original := range r.sessions {
		if original == session {
			r.sessions = append(r.sessions[:i], r.sessions[i+1:]...)
			break
		}
	}
	r.mu.Unlock()
	return nil
}
func (r *directRuntime) retirePosition(ctx context.Context, position *directRuntimeInput) error {
	for _, subscription := range position.subscriptions {
		subscription.Close()
		if err := subscription.WaitClosed(ctx); err != nil {
			return err
		}
		if err := subscription.Release(); err != nil {
			return err
		}
	}
	position.subscriptions = nil
	if position.plan != nil {
		position.plan.Close()
		if err := position.plan.Retire(); err != nil {
			return err
		}
	}
	if position.handlers != nil {
		position.handlers.Close()
		if err := position.handlers.WaitCleanup(ctx); err != nil {
			return err
		}
		if err := position.handlers.Retire(); err != nil {
			return err
		}
	}
	position.scope.Close()
	r.mu.Lock()
	found := false
	for i, original := range r.admissions {
		if original == position {
			r.admissions = append(r.admissions[:i], r.admissions[i+1:]...)
			found = true
			break
		}
	}
	r.mu.Unlock()
	if found {
		<-r.positions
	}
	return nil
}
func (r *directRuntime) Serve(ctx context.Context) error {
	if r.role == protocolv4.ClientToServer {
		return r.serveClient(ctx)
	}
	results := make(chan error, len(r.listeners))
	for _, listener := range r.listeners {
		if !r.enterCallback() {
			return resourcev4.ErrClosed
		}
		original := listener
		go func() {
			defer r.leaveCallback()
			var err error
			if original.websocket != nil {
				err = original.websocket.Serve(original.tcp)
			} else {
				err = original.acceptNative()
			}
			results <- err
		}()
	}
	var serveErr error
	select {
	case <-ctx.Done():
		serveErr = context.Cause(ctx)
	case serveErr = <-results:
	}
	r.Close()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Duration(r.host.config.ShutdownMS)*time.Millisecond)
	defer cancel()
	cleanupErr := r.WaitCleanup(cleanup)
	if errors.Is(serveErr, context.Canceled) || errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) || errors.Is(serveErr, resourcev4.ErrClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, cleanupErr)
}
func (r *directRuntime) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.settleCallbacksLocked()
	sessions := append([]*fs.Session(nil), r.sessions...)
	acceptors := append([]*fs.ServeHandle(nil), r.acceptors...)
	r.mu.Unlock()
	for _, ingress := range r.clientIngress {
		ingress.Close()
	}
	for _, listener := range r.listeners {
		if listener.tcp != nil {
			_ = listener.tcp.Close()
		}
		if listener.quic != nil {
			_ = listener.quic.Close()
		}
		if listener.transport != nil {
			_ = listener.transport.Close()
		}
		if listener.websocket != nil {
			listener.websocket.Close()
		}
	}
	for _, acceptor := range acceptors {
		acceptor.Close()
	}
	for _, session := range sessions {
		_ = session.Close()
	}
	if r.environment != nil {
		r.environment.Close()
	}
}
func (r *directRuntime) WaitCleanup(ctx context.Context) error {
	if r == nil || ctx == nil {
		return resourcev4.ErrConfiguration
	}
	for {
		r.mu.Lock()
		if r.cleaned {
			r.mu.Unlock()
			return nil
		}
		if !r.closed {
			r.mu.Unlock()
			return resourcev4.ErrCapacity
		}
		if previous := r.cleanupDone; previous != nil {
			r.mu.Unlock()
			select {
			case <-previous:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		done := make(chan struct{})
		r.cleanupDone = done
		r.mu.Unlock()
		err := r.cleanup(ctx)
		r.mu.Lock()
		if err == nil {
			r.cleaned = true
		}
		r.cleanupDone = nil
		close(done)
		r.mu.Unlock()
		return err
	}
}
func (r *directRuntime) cleanup(ctx context.Context) error {
	// Close sealed callback registration before this original cleanup observer.
	select {
	case <-r.callbacksDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Failed cleanup retains each original owner for this waiter to retry.
	for _, session := range r.sessions {
		_ = session.Close()
		if err := session.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for _, acceptor := range r.acceptors {
		acceptor.Close()
		if err := acceptor.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for _, ingress := range r.clientIngress {
		if err := ingress.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for _, listener := range r.listeners {
		if listener.quic != nil {
			if err := listener.quic.WaitCleanup(ctx); err != nil {
				return err
			}
		}
		if listener.transport != nil {
			if err := listener.transport.WaitCleanup(ctx); err != nil {
				return err
			}
		}
		if listener.websocket != nil {
			if err := listener.websocket.WaitCleanup(ctx); err != nil {
				return err
			}
		}
	}
	if r.environment != nil {
		if err := r.environment.WaitCleanup(ctx); err != nil {
			return err
		}
	}
	for len(r.admissions) > 0 {
		if err := r.retirePosition(ctx, r.admissions[0]); err != nil {
			return err
		}
	}
	for _, material := range r.materials {
		if material.material != nil {
			material.material.Close()
			if err := material.material.WaitCleanup(ctx); err != nil {
				return err
			}
		}
		if material.identity != nil {
			material.identity.Close()
			if err := material.identity.WaitCleanup(ctx); err != nil {
				return err
			}
		}
		if material.lease != nil {
			material.lease.Close()
			if err := material.lease.WaitCleanup(ctx); err != nil {
				return err
			}
		}
		if material.artifact != nil {
			material.artifact.Release()
			material.artifact = nil
		}
	}
	if r.serviceRegistry != nil {
		r.serviceRegistry.Close()
	}
	for _, binding := range r.executionBindings {
		if binding.History != nil {
			binding.History.Close()
			if !binding.History.CleanupComplete() {
				return cryptov4.ErrTransition
			}
		}
		if binding.DurableHistory != nil {
			binding.DurableHistory.Close()
			if !binding.DurableHistory.CleanupComplete() {
				return cryptov4.ErrTransition
			}
		}
	}
	for _, history := range r.durableHistories {
		if err := history.cleanup(ctx); err != nil {
			return err
		}
	}
	if r.executor != nil {
		r.executor.Close()
		select {
		case <-r.executor.Done():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	r.inputs.Release()
	return r.host.Close(ctx)
}

type directOwnedStream struct {
	owner *fs.StreamOwnership
	ctx   context.Context
}

func (s directOwnedStream) Read(dst []byte) (int, error) {
	result, err := s.owner.ReadInto(s.ctx, dst)
	if err == nil && result.ReadTerminal == protocolv4.V4ReadTerminalEof {
		err = io.EOF
	}
	return int(result.Progress.Filled), err
}
func (s directOwnedStream) Write(src []byte) (int, error) { return s.owner.Write(s.ctx, src) }
func (r *directRuntime) bridge(ctx context.Context, owner *fs.StreamOwnership, target directStreamSpec, scope resourcev4.Account) error {
	if owner == nil {
		return resourcev4.ErrConfiguration
	}
	cost := resourcev4.Vector{resourcev4.SDKBytes: 65536, resourcev4.ProviderBytes: 131072, resourcev4.Tasks: 3, resourcev4.Timers: 2, resourcev4.NativeHandles: 1, resourcev4.Connections: 1, resourcev4.WorkSlots: 1}
	reservation, _, err := r.reserveSession(cost, scope)
	if err != nil {
		return err
	}
	defer reservation.Release()
	call, cancel := context.WithTimeout(ctx, time.Duration(target.TimeoutMS)*time.Millisecond)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(call, target.Network, target.Address)
	if err != nil {
		return err
	}
	defer connection.Close()
	canceled := make(chan struct{})
	stop := context.AfterFunc(call, func() { defer close(canceled); _ = connection.Close(); _ = owner.Close() })
	defer func() {
		if !stop() {
			<-canceled
		}
	}()
	stream := directOwnedStream{owner: owner, ctx: call}
	results := make(chan error, 2)
	go func() {
		_, err := io.CopyBuffer(connection, stream, make([]byte, 32768))
		if tcp, ok := connection.(*net.TCPConn); ok {
			err = errors.Join(err, tcp.CloseWrite())
		}
		results <- err
	}()
	go func() {
		_, err := io.CopyBuffer(stream, connection, make([]byte, 32768))
		err = errors.Join(err, owner.CloseWrite(call))
		results <- err
	}()
	first := <-results
	if first != nil {
		cancel()
		_ = connection.Close()
		_ = owner.Close()
	}
	second := <-results
	if err := errors.Join(first, second); err != nil {
		return err
	}
	return owner.Finish(call)
}

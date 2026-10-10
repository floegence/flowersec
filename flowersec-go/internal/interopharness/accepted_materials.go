package interopharness

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

// AcceptedMaterials selects only independently installed complete materials.
// HELLO supplies a bounded lookup hint. It grants no admission, and every
// selected original lease is verified, durably admitted and authenticated by
// the normal Acceptor after this resolver returns.
type AcceptedMaterials struct {
	mu          sync.Mutex
	authorities [2]*sessionv4.PublicQUICTestHarness
	claimed     [2]bool
	checkers    [2]ledgerv4.SQLiteAdmissionAuthority
}

func NewAcceptedMaterials(first, second *sessionv4.PublicQUICTestHarness) *AcceptedMaterials {
	result := &AcceptedMaterials{authorities: [2]*sessionv4.PublicQUICTestHarness{first, second}}
	result.checkers[0] = first.Authority
	if second != nil && second != first {
		result.checkers[1] = second.Authority
	}
	first.Authority = &acceptedAuthoritySet{owner: result, original: first.Authority}
	return result
}
func (s *AcceptedMaterials) ForRuntime(runtime *Runtime) fs.AcceptedMaterialSource {
	return &acceptedMaterialsView{owner: s, runtime: runtime}
}

type acceptedMaterialsView struct {
	mu       sync.Mutex
	owner    *AcceptedMaterials
	runtime  *Runtime
	selected *sessionv4.PublicQUICTestHarness
}

func (s *acceptedMaterialsView) ResolveAcceptedMaterial(ctx context.Context, hello []byte) (*fs.ConnectionMaterial, fs.InitialHello, error) {
	if err := ctx.Err(); err != nil {
		return nil, fs.InitialHello{}, err
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	document, err := decoder.DecodeShape(hello, "ClientHello", protocolv4.DecodeContext{})
	if err != nil {
		return nil, fs.InitialHello{}, err
	}
	defer document.Release()
	digest, _ := document.Root().Named("ClientHello", "artifact_digest").ByteString()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.selected != nil {
		return nil, fs.InitialHello{}, errors.New("original accepted position was already selected")
	}
	s.owner.mu.Lock()
	var authority *sessionv4.PublicQUICTestHarness
	for index, candidate := range s.owner.authorities {
		if candidate != nil && bytes.Equal(digest, candidate.ArtifactDigest[:]) && !s.owner.claimed[index] {
			s.owner.claimed[index] = true
			authority = candidate
			break
		}
	}
	s.owner.mu.Unlock()
	if authority == nil {
		return nil, fs.InitialHello{}, errors.New("unknown or already claimed current signed material")
	}
	s.selected = authority
	material, err := s.runtime.admitAcceptedMaterial(authority.Lease, authority.Identity[1], authority.Generation)
	return material, authority.Hello, err
}
func (r *Runtime) admitAcceptedMaterial(config fs.ArtifactLeaseBytesConfig, identityConfig fs.ApplicationIdentityBytesConfig, generation fs.MaterialGeneration) (*fs.ConnectionMaterial, error) {
	return construct(r.Reporter, func() *fs.ConnectionMaterial {
		h := r.Authority
		// The accepting root owns the installed verification permissions. Independent
		// issuance supplies signed bytes, never a foreign root or trust owner.
		config.Trust = h.Lease.Trust
		identityConfig.Trust = h.Lease.Trust[2]
		identityConfig.Signer = h.Identity[1].Signer
		identityConfig.StaticDH = h.Identity[1].StaticDH
		lease, err := fs.NewArtifactLeaseFromBytes(config, r.reserve(fs.ArtifactLeaseCharge(config.MapBytes, config.MapNodes, config.RuntimeBytes, len(config.Tunnels))), h.Preauth)
		if err != nil {
			r.Reporter.Fatal(err)
		}
		r.Reporter.Cleanup(func() {
			lease.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r.Reporter.ErrorIf(lease.WaitCleanup(cleanup))
		})
		identity, err := fs.NewApplicationIdentityFromBytes(identityConfig, r.reserve(fs.ApplicationIdentityCharge(identityConfig.MapNodes, identityConfig.RuntimeBytes)), h.Preauth)
		if err != nil {
			r.Reporter.Fatal(err)
		}
		r.Reporter.Cleanup(func() {
			identity.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r.Reporter.ErrorIf(identity.WaitCleanup(cleanup))
		})
		material, err := fs.NewConnectionMaterial(lease, identity, generation, 8192, r.reserve(fs.ConnectionMaterialCharge(8192)))
		if err != nil {
			r.Reporter.Fatal(err)
		}
		r.Reporter.Cleanup(func() {
			material.Close()
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r.Reporter.ErrorIf(material.WaitCleanup(cleanup))
		})
		return material
	})
}

func (s *Server) IndependentAuthority() (authority *sessionv4.PublicQUICTestHarness, err error) {
	child, err := s.Runtime.Reporter.ForkAuthority()
	if err != nil {
		return nil, err
	}
	if child.Capacity != nil {
		child.Capacity = &sessionv4.EngineeringHostCapacity{Sessions: 1, Materials: 1}
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, child.Close())
		}
	}()
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, err
	}
	document, err := decoder.DecodeShape(s.Runtime.Authority.Route, "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer document.Release()
	policy := document.Root().Named("Route", "direct_leg").Named("Leg", "tls_policy").Encoded()
	return construct(child, func() *sessionv4.PublicQUICTestHarness {
		return sessionv4.NewEngineeringNativeHarness(child, s.Runtime.Authority.Lease.Source, s.Runtime.Authority.Admission[0].Initial.Profile, s.Carrier, s.Address, policy, s.Origin, s.Carrier != "websocket" && s.Carrier != "local-websocket")
	})
}
func (s *Server) MaterialFor(h *sessionv4.PublicQUICTestHarness) Material {
	return Material{WireRevision: 4, Profile: h.Admission[0].Initial.Profile, Source: h.Lease.Source, Generation: Generation{Source: h.Generation.Source[:], Generation: h.Generation.Generation}, Role: 0, Artifact: h.Lease.Artifact, Activation: h.Lease.Proof, ClientCertificate: h.Lease.ClientCertificate, ServerCertificate: h.Lease.ServerCertificate, Route: h.Route, RouteDigest: h.BrowserRouteDigest[:], ActivationSigningKeyID: h.Lease.ActivationSigningKeyID, IdentitySeed: h.BrowserIdentitySeed[:], DHSeed: h.BrowserDHSeed[:], Namespaces: []NamespaceRecord{s.Namespace}, Tunnels: []TunnelMaterial{}}
}

// NewHTTPAcceptPosition installs another independent application plan and
// Environment beneath the same complete authority/store and original listener.
// Accepted source lookup remains separate from this finite host position.
func (s *Server) NewHTTPAcceptPosition(source *AcceptedMaterials, handlers HandlerConfig) (result *Server, err error) {
	if source == nil {
		return nil, errors.New("original accepted material mapping is required")
	}
	reporter, h, err := s.forkAcceptedAuthority()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, reporter.Close())
		}
	}()
	runtime := &Runtime{Reporter: reporter, Authority: h, Role: 1, Executor: s.Runtime.Executor}
	reporter.Owner(runtime.CloseOwners, runtime.WaitOwners)
	err = runtime.initialize(s.context, []uint8{1}, handlers)
	if err != nil {
		return nil, err
	}
	position := &Server{Runtime: runtime, Carrier: s.Carrier, Origin: s.Origin, TrustPEM: s.TrustPEM, Address: s.Address, Namespace: s.Namespace, certificate: s.certificate, roots: s.roots, context: s.context, onTransportError: s.onTransportError, externalHTTP: true, localBridgeToken: s.localBridgeToken, results: make(chan SessionResult, 2), acceptedSource: source.ForRuntime(runtime)}
	if err = position.startTransport(reporter); err != nil {
		return nil, err
	}
	return position, nil
}

func (s *AcceptedMaterials) InstallSecond(authority *sessionv4.PublicQUICTestHarness) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authority == nil || authority == s.authorities[0] || authority.Authority == s.authorities[0].Authority || s.authorities[1] != nil || s.claimed[0] || s.claimed[1] {
		return errors.New("independent material must be installed before accepted lookup")
	}
	s.authorities[1] = authority
	s.checkers[1] = authority.Authority
	return nil
}

// acceptedAuthoritySet is the original trusted service mapping for both
// independently signed server identities. It never turns a HELLO hint or
// credential lookup into an authority decision. The complete signed admission
// facts must pass one of the two original immutable mappings.
type acceptedAuthoritySet struct {
	owner    *AcceptedMaterials
	original ledgerv4.SQLiteAdmissionAuthority
}

func (a *acceptedAuthoritySet) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	if err := a.original.CheckAdmission(identity, facts); err == nil {
		return nil
	}
	a.owner.mu.Lock()
	second := a.owner.checkers[1]
	a.owner.mu.Unlock()
	if second == nil {
		return ledgerv4.ErrFenced
	}
	return second.CheckAdmission(identity, facts)
}

func (a *acceptedAuthoritySet) ParentWinnerStore() *ledgerv4.SQLiteStore {
	pool, ok := a.original.(ledgerv4.SQLitePoolAdmissionAuthority)
	if !ok {
		return nil
	}
	return pool.ParentWinnerStore()
}
func (a *acceptedAuthoritySet) CheckParentWinner(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	if pool, ok := a.original.(ledgerv4.SQLitePoolAdmissionAuthority); ok {
		if err := pool.CheckParentWinner(identity, facts); err == nil {
			return nil
		}
	}
	a.owner.mu.Lock()
	second := a.owner.checkers[1]
	a.owner.mu.Unlock()
	if second == nil {
		return ledgerv4.ErrFenced
	}
	pool, ok := second.(ledgerv4.SQLitePoolAdmissionAuthority)
	if !ok {
		return ledgerv4.ErrConfiguration
	}
	return pool.CheckParentWinner(identity, facts)
}

// IssueAuthority produces independently signed original bytes, then retires
// its construction graph. The accepting and consuming graphs install and
// verify those bytes under their own original trust and SQLite owners.
func (s *Server) IssueAuthority(policy []byte, address netip.AddrPort) (*sessionv4.PublicQUICTestHarness, error) {
	if !address.IsValid() {
		address = s.Address
	}
	child, err := s.Runtime.Reporter.detachedAuthority()
	if err != nil {
		return nil, err
	}
	if child.Capacity != nil {
		// Detached issuance owns only one temporary authority graph. It does
		// not inherit the listener's retained Session/material positions.
		child.Capacity = &sessionv4.EngineeringHostCapacity{Materials: 1}
	}
	authority, err := construct(child, func() *sessionv4.PublicQUICTestHarness {
		return sessionv4.NewEngineeringNativeHarness(child, s.Runtime.Authority.Lease.Source, s.Runtime.Authority.Admission[0].Initial.Profile, s.Carrier, address, policy, s.Origin, s.Carrier != "websocket" && s.Carrier != "local-websocket")
	})
	var detached sessionv4.PublicQUICTestHarness
	if authority != nil {
		detached = authority.DetachIssuedAuthority()
	}
	err = errors.Join(err, child.Close())
	if err != nil {
		return nil, err
	}
	return &detached, nil
}

// IssueDirectRouteSet signs one pool Artifact and one activation selecting the
// complete original candidate set. Every route already belongs to its own
// native listener. Issuance is retired before either consumer or acceptor runs.
func (s *Server) IssueDirectRouteSet(routes [][]byte) (*sessionv4.PublicQUICTestHarness, error) {
	if s == nil || len(routes) < 2 || len(routes) > 16 {
		return nil, errors.New("finite original direct routes are required")
	}
	child, err := s.Runtime.Reporter.detachedAuthority()
	if err != nil {
		return nil, err
	}
	if child.Capacity != nil {
		child.Capacity = &sessionv4.EngineeringHostCapacity{Materials: 1}
	}
	child.directRoutes = make([][]byte, len(routes))
	for index, route := range routes {
		child.directRoutes[index] = append([]byte(nil), route...)
	}
	decoder, err := protocolv4.NewDecoder(16384, 1024)
	if err != nil {
		return nil, errors.Join(err, child.Close())
	}
	document, err := decoder.DecodeMap(routes[0], "Route", protocolv4.DecodeContext{})
	if err != nil {
		return nil, errors.Join(err, child.Close())
	}
	policy := append([]byte(nil), document.Root().Named("Route", "direct_leg").Named("Leg", "tls_policy").Encoded()...)
	document.Release()
	authority, err := construct(child, func() *sessionv4.PublicQUICTestHarness {
		return sessionv4.NewEngineeringNativeHarness(child, "preauthorized_pool", s.Runtime.Authority.Admission[0].Initial.Profile, s.Carrier, s.Address, policy, s.Origin, false)
	})
	var detached sessionv4.PublicQUICTestHarness
	if authority != nil {
		detached = authority.DetachIssuedAuthority()
	}
	err = errors.Join(err, child.Close())
	if err != nil {
		return nil, err
	}
	return &detached, nil
}

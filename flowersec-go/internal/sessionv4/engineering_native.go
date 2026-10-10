package sessionv4

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// PublicQUICTestHarness supplies independently signed authority fixtures to an
// external-package test. The test constructs its Environment, public transport
// and Sessions itself; no synthetic carrier or admission result is supplied.
type PublicQUICTestHarness struct {
	Tunnel                        *PublicTunnelAuthority
	Root                          *resourcev4.Root
	SessionLimit                  resourcev4.Vector
	Environment, Preauth          resourcev4.Reference
	Clock                         *timev4.Clock
	Verification                  *protocolv4.NamespaceRegistry
	Scope                         [2]SessionResourceScope
	Admission                     [2]SessionAdmissionConfig
	Lease                         ArtifactLeaseBytesConfig
	Identity                      [2]ApplicationIdentityBytesConfig
	Route                         []byte
	DirectRoutes                  [][]byte
	DirectRouteDigests            [][32]byte
	Hello                         InitialHello
	Limits                        EstablishmentLimits
	Generation                    MaterialGeneration
	ArtifactDigest                [32]byte
	Store                         *ledgerv4.SQLiteStore
	Authority                     ledgerv4.SQLiteAdmissionAuthority
	Pool                          *PoolSessionInput
	Live                          *LiveSessionInput
	LiveIssuance                  SourceLiveIssuance
	Owner                         func() resourcev4.OwnerKey
	Reserve                       func(resourcev4.Vector, ...resourcev4.Account) resourcev4.Reference
	PolicyCalls                   int
	BrowserRootKeyID              [16]byte
	BrowserRootPublicKey          [32]byte
	BrowserIdentitySeed           [32]byte
	BrowserDHSeed                 [32]byte
	EngineeringServerIdentitySeed [32]byte
	EngineeringServerDHSeed       [32]byte
	EngineeringActivationSeed     [32]byte
	BrowserBootstrap              func([32]byte) ([]byte, []byte)
	BrowserRouteDigest            [32]byte
	BrowserTenant                 string
	BrowserAuthority              string
	BrowserAudience               string
	BrowserClientSubject          string
	BrowserServerSubject          string
	BrowserOnceAuthority          string
	BrowserIssuerKeyID            [16]byte
	BrowserAuthorize              func(context.Context, LiveAuthorizationRequest, [32]byte, []byte) (int, error)
	BrowserHello                  func() InitialHello
	BrowserPolicyCalls            func() int
	LocalLoopback                 bool
	PoolIssue                     *EngineeringPoolIssueRecipe
}

// DetachIssuedAuthority retains signed material and immutable issuer facts,
// while retiring every alias to the construction host's execution owners.
func (h *PublicQUICTestHarness) DetachIssuedAuthority() PublicQUICTestHarness {
	d := *h
	d.Root, d.Clock, d.Verification, d.Store = nil, nil, nil, nil
	d.Environment, d.Preauth = resourcev4.Reference{}, resourcev4.Reference{}
	d.Scope = [2]SessionResourceScope{}
	d.SessionLimit = resourcev4.Vector{}
	for role := range d.Admission {
		profile := d.Admission[role].Initial.Profile
		d.Admission[role] = SessionAdmissionConfig{}
		d.Admission[role].Initial.Profile = profile
		d.Identity[role].Trust, d.Identity[role].Signer, d.Identity[role].StaticDH = nil, nil, nil
	}
	d.Lease.Trust = [3]*protocolv4.NamespaceTrustStore{}
	d.Lease.GrantTrust, d.Lease.RelayTrust = nil, nil
	d.Lease.Tunnels = append([]ArtifactLeaseTunnelBytes(nil), d.Lease.Tunnels...)
	for index := range d.Lease.Tunnels {
		d.Lease.Tunnels[index].LiveGrant = nil
		d.Lease.Tunnels[index].GrantTrust, d.Lease.Tunnels[index].RelayTrust = nil, nil
	}
	d.Pool, d.Live, d.Tunnel, d.PoolIssue = nil, nil, nil, nil
	d.LiveIssuance = SourceLiveIssuance{}
	d.Owner, d.Reserve, d.BrowserBootstrap, d.BrowserAuthorize, d.BrowserHello, d.BrowserPolicyCalls = nil, nil, nil, nil, nil, nil
	switch original := d.Authority.(type) {
	case poolSQLiteAuthority:
		original.parent = nil
		original.admissionGate = nil
		d.Authority = original
	case liveSQLiteAuthority:
		original.parent = nil
		d.Authority = original
	case acceptedSQLiteAuthority:
		original.parent = nil
		d.Authority = original
	}
	return d
}

type publicFixtureDH struct{ key *ecdh.PrivateKey }

func (k publicFixtureDH) PublicKey() []byte { return k.key.PublicKey().Bytes() }
func (k publicFixtureDH) SharedSecret(wire []byte) ([]byte, error) {
	peer, err := k.key.Curve().NewPublicKey(wire)
	if err != nil {
		return nil, err
	}
	return k.key.ECDH(peer)
}

func NewPublicQUICTestHarness(t AuthorityReporter, source, profile string, address netip.AddrPort, tlsPolicy []byte, enableDatagrams ...bool) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "quic", len(enableDatagrams) != 0 && enableDatagrams[0], false)
}

func NewPublicWebTransportTestHarness(t AuthorityReporter, source, profile string, address netip.AddrPort, tlsPolicy []byte, enableDatagrams ...bool) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "webtransport", len(enableDatagrams) != 0 && enableDatagrams[0], false)
}

func NewPublicWSSTestHarness(t AuthorityReporter, source, profile string, address netip.AddrPort, tlsPolicy []byte) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "websocket", false, false)
}

func NewPublicWSSBrowserTestHarness(t AuthorityReporter, source, profile string, address netip.AddrPort, tlsPolicy []byte, origin string) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "websocket", false, true, origin)
}

func newPublicNativeTestHarness(t AuthorityReporter, source, profile string, address netip.AddrPort, tlsPolicy []byte, carrierKind string, datagrams, browserInterop bool, origins ...string) *PublicQUICTestHarness {
	t.Helper()
	localLoopback := carrierKind == "local-websocket"
	if localLoopback {
		carrierKind = "websocket"
	}
	f := newAuthorityFixture(t, source, engineeringCapacityRoot(t, source, profile, carrierKind, datagrams))
	for _, subscriptions := range f.trust.subscriptions {
		subscriptions.Close()
	}
	q := &PublicQUICTestHarness{LocalLoopback: localLoopback, Root: f.root, SessionLimit: engineeringSessionLimit(), Environment: f.environment, Preauth: f.preauth, Clock: f.trust.clock,
		Generation: MaterialGeneration{Source: [16]byte{1}, Generation: 1}, Scope: [2]SessionResourceScope{f.scope, engineeringScope(t, f.root, f.root.Snapshot().Limit, engineeringSessionLimit(), 2)}}
	// The harness owns these raw seed projections even if its construction
	// fails later. All consumers registered below join before this callback.
	t.Cleanup(func() {
		clear(q.BrowserIdentitySeed[:])
		clear(q.BrowserDHSeed[:])
		clear(q.EngineeringServerIdentitySeed[:])
		clear(q.EngineeringServerDHSeed[:])
		clear(q.EngineeringActivationSeed[:])
		for role := range q.Identity {
			if signer, ok := q.Identity[role].Signer.(bootstrapSigner); ok {
				clear(signer.key)
			}
		}
		q.Identity = [2]ApplicationIdentityBytesConfig{}
		q.LiveIssuance = SourceLiveIssuance{}
		q.Lease = ArtifactLeaseBytesConfig{}
		q.Admission = [2]SessionAdmissionConfig{}
		q.Live = nil
		q.Pool = nil
		q.Authority = nil
		q.Reserve = nil
		q.Owner = nil
		q.BrowserBootstrap = nil
		q.BrowserAuthorize = nil
		q.BrowserHello = nil
		q.BrowserPolicyCalls = nil
		if q.PoolIssue != nil {
			for _, provider := range []protocolv4.MapSigner{q.PoolIssue.Base.Signer, q.PoolIssue.ActivationSigner, q.PoolIssue.GrantSigner} {
				if signer, ok := provider.(bootstrapSigner); ok {
					clear(signer.key)
				}
			}
			q.PoolIssue.Base.Signer = nil
			clear(q.PoolIssue.ClientIdentitySeed[:])
			clear(q.PoolIssue.ServerIdentitySeed[:])
			clear(q.PoolIssue.ClientDHSeed[:])
			clear(q.PoolIssue.ServerDHSeed[:])
			q.PoolIssue.ActivationSigner = nil
			q.PoolIssue.GrantSigner = nil
			q.PoolIssue = nil
		}
	})
	serverIdentitySeed := f.trust.signers[1].key.Seed()
	copy(q.EngineeringServerIdentitySeed[:], serverIdentitySeed)
	clear(serverIdentitySeed)
	if engineeringOriginalLive(t) {
		activationSeed := f.trust.issueSigner.key.Seed()
		copy(q.EngineeringActivationSeed[:], activationSeed)
		clear(activationSeed)
		if identity, ok := t.(EngineeringAuthorityIdentity); ok {
			q.Generation.Source = identity.AuthorityLeaseID()
		}
	}
	serial := uint32(10000)
	var ownerMu sync.Mutex
	q.Owner = func() resourcev4.OwnerKey {
		ownerMu.Lock()
		defer ownerMu.Unlock()
		serial++
		return admissionResourceKey(f.owner, serial)
	}
	q.Reserve = func(v resourcev4.Vector, accounts ...resourcev4.Account) resourcev4.Reference {
		r, err := f.root.Reserve(q.Owner(), v, accounts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Release)
		return r
	}
	seed := [32]byte{71, 23, 4}
	if profile != protocolv4.DHProfileX25519 {
		spec, err := protocolv4.Profile(profile)
		if err != nil {
			t.Fatal(err)
		}
		for role := range 2 {
			f.trust.keys[role], err = cryptov4.GenerateDHKey(profile)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(f.trust.keys[role].Close)
			dh := admissionEncode(t, "NoiseStaticPublicKey", map[string]protocolv4.Field{"algorithm": {Number: uint64(spec.DHAlgorithm)}, "public_key_bytes": admissionBytes(f.trust.keys[role].PublicKey())})
			wire, err := f.trust.certificates[role].Bytes()
			if err != nil {
				t.Fatal(err)
			}
			f.trust.certificates[role] = initialSignTemplate(t, "IdentityCertificate", wire, map[string]protocolv4.Field{
				"crypto_profile_id": admissionText(profile), "noise_static_public_key": {Kind: protocolv4.EncodedMap, Bytes: dh},
			}, seed)
		}
	}
	var browserDH, engineeringServerDH cryptov4.StaticDH
	if browserInterop {
		for i := range q.BrowserDHSeed {
			q.BrowserDHSeed[i] = 16
		}
		q.BrowserIdentitySeed = [32]byte{73, 29, 8}
		if engineeringOriginalLive(t) {
			identitySeed := f.trust.signers[0].key.Seed()
			copy(q.BrowserIdentitySeed[:], identitySeed)
			clear(identitySeed)
			if _, err := rand.Read(q.BrowserDHSeed[:]); err != nil {
				t.Fatal(err)
			}
		}
		curve := ecdh.X25519()
		if profile == protocolv4.DHProfileP256 {
			curve = ecdh.P256()
		}
		private, err := curve.NewPrivateKey(q.BrowserDHSeed[:])
		if err != nil {
			t.Fatal(err)
		}
		browserDH = publicFixtureDH{private}
		spec, err := protocolv4.Profile(profile)
		if err != nil {
			t.Fatal(err)
		}
		dh := admissionEncode(t, "NoiseStaticPublicKey", map[string]protocolv4.Field{"algorithm": {Number: uint64(spec.DHAlgorithm)}, "public_key_bytes": admissionBytes(browserDH.PublicKey())})
		wire, err := f.trust.certificates[0].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.certificates[0] = initialSignTemplate(t, "IdentityCertificate", wire, map[string]protocolv4.Field{"noise_static_public_key": {Kind: protocolv4.EncodedMap, Bytes: dh}}, seed)
	}
	if _, engineering := t.(EngineeringAuthorityTime); engineering && browserInterop {
		curve := ecdh.X25519()
		if profile == protocolv4.DHProfileP256 {
			curve = ecdh.P256()
		}
		var serverSeed [32]byte
		for i := range serverSeed {
			serverSeed[i] = 17
		}
		if engineeringOriginalLive(t) {
			if _, err := rand.Read(serverSeed[:]); err != nil {
				t.Fatal(err)
			}
		}
		q.EngineeringServerDHSeed = serverSeed
		defer clear(serverSeed[:])
		private, err := curve.NewPrivateKey(serverSeed[:])
		if err != nil {
			t.Fatal(err)
		}
		engineeringServerDH = publicFixtureDH{private}
		spec, err := protocolv4.Profile(profile)
		if err != nil {
			t.Fatal(err)
		}
		dh := admissionEncode(t, "NoiseStaticPublicKey", map[string]protocolv4.Field{"algorithm": {Number: uint64(spec.DHAlgorithm)}, "public_key_bytes": admissionBytes(engineeringServerDH.PublicKey())})
		wire, err := f.trust.certificates[1].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.certificates[1] = initialSignTemplate(t, "IdentityCertificate", wire, map[string]protocolv4.Field{"noise_static_public_key": {Kind: protocolv4.EncodedMap, Bytes: dh}}, seed)
	}
	var carrier uint64
	path, alpn := "", "flowersec-direct/4"
	subprotocol := ""
	if carrierKind == "webtransport" {
		carrier, path, alpn = 2, "/flowersec/webtransport/v4/direct", "h3"
	} else if carrierKind == "websocket" {
		carrier, path, alpn, subprotocol = 1, "/flowersec/v4/direct", "http/1.1", "flowersec.direct.v4"
	}
	legFields := map[string]protocolv4.Field{
		"access_class": {}, "leg_id": admissionBytes(make([]byte, 16)), "endpoint_role": {Number: 1}, "dialer_role": {}, "listener_role": {Number: 1},
		"carrier": {Number: carrier}, "host": admissionText(address.Addr().String()), "port": {Number: uint64(address.Port())},
		"path": admissionText(path), "alpn": admissionText(alpn), "subprotocol": admissionText(subprotocol),
		"tls_policy": {Kind: protocolv4.EncodedMap, Bytes: tlsPolicy},
	}
	if browserInterop && carrierKind == "websocket" {
		legFields["host"] = admissionText("localhost")
		if _, engineering := t.(EngineeringAuthorityTime); engineering {
			legFields["host"] = admissionText(address.Addr().String())
		}
		if len(origins) != 1 || len(origins[0]) == 0 || len(origins[0]) > 255 {
			t.Fatal("browser origin is missing or too long")
		}
		origin := origins[0]
		encoded := []byte{0x81}
		if len(origin) < 24 {
			encoded = append(encoded, 0x60|byte(len(origin)))
		} else {
			encoded = append(encoded, 0x78, byte(len(origin)))
		}
		encoded = append(encoded, origin...)
		policy := admissionEncode(t, "OriginPolicy", map[string]protocolv4.Field{"origins": {Kind: protocolv4.EncodedArray, Bytes: encoded}, "allow_absent": {Kind: protocolv4.Boolean}})
		legFields["origin_policy"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: policy}
	}
	if carrierKind == "webtransport" {
		origin := "https://example.com"
		if len(origins) == 1 {
			origin = origins[0]
		}
		encoded := []byte{0x81}
		if len(origin) < 24 {
			encoded = append(encoded, 0x60|byte(len(origin)))
		} else if len(origin) <= 255 {
			encoded = append(encoded, 0x78, byte(len(origin)))
		} else {
			t.Fatal("WebTransport origin exceeds its declared bound")
		}
		encoded = append(encoded, origin...)
		policy := admissionEncode(t, "OriginPolicy", map[string]protocolv4.Field{"origins": {Kind: protocolv4.EncodedArray, Bytes: encoded}, "allow_absent": {Kind: protocolv4.Boolean, Number: 1}})
		legFields["origin_policy"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: policy}
	}
	if localLoopback {
		if !address.Addr().IsLoopback() || len(origins) != 1 || origins[0] != "http://"+address.String() {
			t.Fatal("local bridge requires its exact numeric loopback origin")
		}
		legFields["access_class"] = protocolv4.Field{Number: 1}
		legFields["path"] = admissionText("/flowersec/v4/local")
		legFields["subprotocol"] = admissionText("flowersec.local.v4")
		legFields["origin"] = admissionText(origins[0])
		delete(legFields, "tls_policy")
		delete(legFields, "alpn")
		delete(legFields, "origin_policy")
	}
	if policy, enabled := t.(EngineeringCarrierHost); enabled && policy.AuthorityCarrierHost() != "" && !localLoopback {
		legFields["host"] = admissionText(policy.AuthorityCarrierHost())
	}
	leg := admissionEncode(t, "Leg", legFields)
	candidateFields := map[string]protocolv4.Field{"direct_leg": {Kind: protocolv4.EncodedMap, Bytes: leg}}
	if identity, ok := t.(EngineeringCandidateIdentity); ok && identity.AuthorityCandidateID() != ([16]byte{}) {
		id := identity.AuthorityCandidateID()
		candidateFields["candidate_id"] = admissionBytes(id[:])
	}
	candidate := admissionMap(t, "Candidate", f.trust.artifact.Field("candidates").Index(0).Encoded(), candidateFields)
	var tunnel *engineeringTunnelMaterials
	if authority, ok := t.(EngineeringTunnelAuthority); ok {
		recipe := authority.AuthorityTunnelRecipe()
		if recipe != nil {
			defer clear(recipe.RelayIdentitySeed[:])
			defer clear(recipe.GrantIssuerSeed[:])
			if source != "preauthorized_pool" && !(source == "live_authority" && engineeringOriginalLive(t)) {
				t.Fatal("engineering tunnel requires an original paired source installation")
			}
			candidate, tunnel = engineeringTunnelCandidate(t, f, recipe, profile)
		}
	}
	candidates := [][]byte{candidate}
	if routeSet, ok := t.(EngineeringDirectRouteSet); ok && len(routeSet.AuthorityDirectRoutes()) != 0 {
		if tunnel != nil {
			t.Fatal("engineering tunnel and direct route selection must be separate original issuance recipes")
		}
		routes := routeSet.AuthorityDirectRoutes()
		if source != "preauthorized_pool" || len(routes) > 16 {
			t.Fatal("engineering route set requires a finite original pool selection")
		}
		candidates = make([][]byte, len(routes))
		for index, wire := range routes {
			candidates[index] = func() []byte {
				route := admissionOwnedDocument(t, "Route", wire)
				defer route.Release()
				kind, ok := route.Root().Named("Route", "path_kind").Uint()
				if !ok || kind != 0 {
					t.Fatal("engineering candidate route set requires original direct routes")
				}
				id, ok := route.Root().Named("Route", "candidate_id").ByteString()
				if !ok || len(id) != 16 {
					t.Fatal("engineering route candidate identity is missing")
				}
				return admissionMap(t, "Candidate", candidate, map[string]protocolv4.Field{"candidate_id": admissionBytes(id), "path_kind": {}, "direct_leg": {Kind: protocolv4.EncodedMap, Bytes: route.Root().Named("Route", "direct_leg").Encoded()}})
			}()
		}
	}
	indices := make([]uint64, len(candidates))
	indexWire := []byte{0x80 | byte(len(candidates))}
	for index := range indices {
		indices[index] = uint64(index)
		indexWire = append(indexWire, byte(index))
	}
	changes := map[string]protocolv4.Field{"crypto_profile_id": admissionText(profile), "candidates": admissionArray(candidates...)}
	var features uint64
	if datagrams {
		features, _ = protocolv4.DatagramFeatureMask()
		changes["allowed_features"] = protocolv4.Field{Number: features}
		changes["required_features"] = protocolv4.Field{Number: features}
	}
	for role, field := range []string{"client_identity_digest", "server_identity_digest"} {
		digest, err := f.trust.certificates[role].Digest("certificate_digest")
		if err != nil {
			t.Fatal(err)
		}
		changes[field] = admissionBytes(digest[:])
	}
	wire, err := f.trust.artifact.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	f.trust.artifact = initialSignTemplate(t, "Artifact", wire, changes, seed)
	f.trust.session, err = f.trust.artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	f.trust.features, err = f.trust.artifact.FeatureEnvelope(0, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: features, ProposedOffer: features, RouteAllowedFeatures: features})
	if err != nil {
		t.Fatal(err)
	}
	route, routeDigest, err := f.trust.artifact.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	q.Route, q.ArtifactDigest = route, f.trust.session.ArtifactDigest
	q.DirectRoutes = make([][]byte, len(candidates))
	q.DirectRouteDigests = make([][32]byte, len(candidates))
	for index := range candidates {
		wire, digest, err := f.trust.artifact.CopyCandidateRoute(uint64(index), make([]byte, 16384))
		if err != nil {
			t.Fatal(err)
		}
		q.DirectRoutes[index] = append([]byte(nil), wire...)
		q.DirectRouteDigests[index] = digest
	}
	q.BrowserRouteDigest = routeDigest
	id, _ := f.trust.artifact.Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
	f.trust.candidate = protocolv4.PoolMember{CandidateID: [16]byte(id), RouteDigest: routeDigest}
	if !engineeringOriginalLive(t) {
		changes = map[string]protocolv4.Field{"artifact_digest": admissionBytes(q.ArtifactDigest[:]), "route_selection": admissionBytes(routeDigest[:])}
		for _, pair := range [][2]string{{"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
			changes[pair[1]] = admissionField(f.trust.artifact.Field(pair[0]))
		}
		if source == "preauthorized_pool" {
			workspace, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
			if err != nil {
				t.Fatal(err)
			}
			selection, err := workspace.Derive(f.trust.artifact, indices)
			if err != nil {
				t.Fatal(err)
			}
			artifactDigest, candidates, routes, err := selection.Digests()
			selection.Release()
			if err != nil {
				t.Fatal(err)
			}
			selected := admissionMap(t, "PoolSelectionRef", f.trust.proof.Field("candidate_selection").Encoded(), map[string]protocolv4.Field{
				"artifact_digest": admissionBytes(artifactDigest[:]), "candidate_set_digest": admissionBytes(candidates[:]),
				"candidate_indices": {Kind: protocolv4.EncodedArray, Bytes: indexWire},
			}, source)
			changes["candidate_selection"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: selected}
			changes["route_selection"] = admissionBytes(routes[:])
		}
		wire, err = f.trust.proof.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.proof = initialSignTemplate(t, "ActivationAuthorization", wire, changes, seed, source)
		workspace, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
		if err != nil {
			t.Fatal(err)
		}
		f.trust.activation, err = workspace.BindActivation(f.trust.artifact, f.trust.proof, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.trust.authority, err = f.trust.rules.BindActivationAuthority(f.trust.activation, f.trust.artifact, f.trust.delegation, f.trust.once)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, credential := range []*protocolv4.SignedMap{f.trust.artifact, f.trust.certificates[0], f.trust.certificates[1]} {
		detached, err := credential.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.trust.scopes[i] = detached.Scope()
	}
	if tunnel != nil {
		if engineeringOriginalPool(t) || engineeringOriginalLive(t) {
			engineeringInstallOriginalPoolPolicy(t, f, tunnel)
		} else {
			engineeringIssueTunnelGrants(t, f, tunnel)
		}
	}
	q.Verification = authorityVerificationRegistry(t, f)
	raw := authorityMaterialBytesFor(t, f, q.Verification)
	if tunnel != nil {
		if engineeringOriginalPool(t) || engineeringOriginalLive(t) {
			relay, e := tunnel.relay.Bytes()
			if e != nil {
				t.Fatal(e)
			}
			q.Tunnel = &PublicTunnelAuthority{RelayCertificate: append([]byte(nil), relay...), RelaySigner: tunnel.signer, Limits: tunnel.recipe.Limits}
		} else {
			engineeringInstallTunnelBytes(t, q, raw, tunnel)
		}
	}
	q.Lease = raw.config
	if browserInterop {
		q.BrowserRootKeyID, q.BrowserRootPublicKey, q.BrowserBootstrap = raw.rootKeyID, raw.rootPublic, raw.bootstrap
		q.BrowserTenant, _ = f.trust.artifact.Field("tenant_id").Text()
		q.BrowserAuthority, _ = f.trust.artifact.Field("revocation_authority_id").Text()
		q.BrowserAudience, _ = f.trust.artifact.Field("audience").Text()
		q.BrowserClientSubject, _ = f.trust.certificates[0].Field("subject_id").Text()
		q.BrowserServerSubject, _ = f.trust.certificates[1].Field("subject_id").Text()
		q.BrowserOnceAuthority = f.trust.trust.activation.SpendAuthority
		issuer, ok := f.trust.artifact.Field("issuer_key_id").ByteString()
		if !ok || len(issuer) != len(q.BrowserIssuerKeyID) {
			t.Fatal("browser fixture issuer key ID is invalid")
		}
		copy(q.BrowserIssuerKeyID[:], issuer)
	}
	for role := range 2 {
		certificate := raw.config.ClientCertificate
		if role == 1 {
			certificate = raw.config.ServerCertificate
		}
		q.Identity[role] = ApplicationIdentityBytesConfig{Certificate: certificate, Trust: raw.trust, Role: protocolv4.Direction(role),
			Signer: f.trust.signers[role], StaticDH: f.trust.keys[role], MapNodes: 4096, RuntimeBytes: 8192}
		if browserInterop && role == 0 {
			q.Identity[role].StaticDH = browserDH
		}
		if role == 1 && engineeringServerDH != nil {
			q.Identity[role].StaticDH = engineeringServerDH
		}
		c := f.config
		roleCarrier := carrierKind
		if tunnel != nil {
			name := "client_leg"
			if role == 1 {
				name = "server_leg"
			}
			value := admissionDocument(t, "Route", q.Route).Root().Named("Route", name).Named("Leg", "carrier")
			carrier, ok := value.Uint()
			if !ok {
				t.Fatal("engineering tunnel carrier is missing")
			}
			switch carrier {
			case 0:
				roleCarrier = "quic"
			case 1:
				roleCarrier = "websocket"
			case 2:
				roleCarrier = "webtransport"
			default:
				t.Fatal("engineering tunnel carrier is unsupported")
			}
		}
		c.Core = engineeringNativeCore(t, c.Core, f.trust.session, roleCarrier, features != 0)
		c.Features = f.trust.features
		c.Initial.Role, c.Initial.Profile = protocolv4.Direction(role), profile
		q.Admission[role] = c
	}
	q.Hello = InitialHello{Index: 0, Attempt: f.trust.attempt, Offered: features, Policy: protocolv4.HelloPolicy{BindingMode: 1, RouteAllowedFeatures: features}, BindingModes: 2}
	q.Limits = EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	if source == "preauthorized_pool" {
		_, err = authorityConsumePool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
			q.Store, q.Authority = store, authority
			q.Pool = &PoolSessionInput{Store: store, Authority: authority, Consume: work}
			return nil, nil
		})
	} else if !engineeringOriginalLive(t) {
		cost, costErr := protocolv4.LiveActivationPlanCharge()
		if costErr != nil {
			t.Fatal(costErr)
		}
		plan, planErr := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner,
			protocolv4.LiveActivationConfig{Index: 0, Attempt: f.trust.attempt, IssuedAt: authorityTime(t, 1150), ActivationEnd: authorityTime(t, 1400), SessionEnd: authorityTime(t, 4000)}, q.Reserve(cost), f.environment, f.preauth)
		if planErr != nil {
			t.Fatal(planErr)
		}
		t.Cleanup(func() { _ = plan.Close() })
		fields, _, planErr := plan.CopyProjection(make([]byte, 4096))
		if planErr != nil {
			t.Fatal(planErr)
		}
		authority := liveSQLiteAuthority{acceptedSQLiteAuthority: acceptedSQLiteAuthority{identity: ledgerv4.SQLiteIdentity{Authority: fields.Authority, StoreID: [32]byte{3}, Generation: 1}}, original: fields}
		credential, credentialErr := f.trust.artifact.DetachCredential()
		if credentialErr != nil {
			t.Fatal(credentialErr)
		}
		guard := func() error {
			now, err := f.trust.clock.Sample()
			if err != nil {
				return err
			}
			return plan.CheckTrust(f.trust.namespace, credential, f.trust.trust.permissions[0], authorityDuration(t, 5000), authorityDuration(t, 59000), authorityTime(t, 4000), now.Interval)
		}
		err = authoritySessionSQLite(t, f, nil, authority.identity, authority, 16384, func(store *ledgerv4.SQLiteStore, reserve func(uint32, resourcev4.Vector) resourcev4.Reference) error {
			owner, invoke, err := ledgerv4.SQLiteLiveSpendCharges(16384)
			if err != nil {
				return err
			}
			q.Store, q.Authority = store, authority
			q.Live = &LiveSessionInput{Store: store, Authority: authority, Guard: guard, Policy: func(context.Context) (bool, error) { q.PolicyCalls++; return true, nil },
				Owner: ledgerv4.LiveSpendOwner{Invocation: [16]byte{1}, Generation: 1, RequestDigest: [32]byte{2}, ClientMaterialNotAfter: authorityTime(t, 1400)}, Buffers: reserve(242, owner), Invocation: reserve(243, invoke)}
			q.LiveIssuance = SourceLiveIssuance{Signer: f.trust.issueSigner, IssuedAt: authorityTime(t, 1150), ActivationEnd: authorityTime(t, 1400), SessionEnd: authorityTime(t, 4000), Reservation: q.Reserve(cost)}
			return nil
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	if browserInterop && source == "live_authority" && !engineeringOriginalLive(t) {
		// The host accepts one independently authenticated request and freezes
		// its actual browser attempt before the original SQLite TxA/policy/TxB.
		// It never signs an uncommitted success or reconstructs a spent intent.
		var mu sync.Mutex
		claimed := false
		hello := q.Hello
		q.BrowserHello = func() InitialHello {
			mu.Lock()
			defer mu.Unlock()
			return hello
		}
		q.BrowserPolicyCalls = func() int {
			mu.Lock()
			defer mu.Unlock()
			return q.PolicyCalls
		}
		q.BrowserAuthorize = func(ctx context.Context, request LiveAuthorizationRequest, digest [32]byte, output []byte) (n int, err error) {
			mu.Lock()
			defer mu.Unlock()
			if claimed || request.AttemptNo != 1 || request.Attempt == ([16]byte{}) || request.ActivationNotAfterMS < authorityTime(t, 1400) {
				return 0, ledgerv4.ErrConflict
			}
			claimed = true
			plan, err := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner,
				protocolv4.LiveActivationConfig{Index: 0, Attempt: request.Attempt, IssuedAt: authorityTime(t, 1150), ActivationEnd: authorityTime(t, 1400), SessionEnd: authorityTime(t, 4000)}, q.LiveIssuance.Reservation, f.environment, f.preauth)
			if err != nil {
				return 0, err
			}
			defer func() {
				if cleanup := plan.Close(); err == nil {
					err = cleanup
				}
			}()
			fields, _, err := plan.CopyProjection(make([]byte, 4096))
			if err != nil {
				return 0, err
			}
			if request.Tenant != fields.Tenant || request.Audience != fields.Audience || request.CryptoProfile != fields.Profile ||
				request.Issuer != fields.Issuer || request.Lease != fields.Lease || request.Artifact != fields.Artifact ||
				request.ClientIdentity != fields.ClientIdentity || request.ServerIdentity != fields.ServerIdentity || request.Winner != fields.Winner ||
				request.ActivationNotAfterMS > fields.ParentInitiationEnd {
				return 0, ledgerv4.ErrConflict
			}
			authority := q.Live.Authority.(liveSQLiteAuthority)
			authority.original = fields
			credential, err := f.trust.artifact.DetachCredential()
			if err != nil {
				return 0, err
			}
			guard := func() error {
				now, err := q.Clock.Sample()
				if err != nil {
					return err
				}
				return plan.CheckTrust(f.trust.namespace, credential, f.trust.trust.permissions[0], authorityDuration(t, 5000), authorityDuration(t, 59000), authorityTime(t, 4000), now.Interval)
			}
			deadline, err := timev4.NewDeadline(q.Clock, fields.ActivationEnd)
			if err != nil {
				return 0, err
			}
			owner := ledgerv4.LiveSpendOwner{Invocation: request.Attempt, Generation: 1, RequestDigest: digest, ClientMaterialNotAfter: fields.ActivationEnd}
			spend, err := ledgerv4.NewSQLiteLiveSpend(ctx, q.Store, authority, plan, owner, q.Clock, deadline, guard, q.Live.Buffers, q.Live.Invocation, q.Environment)
			if err != nil {
				return 0, err
			}
			defer func() {
				if cleanup := spend.Cleanup(); err == nil {
					err = cleanup
				}
			}()
			err = spend.Authorize(q.Live.Policy, func(_ context.Context, wire []byte) error {
				if len(wire) > len(output) {
					return ledgerv4.ErrCapacity
				}
				n = copy(output, wire)
				hello.Attempt = request.Attempt
				return nil
			})
			return n, err
		}
	}
	if tunnel != nil && engineeringOriginalPool(t) {
		q.PoolIssue = engineeringPoolIssueRecipe(t, q, f, tunnel)
	}
	return q
}

// NewEngineeringNativeHarness provides signed authority material and original
// resource/trust/SQLite owners to an explicitly enabled engineering peer. The
// peer still constructs and calls the normal public transport and Session APIs.
func NewEngineeringNativeHarness(t AuthorityReporter, source, profile, carrier string, address netip.AddrPort, tlsPolicy []byte, origin string, datagrams bool) *PublicQUICTestHarness {
	kind := carrier
	if carrier == "raw-quic" {
		kind = "quic"
	}
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, kind, datagrams, true, origin)
}

// UseEngineeringPeerMaterial installs independently bootstrapped peer material
// into this authority's local durable consumer recipe. It verifies the original
// signed maps through the real ArtifactLease before projecting admission facts.
// No durable spend, endpoint handshake or READY result is synthesized here.
func (h *PublicQUICTestHarness) UseEngineeringPeerMaterial(t AuthorityReporter, config ArtifactLeaseBytesConfig, identitySeed, dhSeed [32]byte, role protocolv4.Direction) {
	config.Trust = h.Lease.Trust
	for i := range config.Tunnels {
		if config.Tunnels[i].GrantTrust == nil {
			config.Tunnels[i].GrantTrust = h.Lease.Trust[0]
		}
		if config.Tunnels[i].RelayTrust == nil {
			config.Tunnels[i].RelayTrust = h.Lease.Trust[0]
		}
	}
	charge, err := ArtifactLeaseCharge(config.MapBytes, config.MapNodes, config.RuntimeBytes, len(config.Tunnels))
	if err != nil {
		t.Fatal(err)
	}
	lease, err := NewArtifactLeaseFromBytes(config, h.Reserve(charge), h.Preauth)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if config.Source != "preauthorized_pool" {
		t.Fatal("imported live authority requires its original live issuance provider")
	}
	binding, authority, err := lease.activation(0)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := authority.PoolSpendFacts(config.Proof)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := facts.Fields()
	if err != nil {
		t.Fatal(err)
	}
	local, ok := h.Authority.(poolSQLiteAuthority)
	if !ok {
		t.Fatal("pool consumer authority is unavailable")
	}
	local.original = fields
	// Rebinding this position's signed facts retains the original deployment's
	// shared durable scheduler, rather than creating an independent store gate.
	h.Authority = local
	h.Pool.Authority = local
	h.Lease = config
	route, digest, err := lease.maps[0].CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	h.Route = append([]byte(nil), route...)
	h.ArtifactDigest = lease.session.ArtifactDigest
	h.BrowserRouteDigest = digest
	h.Hello.Attempt = fields.Attempt
	features, _ := lease.maps[0].Field("allowed_features").Uint()
	datagramMask, _ := protocolv4.DatagramFeatureMask()
	for i := range h.Admission {
		h.Admission[i].Core.Session = lease.session
		h.Admission[i].Core.Datagrams = features&datagramMask != 0
	}
	h.Hello.Index = 0
	h.Hello.Offered, _ = lease.maps[0].Field("allowed_features").Uint()
	h.Hello.Policy.RouteAllowedFeatures = h.Hello.Offered
	featuresEnvelope, err := lease.maps[0].FeatureEnvelope(0, protocolv4.FeatureEnvelopePolicy{LocalCapabilities: h.Hello.Offered, ProposedOffer: h.Hello.Offered, RouteAllowedFeatures: h.Hello.Offered})
	if err != nil {
		t.Fatal(err)
	}
	for i := range h.Admission {
		h.Admission[i].Features = featuresEnvelope
	}
	curve := ecdh.X25519()
	if lease.session.Profile == protocolv4.DHProfileP256 {
		curve = ecdh.P256()
	}
	key, err := curve.NewPrivateKey(dhSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	certificate := config.ClientCertificate
	if role == protocolv4.ServerToClient {
		certificate = config.ServerCertificate
	}
	h.Identity[role] = ApplicationIdentityBytesConfig{Certificate: certificate, Trust: config.Trust[1+int(role)], Role: role,
		Signer: bootstrapSigner{ed25519.NewKeyFromSeed(identitySeed[:])}, StaticDH: publicFixtureDH{key}, MapNodes: 4096, RuntimeBytes: 8192}
	_ = binding // Binding is checked by the original activation and pool projection.
}

func (h *PublicQUICTestHarness) PreparationNamespaces(clock *timev4.Clock, environment resourcev4.Reference) ([3]*protocolv4.LiveNamespace, error) {
	var namespaces [3]*protocolv4.LiveNamespace
	for i, store := range h.Lease.Trust {
		namespace, err := store.NamespaceForPreparation(clock, environment)
		if err != nil {
			return namespaces, err
		}
		namespaces[i] = namespace
	}
	return namespaces, nil
}

// engineeringNativeCore retains the original signed stream, receive and crypto
// geometry for both construction and trusted local capacity declarations.
func engineeringNativeCore(t AuthorityReporter, c SessionCoreConfig, parameters protocolv4.ArtifactSessionParameters, roleCarrier string, datagrams bool) SessionCoreConfig {
	c.Session, c.Native, c.MessageCarrier = parameters, roleCarrier != "websocket", roleCarrier == "websocket"
	if roleCarrier == "websocket" {
		c.MessageRuntimeBytes = 65536
		c.NativeAuthWorkers = 0
	}
	if roleCarrier != "websocket" {
		c.NativeAuthWorkers = 1
	}
	c.SendWorkers = [3]uint32{2}
	if datagrams {
		c.Datagrams = true
		c.WorkSlots = 6
	}
	c.Streams = factoryStreamConfig()
	if _, engineering := t.(EngineeringAuthorityTime); engineering {
		maximum := parameters.Contract.Limits().MaxStreams
		registry, err := openAdmissionRegistry()
		if err != nil {
			t.Fatal(err)
		}
		geometry, _, err := internalChannelGeometry(parameters.Contract.Limits().ApplicationProfile)
		if err != nil {
			t.Fatal(err)
		}
		internal := geometry.RPC + geometry.Notify
		fixed := internal + geometry.Management
		if maximum < fixed || internal%2 != 0 {
			t.Fatal("engineering active capacity cannot cover its original profile")
		}
		classes := [3]uint32{maximum - fixed, internal, geometry.Management}
		opener := [2][3]uint32{{classes[0], internal / 2, geometry.Management}, {classes[0], internal / 2, 0}}
		protected := [2][3]uint32{{0, internal / 2, geometry.Management}, {0, internal / 2, 0}}
		lifetime := [2][3]uint64{{registry.Streams.Business, registry.Streams.Internal, 0}, {registry.Streams.Business, registry.Streams.Internal, 0}}
		if geometry.Management != 0 {
			lifetime[0][ManagementStream] = registry.Streams.Management
		}
		pending := min(maximum, registry.Streams.Pending)
		c.MaxScopes, c.PendingScopes = maximum, pending
		c.Open = OpenLimits{Active: maximum, Opening: pending, Terminal: maximum*2 + 2, RejectionReserve: 2, IngressItems: pending, IngressBytes: registry.Records.Caps.Ingress.Bytes, PerClass: classes, PerOpener: opener, Protected: protected, Lifetime: lifetime}
		c.WorkSlots = 6
		// A barrier contains one map and two key/value pairs per signed scope.
		// Keep the fixed record allowance for the enclosing phase and other frames.
		c.DecoderNodes = 128 + 5*int(maximum)
		c.Maintenance = engineeringRekeyReserve(t, c.Session.Profile, maximum, c.Session.Contract.Limits().MaxFrame)
		if c.Native {
			c.SendWorkers = classes
		} else {
			c.SendWorkers = [3]uint32{min(classes[0], 2), min(classes[1], 1), min(classes[2], 1)}
		}
		// Decode every DATA payload allowed by the signed frame. The local
		// publication chunk is independent of the peer's legal frame size;
		// its send ring and plaintext backing are charged before admission.
		c.MaxDataPayloadBytes = uint64(c.Session.Contract.Limits().MaxFrame)
		c.Streams = SessionStreamConfig{ReceivePoolBytes: uint64(maximum) * (128 << 10), ReceiveBytes: 128 << 10, InitialReceiveLimit: engineeringInitialReceiveLimit, SendBytes: 4096, QueueBytes: 16384, WriteWaiters: 4, MaxPlaintext: 4224, Chunk: 4096, RuntimeBytes: 65536}

	}
	c.Messages = MaintenanceMessagePolicy{256, 1, 10000}
	c.Termination = StreamTerminationPolicy{10000, 1000, 8}
	c.NativeIngress = MaintenanceIngressPolicy{10000, 1, 256}
	c.DrainTimeoutMS = 1000
	return c
}

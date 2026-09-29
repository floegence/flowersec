package sessionv4

import (
	"context"
	"crypto/ecdh"
	"net/netip"
	"sync"
	"testing"

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
	Root                 *resourcev4.Root
	Environment, Preauth resourcev4.Reference
	Clock                *timev4.Clock
	Verification         *protocolv4.NamespaceRegistry
	Scope                [2]SessionResourceScope
	Admission            [2]SessionAdmissionConfig
	Lease                ArtifactLeaseBytesConfig
	Identity             [2]ApplicationIdentityBytesConfig
	Route                []byte
	Hello                InitialHello
	Limits               EstablishmentLimits
	Generation           MaterialGeneration
	ArtifactDigest       [32]byte
	Store                *ledgerv4.SQLiteStore
	Authority            ledgerv4.SQLiteAdmissionAuthority
	Pool                 *PoolSessionInput
	Live                 *LiveSessionInput
	LiveIssuance         SourceLiveIssuance
	Owner                func() resourcev4.OwnerKey
	Reserve              func(resourcev4.Vector, ...resourcev4.Account) resourcev4.Reference
	PolicyCalls          int
	BrowserRootKeyID     [16]byte
	BrowserRootPublicKey [32]byte
	BrowserIdentitySeed  [32]byte
	BrowserDHSeed        [32]byte
	BrowserBootstrap     func([32]byte) ([]byte, []byte)
	BrowserRouteDigest   [32]byte
	BrowserTenant        string
	BrowserAuthority     string
	BrowserAudience      string
	BrowserClientSubject string
	BrowserServerSubject string
	BrowserOnceAuthority string
	BrowserIssuerKeyID   [16]byte
	BrowserAuthorize     func(context.Context, LiveAuthorizationRequest, [32]byte, []byte) (int, error)
	BrowserHello         func() InitialHello
	BrowserPolicyCalls   func() int
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

func NewPublicQUICTestHarness(t *testing.T, source, profile string, address netip.AddrPort, tlsPolicy []byte, enableDatagrams ...bool) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "quic", len(enableDatagrams) != 0 && enableDatagrams[0], false)
}

func NewPublicWebTransportTestHarness(t *testing.T, source, profile string, address netip.AddrPort, tlsPolicy []byte, enableDatagrams ...bool) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "webtransport", len(enableDatagrams) != 0 && enableDatagrams[0], false)
}

func NewPublicWSSTestHarness(t *testing.T, source, profile string, address netip.AddrPort, tlsPolicy []byte) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "websocket", false, false)
}

func NewPublicWSSBrowserTestHarness(t *testing.T, source, profile string, address netip.AddrPort, tlsPolicy []byte, origin string) *PublicQUICTestHarness {
	t.Helper()
	return newPublicNativeTestHarness(t, source, profile, address, tlsPolicy, "websocket", false, true, origin)
}

func newPublicNativeTestHarness(t *testing.T, source, profile string, address netip.AddrPort, tlsPolicy []byte, carrierKind string, datagrams, browserInterop bool, origins ...string) *PublicQUICTestHarness {
	t.Helper()
	f := admissionIntegration(t, context.Background(), source)
	f.prepared.Close()
	if err := f.prepared.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.prepared.Retire(); err != nil {
		t.Fatal(err)
	}
	for _, subscriptions := range f.trust.subscriptions {
		subscriptions.Close()
	}
	q := &PublicQUICTestHarness{Root: f.root, Environment: f.environment, Preauth: f.preauth, Clock: f.trust.clock,
		Generation: MaterialGeneration{Source: [16]byte{1}, Generation: 1}, Scope: [2]SessionResourceScope{f.scope, corePlanTestScope(t, f.root, f.root.Snapshot().Limit, 2)}}
	serial := uint32(10000)
	q.Owner = func() resourcev4.OwnerKey {
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
	var browserDH cryptov4.StaticDH
	if browserInterop {
		for i := range q.BrowserDHSeed {
			q.BrowserDHSeed[i] = 16
		}
		q.BrowserIdentitySeed = [32]byte{73, 29, 8}
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
	if browserInterop {
		legFields["host"] = admissionText("localhost")
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
		policy := admissionEncode(t, "OriginPolicy", map[string]protocolv4.Field{"origins": {Kind: protocolv4.EncodedArray, Bytes: append([]byte{0x81, 0x73}, []byte("https://example.com")...)}, "allow_absent": {Kind: protocolv4.Boolean, Number: 1}})
		legFields["origin_policy"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: policy}
	}
	leg := admissionEncode(t, "Leg", legFields)
	candidate := admissionMap(t, "Candidate", f.trust.artifact.Field("candidates").Index(0).Encoded(), map[string]protocolv4.Field{"direct_leg": {Kind: protocolv4.EncodedMap, Bytes: leg}})
	changes := map[string]protocolv4.Field{"crypto_profile_id": admissionText(profile), "candidates": admissionArray(candidate)}
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
	q.BrowserRouteDigest = routeDigest
	id, _ := f.trust.artifact.Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
	f.trust.candidate = protocolv4.PoolMember{CandidateID: [16]byte(id), RouteDigest: routeDigest}
	changes = map[string]protocolv4.Field{"artifact_digest": admissionBytes(q.ArtifactDigest[:]), "route_selection": admissionBytes(routeDigest[:])}
	for _, pair := range [][2]string{{"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
		changes[pair[1]] = admissionField(f.trust.artifact.Field(pair[0]))
	}
	if source == "preauthorized_pool" {
		workspace, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := workspace.Derive(f.trust.artifact, []uint64{0})
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
	for i, credential := range []*protocolv4.SignedMap{f.trust.artifact, f.trust.certificates[0], f.trust.certificates[1]} {
		detached, err := credential.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.trust.scopes[i] = detached.Scope()
	}
	q.Verification = environmentVerificationRegistry(t, f)
	raw := materialBytesFor(t, f, q.Verification)
	q.Lease = raw.config
	if browserInterop {
		q.BrowserRootKeyID, q.BrowserRootPublicKey, q.BrowserBootstrap = raw.rootKeyID, raw.rootPublic, raw.bootstrap
		q.BrowserTenant, _ = f.trust.artifact.Field("tenant_id").Text()
		q.BrowserAuthority, _ = f.trust.artifact.Field("revocation_authority_id").Text()
		q.BrowserAudience, _ = f.trust.artifact.Field("audience").Text()
		q.BrowserClientSubject, _ = f.trust.certificates[0].Field("subject_id").Text()
		q.BrowserServerSubject, _ = f.trust.certificates[1].Field("subject_id").Text()
		q.BrowserOnceAuthority, _ = f.trust.proof.Field("authority_id").Text()
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
		c := f.config
		c.Core.Session, c.Core.Native, c.Core.MessageCarrier = f.trust.session, carrierKind != "websocket", carrierKind == "websocket"
		if carrierKind == "websocket" {
			c.Core.MessageRuntimeBytes = 65536
			c.Core.NativeAuthWorkers = 0
		}
		if carrierKind != "websocket" {
			c.Core.NativeAuthWorkers = 1
		}
		c.Core.SendWorkers = [3]uint32{2}
		if features != 0 {
			c.Core.Datagrams = true
			c.Core.WorkSlots = 6
		}
		c.Core.Streams = factoryStreamConfig()
		c.Core.Messages = MaintenanceMessagePolicy{256, 1, 10000}
		c.Core.Termination = StreamTerminationPolicy{10000, 1000, 8}
		c.Core.NativeIngress = MaintenanceIngressPolicy{10000, 1, 256}
		c.Core.DrainTimeoutMS = 1000
		c.Features = f.trust.features
		c.Initial.Role, c.Initial.Profile = protocolv4.Direction(role), profile
		q.Admission[role] = c
	}
	q.Hello = InitialHello{Index: 0, Attempt: f.trust.attempt, Offered: features, Policy: protocolv4.HelloPolicy{BindingMode: 1, RouteAllowedFeatures: features}, BindingModes: 2}
	q.Limits = EstablishmentLimits{MapBytes: 65536, MapNodes: 4096, Hello: protocolv4.HelloLimits{HelloBytes: 16384, HelloNodes: 4096, RouteBytes: 16384, ContextBytes: 1024}, RuntimeBytes: 65536}
	if source == "preauthorized_pool" {
		_, err = consumeSessionPool(t, f, nil, func(store *ledgerv4.SQLiteStore, authority poolSQLiteAuthority, work resourcev4.Reference) (*InitialExchange, error) {
			q.Store, q.Authority = store, authority
			q.Pool = &PoolSessionInput{Store: store, Authority: authority, Consume: work}
			return nil, nil
		})
	} else {
		cost, costErr := protocolv4.LiveActivationPlanCharge()
		if costErr != nil {
			t.Fatal(costErr)
		}
		plan, planErr := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner,
			protocolv4.LiveActivationConfig{Index: 0, Attempt: f.trust.attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, q.Reserve(cost), f.environment, f.preauth)
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
			return plan.CheckTrust(f.trust.namespace, credential, f.trust.trust.permissions[0], 5000, 59000, 4000, now.Interval)
		}
		err = withSessionSQLite(t, f, nil, authority.identity, authority, 16384, func(store *ledgerv4.SQLiteStore, reserve func(uint32, resourcev4.Vector) resourcev4.Reference) error {
			owner, invoke, err := ledgerv4.SQLiteLiveSpendCharges(16384)
			if err != nil {
				return err
			}
			q.Store, q.Authority = store, authority
			q.Live = &LiveSessionInput{Store: store, Authority: authority, Guard: guard, Policy: func(context.Context) (bool, error) { q.PolicyCalls++; return true, nil },
				Owner: ledgerv4.LiveSpendOwner{Invocation: [16]byte{1}, Generation: 1, RequestDigest: [32]byte{2}, ClientMaterialNotAfter: 1400}, Buffers: reserve(242, owner), Invocation: reserve(243, invoke)}
			q.LiveIssuance = SourceLiveIssuance{Signer: f.trust.issueSigner, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000, Reservation: q.Reserve(cost)}
			return nil
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	if browserInterop && source == "live_authority" {
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
			if claimed || request.AttemptNo != 1 || request.Attempt == ([16]byte{}) || request.ActivationNotAfterMS < 1400 {
				return 0, ledgerv4.ErrConflict
			}
			claimed = true
			plan, err := protocolv4.NewLiveActivationPlan(f.trust.artifact, f.trust.rules, f.trust.delegation, f.trust.once, f.trust.issueSigner,
				protocolv4.LiveActivationConfig{Index: 0, Attempt: request.Attempt, IssuedAt: 1150, ActivationEnd: 1400, SessionEnd: 4000}, q.LiveIssuance.Reservation, f.environment, f.preauth)
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
				return plan.CheckTrust(f.trust.namespace, credential, f.trust.trust.permissions[0], 5000, 59000, 4000, now.Interval)
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
	return q
}

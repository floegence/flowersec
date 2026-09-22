package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// This fixture composes public protocol APIs with exact independently pinned
// test trust entries. It does not bypass the production authorization owner.
type sessionAdmissionTrustFixture struct {
	rules            *protocolv4.NamespaceRules
	delegation, once []byte
	issueSigner      bootstrapSigner
	source           string
	artifact, proof  *protocolv4.SignedMap
	certificates     [2]*protocolv4.SignedMap
	activation       *protocolv4.ActivationBinding
	authority        *protocolv4.ActivationAuthority
	subscriptions    [2]*protocolv4.CredentialSubscriptions
	features         protocolv4.FeatureEnvelope
	session          protocolv4.ArtifactSessionParameters
	candidate        protocolv4.PoolMember
	attempt          [16]byte
	clock            *timev4.Clock
	tick             *atomic.Uint64
	namespace        *protocolv4.LiveNamespace
	trust            *sessionAdmissionTrust
	keys             [2]*cryptov4.DHKey
	signers          [2]bootstrapSigner
}

type sessionAdmissionTrust struct {
	rejected    atomic.Bool
	head        protocolv4.NamespaceHeadTrust
	activation  protocolv4.ActivationTrustBinding
	permissions [3]protocolv4.IssuerPermission
	scopes      [3]protocolv4.CredentialScope
	policy      *protocolv4.CredentialPolicy
}

func (s *sessionAdmissionTrust) Head(h protocolv4.NamespaceHeadTrust) error {
	if s.rejected.Load() || h != s.head {
		return protocolv4.CBORFailure("independent_trust_rejected")
	}
	return nil
}
func (s *sessionAdmissionTrust) Issuer(p protocolv4.IssuerPermission, c protocolv4.CredentialScope) error {
	if !s.rejected.Load() {
		for i := range s.permissions {
			if p == s.permissions[i] && c == s.scopes[i] {
				return nil
			}
		}
	}
	return protocolv4.CBORFailure("independent_trust_rejected")
}
func (s *sessionAdmissionTrust) Policy(p *protocolv4.CredentialPolicy) error {
	if s.rejected.Load() || p != s.policy {
		return protocolv4.CBORFailure("independent_trust_rejected")
	}
	return nil
}
func (s *sessionAdmissionTrust) Activation(a protocolv4.ActivationTrustBinding) error {
	if s.rejected.Load() || a != s.activation {
		return protocolv4.CBORFailure("independent_activation_rejected")
	}
	return nil
}
func (*sessionAdmissionTrust) RetiredIssuer([16]byte) bool                   { return false }
func (*sessionAdmissionTrust) StateHistory(*protocolv4.NamespaceState) error { return nil }

func admissionBytes(b []byte) protocolv4.Field {
	return protocolv4.Field{Kind: protocolv4.ByteString, Bytes: b}
}
func admissionText(s string) protocolv4.Field {
	return protocolv4.Field{Kind: protocolv4.TextString, Text: s}
}
func admissionArray(maps ...[]byte) protocolv4.Field {
	if len(maps) > 23 {
		panic("fixture array too large")
	}
	b := []byte{0x80 | byte(len(maps))}
	for _, m := range maps {
		b = append(b, m...)
	}
	return protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: b}
}

func admissionDocument(t *testing.T, schema string, wire []byte, sources ...string) *protocolv4.Document {
	t.Helper()
	d, err := protocolv4.NewDecoder(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	doc, err := d.DecodeShape(wire, schema, protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": source}, Limits: map[string]uint64{"max_state_encoded_bytes": 4096, "max_revoked_issuer_authorizations": 93, "max_revoked_issuers": 63, "max_revoked_certificates": 102, "max_revoked_leases": 53, "max_cohort_policy_segments": 16}})
	if err != nil {
		t.Fatal(schema, err)
	}
	t.Cleanup(doc.Release)
	return doc
}

func admissionField(v protocolv4.Value) protocolv4.Field {
	if b, ok := v.ByteString(); ok {
		return admissionBytes(b)
	}
	if s, ok := v.Text(); ok {
		return admissionText(s)
	}
	if n, ok := v.Uint(); ok {
		return protocolv4.Field{Number: n}
	}
	if b, ok := v.Bool(); ok {
		var n uint64
		if b {
			n = 1
		}
		return protocolv4.Field{Kind: protocolv4.Boolean, Number: n}
	}
	b := v.Encoded()
	if len(b) > 0 && b[0]>>5 == 4 {
		return protocolv4.Field{Kind: protocolv4.EncodedArray, Bytes: b}
	}
	return protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: b}
}

// EncodeMap resolves field IDs from the generated schema. The fixture only
// replaces named fields in checked-in canonical templates.
func admissionMap(t *testing.T, schema string, wire []byte, changes map[string]protocolv4.Field, sources ...string) []byte {
	t.Helper()
	doc := admissionDocument(t, schema, wire, sources...)
	var registry struct {
		Maps map[string]struct {
			Fields map[string]struct{ Name string }
		} `json:"frame_maps"`
	}
	if err := json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &registry); err != nil {
		t.Fatal(err)
	}
	var fields []protocolv4.Field
	for _, spec := range registry.Maps[schema].Fields {
		field, ok := changes[spec.Name]
		if !ok {
			v := doc.Root().Named(schema, spec.Name)
			if v.Encoded() == nil {
				continue
			}
			field = admissionField(v)
		}
		field.Name = spec.Name
		fields = append(fields, field)
	}
	result, err := protocolv4.EncodeMap(make([]byte, 65536), schema, fields)
	if err != nil {
		t.Fatal(schema, err)
	}
	return bytes.Clone(result)
}

func admissionEncode(t *testing.T, schema string, fields map[string]protocolv4.Field) []byte {
	t.Helper()
	list := make([]protocolv4.Field, 0, len(fields))
	for name, f := range fields {
		f.Name = name
		list = append(list, f)
	}
	b, err := protocolv4.EncodeMap(make([]byte, 65536), schema, list)
	if err != nil {
		t.Fatal(schema, err)
	}
	return bytes.Clone(b)
}

// Public unsigned maps have no production digest escape hatch. The fixture
// derives the registry's full-map digest after constructing canonical bytes.
func admissionDigest(t *testing.T, name string, wire []byte) [32]byte {
	t.Helper()
	var domains []struct {
		Name  string
		Label string `json:"label_bytes"`
	}
	if err := json.Unmarshal([]byte(protocolv4.DomainRegistryJSON), &domains); err != nil {
		t.Fatal(err)
	}
	for _, d := range domains {
		if d.Name == name {
			label, err := hex.DecodeString(d.Label)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			h.Write(label)
			var n [4]byte
			binary.BigEndian.PutUint32(n[:], uint32(len(wire)))
			h.Write(n[:])
			h.Write(wire)
			var out [32]byte
			h.Sum(out[:0])
			return out
		}
	}
	t.Fatal("missing map domain", name)
	return [32]byte{}
}

func newSessionAdmissionTrustFixture(t *testing.T, root *resourcev4.Root, environment resourcev4.Reference, owner resourcev4.OwnerKey, sources ...string) *sessionAdmissionTrustFixture {
	t.Helper()
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	f := &sessionAdmissionTrustFixture{source: source, trust: &sessionAdmissionTrust{}}
	var tick atomic.Uint64
	f.tick = &tick
	var err error
	f.clock, err = timev4.NewClock(timev4.Profile{Rate: timev4.Rate{Denominator: 1}, MaxWidthMS: 2000, MaxAgeMS: 100000, MaxRoundTripMS: 1000}, func() (timev4.Tick, error) {
		return timev4.Tick{Milliseconds: tick.Load(), Incarnation: [16]byte{1}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.clock.Close)
	mark, err := f.clock.Monotonic()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.clock.InstallTrusted(mark, timev4.Interval{LowerMS: 1200, UpperMS: 1250}); err != nil {
		t.Fatal(err)
	}
	capacity := admissionMap(t, "NamespaceCapacity", initialFixture(t, "namespace_capacity_fields"), map[string]protocolv4.Field{"max_state_encoded_bytes": {Number: 4096}})
	capacityDigest := admissionDigest(t, "namespace_capacity_digest", capacity)
	publication := initialFixture(t, "publication_policy")
	rules, err := protocolv4.NewNamespaceRules(capacity, publication)
	if err != nil {
		t.Fatal(err)
	}
	common := func() map[string]protocolv4.Field {
		return map[string]protocolv4.Field{
			"tenant_id": admissionText("tenant-1"), "revocation_authority_id": admissionText("revocation-1"), "namespace_capacity_digest": admissionBytes(capacityDigest[:]),
			"revocation_authority_generation": {Number: 1}, "revocation_epoch": {Number: 0}, "revocation_policy_id": admissionText("online"), "revocation_policy_revision": {Number: 1},
			"issued_at_ms": {Number: 1050},
		}
	}
	seed := [32]byte{71, 23, 4}
	for role := range 2 {
		f.keys[role], err = cryptov4.GenerateDHKey(protocolv4.DHProfileX25519)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.keys[role].Close)
		signerSeed := [32]byte{byte(73 + role), 29, 8}
		f.signers[role] = bootstrapSigner{ed25519.NewKeyFromSeed(signerSeed[:])}
		dh := admissionEncode(t, "NoiseStaticPublicKey", map[string]protocolv4.Field{"algorithm": {Number: 0}, "public_key_bytes": admissionBytes(f.keys[role].PublicKey())})
		changes := common()
		changes["role"] = protocolv4.Field{Number: uint64(role)}
		changes["expires_at_ms"] = protocolv4.Field{Number: 2000}
		changes["noise_static_public_key"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: dh}
		changes["ed25519_public_key"] = admissionBytes(f.signers[role].PublicKey())
		if role == 1 {
			changes["subject_id"] = admissionText("server-1")
		}
		f.certificates[role] = initialSignTemplate(t, "IdentityCertificate", initialFixture(t, "certificate_fields"), changes, seed)
	}
	parentTemplate := initialFixture(t, "artifact_transport_fields")
	parent := admissionDocument(t, "Artifact", parentTemplate)
	candidate := parent.Root().Named("Artifact", "candidates").Index(0)
	reference := admissionEncode(t, "RevocationNamespaceRef", map[string]protocolv4.Field{"tenant_id": admissionText("tenant-1"), "revocation_authority_id": admissionText("revocation-1"), "generation": {Number: 1}, "namespace_capacity_digest": admissionBytes(capacityDigest[:]), "role_mask": {Number: 3}})
	candidateWire := admissionMap(t, "Candidate", candidate.Encoded(), map[string]protocolv4.Field{"revocation_namespace_refs": admissionArray(reference)})
	contract := admissionMap(t, "SessionContract", parent.Root().Named("Artifact", "session_contract").Encoded(), map[string]protocolv4.Field{"max_frame": {Number: 65536}, "max_streams": {Number: 4}, "max_credit": {Number: 1 << 20}, "idle_duration_ms": {Number: 1000000}})
	changes := common()
	changes["initiation_not_after_ms"] = protocolv4.Field{Number: 1500}
	changes["session_not_after_ms"] = protocolv4.Field{Number: 5000}
	changes["candidates"] = admissionArray(candidateWire)
	changes["session_contract"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: contract}
	changes["allowed_features"] = protocolv4.Field{Number: 0}
	changes["required_features"] = protocolv4.Field{Number: 0}
	for role, name := range []string{"client_identity_digest", "server_identity_digest"} {
		d, err := f.certificates[role].Digest("certificate_digest")
		if err != nil {
			t.Fatal(err)
		}
		changes[name] = admissionBytes(d[:])
	}
	f.artifact = initialSignTemplate(t, "Artifact", parentTemplate, changes, seed)
	f.session, err = f.artifact.SessionParameters()
	if err != nil {
		t.Fatal(err)
	}
	f.features, err = f.artifact.FeatureEnvelope(0, protocolv4.FeatureEnvelopePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	_, route, err := f.artifact.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := f.artifact.Field("candidates").Index(0).Named("Candidate", "candidate_id").ByteString()
	f.candidate = protocolv4.PoolMember{CandidateID: [16]byte(id), RouteDigest: route}
	changes = map[string]protocolv4.Field{"artifact_digest": admissionBytes(f.session.ArtifactDigest[:]), "candidate_selection": admissionBytes(id), "route_selection": admissionBytes(route[:]), "issued_at_ms": {Number: 1150}, "activation_not_after_ms": {Number: 1400}, "session_not_after_ms": {Number: 4000}}
	for _, pair := range [][2]string{{"tenant_id", "tenant_id"}, {"issuer_key_id", "artifact_issuer_key_id"}, {"lease_id", "lease_id"}, {"audience", "audience"}, {"client_identity_digest", "client_identity_digest"}, {"server_identity_digest", "server_identity_digest"}} {
		changes[pair[1]] = admissionField(f.artifact.Field(pair[0]))
	}
	proofTemplate := initialFixture(t, "activation_live_fields")
	if source == "preauthorized_pool" {
		proofTemplate = initialFixture(t, "activation_pool_fields")
		d := admissionDocument(t, "ActivationAuthorization", proofTemplate, source)
		ref := d.Root().Named("ActivationAuthorization", "candidate_selection")
		w, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := w.Derive(f.artifact, []uint64{0})
		if err != nil {
			t.Fatal(err)
		}
		artifactDigest, candidateDigest, routeDigest, err := selection.Digests()
		if err != nil {
			t.Fatal(err)
		}
		selection.Release()
		once := admissionMap(t, "OnceAuthorityRef", ref.Named("PoolSelectionRef", "once_authority_ref").Encoded(), map[string]protocolv4.Field{
			"tenant_id": admissionField(f.artifact.Field("tenant_id")), "artifact_issuer_key_id": admissionField(f.artifact.Field("issuer_key_id")), "winner_authority_id": admissionText("winner-1"),
		})
		selectionWire := admissionMap(t, "PoolSelectionRef", ref.Encoded(), map[string]protocolv4.Field{
			"artifact_digest": admissionBytes(artifactDigest[:]), "candidate_set_digest": admissionBytes(candidateDigest[:]),
			"candidate_indices": {Kind: protocolv4.EncodedArray, Bytes: []byte{0x81, 0}}, "once_authority_ref": {Kind: protocolv4.EncodedMap, Bytes: once},
		}, source)
		changes["candidate_selection"] = protocolv4.Field{Kind: protocolv4.EncodedMap, Bytes: selectionWire}
		changes["route_selection"] = admissionBytes(routeDigest[:])
	}
	f.proof = initialSignTemplate(t, "ActivationAuthorization", proofTemplate, changes, seed, source)
	attempt, _ := f.proof.Field("attempt_id").ByteString()
	f.attempt = [16]byte(attempt)
	workspace, err := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
	if err != nil {
		t.Fatal(err)
	}
	f.activation, err = workspace.BindActivation(f.artifact, f.proof, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	authorityID, _ := f.proof.Field("authority_id").Text()
	signingID, _ := f.proof.Field("signing_key_id").Text()
	issuer, _ := f.artifact.Field("issuer_key_id").ByteString()
	proofKey := f.proof.Key()
	signingEnd := uint64(1250)
	if source == "live_authority" {
		// Live material must leave a positive current signing window beyond
		// this fixture's independently trusted upper time bound (1250).
		signingEnd = 1350
	}
	delegation := admissionMap(t, "ConnectionActivationDelegation", initialFixture(t, "activation_delegation_fields"), map[string]protocolv4.Field{
		"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "artifact_issuer_key_id": admissionBytes(issuer), "authority_id": admissionText(authorityID), "signing_key_id": admissionText(signingID), "signer_public_key": admissionBytes(proofKey[:]),
		"signing_not_before_ms": {Number: 1100}, "signing_not_after_ms": {Number: signingEnd}, "max_activation_not_after_ms": {Number: 1400}, "max_session_not_after_ms": {Number: 4000},
	})
	once := admissionEncode(t, "OnceAuthorityRef", map[string]protocolv4.Field{"tenant_id": admissionText("tenant-1"), "artifact_issuer_key_id": admissionBytes(issuer), "spend_authority_id": admissionText(authorityID), "winner_authority_id": admissionText("winner-1")})
	f.rules, f.delegation, f.once = rules, delegation, once
	f.issueSigner = bootstrapSigner{ed25519.NewKeyFromSeed(seed[:])}
	f.authority, err = rules.BindActivationAuthority(f.activation, f.artifact, delegation, once)
	if err != nil {
		t.Fatal(err)
	}
	delegationIssuer, _ := admissionDocument(t, "ConnectionActivationDelegation", delegation).Root().Named("ConnectionActivationDelegation", "issuer_key_id").ByteString()
	f.trust.activation = protocolv4.ActivationTrustBinding{Tenant: "tenant-1", AuthorityNamespace: "revocation-1", SigningKeyID: signingID, SpendAuthority: authorityID, WinnerAuthority: "winner-1", CapacityDigest: capacityDigest, DelegationDigest: admissionDigest(t, "connection_activation_delegation_digest", delegation), Key: proofKey, ParentIssuer: [16]byte(issuer), Issuer: [16]byte(delegationIssuer), Generation: 1}
	headKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	headDelegation := admissionMap(t, "HeadSignerDelegation", initialFixture(t, "head_delegation_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_public_key": admissionBytes(headKey)})
	headDelegationDigest := admissionDigest(t, "head_signer_delegation_digest", headDelegation)
	segment := admissionEncode(t, "CohortPolicySegment", map[string]protocolv4.Field{"first_cohort": {Number: 0}, "last_cohort": {Number: 100}, "certificate_impact_ms": {Number: 1000}, "connection_impact_ms": {Number: 10000}})
	state := admissionMap(t, "RevocationState", initialFixture(t, "revocation_state_fields"), map[string]protocolv4.Field{"namespace_capacity_digest": admissionBytes(capacityDigest[:]), "revoked_issuers": admissionArray(), "revoked_certificates": admissionArray(), "revoked_leases": admissionArray(), "cohort_policy_segments": admissionArray(segment)})
	stateDigest := admissionDigest(t, "revocation_state_digest", state)
	signedHead := initialSignTemplate(t, "FreshnessHead", initialFixture(t, "freshness_head_fields"), map[string]protocolv4.Field{"credential_revocation_floors": {Kind: protocolv4.EncodedArray, Bytes: []byte{0x82, 0, 0}}, "namespace_capacity_digest": admissionBytes(capacityDigest[:]), "signer_delegation_digest": admissionBytes(headDelegationDigest[:]), "state_digest": admissionBytes(stateDigest[:]), "state_encoded_bytes": {Number: uint64(len(state))}}, seed)
	head, err := rules.BindHead(signedHead, headDelegation, 1, 900, 100000)
	if err != nil {
		t.Fatal(err)
	}
	headSigner, _ := signedHead.Field("signing_key_id").ByteString()
	f.trust.head = protocolv4.NamespaceHeadTrust{Tenant: "tenant-1", Authority: "revocation-1", Capacity: capacityDigest, Delegation: headDelegationDigest, Signer: [16]byte(headSigner), Generation: 1, TrustIssuedMS: 900, TrustNotAfterMS: 100000}
	policyWire := admissionEncode(t, "CredentialRevocationPolicy", map[string]protocolv4.Field{"revocation_policy_id": admissionText("online"), "revocation_policy_revision": {Number: 1}, "max_staleness_ms": {Number: 5000}, "max_head_signer_lifetime_ms": {Number: 59000}})
	f.trust.policy, err = protocolv4.NewCredentialPolicy(policyWire)
	if err != nil {
		t.Fatal(err)
	}
	for i, original := range []*protocolv4.SignedMap{f.artifact, f.certificates[0], f.certificates[1]} {
		detached, err := original.DetachCredential()
		if err != nil {
			t.Fatal(err)
		}
		f.trust.scopes[i] = detached.Scope()
		f.trust.permissions[i] = protocolv4.IssuerPermission{Schema: detached.Scope().Schema, Issuer: detached.Scope().Issuer, Key: original.Key(), SigningStart: 1000, SigningEnd: 1100}
	}
	allocation := protocolv4.NamespaceAllocation{Root: root}
	for i := range allocation.Owners {
		allocation.Owners[i] = admissionResourceKey(owner, uint32(i+101))
	}
	f.namespace, err = protocolv4.NewBootstrappedNamespace(context.Background(), f.clock, f.trust, protocolv4.NamespaceBootstrap{Rules: rules, Head: head, State: state}, 4000, 2, 8, allocation)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.namespace.Close(nil)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.namespace.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
		root.Close()
		if err := f.namespace.DestroyEnvironment(); err != nil {
			t.Error(err)
		}
	})
	var bindings [3]protocolv4.CredentialValidation
	for i := range bindings {
		bindings[i] = protocolv4.CredentialValidation{Namespace: f.namespace, Issuer: f.trust.permissions[i], Policy: f.trust.policy}
	}
	for role := range 2 {
		closure, err := protocolv4.BindEndpointCredentials(protocolv4.Direction(role), f.artifact, 0, f.certificates[0], f.certificates[1], nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		reservation, err := root.Reserve(admissionResourceKey(owner, uint32(role+111)), protocolv4.CredentialSubscriptionsCharge())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(reservation.Release)
		f.subscriptions[role], err = closure.Subscribe(bindings[:], 5000, reservation)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.subscriptions[role].Close)
		if _, err = f.subscriptions[role].CheckOriginalFor(environment, f.session, protocolv4.Direction(role), f.candidate); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestSessionAdmissionTrustFixtureChecksOriginalMaterials(t *testing.T) {
	limit := resourcev4.Vector{}
	for i := range limit {
		limit[i] = 1 << 30
	}
	root, err := resourcev4.NewRoot(resourcev4.Config{ProfileRevision: [32]byte{1}, Limit: limit, AccountSlots: 8, ReservationSlots: 128, ReferenceSlots: 512})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Close)
	owner := resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{83}, Backing: [16]byte{1}, Kind: 83}
	environment, err := root.Reserve(owner, resourcev4.Vector{resourcev4.SDKBytes: 1, resourcev4.Items: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(environment.Release)
	f := newSessionAdmissionTrustFixture(t, root, environment, owner)
	if err := f.authority.MatchOriginal(f.session, f.attempt, f.candidate); err != nil {
		t.Fatal(err)
	}
	var authorization [2]*protocolv4.EndpointAuthorization
	for role := range 2 {
		a, err := protocolv4.NewEndpointAuthorization(f.subscriptions[role], f.authority)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close(nil) })
		if err := a.Check(); err != nil {
			t.Fatal(err)
		}
		authorization[role] = a
	}
	f.trust.rejected.Store(true)
	f.namespace.NotifyTrust()
	for _, a := range authorization {
		if err := a.Check(); err == nil {
			t.Fatal("independent trust rejection did not close the live gate")
		}
	}
}

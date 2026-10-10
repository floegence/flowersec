// Engineering authority helpers sign current canonical credentials and assemble
// original trust and durable admission owners. They never provide a handshake,
// READY result, stream, or authorization success to a peer.
package sessionv4

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// AuthorityReporter allows explicit engineering peers and tests to share only
// credential construction. A peer reporter must terminate construction on Fatal.
type AuthorityReporter interface {
	Helper()
	Fatal(...any)
	Error(...any)
	Cleanup(func())
	TempDir() string
}

// This fixture composes public protocol APIs with exact independently pinned
// test trust entries. It does not bypass the production authorization owner.
type sessionAdmissionTrustFixture struct {
	rules                  *protocolv4.NamespaceRules
	delegation, once       []byte
	issueSigner            bootstrapSigner
	activationSigningKeyID string
	source                 string
	artifact, proof        *protocolv4.SignedMap
	certificates           [2]*protocolv4.SignedMap
	activation             *protocolv4.ActivationBinding
	authority              *protocolv4.ActivationAuthority
	subscriptions          [2]*protocolv4.CredentialSubscriptions
	features               protocolv4.FeatureEnvelope
	session                protocolv4.ArtifactSessionParameters
	candidate              protocolv4.PoolMember
	attempt                [16]byte
	clock                  *timev4.Clock
	tick                   *atomic.Uint64
	namespace              *protocolv4.LiveNamespace
	trust                  *sessionAdmissionTrust
	keys                   [2]*cryptov4.DHKey
	signers                [2]bootstrapSigner
}

type sessionAdmissionTrust struct {
	rejected          atomic.Bool
	head              protocolv4.NamespaceHeadTrust
	activation        protocolv4.ActivationTrustBinding
	additional        []engineeringCredentialAuthority
	permissions       [3]protocolv4.IssuerPermission
	scopes            [3]protocolv4.CredentialScope
	policy            *protocolv4.CredentialPolicy
	preparationPolicy atomic.Pointer[protocolv4.CredentialPolicy]
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
		for _, entry := range s.additional {
			if p == entry.permission && c == entry.scope {
				return nil
			}
		}
	}
	return protocolv4.CBORFailure("independent_trust_rejected")
}
func (s *sessionAdmissionTrust) Policy(p *protocolv4.CredentialPolicy) error {
	if s.rejected.Load() || p != s.policy && p != s.preparationPolicy.Load() {
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

func admissionDocument(t AuthorityReporter, schema string, wire []byte, sources ...string) *protocolv4.Document {
	doc := admissionOwnedDocument(t, schema, wire, sources...)
	t.Cleanup(doc.Release)
	return doc
}

// admissionOwnedDocument is released by its synchronous caller. It keeps
// temporary rewrite/planning decoders out of the authority's cleanup graph.
func admissionOwnedDocument(t AuthorityReporter, schema string, wire []byte, sources ...string) *protocolv4.Document {
	t.Helper()
	// This authority owns the complete input already. Reserve its actual
	// encoded size while retaining the original maximum byte/node limits.
	d, err := protocolv4.NewDecoder(min(len(wire), 65536), min(len(wire), 4096))
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

// Generated registry metadata is immutable. Each authority still decodes,
// rewrites and signs private credential bytes for its own original owner.
type authorityFieldRegistry struct {
	Maps map[string]struct {
		Fields map[string]struct{ Name, Type string }
	} `json:"frame_maps"`
}

var authorityRegistry = sync.OnceValues(func() (authorityFieldRegistry, error) {
	var registry authorityFieldRegistry
	err := json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &registry)
	return registry, err
})

// EncodeMap resolves field IDs from the generated schema. The fixture only
// replaces named fields in checked-in canonical templates.
func admissionMap(t AuthorityReporter, schema string, wire []byte, changes map[string]protocolv4.Field, sources ...string) []byte {
	t.Helper()
	doc := admissionOwnedDocument(t, schema, wire, sources...)
	defer doc.Release()
	registry, err := authorityRegistry()
	if err != nil {
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
	result, err := protocolv4.EncodeMap(make([]byte, 65536), schema, authorityFields(t, schema, fields))
	if err != nil {
		t.Fatal(schema, err)
	}
	return bytes.Clone(result)
}

func admissionEncode(t AuthorityReporter, schema string, fields map[string]protocolv4.Field) []byte {
	t.Helper()
	list := make([]protocolv4.Field, 0, len(fields))
	for name, f := range fields {
		f.Name = name
		list = append(list, f)
	}
	b, err := protocolv4.EncodeMap(make([]byte, 65536), schema, authorityFields(t, schema, list))
	if err != nil {
		t.Fatal(schema, err)
	}
	return bytes.Clone(b)
}

// Public unsigned maps have no production digest escape hatch. The fixture
// derives the registry's full-map digest after constructing canonical bytes.
func admissionDigest(t AuthorityReporter, name string, wire []byte) [32]byte {
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

func newSessionAdmissionTrustFixture(t AuthorityReporter, root *resourcev4.Root, environment resourcev4.Reference, owner resourcev4.OwnerKey, sources ...string) *sessionAdmissionTrustFixture {
	t.Helper()
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	return newSessionAdmissionTrustProfile(t, root, environment, owner, source, "transport")
}

func newSessionAdmissionTrustProfile(t AuthorityReporter, root *resourcev4.Root, environment resourcev4.Reference, owner resourcev4.OwnerKey, source, application string, clocks ...*timev4.Clock) *sessionAdmissionTrustFixture {
	t.Helper()
	f := &sessionAdmissionTrustFixture{source: source, trust: &sessionAdmissionTrust{}}
	// The fixture owns these detached Ed25519 slices. Register before maps and
	// live plans so no original signing callback can outlive their key material.
	t.Cleanup(func() {
		clear(f.issueSigner.key)
		f.issueSigner.key = nil
		for role := range f.signers {
			clear(f.signers[role].key)
			f.signers[role].key = nil
		}
		f.session = protocolv4.ArtifactSessionParameters{}
	})
	var tick atomic.Uint64
	f.tick = &tick
	var err error
	if len(clocks) == 1 {
		f.clock = clocks[0]
	} else {
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
		if engineeringOriginalLive(t) {
			if _, err = rand.Read(signerSeed[:]); err != nil {
				t.Fatal(err)
			}
		}
		f.signers[role] = bootstrapSigner{ed25519.NewKeyFromSeed(signerSeed[:])}
		clear(signerSeed[:])
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
	parent := admissionOwnedDocument(t, "Artifact", parentTemplate)
	defer parent.Release()
	candidate := parent.Root().Named("Artifact", "candidates").Index(0)
	reference := admissionEncode(t, "RevocationNamespaceRef", map[string]protocolv4.Field{"tenant_id": admissionText("tenant-1"), "revocation_authority_id": admissionText("revocation-1"), "generation": {Number: 1}, "namespace_capacity_digest": admissionBytes(capacityDigest[:]), "role_mask": {Number: 3}})
	candidateWire := admissionMap(t, "Candidate", candidate.Encoded(), map[string]protocolv4.Field{"revocation_namespace_refs": admissionArray(reference)})
	contract := engineeringSessionContract(t, parent.Root().Named("Artifact", "session_contract").Encoded(), application)
	changes := common()
	if engineeringOriginalLive(t) {
		var psk, nonce [32]byte
		defer clear(psk[:])
		defer clear(nonce[:])
		if _, err = rand.Read(psk[:]); err != nil {
			t.Fatal(err)
		}
		if _, err = rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		changes["e2ee_psk"] = admissionBytes(psk[:])
		changes["session_nonce"] = admissionBytes(nonce[:])
		changes["issued_at_ms"] = protocolv4.Field{Number: 1200}
		// The pending live Artifact is issued in the current cohort, while the
		// independently installed identity certificates retain their own cohort.
		capacityFields := admissionDocument(t, "NamespaceCapacity", capacity).Root()
		origin, _ := capacityFields.Named("NamespaceCapacity", "cohort_time_origin_ms").Uint()
		duration, _ := capacityFields.Named("NamespaceCapacity", "cohort_duration_ms").Uint()
		changes["revocation_epoch"] = protocolv4.Field{Number: (authorityTime(t, 1200) - origin) / duration}
		contract = admissionMap(t, "SessionContract", contract, map[string]protocolv4.Field{"max_frame": {Number: 65528}})
	}
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
		d := admissionOwnedDocument(t, "ActivationAuthorization", proofTemplate, source)
		defer d.Release()
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
	var authorityID, signingID string
	var proofKey [32]byte
	if engineeringOriginalLive(t) {
		// Read policy declarations directly. Pending source installation never
		// creates or binds an ActivationAuthorization, including a fixture proof.
		declared := admissionDocument(t, "ConnectionActivationDelegation", initialFixture(t, "activation_delegation_fields"))
		authorityID, _ = declared.Root().Named("ConnectionActivationDelegation", "authority_id").Text()
		signingID, _ = declared.Root().Named("ConnectionActivationDelegation", "signing_key_id").Text()
		var activationSeed [32]byte
		defer clear(activationSeed[:])
		if _, err = rand.Read(activationSeed[:]); err != nil {
			t.Fatal(err)
		}
		f.issueSigner = bootstrapSigner{ed25519.NewKeyFromSeed(activationSeed[:])}
		copy(proofKey[:], f.issueSigner.PublicKey())
		if owner, ok := t.(EngineeringAuthorityIdentity); ok {
			f.attempt = owner.AuthorityAttemptID()
		}
	} else {
		f.proof = initialSignTemplate(t, "ActivationAuthorization", proofTemplate, changes, seed, source)
		attempt, _ := f.proof.Field("attempt_id").ByteString()
		f.attempt = [16]byte(attempt)
		workspace, e := protocolv4.NewPoolSelectionWorkspace(65536, 4096)
		if e != nil {
			t.Fatal(e)
		}
		f.activation, err = workspace.BindActivation(f.artifact, f.proof, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		authorityID, _ = f.proof.Field("authority_id").Text()
		signingID, _ = f.proof.Field("signing_key_id").Text()
		proofKey = f.proof.Key()
	}
	f.activationSigningKeyID = signingID
	issuer, _ := f.artifact.Field("issuer_key_id").ByteString()
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
	if !engineeringOriginalLive(t) {
		f.issueSigner = bootstrapSigner{ed25519.NewKeyFromSeed(seed[:])}
	}
	if !engineeringOriginalLive(t) {
		f.authority, err = rules.BindActivationAuthority(f.activation, f.artifact, delegation, once)
		if err != nil {
			t.Fatal(err)
		}
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
	head, err := rules.BindHead(signedHead, headDelegation, 1, authorityTime(t, 900), authorityTime(t, 100000))
	if err != nil {
		t.Fatal(err)
	}
	headSigner, _ := signedHead.Field("signing_key_id").ByteString()
	f.trust.head = protocolv4.NamespaceHeadTrust{Tenant: "tenant-1", Authority: "revocation-1", Capacity: capacityDigest, Delegation: headDelegationDigest, Signer: [16]byte(headSigner), Generation: 1, TrustIssuedMS: authorityTime(t, 900), TrustNotAfterMS: authorityTime(t, 100000)}
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
		f.trust.permissions[i] = protocolv4.IssuerPermission{Schema: detached.Scope().Schema, Issuer: detached.Scope().Issuer, Key: original.Key(), SigningStart: authorityTime(t, 1000), SigningEnd: authorityTime(t, 1100)}
		if engineeringOriginalLive(t) {
			f.trust.permissions[i].SigningEnd = authorityTime(t, 4000)
		}
	}
	allocation := protocolv4.NamespaceAllocation{Root: root}
	for i := range allocation.Owners {
		allocation.Owners[i] = admissionResourceKey(owner, uint32(i+101))
	}
	f.namespace, err = protocolv4.NewBootstrappedNamespace(context.Background(), f.clock, f.trust, protocolv4.NamespaceBootstrap{Rules: rules, Head: head, State: state}, authorityDuration(t, 4000), 2, 8, allocation)
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
		f.subscriptions[role], err = closure.Subscribe(bindings[:], authorityTime(t, 5000), reservation)
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

func initialSignTemplate(t AuthorityReporter, schema string, wire []byte, changes map[string]protocolv4.Field, seed [32]byte, sources ...string) *protocolv4.SignedMap {
	t.Helper()
	d, err := protocolv4.NewDecoder(min(len(wire), 65536), min(len(wire), 4096))
	if err != nil {
		t.Fatal(err)
	}
	source := "live_authority"
	if len(sources) > 0 {
		source = sources[0]
	}
	context := protocolv4.DecodeContext{Selectors: map[string]string{"activation_source_profile": source}}
	doc, err := d.DecodeShape(wire, schema, context)
	if err != nil {
		t.Fatal(schema, err)
	}
	defer doc.Release()
	registry, err := authorityRegistry()
	if err != nil {
		t.Fatal(err)
	}
	var fields []protocolv4.Field
	var signatureName string
	for _, spec := range registry.Maps[schema].Fields {
		if spec.Name == "signature" || spec.Name == "client_signature" || spec.Name == "server_signature" {
			signatureName = spec.Name
			continue
		}
		if replacement, ok := changes[spec.Name]; ok {
			replacement.Name = spec.Name
			fields = append(fields, replacement)
			continue
		}
		v := doc.Root().Named(schema, spec.Name)
		if v.Encoded() == nil {
			continue
		}
		f := protocolv4.Field{Name: spec.Name}
		switch spec.Type {
		case "bytes":
			f.Kind = protocolv4.ByteString
			f.Bytes, _ = v.ByteString()
		case "text":
			f.Kind = protocolv4.TextString
			f.Text, _ = v.Text()
		case "map":
			f.Kind = protocolv4.EncodedMap
			f.Bytes = v.Encoded()
		case "array":
			f.Kind = protocolv4.EncodedArray
			f.Bytes = v.Encoded()
		case "bool":
			f.Kind = protocolv4.Boolean
			b, _ := v.Bool()
			if b {
				f.Number = 1
			}
		default:
			if b, ok := v.ByteString(); ok {
				f.Kind = protocolv4.ByteString
				f.Bytes = b
			} else if encoded := v.Encoded(); len(encoded) > 0 && encoded[0]>>5 == 5 {
				f.Kind, f.Bytes = protocolv4.EncodedMap, encoded
			} else {
				f.Number, _ = v.Uint()
			}
		}
		fields = append(fields, f)
	}
	fields = authorityFields(t, schema, fields)
	// Measure the final canonical map with its fixed Ed25519 signature field.
	// Fresh signing and verification still use the original production codec;
	// a small credential needs no maximum-size normalization workspace.
	var signature [ed25519.SignatureSize]byte
	sized := append(append([]protocolv4.Field(nil), fields...), protocolv4.Field{Name: signatureName, Kind: protocolv4.ByteString, Bytes: signature[:]})
	encoded, err := protocolv4.EncodeMap(make([]byte, 65536), schema, sized)
	if err != nil {
		t.Fatal(schema, err)
	}
	codec, err := protocolv4.NewOnceSigningMapCodec(schema, len(encoded), min(len(encoded), 4096))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := codec.Sign(fields, seed, context)
	if err != nil {
		t.Fatal(schema, err)
	}
	t.Cleanup(signed.Release)
	return signed
}

type bootstrapSigner struct{ key ed25519.PrivateKey }

func (s bootstrapSigner) PublicKey() []byte { return s.key.Public().(ed25519.PublicKey) }

func (s bootstrapSigner) Sign(p []byte) ([]byte, error) { return ed25519.Sign(s.key, p), nil }

func corePlanTestScope(t AuthorityReporter, root *resourcev4.Root, limit resourcev4.Vector, sessionID byte) SessionResourceScope {
	return engineeringScope(t, root, limit, limit, sessionID)
}

func engineeringScope(t AuthorityReporter, root *resourcev4.Root, tenantLimit, sessionLimit resourcev4.Vector, sessionID byte) SessionResourceScope {
	t.Helper()
	tenant, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.TenantAccount, ID: [16]byte{1}}, tenantLimit)
	if err != nil {
		t.Fatal(err)
	}
	sessionLimit[resourcev4.Sessions] = 1
	session, err := root.Account(resourcev4.AccountKey{Kind: resourcev4.SessionAccount, ID: [16]byte{sessionID}}, sessionLimit)
	if err != nil {
		t.Fatal(err)
	}
	return SessionResourceScope{Tenant: tenant, Session: session}
}

func openResourceLimits() OpenLimits {
	return OpenLimits{Active: 2, Opening: 2, Terminal: 6, RejectionReserve: 1, IngressItems: 2, IngressBytes: 64 << 10,
		PerClass: [3]uint32{2}, PerOpener: [2][3]uint32{{2}, {2}}, Lifetime: [2][3]uint64{{1024}, {1024}}}
}

func factoryStreamConfig() SessionStreamConfig {
	return SessionStreamConfig{ReceivePoolBytes: 128, ReceiveBytes: 64, InitialReceiveLimit: 64,
		SendBytes: 64, QueueBytes: 64, WriteWaiters: 2, MaxPlaintext: 128, Chunk: 64, RuntimeBytes: 16384}
}

type acceptedSQLiteAuthority struct {
	identity ledgerv4.SQLiteIdentity
	facts    protocolv4.AdmissionFacts
	parent   *ledgerv4.SQLiteStore
}

func (a acceptedSQLiteAuthority) Check(identity ledgerv4.SQLiteIdentity, epoch uint64, create bool) error {
	if identity != a.identity || create && epoch != 0 {
		return ledgerv4.ErrFenced
	}
	return nil
}

func (a acceptedSQLiteAuthority) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	want, _ := a.facts.Fields()
	actual, err := facts.Fields()
	if err != nil || identity != a.identity || want.Tenant != actual.Tenant || want.Issuer != actual.Issuer || want.ServerIdentity != actual.ServerIdentity || want.Audience != actual.Audience {
		return ledgerv4.ErrFenced
	}
	return nil
}

func (a acceptedSQLiteAuthority) ParentWinnerStore() *ledgerv4.SQLiteStore { return a.parent }

func (a acceptedSQLiteAuthority) CheckParentWinner(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	want, _ := a.facts.Fields()
	actual, err := facts.Fields()
	if err != nil || actual.WinnerAuthority == "" || actual.WinnerAuthority != want.WinnerAuthority {
		return ledgerv4.ErrFenced
	}
	return a.CheckAdmission(identity, facts)
}

type poolSQLiteAuthority struct {
	acceptedSQLiteAuthority
	original      protocolv4.PoolSpendFields
	admissionGate chan struct{}
}

// ScheduleAdmission serializes only the original TxA-P and its local activation
// continuation. Independent imported materials retain this same deployment
// token; each wait keeps its own context, deadline and admission guard.
func (a poolSQLiteAuthority) ScheduleAdmission(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ledgerv4.ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, context.Cause(ctx)
	}
	if a.admissionGate == nil {
		return func() {}, nil
	}
	schedule, ok := ctx.(sqliteAdmissionScheduleContext)
	if !ok || schedule.deadline == nil || schedule.guard == nil {
		return nil, ledgerv4.ErrConfiguration
	}
	if err := schedule.guard(); err != nil {
		return nil, err
	}
	remaining, err := schedule.deadline.RemainingMS()
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(time.Duration(min(remaining, uint64((1<<63-1)/int64(time.Millisecond)))) * time.Millisecond)
	defer timer.Stop()
	release := func() { <-a.admissionGate }
	for {
		select {
		case a.admissionGate <- struct{}{}:
			if err := schedule.guard(); err != nil {
				release()
				return nil, err
			}
			return release, nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		case <-schedule.wake:
			if err := schedule.guard(); err != nil {
				return nil, err
			}
		case <-timer.C:
			if err := schedule.guard(); err != nil {
				return nil, err
			}
			remaining, err = schedule.deadline.RemainingMS()
			if err != nil {
				return nil, err
			}
			timer.Reset(time.Duration(min(remaining, uint64((1<<63-1)/int64(time.Millisecond)))) * time.Millisecond)
		}
	}
}

func (a poolSQLiteAuthority) CheckPoolSpend(i ledgerv4.SQLiteIdentity, f protocolv4.PoolSpendFacts) error {
	fields, err := f.Fields()
	if err != nil || i != a.identity {
		return ledgerv4.ErrConflict
	}
	// The signed Artifact fixes the finite candidate set. The activation
	// verifier has already checked the selected member against that set; the
	// local spend authority therefore compares the common immutable projection
	// while allowing the one actual winner to vary across racing candidates.
	fields.Winner = a.original.Winner
	if fields != a.original {
		return ledgerv4.ErrConflict
	}
	return nil
}

type liveSQLiteAuthority struct {
	acceptedSQLiteAuthority
	original protocolv4.LiveActivationFields
}

func (a liveSQLiteAuthority) CheckLiveSpend(identity ledgerv4.SQLiteIdentity, fields protocolv4.LiveActivationFields) error {
	if identity != a.identity || fields != a.original {
		return ledgerv4.ErrConflict
	}
	return nil
}

func (p poolSQLiteAuthority) CheckAdmission(i ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	f, err := facts.Fields()
	if err != nil || i != p.identity || f.Tenant != p.original.Tenant || f.Issuer != p.original.Issuer || f.ServerIdentity != p.original.ServerIdentity || f.Audience != p.original.Audience {
		return ledgerv4.ErrConflict
	}
	return nil
}

// Fixture lookup shares only immutable template text. Each call decodes into
// private bytes before applying its authority's time, identity and signatures.
func initialFixture(t AuthorityReporter, id string) []byte {
	t.Helper()
	templates := engineeringTemplates
	if _, engineering := t.(EngineeringAuthorityTime); !engineering {
		var err error
		templates, err = standardFixtureTemplates()
		if err != nil {
			t.Fatal(err)
		}
	}
	encoded, ok := templates[id]
	if !ok {
		t.Fatal("missing fixture", id)
	}
	wire, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if id == "publication_policy" {
		return admissionMap(t, "PublicationPolicy", wire, nil)
	}
	return wire
}

var standardFixtureTemplates = sync.OnceValues(func() (map[string]string, error) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		return nil, err
	}
	var corpus struct{ Vectors []struct{ ID, Hex string } }
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return nil, err
	}
	templates := make(map[string]string, len(corpus.Vectors))
	for _, vector := range corpus.Vectors {
		if _, exists := templates[vector.ID]; !exists {
			templates[vector.ID] = vector.Hex
		}
	}
	return templates, nil
})

func (p poolSQLiteAuthority) CheckParentWinner(i ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	f, err := facts.Fields()
	if err != nil || f.WinnerAuthority == "" || f.WinnerAuthority != p.original.WinnerAuthority {
		return ledgerv4.ErrConflict
	}
	return p.CheckAdmission(i, facts)
}

func (a liveSQLiteAuthority) CheckAdmission(identity ledgerv4.SQLiteIdentity, facts protocolv4.AdmissionFacts) error {
	f, err := facts.Fields()
	if err != nil || identity != a.identity || f.Tenant != a.original.Tenant || f.Issuer != a.original.Issuer || f.ServerIdentity != a.original.ServerIdentity || f.Audience != a.original.Audience {
		return ledgerv4.ErrConflict
	}
	return nil
}

// EngineeringServiceContract changes only explicit local service fields in the
// shared current canonical contract templates. It provides no execution grant;
// the ordinary SessionPlan lease still grants each registered method separately.
func EngineeringServiceContract(t AuthorityReporter, namespace string, typeID uint32, notify bool) ([]byte, protocolv4.ServiceContractPolicy) {
	return EngineeringServiceContractWithLimit(t, namespace, typeID, notify, 4096)
}
func EngineeringServiceContractWithLimit(t AuthorityReporter, namespace string, typeID uint32, notify bool, maximum uint32) ([]byte, protocolv4.ServiceContractPolicy) {
	if maximum == 0 || maximum > 1<<20 {
		t.Fatal("engineering service codec exceeds its finite declared bound")
	}
	template := "service_unary_transient"
	if notify {
		template = "service_notify_observation"
	}
	fields := map[string]protocolv4.Field{"service_namespace": admissionText(namespace), "type_id": {Number: uint64(typeID)}, "request_max_bytes": {Number: uint64(maximum)}, "max_message_lifetime_ms": {Number: 30000}}
	if !notify {
		fields["max_response_bytes"] = protocolv4.Field{Number: uint64(maximum)}
		fields["max_transient_run_ms"] = protocolv4.Field{Number: 30000}
	}
	wire := admissionMap(t, "ServiceContract", initialFixture(t, template), fields)
	codec, err := protocolv4.NewServiceContractCodec(256)
	if err != nil {
		t.Fatal(err)
	}
	contract, err := codec.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer contract.Release()
	policy, err := contract.Policy()
	if err != nil {
		t.Fatal(err)
	}
	return wire, policy
}

// engineeringSessionContract is the original authority recipe shared with local
// capacity planning. Its unsigned geometry never supplies admission authority.
func engineeringSessionContract(t AuthorityReporter, template []byte, application string) []byte {
	contractFields := map[string]protocolv4.Field{"max_frame": {Number: 65536}, "max_streams": {Number: 4}, "max_credit": {Number: 1 << 20}, "idle_duration_ms": {Number: 1000000}}
	if application != "transport" {
		value, err := protocolv4.EnumValue("SessionContract", "application_profile", application)
		if err != nil {
			t.Fatal(err)
		}
		contractFields["application_profile"] = protocolv4.Field{Number: value}
		contractFields["max_streams"] = protocolv4.Field{Number: 16}
		contractFields["rpc_max_general_outstanding"] = protocolv4.Field{Number: 32}
	}
	if capacity, enabled := t.(EngineeringStreamCapacity); enabled && capacity.AuthorityMaxStreams() != 0 {
		maximum := capacity.AuthorityMaxStreams()
		if maximum > 139 {
			t.Fatal("engineering active capacity exceeds the fixed provider envelope")
		}
		contractFields["max_streams"] = protocolv4.Field{Number: uint64(maximum)}
		contractFields["max_credit"] = protocolv4.Field{Number: max(uint64(1<<20), uint64(maximum)*engineeringInitialReceiveLimit)}
	}
	return admissionMap(t, "SessionContract", template, contractFields)
}

package sessionv4

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// EngineeringTunnelRecipe is explicit authority input. Route is the complete
// canonical two-leg route; the relay identity and finite forwarding policy are
// independent of the endpoint identities and the Artifact's stream geometry.
// It contains no claim, publication, admission, or transport success evidence.
type EngineeringTunnelRecipe struct {
	Route                       []byte
	RelaySubject, RelayAudience string
	RelayIdentitySeed           [32]byte
	GrantIssuerID               [16]byte
	GrantIssuerSeed             [32]byte
	Limits                      [2]protocolv4.RelayGrantLimits
}

type EngineeringTunnelAuthority interface {
	AuthorityTunnelRecipe() *EngineeringTunnelRecipe
}

type PublicTunnelAuthority struct {
	RelayCertificate []byte
	RelaySigner      cryptov4.IdentitySigner
	Grants           [2][]byte
	Limits           [2]protocolv4.RelayGrantLimits
}

type engineeringCredentialAuthority struct {
	scope      protocolv4.CredentialScope
	permission protocolv4.IssuerPermission
}

type engineeringTunnelMaterials struct {
	recipe EngineeringTunnelRecipe
	relay  *protocolv4.SignedMap
	grants [2]*protocolv4.SignedMap
	signer bootstrapSigner
}

func engineeringTunnelCandidate(t AuthorityReporter, f *authorityFixture, recipe *EngineeringTunnelRecipe, profileID string) ([]byte, *engineeringTunnelMaterials) {
	if recipe == nil || len(recipe.Route) == 0 || recipe.RelaySubject == "" || recipe.RelayAudience == "" || recipe.RelayIdentitySeed == ([32]byte{}) || recipe.GrantIssuerID == ([16]byte{}) || recipe.GrantIssuerSeed == ([32]byte{}) {
		t.Fatal("engineering tunnel requires an explicit route, relay identity and grant issuer")
	}
	route := admissionDocument(t, "Route", recipe.Route).Root()
	kind, ok := route.Named("Route", "path_kind").Uint()
	if !ok || kind != 1 {
		t.Fatal("engineering tunnel requires an original two-leg route")
	}
	id, ok := route.Named("Route", "candidate_id").ByteString()
	if !ok || len(id) != 16 {
		t.Fatal("engineering tunnel candidate identity is missing")
	}
	template := f.trust.artifact.Field("candidates").Index(0)
	refs := template.Named("Candidate", "revocation_namespace_refs").Encoded()
	if engineeringOriginalPool(t) || engineeringOriginalLive(t) {
		reference := template.Named("Candidate", "revocation_namespace_refs").Index(0)
		ref := admissionMap(t, "RevocationNamespaceRef", reference.Encoded(), map[string]protocolv4.Field{"role_mask": {Number: 7}})
		refs = admissionArray(ref).Bytes
	}
	candidate := admissionEncode(t, "Candidate", map[string]protocolv4.Field{
		"candidate_id": admissionBytes(id), "priority": {}, "path_kind": {Number: 1},
		"client_leg":                {Kind: protocolv4.EncodedMap, Bytes: route.Named("Route", "client_leg").Encoded()},
		"server_leg":                {Kind: protocolv4.EncodedMap, Bytes: route.Named("Route", "server_leg").Encoded()},
		"revocation_namespace_refs": {Kind: protocolv4.EncodedArray, Bytes: refs},
	})
	m := &engineeringTunnelMaterials{recipe: *recipe, signer: bootstrapSigner{ed25519.NewKeyFromSeed(recipe.RelayIdentitySeed[:])}}
	m.recipe.Route = append([]byte(nil), recipe.Route...)
	t.Cleanup(func() {
		clear(m.recipe.RelayIdentitySeed[:])
		clear(m.recipe.GrantIssuerSeed[:])
		clear(m.signer.key)
		m.signer.key = nil
	})
	dh, err := cryptov4.GenerateDHKey(profileID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dh.Close)
	profile, err := protocolv4.Profile(profileID)
	if err != nil {
		t.Fatal(err)
	}
	noise := admissionEncode(t, "NoiseStaticPublicKey", map[string]protocolv4.Field{
		"algorithm": {Number: uint64(profile.DHAlgorithm)}, "public_key_bytes": admissionBytes(dh.PublicKey()),
	})
	certificate, err := f.trust.certificates[1].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	m.relay = initialSignTemplate(t, "IdentityCertificate", certificate, map[string]protocolv4.Field{
		"subject_id": admissionText(recipe.RelaySubject), "role": {Number: 2}, "audience": admissionText(recipe.RelayAudience),
		"ed25519_public_key": admissionBytes(m.signer.PublicKey()), "noise_static_public_key": {Kind: protocolv4.EncodedMap, Bytes: noise},
	}, [32]byte{71, 23, 4})
	engineeringAddCredentialAuthority(t, f, m.relay)
	return candidate, m
}

func engineeringAddCredentialAuthority(t AuthorityReporter, f *authorityFixture, signed *protocolv4.SignedMap) {
	credential, err := signed.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	scope := credential.Scope()
	f.trust.trust.additional = append(f.trust.trust.additional, engineeringCredentialAuthority{
		scope: scope, permission: protocolv4.IssuerPermission{Schema: scope.Schema, Issuer: scope.Issuer, Key: signed.Key(), SigningStart: scope.IssuedMS, SigningEnd: scope.IssuedMS + 1},
	})
}

// The paired grants bind the original signed parent, activation, route and
// complete identities. These signatures do not publish relay authority; only
// the original issuer outbox and its committed publication can do that.
func engineeringIssueTunnelGrants(t AuthorityReporter, f *authorityFixture, m *engineeringTunnelMaterials) {
	parent, err := f.trust.artifact.DetachCredential()
	if err != nil {
		t.Fatal(err)
	}
	p := parent.Scope()
	artifact := f.trust.artifact
	scalar := func(name string) protocolv4.Field { return admissionField(artifact.Field(name)) }
	parentRef := admissionEncode(t, "GrantParentRef", map[string]protocolv4.Field{
		"tenant_id": admissionText(p.Tenant), "revocation_authority_id": admissionText(p.Authority),
		"authority_generation": {Number: p.Generation}, "namespace_capacity_digest": admissionBytes(p.CapacityDigest[:]),
		"revocation_policy_id": scalar("revocation_policy_id"), "revocation_policy_revision": scalar("revocation_policy_revision"),
		"artifact_issuer_key_id": admissionBytes(p.Issuer[:]), "lease_id": scalar("lease_id"), "revocation_epoch": {Number: p.Cohort},
		"issued_at_ms": {Number: p.IssuedMS}, "initiation_not_after_ms": scalar("initiation_not_after_ms"),
		"session_not_after_ms": {Number: p.ExpiresMS}, "artifact_digest": admissionBytes(f.trust.session.ArtifactDigest[:]),
	})
	route, routeDigest, err := artifact.CopyCandidateRoute(0, make([]byte, 16384))
	if err != nil {
		t.Fatal(err)
	}
	routeValue := admissionDocument(t, "Route", route).Root()
	legs := [2][]byte{}
	for role, name := range []string{"client_leg", "server_leg"} {
		legID, ok := routeValue.Named("Route", name).Named("Leg", "leg_id").ByteString()
		if !ok || len(legID) != 16 {
			t.Fatal("engineering tunnel leg identity is missing")
		}
		legs[role] = admissionEncode(t, "GrantLegRef", map[string]protocolv4.Field{"leg_id": admissionBytes(legID), "logical_role": {Number: uint64(role)}})
	}
	identities := [2][]byte{}
	for role := range 2 {
		digest, err := f.trust.certificates[role].Digest("certificate_digest")
		if err != nil {
			t.Fatal(err)
		}
		identities[role] = append([]byte{0x58, 32}, digest[:]...)
	}
	relayDigest, err := m.relay.Digest("certificate_digest")
	if err != nil {
		t.Fatal(err)
	}
	contractDigest := admissionDigest(t, "session_contract_digest", artifact.Field("session_contract").Encoded())
	var pairing [16]byte
	if _, err := rand.Read(pairing[:]); err != nil {
		t.Fatal(err)
	}
	if pairing == ([16]byte{}) {
		t.Fatal("engineering tunnel pairing entropy is unavailable")
	}
	issued, ok := f.trust.proof.Field("issued_at_ms").Uint()
	if !ok {
		t.Fatal("engineering tunnel activation issue time is missing")
	}
	end, ok := f.trust.proof.Field("activation_not_after_ms").Uint()
	if !ok {
		t.Fatal("engineering tunnel activation deadline is missing")
	}
	for role := range 2 {
		var id [16]byte
		var nonce [32]byte
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		if id == ([16]byte{}) || nonce == ([32]byte{}) {
			t.Fatal("engineering tunnel grant entropy is unavailable")
		}
		namespace := admissionEncode(t, "GrantNamespace", map[string]protocolv4.Field{
			"tenant_id": admissionText(p.Tenant), "revocation_authority_id": admissionText(p.Authority), "generation": {Number: p.Generation},
			"namespace_capacity_digest": admissionBytes(p.CapacityDigest[:]), "role_mask": {Number: 5 + uint64(role)}, "revocation_epoch": {Number: p.Cohort},
			"revocation_policy_id": scalar("revocation_policy_id"), "revocation_policy_revision": scalar("revocation_policy_revision"),
		})
		policy := m.recipe.Limits[role]
		envelope := uint64(f.trust.session.Contract.Limits().MaxFrame) + uint64(protocolv4.EnvelopePrefixSize)
		if policy.EnvelopeBytes != 0 && policy.EnvelopeBytes != envelope {
			t.Fatal("engineering relay envelope must match the signed Session contract")
		}
		policy.EnvelopeBytes = envelope
		m.recipe.Limits[role] = policy
		limits := admissionEncode(t, "GrantLimits", map[string]protocolv4.Field{
			"max_envelope_bytes": {Number: policy.EnvelopeBytes}, "max_total_bytes": {Number: policy.TotalBytes}, "max_datagram_bytes": {Number: policy.DatagramBytes},
			"max_rate_bytes_per_s": {Number: policy.RateBytesPerSecond}, "max_queue_bytes": {Number: policy.QueueBytes},
			"max_pending_native_mappings": {Number: policy.PendingMappings}, "max_resident_native_mappings": {Number: policy.ResidentMappings},
			"max_total_native_mappings": {Number: policy.TotalMappings}, "max_queue_items": {Number: policy.QueueItems},
		})
		wire := admissionEncode(t, "Grant", map[string]protocolv4.Field{
			"tenant_id": admissionText(p.Tenant), "grant_id": admissionBytes(id[:]), "replay_nonce": admissionBytes(nonce[:]),
			"parent_ref": {Kind: protocolv4.EncodedMap, Bytes: parentRef}, "route_descriptor": {Kind: protocolv4.EncodedMap, Bytes: route},
			"route_digest": admissionBytes(routeDigest[:]), "attempt_id": admissionField(f.trust.proof.Field("attempt_id")), "pairing_id": admissionBytes(pairing[:]),
			"identity_digests": admissionArray(identities[:]...), "legs": admissionArray(legs[:]...), "service": scalar("audience"),
			"audience": admissionText(m.recipe.RelayAudience), "issuer_key_id": admissionBytes(m.recipe.GrantIssuerID[:]),
			"namespace": {Kind: protocolv4.EncodedMap, Bytes: namespace}, "issued_at_ms": {Number: issued}, "not_after_ms": {Number: end},
			"limits": {Kind: protocolv4.EncodedMap, Bytes: limits}, "session_contract_digest": admissionBytes(contractDigest[:]),
			"relay_identity_digest": admissionBytes(relayDigest[:]), "signature": admissionBytes(make([]byte, 64)),
		})
		m.grants[role] = initialSignTemplate(t, "Grant", wire, nil, m.recipe.GrantIssuerSeed)
		engineeringAddCredentialAuthority(t, f, m.grants[role])
	}
}

func engineeringInstallTunnelBytes(t AuthorityReporter, q *PublicQUICTestHarness, raw *materialBytesFixture, m *engineeringTunnelMaterials) {
	relay, err := m.relay.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	q.Tunnel = &PublicTunnelAuthority{RelayCertificate: append([]byte(nil), relay...), RelaySigner: m.signer, Limits: m.recipe.Limits}
	raw.config.Tunnels = make([]ArtifactLeaseTunnelBytes, 2)
	for role := range 2 {
		grant, err := m.grants[role].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		q.Tunnel.Grants[role] = append([]byte(nil), grant...)
		raw.config.Tunnels[role] = ArtifactLeaseTunnelBytes{CandidateIndex: 0, Role: protocolv4.Direction(role), Grant: grant, RelayCertificate: relay, GrantTrust: raw.trust, RelayTrust: raw.trust}
	}
}

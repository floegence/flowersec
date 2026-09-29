package protocolv4

import (
	"bytes"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RelayCredentials contains the parent reference, local endpoint certificate,
// leg Grant and relay certificate. The opposite endpoint's secret material or
// independently hosted hop roots are not required by this leg's verifier.
type RelayCredentials struct{ closure EndpointCredentials }

func RelayCredentialsBackingBytes() (uint64, error) {
	bytes := uint64(unsafe.Sizeof(RelayCredentials{}))
	for _, schema := range []string{"Artifact", "IdentityCertificate", "Grant", "IdentityCertificate"} {
		n, err := CredentialBackingBytes(schema)
		if err != nil {
			return 0, err
		}
		bytes += n
	}
	return bytes, nil
}

// BindRelayCredentials reconstructs only the public parent revocation facts
// attested by the verified Grant. parentPermission is independently resolved
// trust, never a key derived from the Grant. The relay's claim authority must
// additionally verify that this grant issuer may attest this exact original
// parent and resolve its immutable activation/selection record.
func BindRelayCredentials(grant, endpoint, relay *SignedMap, parentPermission IssuerPermission) (*RelayCredentials, error) {
	if grant == nil || endpoint == nil || relay == nil {
		return nil, ErrHopAuthContext
	}
	g, err := grant.DetachCredential()
	if err != nil {
		return nil, err
	}
	e, err := endpoint.DetachCredential()
	if err != nil {
		return nil, err
	}
	r, err := relay.DetachCredential()
	if err != nil {
		return nil, err
	}
	role := e.scope.Role
	if g.scope.Schema != "Grant" || e.scope.Schema != "IdentityCertificate" || r.scope.Schema != "IdentityCertificate" || role > 1 || r.scope.Role != 2 || g.scope.Role != 4|(1<<role) || g.scope.Tenant != e.scope.Tenant || g.scope.Tenant != r.scope.Tenant || g.scope.Audience != r.scope.Audience || e.scope.Profile != r.scope.Profile {
		return nil, ErrHopAuthContext
	}
	if g.scope.ParentIssuer != parentPermission.Issuer || parentPermission.Schema != "Artifact" {
		return nil, CBORFailure("revocation_issuer_permission")
	}
	c := grant.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != grant {
		return nil, CBORFailure("document_released")
	}
	root := grant.document.Root()
	localDigest, _ := root.Named("Grant", "identity_digests").Index(int(role)).ByteString()
	relayDigest, _ := root.Named("Grant", "relay_identity_digest").ByteString()
	if !bytes.Equal(localDigest, e.facts.Digest[:]) || !bytes.Equal(relayDigest, r.facts.Digest[:]) {
		return nil, ErrHopAuthContext
	}
	ref := root.Named("Grant", "parent_ref")
	text := func(name string) string { s, _ := ref.Named("GrantParentRef", name).Text(); return strings.Clone(s) }
	id, _ := ref.Named("GrantParentRef", "lease_id").ByteString()
	digest, _ := ref.Named("GrantParentRef", "artifact_digest").ByteString()
	parent := &Credential{key: parentPermission.Key, lease: [16]byte(id), admissionEnd: valueUint(ref, "GrantParentRef", "initiation_not_after_ms"),
		scope: CredentialScope{Schema: "Artifact", Tenant: text("tenant_id"), Authority: text("revocation_authority_id"), Audience: strings.Clone(e.scope.Audience), Profile: strings.Clone(e.scope.Profile),
			CapacityDigest: g.scope.ParentCapacityDigest, Issuer: g.scope.ParentIssuer, Generation: g.scope.ParentGeneration, Cohort: g.scope.ParentCohort, IssuedMS: valueUint(ref, "GrantParentRef", "issued_at_ms"), ExpiresMS: valueUint(ref, "GrantParentRef", "session_not_after_ms")}}
	parent.facts = CredentialStateFacts{Digest: [32]byte(digest), Cohort: parent.scope.Cohort, HardDeadlineMS: parent.scope.ExpiresMS, PolicyID: text("revocation_policy_id"), PolicyRevision: valueUint(ref, "GrantParentRef", "revocation_policy_revision"), class: 1}
	if err = parent.checkPermission(parentPermission); err != nil {
		return nil, err
	}
	closure := EndpointCredentials{count: 4, role: Direction(2), tunnel: true, credentials: [5]*Credential{parent, e, g, r}, hardEnd: min(parent.scope.ExpiresMS, e.scope.ExpiresMS, g.scope.ExpiresMS, r.scope.ExpiresMS)}
	return &RelayCredentials{closure: closure}, nil
}

// The order is parent, local endpoint, Grant, relay identity. Namespace owners
// may be shared, while credential/cohort decisions remain distinct. These
// subscriptions are owned by the original relay hop and never authorize e2e
// Noise, READY, an endpoint Session, or an extra relay claim.
func (r *RelayCredentials) Subscribe(bindings [4]CredentialValidation, hardEnd uint64, reservation resourcev4.Reference) (*CredentialSubscriptions, error) {
	if r == nil {
		return nil, ErrHopAuthContext
	}
	return r.closure.Subscribe(bindings[:], hardEnd, reservation)
}

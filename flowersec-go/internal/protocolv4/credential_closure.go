package protocolv4

import (
	"bytes"
	"unsafe"
)

// NamespaceReference is a detached public dependency, not permission to read a
// State, acquire roots or reserve a subscription.
type NamespaceReference struct {
	Tenant, Authority string
	Generation        uint64
	CapacityDigest    [32]byte
	RoleMask          uint64
}

// EndpointCredentials owns the selected role's complete credential closure.
// It retains neither the remote leg's grant nor any secret-bearing map. The
// issuer still verifies the complete route at issuance; an endpoint checks
// exactly its signed role subset before consumption and on later credentials.
type EndpointCredentials struct {
	credentials [5]*Credential // Parent, client, server, optional own grant/relay.
	count       int
	refs        []NamespaceReference
	role        Direction
	selection   PoolMember
	attempt     [16]byte
	tunnel      bool
	hardEnd     uint64
}

func EndpointCredentialsBackingBytes() (uint64, error) {
	count, err := FieldItemLimit("Candidate", "revocation_namespace_refs")
	if err != nil {
		return 0, err
	}
	// Route and all reference text are subsets of the original bounded Artifact.
	artifactBytes, err := SchemaByteLimit("Artifact")
	if err != nil {
		return 0, err
	}
	cost := uint64(unsafe.Sizeof(EndpointCredentials{})) + 2*uint64(artifactBytes) + uint64(count)*uint64(unsafe.Sizeof(NamespaceReference{}))
	for _, schema := range []string{"Artifact", "IdentityCertificate", "IdentityCertificate", "Grant", "IdentityCertificate"} {
		n, err := CredentialBackingBytes(schema)
		if err != nil {
			return 0, err
		}
		cost += n
	}
	return cost, nil
}

func namespaceReference(v Value) NamespaceReference {
	capacity, _ := v.Named("RevocationNamespaceRef", "namespace_capacity_digest").ByteString()
	r := NamespaceReference{CapacityDigest: [32]byte(capacity), Generation: valueUint(v, "RevocationNamespaceRef", "generation"), RoleMask: valueUint(v, "RevocationNamespaceRef", "role_mask")}
	r.Tenant, _ = v.Named("RevocationNamespaceRef", "tenant_id").Text()
	r.Authority, _ = v.Named("RevocationNamespaceRef", "revocation_authority_id").Text()
	return r
}

// BindEndpointCredentials consumes only locally applicable original signed
// objects. Independent issuer/trust/policy/read ACL and capacity admission are
// required before using this closure. It cannot construct relay authorization:
// a relay must never receive the secret-bearing Artifact accepted here.
func BindEndpointCredentials(role Direction, artifact *SignedMap, index uint64, client, server, grant, relay *SignedMap) (*EndpointCredentials, error) {
	if role != ClientToServer && role != ServerToClient {
		return nil, CBORFailure("credential_role")
	}
	result := &EndpointCredentials{role: role, count: 3}
	for i, original := range []*SignedMap{artifact, client, server} {
		credential, err := original.DetachCredential()
		if err != nil {
			return nil, err
		}
		result.credentials[i] = credential
	}
	parent := result.credentials[0]
	if parent.scope.Schema != "Artifact" {
		return nil, CBORFailure("artifact_owner")
	}
	routeCap, err := SchemaByteLimit("Artifact")
	if err != nil {
		return nil, err
	}
	route := make([]byte, routeCap)
	defer clear(route)
	var contract [32]byte
	var maxFrame uint64
	err = func() error {
		c := artifact.codec
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.current != artifact {
			return CBORFailure("artifact_owner")
		}
		root := artifact.document.Root()
		candidates := root.Named("Artifact", "candidates")
		if index >= uint64(candidates.Len()) {
			return CBORFailure("credential_candidate_index")
		}
		candidate := candidates.Index(int(index))
		result.tunnel = valueUint(candidate, "Candidate", "path_kind") == 1
		if (grant != nil) != result.tunnel || (relay != nil) != result.tunnel {
			return CBORFailure("credential_hop_presence")
		}
		for i, name := range []string{"client_identity_digest", "server_identity_digest"} {
			cert := result.credentials[i+1]
			digest, _ := root.Named("Artifact", name).ByteString()
			if cert.scope.Schema != "IdentityCertificate" || cert.scope.Role != uint64(i) || cert.scope.Tenant != parent.scope.Tenant || cert.scope.Audience != parent.scope.Audience || cert.scope.Profile != parent.scope.Profile || !bytes.Equal(digest, cert.facts.Digest[:]) {
				return CBORFailure("credential_identity_binding")
			}
		}
		refs := candidate.Named("Candidate", "revocation_namespace_refs")
		result.refs = make([]NamespaceReference, 0, refs.Len())
		for i := 0; i < refs.Len(); i++ {
			ref := namespaceReference(refs.Index(i))
			if !result.tunnel && ref.RoleMask != 3 {
				return CBORFailure("credential_namespace_binding")
			}
			if ref.RoleMask&(uint64(1)<<uint64(role)) != 0 {
				result.refs = append(result.refs, ref)
			}
		}
		var err error
		route, err = projectCandidate(route, candidate)
		if err != nil {
			return err
		}
		id, _ := candidate.Named("Candidate", "candidate_id").ByteString()
		result.selection = PoolMember{Index: index, CandidateID: [16]byte(id)}
		result.selection.RouteDigest, err = fullMapDigest("route_digest", "Route", route)
		if err != nil {
			return err
		}
		session := root.Named("Artifact", "session_contract")
		maxFrame = valueUint(session, "SessionContract", "max_frame")
		contract, err = fullMapDigest("session_contract_digest", "SessionContract", session.Encoded())
		return err
	}()
	if err != nil {
		return nil, err
	}
	if result.tunnel {
		for i, original := range []*SignedMap{grant, relay} {
			result.credentials[i+3], err = original.DetachCredential()
			if err != nil {
				return nil, err
			}
		}
		result.count = 5
		if err := result.bindGrant(grant, route, contract, maxFrame); err != nil {
			return nil, err
		}
	}
	if err := result.checkReferences(); err != nil {
		return nil, err
	}
	result.hardEnd = parent.facts.HardDeadlineMS
	for _, credential := range result.credentials[1:result.count] {
		result.hardEnd = min(result.hardEnd, credential.facts.HardDeadlineMS)
	}
	return result, nil
}

func (e *EndpointCredentials) bindGrant(grant *SignedMap, route []byte, contract [32]byte, maxFrame uint64) error {
	g, relay, parent := e.credentials[3], e.credentials[4], e.credentials[0]
	mask := uint64(4) | uint64(1)<<uint64(e.role)
	if g.scope.Schema != "Grant" || g.scope.Tenant != parent.scope.Tenant || g.scope.Role != mask || relay.scope.Schema != "IdentityCertificate" || relay.scope.Role != 2 || relay.scope.Tenant != parent.scope.Tenant {
		return CBORFailure("credential_grant_binding")
	}
	c := grant.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != grant {
		return CBORFailure("credential_owner")
	}
	root := grant.document.Root()
	ref := root.Named("Grant", "parent_ref")
	text := func(name string) string { value, _ := ref.Named("GrantParentRef", name).Text(); return value }
	if text("tenant_id") != parent.scope.Tenant || text("revocation_authority_id") != parent.scope.Authority || text("revocation_policy_id") != parent.facts.PolicyID {
		return CBORFailure("credential_grant_parent")
	}
	for name, want := range map[string]uint64{"authority_generation": parent.scope.Generation, "revocation_policy_revision": parent.facts.PolicyRevision, "revocation_epoch": parent.scope.Cohort, "issued_at_ms": parent.scope.IssuedMS, "initiation_not_after_ms": parent.admissionEnd, "session_not_after_ms": parent.scope.ExpiresMS} {
		if valueUint(ref, "GrantParentRef", name) != want {
			return CBORFailure("credential_grant_parent")
		}
	}
	for _, entry := range []struct {
		name string
		want []byte
	}{
		{"namespace_capacity_digest", parent.scope.CapacityDigest[:]}, {"artifact_issuer_key_id", parent.scope.Issuer[:]}, {"lease_id", parent.lease[:]}, {"artifact_digest", parent.facts.Digest[:]},
	} {
		got, _ := ref.Named("GrantParentRef", entry.name).ByteString()
		if !bytes.Equal(got, entry.want) {
			return CBORFailure("credential_grant_parent")
		}
	}
	for _, entry := range []struct {
		name string
		want []byte
	}{
		{"route_digest", e.selection.RouteDigest[:]}, {"session_contract_digest", contract[:]}, {"relay_identity_digest", relay.facts.Digest[:]},
	} {
		got, _ := root.Named("Grant", entry.name).ByteString()
		if !bytes.Equal(got, entry.want) {
			return CBORFailure("credential_grant_binding")
		}
	}
	if !bytes.Equal(root.Named("Grant", "route_descriptor").Encoded(), route) || valueUint(root.Named("Grant", "limits"), "GrantLimits", "max_envelope_bytes") != maxFrame+uint64(EnvelopePrefixSize) {
		return CBORFailure("credential_grant_route")
	}
	identities := root.Named("Grant", "identity_digests")
	for i := 0; i < 2; i++ {
		digest, _ := identities.Index(i).ByteString()
		if !bytes.Equal(digest, e.credentials[i+1].facts.Digest[:]) {
			return CBORFailure("credential_grant_identity")
		}
	}
	attempt, _ := root.Named("Grant", "attempt_id").ByteString()
	e.attempt = [16]byte(attempt)
	return nil
}

func (e *EndpointCredentials) checkReferences() error {
	// The fixed credential count bounds both loops. Every local signed reference
	// must have an actual local dependency; every dependency must match the full
	// generation/capacity and required common or hop mask.
	for _, credential := range e.credentials[:e.count] {
		found := false
		for _, ref := range e.refs {
			if ref.Tenant != credential.scope.Tenant || ref.Authority != credential.scope.Authority {
				continue
			}
			mask := uint64(3)
			if e.tunnel {
				mask = 7
			}
			if credential == e.credentials[3] || credential == e.credentials[4] {
				mask = 4 | uint64(1)<<uint64(e.role)
			}
			if ref.Generation != credential.scope.Generation || ref.CapacityDigest != credential.scope.CapacityDigest || ref.RoleMask&mask != mask || !e.tunnel && ref.RoleMask != mask {
				return CBORFailure("credential_namespace_binding")
			}
			found = true
		}
		if !found {
			return CBORFailure("credential_namespace_missing")
		}
	}
	for _, ref := range e.refs {
		found := false
		for _, credential := range e.credentials[:e.count] {
			found = found || ref.Tenant == credential.scope.Tenant && ref.Authority == credential.scope.Authority
		}
		if !found {
			return CBORFailure("credential_namespace_extra")
		}
	}
	return nil
}

func (e *EndpointCredentials) CredentialCount() int { return e.count }
func (e *EndpointCredentials) Credential(index int) *Credential {
	if index < 0 || index >= e.count {
		return nil
	}
	return e.credentials[index]
}
func (e *EndpointCredentials) NamespaceCount() int { return len(e.refs) }
func (e *EndpointCredentials) Namespace(index int) (NamespaceReference, bool) {
	if index < 0 || index >= len(e.refs) {
		return NamespaceReference{}, false
	}
	return e.refs[index], true
}
func (e *EndpointCredentials) Deadline() uint64 { return e.hardEnd }

// MatchActivation prevents a later proof/attempt from replacing the closure
// admitted for this exact route. Activation inherits the parent's policy.
func (e *EndpointCredentials) MatchActivation(a *ActivationAuthority) error {
	if a == nil || e.credentials[0].facts.Digest != a.binding.artifactDigest || e.selection != a.binding.winner || e.tunnel && e.attempt != a.binding.attempt {
		return CBORFailure("credential_activation_binding")
	}
	return nil
}

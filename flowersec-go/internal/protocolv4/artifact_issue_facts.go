package protocolv4

import "bytes"

// CheckArtifactIssueFacts binds a retained original Artifact to the complete
// issuance obligation. Per-candidate namespace masks are unioned; no dependency
// is inferred from a digest or omitted from the independent authorization facts.
func (m *SignedMap) CheckArtifactIssueFacts(f DirectIssueFacts) error {
	if m == nil || f.NamespaceCount == 0 || int(f.NamespaceCount) > len(f.Namespaces) {
		return CBORFailure("issuance_facts")
	}
	credential, err := m.DetachCredential()
	if err != nil {
		return err
	}
	if credential.scope != f.Scope || credential.lease != f.LeaseID || credential.admissionEnd != f.InitiationNotAfterMS || credential.facts.PolicyID != f.RevocationPolicyID || credential.facts.PolicyRevision != f.RevocationPolicyRevision {
		return CBORFailure("issuance_facts")
	}
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != m || c.schema != "Artifact" {
		return CBORFailure("artifact_owner")
	}
	root := m.document.Root()
	client, _ := root.Named("Artifact", "client_identity_digest").ByteString()
	server, _ := root.Named("Artifact", "server_identity_digest").ByteString()
	if !bytes.Equal(client, f.ClientIdentity[:]) || !bytes.Equal(server, f.ServerIdentity[:]) {
		return CBORFailure("issuance_facts")
	}
	var refs [MaxArtifactIssueNamespaces]NamespaceReference
	var count uint8
	candidates := root.Named("Artifact", "candidates")
	for i := 0; i < candidates.Len(); i++ {
		namespaces := candidates.Index(i).Named("Candidate", "revocation_namespace_refs")
		for j := 0; j < namespaces.Len(); j++ {
			if err = addIssueNamespace(&refs, &count, namespaceReference(namespaces.Index(j))); err != nil {
				return err
			}
		}
	}
	if count != f.NamespaceCount {
		return CBORFailure("credential_namespace_count")
	}
	for i, ref := range f.Namespaces[:count] {
		found := false
		for _, actual := range refs[:count] {
			found = found || actual == ref
		}
		if !found {
			return CBORFailure("credential_namespace_binding")
		}
		for _, prior := range f.Namespaces[:i] {
			if prior.Tenant == ref.Tenant && prior.Authority == ref.Authority {
				return CBORFailure("credential_namespace_binding")
			}
		}
	}
	for _, ref := range f.Namespaces[count:] {
		if ref != (NamespaceReference{}) {
			return CBORFailure("credential_namespace_count")
		}
	}
	return nil
}

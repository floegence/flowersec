package protocolv4

// IssuerPolicySelection is immutable original deployment input. It selects one
// independently signed issuance authorization; it cannot come from a request,
// an unverified Grant or a credential being issued. Inapplicable fields must be
// empty. Grant role is the logical endpoint role, rather than its namespace mask.
type IssuerPolicySelection struct {
	Schema                     string
	Issuer                     [16]byte
	Audience, Profile, Service string
	Role                       uint64
	Parent                     NamespaceReference
	ParentIssuer               [16]byte
	PolicyID                   string
	PolicyRevision             uint64
}

// ResolveIssuerPolicy supplies original live namespace and policy owners before
// any Artifact/Grant exists. It never constructs a permission from a sample
// credential or signs a fixture to discover authority. Every later issuance and
// publication still checks the live trust, State, Head and original permit.
func (t *NamespaceTrustStore) ResolveIssuerPolicy(s IssuerPolicySelection) (CredentialValidation, NamespaceReference, error) {
	if t == nil || s.Issuer == ([16]byte{}) || s.Audience == "" || len(s.Audience) > 128 || s.PolicyID == "" || len(s.PolicyID) > 128 || s.PolicyRevision == 0 {
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
	}
	switch s.Schema {
	case "Artifact":
		if s.Profile == "" || s.Service != "" || s.Role != 0 || s.Parent != (NamespaceReference{}) || s.ParentIssuer != ([16]byte{}) {
			return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
		}
	case "Grant":
		if s.Profile != "" || s.Service == "" || s.Role > 1 || s.Parent.Tenant == "" || s.Parent.Authority == "" || s.Parent.CapacityDigest == ([32]byte{}) || s.Parent.Generation == 0 || s.Parent.RoleMask != 3 && s.Parent.RoleMask != 7 || s.ParentIssuer == ([16]byte{}) {
			return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
		}
	default:
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
	}
	sample, err := t.sampleCurrent()
	if err != nil {
		return CredentialValidation{}, NamespaceReference{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err = t.checkCurrentLockedAt(sample); err != nil {
		return CredentialValidation{}, NamespaceReference{}, err
	}
	if t.namespace == nil {
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_namespace_owner")
	}
	current := &t.configurations[t.count-1]
	if includesTrustID(current.retired, s.Issuer) {
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_rejected")
	}
	var selected *trustedIssuer
	for i := range current.issuers {
		entry := &current.issuers[i]
		scope := entry.scope
		if entry.permission.Schema != s.Schema || entry.permission.Issuer != s.Issuer || scope.Audience != s.Audience || scope.Profile != s.Profile || scope.Service != s.Service {
			continue
		}
		if s.Schema == "Grant" && ((4|1<<s.Role)&^scope.Role != 0 || scope.ParentAuthority != s.Parent.Authority || scope.ParentCapacityDigest != s.Parent.CapacityDigest || scope.ParentGeneration != s.Parent.Generation || scope.ParentIssuer != s.ParentIssuer || scope.Tenant != s.Parent.Tenant) {
			continue
		}
		if selected != nil {
			return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
		}
		selected = entry
	}
	if selected == nil {
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("revocation_issuer_permission")
	}
	var policy *CredentialPolicy
	for _, candidate := range current.policies {
		if candidate.id == s.PolicyID && candidate.revision == s.PolicyRevision {
			policy = candidate
			break
		}
	}
	if policy == nil {
		return CredentialValidation{}, NamespaceReference{}, CBORFailure("credential_policy_reference")
	}
	role := uint64(3)
	if s.Schema == "Grant" {
		role = 4 | 1<<s.Role
	}
	namespace := NamespaceReference{Tenant: selected.scope.Tenant, Authority: selected.scope.Authority, CapacityDigest: selected.scope.CapacityDigest, Generation: selected.scope.Generation, RoleMask: role}
	return CredentialValidation{Namespace: t.namespace, Issuer: selected.permission, Policy: policy}, namespace, nil
}

// ResolveActivationIssuer selects the original independently signed mapping
// before a parent Artifact exists. It grants no spend, signing or admission
// capability; the configured private signer and durable owner remain required.
func (t *NamespaceTrustStore) ResolveActivationIssuer(parent [16]byte, keyID string) (ActivationTrustBinding, error) {
	if t == nil || parent == ([16]byte{}) || keyID == "" || len(keyID) > 128 {
		return ActivationTrustBinding{}, CBORFailure("activation_delegation_authority")
	}
	sample, err := t.sampleCurrent()
	if err != nil {
		return ActivationTrustBinding{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err = t.checkCurrentLockedAt(sample); err != nil {
		return ActivationTrustBinding{}, err
	}
	if t.namespace == nil {
		return ActivationTrustBinding{}, CBORFailure("revocation_namespace_owner")
	}
	var result ActivationTrustBinding
	found := false
	for _, entry := range t.configurations[t.count-1].activations {
		if entry.binding.ParentIssuer != parent || entry.binding.SigningKeyID != keyID {
			continue
		}
		if includesTrustID(t.configurations[t.count-1].retired, entry.binding.Issuer) {
			return ActivationTrustBinding{}, CBORFailure("activation_delegation_authority")
		}
		if found {
			return ActivationTrustBinding{}, CBORFailure("activation_delegation_authority")
		}
		result, found = entry.binding, true
	}
	if !found {
		return ActivationTrustBinding{}, CBORFailure("activation_delegation_authority")
	}
	return result, nil
}

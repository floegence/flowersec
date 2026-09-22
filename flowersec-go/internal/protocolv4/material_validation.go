package protocolv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// CheckMaterialCredential validates one original credential before material
// capture, against its independently resolved policy and live namespace. The
// complete selected endpoint closure still combines every applicable policy
// and subscription before spend; this check grants no activation authority.
func (v CredentialValidation) CheckMaterialCredential(c *Credential, hardEnd uint64, environment resourcev4.Reference) (uint64, error) {
	if v.Namespace == nil || v.Policy == nil || c == nil {
		return 0, CBORFailure("credential_validation_count")
	}
	if err := v.Namespace.reservation.CheckSameEnvironment(environment); err != nil {
		return 0, err
	}
	end, err := v.Namespace.checkBoundCredential(c, v.Issuer, v.Policy, v.Policy.Requirements(), hardEnd)
	if err != nil {
		return 0, err
	}
	if c.scope.Schema == "Artifact" {
		now, err := v.Namespace.clock.Sample()
		if err != nil {
			return 0, err
		}
		if err := c.CheckAdmission(now.Interval); err != nil {
			return 0, err
		}
	}
	return end, nil
}

// CheckLiveActivationSource rejects invalid or currently unusable original
// delegation/once-authority configuration before contacting a live authority.
// There is no proof, selected winner, attempt or activation capability here.
// The returned TxB proof must still pass BindActivationAuthority and the exact
// original trust/admission checks before any carrier activation.
func (v CredentialValidation) CheckLiveActivationSource(r *NamespaceRules, parent *Credential, delegation, once []byte, key [32]byte, environment resourcev4.Reference) error {
	return v.checkLiveActivationConfiguration(r, parent, delegation, once, key, environment, true)
}

// CheckLiveActivationConfiguration validates the verifier's original authority
// mapping independently of whether that authority can still issue a NEW proof.
// Received proof issuance time is checked by BindActivationAuthority; current
// trust and its actual activation deadline remain mandatory admission checks.
func (v CredentialValidation) CheckLiveActivationConfiguration(r *NamespaceRules, parent *Credential, delegation, once []byte, key [32]byte, environment resourcev4.Reference) error {
	return v.checkLiveActivationConfiguration(r, parent, delegation, once, key, environment, false)
}

func (v CredentialValidation) checkLiveActivationConfiguration(r *NamespaceRules, parent *Credential, delegation, once []byte, key [32]byte, environment resourcev4.Reference, issuing bool) error {
	if r == nil || parent == nil || parent.scope.Schema != "Artifact" || v.Namespace == nil || v.Namespace.rules != r || key == ([32]byte{}) || uint64(len(delegation)) > r.trustBytes {
		return CBORFailure("activation_authority_owner")
	}
	if _, err := v.CheckMaterialCredential(parent, parent.scope.ExpiresMS, environment); err != nil {
		return err
	}
	d, err := boundedMap(delegation, "ConnectionActivationDelegation")
	if err != nil {
		return err
	}
	defer d.Release()
	o, err := boundedMap(once, "OnceAuthorityRef")
	if err != nil {
		return err
	}
	defer o.Release()
	entry, authority := d.Root(), o.Root()
	get := func(name string) uint64 { return valueUint(entry, "ConnectionActivationDelegation", name) }
	if !r.matchesNamespace(entry, "ConnectionActivationDelegation") || get("authority_generation") != parent.scope.Generation {
		return CBORFailure("activation_delegation_namespace")
	}
	for _, part := range []struct {
		value  Value
		schema string
	}{{entry, "ConnectionActivationDelegation"}, {authority, "OnceAuthorityRef"}} {
		tenant, _ := part.value.Named(part.schema, "tenant_id").Text()
		issuer, _ := part.value.Named(part.schema, "artifact_issuer_key_id").ByteString()
		if tenant != parent.scope.Tenant || !bytes.Equal(issuer, parent.scope.Issuer[:]) {
			return CBORFailure("activation_delegation_authority")
		}
	}
	spend, _ := authority.Named("OnceAuthorityRef", "spend_authority_id").Text()
	winner, _ := authority.Named("OnceAuthorityRef", "winner_authority_id").Text()
	declared, _ := entry.Named("ConnectionActivationDelegation", "authority_id").Text()
	signingKey, _ := entry.Named("ConnectionActivationDelegation", "signing_key_id").Text()
	public, _ := entry.Named("ConnectionActivationDelegation", "signer_public_key").ByteString()
	issuer, _ := entry.Named("ConnectionActivationDelegation", "issuer_key_id").ByteString()
	if spend != declared || !bytes.Equal(public, key[:]) {
		return CBORFailure("activation_delegation_authority")
	}
	if parent.scope.Cohort < get("first_parent_cohort") || parent.scope.Cohort > get("last_parent_cohort") {
		return CBORFailure("activation_delegation_cohort")
	}
	digest, err := fullMapDigest("connection_activation_delegation_digest", "ConnectionActivationDelegation", d.Bytes())
	if err != nil {
		return err
	}
	binding := ActivationTrustBinding{Tenant: r.tenant, AuthorityNamespace: r.authority, SigningKeyID: signingKey, SpendAuthority: spend, WinnerAuthority: winner, CapacityDigest: r.capacityDigest, DelegationDigest: digest, Key: key, ParentIssuer: parent.scope.Issuer, Issuer: [16]byte(issuer), Generation: parent.scope.Generation}
	n := v.Namespace
	n.mu.Lock()
	defer n.mu.Unlock()
	now, err := n.check()
	if err != nil {
		return err
	}
	if err = n.checkHead(n.active.head, now.Interval); err != nil {
		return err
	}
	if err = n.trust.Activation(binding); err != nil {
		return err
	}
	end := min(get("max_activation_not_after_ms"), get("max_session_not_after_ms"), parent.admissionEnd, parent.scope.ExpiresMS)
	if issuing {
		if err = now.LowerBound(get("signing_not_before_ms"), true); err != nil {
			return err
		}
		end = min(end, get("signing_not_after_ms"))
	}
	if !now.ValidBefore(end) {
		return timev4.ErrExpired
	}
	state := n.active
	w := state.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != state || state.head.generation != binding.Generation {
		return CBORFailure("activation_authority_owner")
	}
	if err = w.reservation.Check(); err != nil {
		return err
	}
	cohort, err := state.cohort(1, parent.scope.Cohort)
	if err != nil {
		return err
	}
	if parent.scope.ExpiresMS > cohort.impact {
		return CBORFailure("revocation_activation_impact")
	}
	root := state.document.Root()
	for _, issuer := range [][16]byte{binding.ParentIssuer, binding.Issuer} {
		if searchRevocation(root.Named("RevocationState", "revoked_issuers"), "RevokedIssuerEntry", []string{"issuer_key_id"}, issuer[:]).valid() {
			return CBORFailure("revocation_issuer_rejected")
		}
	}
	if searchRevocation(root.Named("RevocationState", "revoked_leases"), "RevokedLeaseEntry", []string{"issuer_key_id", "lease_id"}, parent.scope.Issuer[:], parent.lease[:]).valid() {
		return CBORFailure("revocation_lease_rejected")
	}
	return nil
}

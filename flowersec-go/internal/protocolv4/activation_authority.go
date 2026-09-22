package protocolv4

import (
	"bytes"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/timev4"
)

// ActivationTrustBinding identifies one immutable independent-trust entry and
// the original parent issuer's fixed once-authority mapping. It is not an
// authority selection request or a durable authorization/admission receipt.
type ActivationTrustBinding struct {
	Tenant, AuthorityNamespace, SigningKeyID string
	SpendAuthority, WinnerAuthority          string
	CapacityDigest, DelegationDigest, Key    [32]byte
	ParentIssuer, Issuer                     [16]byte
	Generation                               uint64
}

// ActivationAuthority retains only the original public delegation/mapping and
// detached binding facts. It neither holds the Artifact's PSK nor permits a
// trust refresh to change the original signer, authority or influence bounds.
type ActivationAuthority struct {
	rules                       *NamespaceRules
	binding                     *ActivationBinding
	trust                       ActivationTrustBinding
	delegation, authority       []byte
	parentCohort, parentIssued  uint64
	parentActivation, parentEnd uint64
}

func ActivationAuthorityBackingBytes() (uint64, error) {
	var cost uint64
	for _, schema := range []string{"ConnectionActivationDelegation", "OnceAuthorityRef"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return 0, err
		}
		decoder, err := DecoderBackingBytes(limit, limit)
		if err != nil {
			return 0, err
		}
		// Original bytes plus detached public text are bounded by the full map.
		cost, err = namespaceAdd(cost, decoder+2*uint64(limit))
		if err != nil {
			return 0, err
		}
	}
	return namespaceAdd(cost, uint64(unsafe.Sizeof(ActivationAuthority{})))
}

// BindActivationAuthority checks the independently authenticated original
// delegation and OnceAuthorityRef against the actual parent/proof signature
// binding. Current trust and complete State membership remain live checks.
func (r *NamespaceRules) BindActivationAuthority(binding *ActivationBinding, artifact *SignedMap, delegation, authority []byte) (*ActivationAuthority, error) {
	if r == nil || binding == nil || artifact == nil || artifact.codec.schema != "Artifact" || uint64(len(delegation)) > r.trustBytes {
		return nil, CBORFailure("activation_authority_owner")
	}
	d, err := boundedMap(delegation, "ConnectionActivationDelegation")
	if err != nil {
		return nil, err
	}
	defer d.Release()
	o, err := boundedMap(authority, "OnceAuthorityRef")
	if err != nil {
		return nil, err
	}
	defer o.Release()
	c := artifact.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != artifact || artifact.key != binding.artifactKey {
		return nil, CBORFailure("activation_authority_owner")
	}
	digest, err := fullMapDigest("artifact_digest", "Artifact", artifact.document.Bytes())
	if err != nil {
		return nil, err
	}
	if digest != binding.artifactDigest {
		return nil, CBORFailure("activation_parent_binding")
	}
	parent, entry, once := artifact.document.Root(), d.Root(), o.Root()
	generation := valueUint(parent, "Artifact", "revocation_authority_generation")
	if !r.matchesNamespace(parent, "Artifact") || !r.matchesNamespace(entry, "ConnectionActivationDelegation") || valueUint(entry, "ConnectionActivationDelegation", "authority_generation") != generation {
		return nil, CBORFailure("activation_delegation_namespace")
	}
	for _, original := range []struct {
		root                   Value
		schema, tenant, issuer string
	}{
		{entry, "ConnectionActivationDelegation", "tenant_id", "artifact_issuer_key_id"},
		{once, "OnceAuthorityRef", "tenant_id", "artifact_issuer_key_id"},
	} {
		tenant, _ := original.root.Named(original.schema, original.tenant).Text()
		issuer, _ := original.root.Named(original.schema, original.issuer).ByteString()
		if tenant != binding.tenant || !bytes.Equal(issuer, binding.issuer[:]) {
			return nil, CBORFailure("activation_delegation_authority")
		}
	}
	spend, _ := once.Named("OnceAuthorityRef", "spend_authority_id").Text()
	winner, _ := once.Named("OnceAuthorityRef", "winner_authority_id").Text()
	delegatedAuthority, _ := entry.Named("ConnectionActivationDelegation", "authority_id").Text()
	signingKey, _ := entry.Named("ConnectionActivationDelegation", "signing_key_id").Text()
	key, _ := entry.Named("ConnectionActivationDelegation", "signer_public_key").ByteString()
	if spend != binding.authority || delegatedAuthority != spend || signingKey != binding.signingKey || !bytes.Equal(key, binding.proofKey[:]) || binding.source == "preauthorized_pool" && winner != binding.winnerAuthority {
		return nil, CBORFailure("activation_delegation_authority")
	}
	a := &ActivationAuthority{rules: r, binding: binding,
		parentCohort: valueUint(parent, "Artifact", "revocation_epoch"), parentIssued: valueUint(parent, "Artifact", "issued_at_ms"),
		parentActivation: valueUint(parent, "Artifact", "initiation_not_after_ms"), parentEnd: valueUint(parent, "Artifact", "session_not_after_ms")}
	get := func(field string) uint64 { return valueUint(entry, "ConnectionActivationDelegation", field) }
	if a.parentCohort < get("first_parent_cohort") || a.parentCohort > get("last_parent_cohort") {
		return nil, CBORFailure("activation_delegation_cohort")
	}
	if binding.issuedAt < a.parentIssued || binding.issuedAt < get("signing_not_before_ms") || binding.issuedAt >= get("signing_not_after_ms") {
		return nil, CBORFailure("activation_delegation_signing_time")
	}
	end, err := r.cohortEnd(a.parentCohort)
	if err != nil {
		return nil, err
	}
	impact, err := r.mature(1, a.parentCohort)
	if err != nil {
		return nil, err
	}
	if a.parentIssued < end-r.duration || a.parentIssued >= end || a.parentEnd > impact || binding.activationEnd > min(a.parentActivation, get("max_activation_not_after_ms")) || binding.sessionEnd > min(a.parentEnd, get("max_session_not_after_ms")) {
		return nil, CBORFailure("activation_delegation_impact")
	}
	delegationDigest, err := fullMapDigest("connection_activation_delegation_digest", "ConnectionActivationDelegation", d.Bytes())
	if err != nil {
		return nil, err
	}
	issuer, _ := entry.Named("ConnectionActivationDelegation", "issuer_key_id").ByteString()
	a.trust = ActivationTrustBinding{Tenant: r.tenant, AuthorityNamespace: r.authority, SigningKeyID: signingKey, SpendAuthority: spend, WinnerAuthority: winner, CapacityDigest: r.capacityDigest, DelegationDigest: delegationDigest, Key: binding.proofKey, ParentIssuer: binding.issuer, Issuer: [16]byte(issuer), Generation: generation}
	a.delegation, a.authority = bytes.Clone(d.Bytes()), bytes.Clone(o.Bytes())
	return a, nil
}

func (a *ActivationAuthority) Matches(delegation, authority []byte) bool {
	return a != nil && bytes.Equal(a.delegation, delegation) && bytes.Equal(a.authority, authority)
}

// CheckAdmission adds only the original initiation/activation time boundary.
// The owner must also perform CheckActivation and its original carrier/once
// guards. Ending this window does not expire an already admitted Session.
func (a *ActivationAuthority) CheckAdmission(now timev4.Interval) error {
	if a == nil || !now.ValidBefore(min(a.parentActivation, a.binding.activationEnd)) {
		return timev4.ErrExpired
	}
	return now.LowerBound(a.binding.issuedAt, true)
}

func (s *NamespaceState) CheckActivation(a *ActivationAuthority, now timev4.Interval) error {
	w := s.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != s || a == nil || a.rules != w.rules || a.trust.Generation != s.head.generation {
		return CBORFailure("activation_authority_owner")
	}
	if err := w.reservation.Check(); err != nil {
		return err
	}
	if err := s.head.CheckTime(now); err != nil {
		return err
	}
	cohort, err := s.cohort(1, a.parentCohort)
	if err != nil {
		return err
	}
	if a.parentEnd > cohort.impact || a.binding.sessionEnd > a.parentEnd {
		return CBORFailure("revocation_activation_impact")
	}
	if !now.ValidBefore(a.binding.sessionEnd) {
		return timev4.ErrExpired
	}
	if err := now.LowerBound(a.binding.issuedAt, true); err != nil {
		return err
	}
	root := s.document.Root()
	for _, issuer := range [][16]byte{a.trust.ParentIssuer, a.trust.Issuer} {
		if searchRevocation(root.Named("RevocationState", "revoked_issuers"), "RevokedIssuerEntry", []string{"issuer_key_id"}, issuer[:]).valid() {
			return CBORFailure("revocation_issuer_rejected")
		}
	}
	if searchRevocation(root.Named("RevocationState", "revoked_leases"), "RevokedLeaseEntry", []string{"issuer_key_id", "lease_id"}, a.binding.issuer[:], a.binding.lease[:]).valid() {
		return CBORFailure("revocation_lease_rejected")
	}
	return nil
}

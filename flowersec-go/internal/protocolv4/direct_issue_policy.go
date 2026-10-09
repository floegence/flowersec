package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

type DirectIssuePolicyConfig struct {
	Trust                             *NamespaceTrustStore
	Clock                             *timev4.Clock
	Issuer                            [16]byte
	Audience, CryptoProfile, PolicyID string
	PolicyRevision                    uint64
	// Namespaces fixes the complete issuer route closure, including role masks.
	// Empty uses the parent namespace with the direct endpoint mask. Nonempty
	// input must include that parent and every actual endpoint/Grant/relay owner.
	Namespaces []NamespaceReference
}

// DirectIssuePolicy retains one original independent issuer authorization and
// its exact namespace/policy. A containing authority reserves BackingBytes and
// retains the returned trust borrow through its actual invocation cleanup.
type DirectIssuePolicy struct {
	trust         *NamespaceTrustStore
	issuer        trustedIssuer
	policy        *CredentialPolicy
	rules         *NamespaceRules
	authorization []byte
	namespaces    [MaxArtifactIssueNamespaces]NamespaceReference
	count         uint8
}

type DirectIssuePolicyLimits struct {
	Namespace                                                            NamespaceReference
	Issuer                                                               [16]byte
	MaxStateBytes, MaxLeases, MaxIssuers, MaxSegments, MaxAuthorizations uint64
	SigningStart, SigningEnd, FirstCohort, LastCohort, MaxExpiry         uint64
}

func DirectIssuePolicyBackingBytes() uint64 {
	return uint64(unsafe.Sizeof(DirectIssuePolicy{})) + 2048 + MaxArtifactIssueNamespaces*256
}

func NewDirectIssuePolicy(c DirectIssuePolicyConfig, environment resourcev4.Reference) (*DirectIssuePolicy, resourcev4.Reference, error) {
	if c.Trust == nil || c.Clock == nil || c.Trust.clock != c.Clock {
		return nil, resourcev4.Reference{}, resourcev4.ErrConfiguration
	}
	t := c.Trust
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return nil, resourcev4.Reference{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.checkCurrentLockedAt(sample); err != nil {
		return nil, resourcev4.Reference{}, err
	}
	if t.namespace == nil {
		return nil, resourcev4.Reference{}, CBORFailure("revocation_namespace_owner")
	}
	if err := t.reservation.CheckSameEnvironment(environment); err != nil {
		return nil, resourcev4.Reference{}, err
	}
	current := &t.configurations[t.count-1]
	var selected *trustedIssuer
	for i := range current.issuers {
		entry := &current.issuers[i]
		// One signing key may be authorized for multiple credential schemas
		// (for example the Artifact and its endpoint certificates). Select the
		// exact Artifact authorization for this issuance policy; unrelated
		// schema entries sharing the key do not make the policy ambiguous.
		if entry.permission.Schema == "Artifact" && entry.permission.Issuer == c.Issuer && entry.scope.Audience == c.Audience && entry.scope.Profile == c.CryptoProfile {
			if selected != nil {
				return nil, resourcev4.Reference{}, CBORFailure("revocation_issuer_permission")
			}
			selected = entry
		}
	}
	if selected == nil {
		return nil, resourcev4.Reference{}, CBORFailure("revocation_issuer_permission")
	}
	var policy *CredentialPolicy
	for _, p := range current.policies {
		if p.id == c.PolicyID && p.revision == c.PolicyRevision {
			policy = p
		}
	}
	if policy == nil {
		return nil, resourcev4.Reference{}, CBORFailure("credential_policy_reference")
	}
	entries := current.signed.Field("issuer_authorizations")
	var authorization []byte
	for i := 0; i < entries.Len(); i++ {
		entry := entries.Index(i)
		id, _ := entry.Named("CredentialIssuerAuthorization", "authorization_id").ByteString()
		if bytes.Equal(id, selected.id[:]) {
			authorization = entry.Encoded()
			break
		}
	}
	if len(authorization) == 0 || len(authorization) > 2048 {
		return nil, resourcev4.Reference{}, CBORFailure("revocation_issuer_permission")
	}
	ref, err := t.reservation.Borrow()
	if err != nil {
		return nil, ref, err
	}
	p := &DirectIssuePolicy{trust: t, issuer: *selected, policy: policy, rules: t.rules, authorization: bytes.Clone(authorization)}
	namespaces := c.Namespaces
	if len(namespaces) == 0 {
		parent := p.Limits().Namespace
		namespaces = []NamespaceReference{parent}
	}
	if len(namespaces) > MaxArtifactIssueNamespaces {
		ref.Release()
		return nil, resourcev4.Reference{}, CBORFailure("credential_namespace_count")
	}
	parentFound := false
	parent := p.Limits().Namespace
	for _, input := range namespaces {
		if input.Tenant != parent.Tenant || !validIssueNamespace(input) {
			ref.Release()
			return nil, resourcev4.Reference{}, CBORFailure("credential_namespace_binding")
		}
		if input.Authority == parent.Authority {
			if input.Generation != parent.Generation || input.CapacityDigest != parent.CapacityDigest || input.RoleMask != 3 && input.RoleMask != 7 {
				ref.Release()
				return nil, resourcev4.Reference{}, CBORFailure("credential_namespace_binding")
			}
			parentFound = true
		}
		for _, prior := range p.namespaces[:p.count] {
			if prior.Tenant == input.Tenant && prior.Authority == input.Authority {
				ref.Release()
				return nil, resourcev4.Reference{}, CBORFailure("credential_namespace_binding")
			}
		}
		input.Tenant, input.Authority = strings.Clone(input.Tenant), strings.Clone(input.Authority)
		p.namespaces[p.count], p.count = input, p.count+1
	}
	if !parentFound {
		ref.Release()
		return nil, resourcev4.Reference{}, CBORFailure("credential_namespace_missing")
	}
	// Configuration binds a set. Canonical local order keeps a harmless host
	// reordering from changing the durable configuration digest on reopen.
	sort.Slice(p.namespaces[:p.count], func(i, j int) bool {
		left, right := p.namespaces[i], p.namespaces[j]
		if left.Tenant != right.Tenant {
			return left.Tenant < right.Tenant
		}
		return left.Authority < right.Authority
	})
	return p, ref, nil
}

func (p *DirectIssuePolicy) Limits() DirectIssuePolicyLimits {
	s := p.issuer.scope
	r := p.rules
	return DirectIssuePolicyLimits{Namespace: NamespaceReference{Tenant: s.Tenant, Authority: s.Authority, Generation: s.Generation, CapacityDigest: s.CapacityDigest, RoleMask: 3}, Issuer: p.issuer.permission.Issuer, MaxStateBytes: r.stateBytes, MaxLeases: r.limits["max_revoked_leases"], MaxIssuers: r.limits["max_revoked_issuers"], MaxSegments: r.limits["max_cohort_policy_segments"], MaxAuthorizations: r.limits["max_revoked_issuer_authorizations"], SigningStart: p.issuer.permission.SigningStart, SigningEnd: p.issuer.permission.SigningEnd, FirstCohort: p.issuer.first, LastCohort: p.issuer.last, MaxExpiry: p.issuer.lastExpiry}
}

// CopyConfiguration copies the exact canonical immutable namespace, original
// issuer authorization and credential policy. This is a storage projection,
// never a replacement signature or independently trusted wire object.
func (p *DirectIssuePolicy) CopyConfiguration(dst []byte) (int, error) {
	if p == nil {
		return 0, CBORFailure("revocation_issuer_permission")
	}
	n := 0
	for _, wire := range [][]byte{p.rules.capacity, p.rules.publication, p.authorization, p.policy.bytes} {
		if len(wire) > len(dst)-n-4 {
			return 0, CBORFailure("encoder_capacity")
		}
		binary.BigEndian.PutUint32(dst[n:], uint32(len(wire)))
		n += 4
		n += copy(dst[n:], wire)
	}
	// The independently supplied closure is immutable for this authority. Its
	// complete length-framed digest binds reopened storage to exactly the same
	// public dependencies without duplicating them in every lease obligation.
	if len(dst)-n < 32 {
		return 0, CBORFailure("encoder_capacity")
	}
	h := sha256.New()
	_, _ = h.Write([]byte("flowersec/v4/issuer-namespace-closure\x00"))
	_, _ = h.Write([]byte{p.count})
	for _, ref := range p.namespaces[:p.count] {
		for _, text := range []string{ref.Tenant, ref.Authority} {
			_, _ = h.Write([]byte{byte(len(text))})
			_, _ = h.Write([]byte(text))
		}
		var numeric [16]byte
		binary.BigEndian.PutUint64(numeric[:8], ref.Generation)
		binary.BigEndian.PutUint64(numeric[8:], ref.RoleMask)
		_, _ = h.Write(numeric[:])
		_, _ = h.Write(ref.CapacityDigest[:])
	}
	n += copy(dst[n:], h.Sum(nil))
	return n, nil
}

func (p *DirectIssuePolicy) NamespaceClosure() ([MaxArtifactIssueNamespaces]NamespaceReference, uint8) {
	return p.namespaces, p.count
}

func (p *DirectIssuePolicy) CheckHistoricalFacts(f DirectIssueFacts) error {
	if p == nil || f.LeaseID == ([16]byte{}) || f.ClientIdentity == ([32]byte{}) || f.ServerIdentity == ([32]byte{}) || f.ClientIdentity == f.ServerIdentity || f.NamespaceCount != p.count || f.RevocationPolicyID != p.policy.id || f.RevocationPolicyRevision != p.policy.revision || f.Scope.IssuedMS >= f.InitiationNotAfterMS || f.InitiationNotAfterMS > f.Scope.ExpiresMS || !trustIssuerMatches(p.issuer, p.issuer.permission, f.Scope) {
		return CBORFailure("revocation_issuer_permission")
	}
	for i, ref := range f.Namespaces {
		if i >= int(f.NamespaceCount) {
			if ref != (NamespaceReference{}) {
				return CBORFailure("credential_namespace_extra")
			}
			continue
		}
		found := false
		for _, expected := range p.namespaces[:p.count] {
			found = found || ref == expected
		}
		for _, prior := range f.Namespaces[:i] {
			if prior.Tenant == ref.Tenant && prior.Authority == ref.Authority {
				return CBORFailure("credential_namespace_binding")
			}
		}
		if !found {
			return CBORFailure("credential_namespace_binding")
		}
	}
	end, err := p.rules.cohortEnd(f.Scope.Cohort)
	if err != nil {
		return err
	}
	impact, err := p.rules.mature(1, f.Scope.Cohort)
	if err != nil {
		return err
	}
	if f.Scope.IssuedMS < end-p.rules.duration || f.Scope.IssuedMS >= end || f.Scope.ExpiresMS > impact {
		return CBORFailure("revocation_credential_impact")
	}
	return nil
}

func (p *DirectIssuePolicy) CheckFacts(f DirectIssueFacts) error {
	if err := p.CheckHistoricalFacts(f); err != nil {
		return err
	}
	credential := &Credential{scope: f.Scope, key: p.issuer.permission.Key, lease: f.LeaseID, admissionEnd: f.InitiationNotAfterMS, facts: CredentialStateFacts{Cohort: f.Scope.Cohort, HardDeadlineMS: f.Scope.ExpiresMS, PolicyID: p.policy.id, PolicyRevision: p.policy.revision, class: 1}}
	if err := p.trust.Issuer(p.issuer.permission, f.Scope); err != nil {
		return err
	}
	if err := p.trust.Policy(p.policy); err != nil {
		return err
	}
	validation, err := p.trust.ResolveCredential(credential)
	if err != nil {
		return err
	}
	r := p.policy.Requirements()
	_, _, err = validation.Namespace.CheckDetachedCredential(credential, p.issuer.permission, r.StalenessMS, r.SignerLifetimeMS, f.Scope.ExpiresMS)
	if err != nil {
		return err
	}
	now, err := p.trust.clock.Sample()
	if err != nil {
		return err
	}
	return credential.CheckAdmission(now.Interval)
}

// CopyCohortEvidence copies the original complete immutable policy segment
// covering this issuance. Its shared issuer authorization is in Configuration.
func (p *DirectIssuePolicy) CopyCohortEvidence(f DirectIssueFacts, dst []byte) (int, error) {
	if err := p.CheckFacts(f); err != nil {
		return 0, err
	}
	p.trust.mu.Lock()
	n := p.trust.namespace
	p.trust.mu.Unlock()
	if n == nil {
		return 0, CBORFailure("revocation_namespace_owner")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.active == nil {
		return 0, CBORFailure("revocation_state_owner")
	}
	w := n.active.workspace
	w.mu.Lock()
	defer w.mu.Unlock()
	segments := w.segments[1]
	i := sort.Search(len(segments), func(i int) bool {
		return segments[i].last >= f.Scope.Cohort
	})
	if i == len(segments) || segments[i].first > f.Scope.Cohort {
		return 0, CBORFailure("revocation_segment_missing")
	}
	wire := segments[i].value.Encoded()
	if len(wire) > len(dst) {
		return 0, CBORFailure("encoder_capacity")
	}
	return copy(dst, wire), nil
}

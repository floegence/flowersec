package protocolv4

import (
	"bytes"
	"math"
	"unsafe"
)

// CredentialPolicy retains the complete immutable independently trusted
// policy mapping. Parsing proves syntax only; the Environment must resolve
// it from the credential's exact namespace/reference before binding it.
type CredentialPolicy struct {
	bytes                               []byte
	id                                  string
	revision, staleness, signerLifetime uint64
}

type CredentialRequirements struct {
	StalenessMS, SignerLifetimeMS uint64
}

func CredentialPolicyBackingBytes() (uint64, error) {
	limit, err := SchemaByteLimit("CredentialRevocationPolicy")
	if err != nil {
		return 0, err
	}
	decoder, err := DecoderBackingBytes(limit, limit)
	if err != nil {
		return 0, err
	}
	return decoder + 2*uint64(limit) + uint64(unsafe.Sizeof(CredentialPolicy{})), nil
}

func NewCredentialPolicy(original []byte) (*CredentialPolicy, error) {
	d, err := boundedMap(original, "CredentialRevocationPolicy")
	if err != nil {
		return nil, err
	}
	defer d.Release()
	root := d.Root()
	id, _ := root.Named("CredentialRevocationPolicy", "revocation_policy_id").Text()
	return &CredentialPolicy{bytes: bytes.Clone(d.Bytes()), id: id,
		revision:       valueUint(root, "CredentialRevocationPolicy", "revocation_policy_revision"),
		staleness:      valueUint(root, "CredentialRevocationPolicy", "max_staleness_ms"),
		signerLifetime: valueUint(root, "CredentialRevocationPolicy", "max_head_signer_lifetime_ms")}, nil
}

func (p *CredentialPolicy) Matches(original []byte) bool {
	return p != nil && bytes.Equal(p.bytes, original)
}
func (p *CredentialPolicy) Reference() (string, uint64) { return p.id, p.revision }
func (p *CredentialPolicy) Requirements() CredentialRequirements {
	return CredentialRequirements{p.staleness, p.signerLifetime}
}

// ResolvePolicies applies the original parent's envelope and the complete
// role-local numeric intersection. It does not order policy names/revisions
// or let an activation proof introduce an independent competing policy.
func (e *EndpointCredentials) ResolvePolicies(policies []*CredentialPolicy) (CredentialRequirements, error) {
	result := CredentialRequirements{math.MaxUint64, math.MaxUint64}
	if e == nil || len(policies) != e.count {
		return result, CBORFailure("credential_policy_count")
	}
	for i, policy := range policies {
		credential := e.credentials[i]
		if policy == nil || policy.staleness == 0 || policy.signerLifetime == 0 || policy.id != credential.facts.PolicyID || policy.revision != credential.facts.PolicyRevision {
			return result, CBORFailure("credential_policy_reference")
		}
		for _, earlier := range policies[:i] {
			if policy.id == earlier.id && policy.revision == earlier.revision && !bytes.Equal(policy.bytes, earlier.bytes) {
				return result, CBORFailure("credential_policy_equivocation")
			}
		}
		if i != 0 && (policies[0].staleness > policy.staleness || policies[0].signerLifetime > policy.signerLifetime) {
			return result, CBORFailure("credential_policy_parent_envelope")
		}
		result.StalenessMS = min(result.StalenessMS, policy.staleness)
		result.SignerLifetimeMS = min(result.SignerLifetimeMS, policy.signerLifetime)
	}
	return result, nil
}

// CheckPublication is a pre-consumption check of the immutable publishing
// envelope, independent of a currently short or nearly expired delegation.
func (r *NamespaceRules) CheckPublication(requirement CredentialRequirements) error {
	if r == nil || requirement.StalenessMS == 0 || requirement.SignerLifetimeMS == 0 {
		return CBORFailure("revocation_requirement")
	}
	if r.signerLife > requirement.SignerLifetimeMS {
		return CBORFailure("revocation_policy_incompatible")
	}
	return nil
}

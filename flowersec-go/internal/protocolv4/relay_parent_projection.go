package protocolv4

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// RelayParentKey identifies one original public selection. It is an index,
// never permission to create a projection or replace its signed Grant bytes.
type RelayParentKey struct {
	Tenant                            string
	Issuer, Lease, Candidate, Attempt [16]byte
}

type RelayActivationSelection struct {
	Source, WinnerAuthority             string
	ActivationDigest, CandidateSet      [32]byte
	IssuedAt, ActivationEnd, SessionEnd uint64
}

// RelayIssuerMapping is independent local trust configuration. In particular,
// its parent -> activation/once -> Grant issuer links must not be synthesized
// from the Grant being authenticated. All roles and namespaces are exact.
type RelayIssuerMapping struct {
	Parent                                            NamespaceReference
	ParentIssuer                                      [16]byte
	ParentKey                                         [32]byte
	Activation                                        ActivationTrustBinding
	Grants                                            [2]RelayGrantIssuer
	Service, RelayAudience, EndpointAudience, Profile string
}

type RelayGrantIssuer struct {
	Namespace NamespaceReference
	Issuer    [16]byte
	Key       [32]byte
}

// RelayParentProjection is made at the original issuer/control boundary from
// the full parent and its original activation plus both leg Grants. A relay
// receives only this detached public object: no Artifact bytes, PSK, signer,
// endpoint admission, secret session nonce, or publication capability.
type RelayParentProjection struct {
	parent          *Credential
	activation      *ActivationAuthority
	grants          [2]*Credential
	parentReference [32]byte
	relayIdentity   [32]byte
	proof           []byte
	grantBytes      [2][]byte
}

func RelayParentProjectionBackingBytes() (uint64, error) {
	endpoint, err := EndpointCredentialsBackingBytes()
	if err != nil {
		return 0, err
	}
	activation, err := ActivationAuthorityBackingBytes()
	if err != nil {
		return 0, err
	}
	binding, err := ActivationBindingBackingBytes()
	if err != nil {
		return 0, err
	}
	grant, err := SchemaByteLimit("Grant")
	if err != nil {
		return 0, err
	}
	proof, err := SchemaByteLimit("ActivationAuthorization")
	if err != nil {
		return 0, err
	}
	return uint64(unsafe.Sizeof(RelayParentProjection{})) + 2*endpoint + activation + binding + uint64(2*grant+proof), nil
}

// NewRelayParentProjection must run inside the issuer's admitted original
// material owner. Installation is reserved for its committed issuance/TxB
// record; this constructor checks binding, not a durable publication receipt.
// BindActivation already checked the complete pool selection, including direct
// alternatives. The public candidate-set digest therefore remains unchanged.
func NewRelayParentProjection(artifact *SignedMap, activation *ActivationAuthority, client, server *SignedMap, grants [2]*SignedMap, relay *SignedMap) (*RelayParentProjection, error) {
	if activation == nil || activation.binding == nil {
		return nil, ErrHopAuthContext
	}
	var closures [2]*EndpointCredentials
	for side := 0; side < 2; side++ {
		closure, err := BindEndpointCredentials(Direction(side), artifact, activation.binding.winner.Index, client, server, grants[side], relay)
		if err != nil {
			return nil, err
		}
		if !closure.tunnel {
			return nil, ErrHopAuthContext
		}
		if err = closure.MatchActivation(activation); err != nil {
			return nil, err
		}
		closures[side] = closure
	}
	first, second := grants[0].Field("parent_ref").Encoded(), grants[1].Field("parent_ref").Encoded()
	if len(first) == 0 || !bytes.Equal(first, second) {
		return nil, ErrHopAuthContext
	}
	if !bytes.Equal(grants[0].Field("pairing_id").Encoded(), grants[1].Field("pairing_id").Encoded()) || closures[0].credentials[3].scope.Service != closures[1].credentials[3].scope.Service || closures[0].credentials[3].scope.Audience != closures[1].credentials[3].scope.Audience {
		return nil, ErrHopAuthContext
	}
	p := &RelayParentProjection{parent: closures[0].credentials[0], activation: activation, grants: [2]*Credential{closures[0].credentials[3], closures[1].credentials[3]}, parentReference: sha256.Sum256(first), relayIdentity: closures[0].credentials[4].facts.Digest}
	for side, grant := range grants {
		wire, err := grant.Bytes()
		if err != nil {
			return nil, err
		}
		p.grantBytes[side] = wire
	}
	return p.Clone(), nil
}

func cloneRelayCredential(c *Credential) *Credential {
	copy := *c
	scope := &copy.scope
	for _, v := range []*string{&scope.Schema, &scope.Tenant, &scope.Authority, &scope.Audience, &scope.Subject, &scope.Profile, &scope.Service, &scope.ParentAuthority, &copy.facts.PolicyID} {
		*v = strings.Clone(*v)
	}
	return &copy
}

// Clone is charged by RelayParentProjectionBackingBytes before it is called.
// The only shared object is the immutable NamespaceRules from the caller's
// separately retained Environment trust dependency.
func (p *RelayParentProjection) Clone() *RelayParentProjection {
	if p == nil || p.parent == nil || p.activation == nil || p.grants[0] == nil || p.grants[1] == nil {
		return nil
	}
	result := *p
	result.parent = cloneRelayCredential(p.parent)
	result.proof = bytes.Clone(p.proof)
	for i, g := range p.grants {
		result.grants[i] = cloneRelayCredential(g)
		result.grantBytes[i] = bytes.Clone(p.grantBytes[i])
	}
	a := *p.activation
	b := *a.binding
	for _, v := range []*string{&b.tenant, &b.audience, &b.authority, &b.signingKey, &b.profile, &b.source, &b.winnerAuthority} {
		*v = strings.Clone(*v)
	}
	// This is not the endpoint's Noise material or Session nonce projection.
	b.sessionNonce = [32]byte{}
	a.binding = &b
	a.authority, a.delegation = bytes.Clone(a.authority), bytes.Clone(a.delegation)
	for _, v := range []*string{&a.trust.Tenant, &a.trust.AuthorityNamespace, &a.trust.SigningKeyID, &a.trust.SpendAuthority, &a.trust.WinnerAuthority} {
		*v = strings.Clone(*v)
	}
	result.activation = &a
	return &result
}

func (p *RelayParentProjection) Key() (RelayParentKey, error) {
	if p == nil || p.parent == nil || p.activation == nil {
		return RelayParentKey{}, ErrHopAuthContext
	}
	b := p.activation.binding
	return RelayParentKey{Tenant: b.tenant, Issuer: b.issuer, Lease: b.lease, Candidate: b.winner.CandidateID, Attempt: b.attempt}, nil
}

func (p *RelayParentProjection) MatchMapping(mapping RelayIssuerMapping) error {
	if _, err := p.Key(); err != nil {
		return err
	}
	s := p.parent.scope
	if mapping.Parent.Tenant != s.Tenant || mapping.Parent.Authority != s.Authority || mapping.Parent.Generation != s.Generation || mapping.Parent.CapacityDigest != s.CapacityDigest || mapping.Parent.RoleMask != 7 || mapping.ParentIssuer != s.Issuer || mapping.ParentKey != p.parent.key || mapping.Activation != p.activation.trust || mapping.EndpointAudience != s.Audience || mapping.Profile != s.Profile || mapping.Service == "" || mapping.RelayAudience == "" {
		return ErrHopAuthContext
	}
	for side, g := range p.grants {
		expected := mapping.Grants[side]
		s := g.scope
		if expected.Namespace.Tenant != s.Tenant || expected.Namespace.Authority != s.Authority || expected.Namespace.Generation != s.Generation || expected.Namespace.CapacityDigest != s.CapacityDigest || expected.Namespace.RoleMask != uint64(4|1<<side) || expected.Namespace.RoleMask != s.Role || expected.Issuer != s.Issuer || expected.Key != g.key || mapping.Service != s.Service || mapping.RelayAudience != s.Audience {
			return ErrHopAuthContext
		}
	}
	return nil
}

// CheckCurrent reevaluates the original activation delegation's independent
// trust and revocation identity as well as the parent. It intentionally uses
// the Session horizon here; each new claim applies the shorter initiation cap.
func (p *RelayParentProjection) CheckCurrent(v CredentialValidation, environment resourcev4.Reference) error {
	if _, err := p.Key(); err != nil {
		return err
	}
	if v.Namespace == nil || v.Policy == nil {
		return ErrHopAuthContext
	}
	if err := v.Namespace.reservation.CheckSameEnvironment(environment); err != nil {
		return err
	}
	cap := p.activation.binding.sessionEnd
	if _, err := v.Namespace.checkBoundCredential(p.parent, v.Issuer, v.Policy, v.Policy.Requirements(), cap); err != nil {
		return err
	}
	_, err := v.Namespace.CheckDetachedActivation(p.activation, p.parent, v.Issuer, v.Policy.staleness, v.Policy.signerLifetime, cap)
	return err
}

func (p *RelayParentProjection) Resolve(facts RelayClaimFacts) (RelayActivationSelection, error) {
	f, err := facts.Fields()
	if err != nil {
		return RelayActivationSelection{}, err
	}
	key, err := p.Key()
	if err != nil {
		return RelayActivationSelection{}, err
	}
	if key != (RelayParentKey{Tenant: f.Tenant, Issuer: f.Issuer, Lease: f.Lease, Candidate: f.Candidate, Attempt: f.Attempt}) || f.EndpointRole > ServerToClient || p.grants[f.EndpointRole].facts.Digest != f.Grant || p.parentReference != f.ParentReference {
		return RelayActivationSelection{}, ErrHopAuthContext
	}
	b := p.activation.binding
	if b.winner.RouteDigest != f.Route || b.artifactDigest != f.Artifact || b.clientDigest != f.ClientIdentity || b.serverDigest != f.ServerIdentity || b.profile != f.Profile || b.audience != f.EndpointAudience {
		return RelayActivationSelection{}, ErrHopAuthContext
	}
	return RelayActivationSelection{Source: b.source, WinnerAuthority: p.activation.trust.WinnerAuthority, ActivationDigest: b.proofDigest, CandidateSet: b.candidateSetDigest, IssuedAt: b.issuedAt, ActivationEnd: b.activationEnd, SessionEnd: b.sessionEnd}, nil
}

// RelayClaimKey reads only a verified immutable possession claim.
func RelayClaimKey(f RelayClaimFacts) (RelayParentKey, error) {
	fields, err := f.Fields()
	if err != nil {
		return RelayParentKey{}, err
	}
	return RelayParentKey{Tenant: fields.Tenant, Issuer: fields.Issuer, Lease: fields.Lease, Candidate: fields.Candidate, Attempt: fields.Attempt}, nil
}

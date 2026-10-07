package protocolv4

import (
	"context"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// Three common owners plus two Grant/relay owners for each of sixteen routes.
const MaxArtifactIssueNamespaces = 67

type ArtifactIssueRequest = DirectIssueRequest
type ArtifactIssueFacts = DirectIssueFacts
type ArtifactIssuePermit = DirectIssuePermit

type ArtifactIssueAuthority interface {
	BeginArtifactIssue(context.Context, ArtifactIssueRequest, ArtifactIssueFacts) (ArtifactIssuePermit, error)
}

// ArtifactIssueRetention reserves the original material owner before durable
// issuance begins. Publish receives the complete signed Artifact only after
// its original issuance permit commits. Implementations must not reconstruct
// an issuance or activation capability from a retained digest.
type ArtifactIssueRetention interface {
	ReserveArtifact(context.Context, ArtifactIssueRequest, ArtifactIssueFacts) (ArtifactRetentionSlot, error)
}

// Close joins this issuance borrow; published material retains its separately
// admitted owner. Failure may discard local material but never refunds the
// durable issuance obligation. Calls are serialized by the original issuer.
type ArtifactRetentionSlot interface {
	Check(context.Context) error
	Publish(context.Context, []byte) error
	Close()
}

type artifactIssueAuthorityAdapter struct{ authority ArtifactIssueAuthority }

func (a artifactIssueAuthorityAdapter) BeginDirectIssue(ctx context.Context, request DirectIssueRequest, facts DirectIssueFacts) (DirectIssuePermit, error) {
	return a.authority.BeginArtifactIssue(ctx, request, facts)
}

// Each original leg names independently installed Grant policy and the actual
// relay certificate/trust owner. These inputs do not contain a Grant signature,
// activation capability or a peer-selected namespace/issuer mapping.
type ArtifactTunnelLegIssueConfig struct {
	Grant                  CredentialValidation
	Service, RelayAudience string
	RelayCertificate       []byte
	RelayTrust             *NamespaceTrustStore
}

type ArtifactTunnelIssueConfig struct {
	Legs [2]ArtifactTunnelLegIssueConfig
}

// Base contains the fixed endpoint identities, canonical candidates, contract,
// parent issuer and lifetimes. Base.Authority must be nil; Authority receives
// the complete union, including tunnel role masks, before signing. Tunnels is
// indexed by the original candidate index, with nil for each direct candidate.
type ArtifactIssuerConfig struct {
	Base      DirectIssuerConfig
	Tunnels   [16]*ArtifactTunnelIssueConfig
	Authority ArtifactIssueAuthority
	Retention ArtifactIssueRetention
}

type ArtifactIssuer struct{ core *DirectIssuer }

type artifactTunnelLeg struct {
	grant              CredentialValidation
	service, audience  string
	relay              *Credential
	relayTrust         *NamespaceTrustStore
	grantNamespace     NamespaceReference
	grantRef, relayRef resourcev4.Reference
}

type artifactTunnelIssuance struct {
	present    [16]bool
	legs       [16][2]artifactTunnelLeg
	namespaces [MaxArtifactIssueNamespaces]NamespaceReference
	count      uint8
	owners     [MaxArtifactIssueNamespaces]*LiveNamespace
	ownerRefs  [MaxArtifactIssueNamespaces]NamespaceReference
	ownerCount uint8
}

func ArtifactIssuerCharge(c ArtifactIssuerConfig) (resourcev4.Vector, error) {
	if c.Authority == nil || c.Base.Authority != nil {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	base := c.Base
	base.Authority = artifactIssueAuthorityAdapter{c.Authority}
	charge, err := DirectIssuerCharge(base)
	if err != nil {
		return charge, err
	}
	certificate, err := CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return charge, err
	}
	legs := uint64(0)
	for index, tunnel := range c.Tunnels {
		if tunnel == nil {
			continue
		}
		if index >= len(c.Base.Candidates) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		for _, leg := range tunnel.Legs {
			if leg.Grant.Namespace == nil || leg.Grant.Policy == nil || leg.Grant.Issuer.Schema != "Grant" || leg.Grant.Issuer.Key == ([32]byte{}) || leg.RelayTrust == nil || len(leg.RelayCertificate) == 0 || len(leg.RelayCertificate) > 8192 || len(leg.Service) == 0 || len(leg.Service) > 128 || len(leg.RelayAudience) == 0 || len(leg.RelayAudience) > 128 {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
			legs++
		}
	}
	// The shared core already owns both constructor codecs. Retained relay
	// credentials, future Grant checks and all dependency copies remain charged.
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(ArtifactIssuer{})) + uint64(unsafe.Sizeof(artifactTunnelIssuance{})) + legs*(certificate+1024) + 4*uint64(unsafe.Sizeof(LiveGrantPreparation{})) + MaxArtifactIssueNamespaces*512})
}

func NewArtifactIssuer(c ArtifactIssuerConfig, reservation, dependencies resourcev4.Reference) (*ArtifactIssuer, error) {
	charge, err := ArtifactIssuerCharge(c)
	if err != nil {
		return nil, err
	}
	base := c.Base
	base.Authority = artifactIssueAuthorityAdapter{c.Authority}
	core, err := newArtifactIssuerCore(base, &c.Tunnels, charge, reservation, dependencies)
	if err != nil {
		return nil, err
	}
	core.retention = c.Retention
	return &ArtifactIssuer{core: core}, nil
}

func (s *ArtifactIssuer) IssueArtifactBytes(ctx context.Context, request ArtifactIssueRequest, dst []byte) (int, error) {
	if s == nil || s.core == nil {
		return 0, resourcev4.ErrClosed
	}
	return s.core.IssueArtifactBytes(ctx, request, dst)
}

// NamespaceClosure returns detached public configuration for host admission.
// It is not a namespace read permission or a durable issuance reservation.
func (s *ArtifactIssuer) NamespaceClosure() ([MaxArtifactIssueNamespaces]NamespaceReference, uint8, error) {
	if s == nil || s.core == nil {
		return [MaxArtifactIssueNamespaces]NamespaceReference{}, 0, resourcev4.ErrClosed
	}
	s.core.mu.Lock()
	defer s.core.mu.Unlock()
	if s.core.closed {
		return [MaxArtifactIssueNamespaces]NamespaceReference{}, 0, resourcev4.ErrClosed
	}
	refs, count := s.core.namespaceClosure()
	return refs, count, nil
}

func (s *ArtifactIssuer) ReferenceFor(clock *timev4.Clock, environment resourcev4.Reference) (resourcev4.Reference, error) {
	if s == nil || s.core == nil {
		return resourcev4.Reference{}, resourcev4.ErrClosed
	}
	return s.core.ReferenceFor(clock, environment)
}
func (s *ArtifactIssuer) Close() {
	if s != nil && s.core != nil {
		s.core.Close()
	}
}
func (s *ArtifactIssuer) WaitCleanup(ctx context.Context) error {
	if s == nil || s.core == nil {
		return resourcev4.ErrClosed
	}
	return s.core.WaitCleanup(ctx)
}
func (*ArtifactIssuer) String() string   { return "ArtifactIssuer(<redacted>)" }
func (*ArtifactIssuer) GoString() string { return "ArtifactIssuer(<redacted>)" }

func validIssueNamespace(ref NamespaceReference) bool {
	return len(ref.Tenant) > 0 && len(ref.Tenant) <= 128 && len(ref.Authority) > 0 && len(ref.Authority) <= 128 && ref.Generation != 0 && ref.CapacityDigest != ([32]byte{}) && ref.RoleMask != 0 && ref.RoleMask&^uint64(7) == 0
}

func addIssueNamespace(refs *[MaxArtifactIssueNamespaces]NamespaceReference, count *uint8, ref NamespaceReference) error {
	if !validIssueNamespace(ref) {
		return CBORFailure("credential_namespace_binding")
	}
	for i := range refs[:*count] {
		prior := &refs[i]
		if prior.Tenant != ref.Tenant || prior.Authority != ref.Authority {
			continue
		}
		if prior.Generation != ref.Generation || prior.CapacityDigest != ref.CapacityDigest {
			return CBORFailure("credential_namespace_binding")
		}
		prior.RoleMask |= ref.RoleMask
		return nil
	}
	if int(*count) == len(refs) {
		return CBORFailure("credential_namespace_count")
	}
	ref.Tenant, ref.Authority = strings.Clone(ref.Tenant), strings.Clone(ref.Authority)
	refs[*count] = ref
	(*count)++
	return nil
}

func issueCredentialNamespace(scope CredentialScope, mask uint64) NamespaceReference {
	return NamespaceReference{Tenant: scope.Tenant, Authority: scope.Authority, Generation: scope.Generation, CapacityDigest: scope.CapacityDigest, RoleMask: mask}
}

func (t *artifactTunnelIssuance) addOwner(ref NamespaceReference, owner *LiveNamespace) error {
	if owner == nil {
		return CBORFailure("credential_namespace_owner")
	}
	for i, prior := range t.ownerRefs[:t.ownerCount] {
		if prior.Tenant == ref.Tenant && prior.Authority == ref.Authority {
			if prior.Generation != ref.Generation || prior.CapacityDigest != ref.CapacityDigest || t.owners[i] != owner {
				return CBORFailure("credential_namespace_owner")
			}
			return nil
		}
	}
	if int(t.ownerCount) == len(t.owners) {
		return CBORFailure("credential_namespace_count")
	}
	t.ownerRefs[t.ownerCount], t.owners[t.ownerCount] = ref, owner
	t.ownerCount++
	return nil
}

func issuerTrustNamespace(trust *NamespaceTrustStore) *LiveNamespace {
	trust.mu.Lock()
	defer trust.mu.Unlock()
	return trust.namespace
}

func (t *artifactTunnelIssuance) checkOwner(ref NamespaceReference, owner *LiveNamespace) error {
	for i, expected := range t.ownerRefs[:t.ownerCount] {
		if expected.Tenant == ref.Tenant && expected.Authority == ref.Authority {
			if expected.Generation == ref.Generation && expected.CapacityDigest == ref.CapacityDigest && t.owners[i] == owner {
				return nil
			}
			break
		}
	}
	return CBORFailure("credential_namespace_owner")
}

func (s *DirectIssuer) prepareArtifactTunnels(config [16]*ArtifactTunnelIssueConfig, decoder *Decoder, codec *SignedMapCodec) error {
	t := &artifactTunnelIssuance{}
	s.tunnels = t
	parent := NamespaceReference{Tenant: s.c.Tenant, Authority: s.rules.authority, Generation: s.c.Generation, CapacityDigest: s.rules.capacityDigest, RoleMask: 3}
	if err := t.addOwner(parent, issuerTrustNamespace(s.c.Trust[0])); err != nil {
		return err
	}
	for i, cert := range s.certificates {
		if err := t.addOwner(issueCredentialNamespace(cert.scope, 3), issuerTrustNamespace(s.c.Trust[i+1])); err != nil {
			return err
		}
	}
	for index, input := range config {
		if input == nil {
			continue
		}
		t.present[index] = true
		for side, input := range input.Legs {
			leg := &t.legs[index][side]
			leg.grant, leg.relayTrust = input.Grant, input.RelayTrust
			leg.grant.Issuer.Schema = strings.Clone(input.Grant.Issuer.Schema)
			leg.service, leg.audience = strings.Clone(input.Service), strings.Clone(input.RelayAudience)
			if input.RelayTrust.clock != s.c.Clock {
				return resourcev4.ErrConfiguration
			}
			var err error
			leg.relayRef, err = input.RelayTrust.ReferenceFor(s.c.Clock, s.reservation)
			if err != nil {
				return err
			}
			n := input.Grant.Namespace
			if err = n.reservation.CheckSameEnvironment(s.reservation); err != nil {
				return err
			}
			leg.grantRef, err = n.reservation.Borrow()
			if err != nil {
				return err
			}
			n.mu.Lock()
			if n.clock != s.c.Clock || n.rules == nil || n.rules.tenant != s.c.Tenant {
				n.mu.Unlock()
				return resourcev4.ErrConfiguration
			}
			err = n.checkAvailable()
			leg.grantNamespace = NamespaceReference{Tenant: strings.Clone(n.rules.tenant), Authority: strings.Clone(n.rules.authority), Generation: n.observed.generation, CapacityDigest: n.rules.capacityDigest, RoleMask: 4 | 1<<uint64(side)}
			n.mu.Unlock()
			if err != nil {
				return err
			}
			if err = t.addOwner(leg.grantNamespace, n); err != nil {
				return err
			}
			doc, err := decoder.DecodeMap(input.RelayCertificate, "IdentityCertificate", DecodeContext{})
			if err != nil {
				return err
			}
			id, _ := doc.Root().Named("IdentityCertificate", "issuer_key_id").ByteString()
			issuer := [16]byte(id)
			doc.Release()
			key, err := input.RelayTrust.CredentialKey("IdentityCertificate", issuer)
			if err != nil {
				return err
			}
			signed, err := codec.Verify(input.RelayCertificate, key, DecodeContext{})
			if err != nil {
				return err
			}
			leg.relay, err = signed.DetachCredential()
			signed.Release()
			if err != nil {
				return err
			}
			scope := leg.relay.scope
			if scope.Role != 2 || scope.Tenant != s.c.Tenant || scope.Audience != leg.audience || scope.Profile != s.c.CryptoProfile {
				return CBORFailure("credential_identity_binding")
			}
			if err = t.addOwner(issueCredentialNamespace(scope, 4|1<<uint64(side)), issuerTrustNamespace(input.RelayTrust)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *DirectIssuer) checkArtifactCandidate(index int, candidate Value) error {
	tunnel := valueUint(candidate, "Candidate", "path_kind") == 1
	if s.tunnels == nil {
		if tunnel {
			return CBORFailure("credential_hop_presence")
		}
		return s.checkCandidateClosure(candidate)
	}
	t := s.tunnels
	if tunnel != t.present[index] {
		return CBORFailure("credential_hop_presence")
	}
	var refs [MaxArtifactIssueNamespaces]NamespaceReference
	var count uint8
	mask := uint64(3)
	if tunnel {
		mask = 7
	}
	if err := addIssueNamespace(&refs, &count, NamespaceReference{Tenant: s.c.Tenant, Authority: s.rules.authority, Generation: s.c.Generation, CapacityDigest: s.rules.capacityDigest, RoleMask: mask}); err != nil {
		return err
	}
	for _, cert := range s.certificates {
		if err := addIssueNamespace(&refs, &count, issueCredentialNamespace(cert.scope, mask)); err != nil {
			return err
		}
	}
	if tunnel {
		for side, leg := range t.legs[index] {
			if err := addIssueNamespace(&refs, &count, leg.grantNamespace); err != nil {
				return err
			}
			if err := addIssueNamespace(&refs, &count, issueCredentialNamespace(leg.relay.scope, 4|1<<uint64(side))); err != nil {
				return err
			}
		}
	}
	actual := candidate.Named("Candidate", "revocation_namespace_refs")
	if actual.Len() != int(count) {
		return CBORFailure("credential_namespace_binding")
	}
	for i := 0; i < actual.Len(); i++ {
		ref := namespaceReference(actual.Index(i))
		found := false
		for _, expected := range refs[:count] {
			found = found || ref == expected
		}
		for j := 0; j < i; j++ {
			prior := namespaceReference(actual.Index(j))
			if ref.Tenant == prior.Tenant && ref.Authority == prior.Authority {
				return CBORFailure("credential_namespace_binding")
			}
		}
		if !found {
			return CBORFailure("credential_namespace_binding")
		}
	}
	for _, ref := range refs[:count] {
		if err := addIssueNamespace(&t.namespaces, &t.count, ref); err != nil {
			return err
		}
	}
	return nil
}

func (s *DirectIssuer) checkArtifactTunnels(parent *Credential) (err error) {
	t := s.tunnels
	if t == nil {
		return nil
	}
	var parentRequirement CredentialRequirements
	if parent != nil {
		validation, err := s.c.Trust[0].ResolveCredential(parent)
		if err != nil {
			return err
		}
		parentRequirement = validation.Policy.Requirements()
		if err = t.checkOwner(issueCredentialNamespace(parent.scope, 3), validation.Namespace); err != nil {
			return err
		}
	}
	for i, cert := range s.certificates {
		validation, err := s.c.Trust[i+1].ResolveCredential(cert)
		if err != nil {
			return err
		}
		if err = t.checkOwner(issueCredentialNamespace(cert.scope, 3), validation.Namespace); err != nil {
			return err
		}
	}
	for index, present := range t.present {
		if !present {
			continue
		}
		for side, leg := range t.legs[index] {
			for _, ref := range []resourcev4.Reference{leg.grantRef, leg.relayRef} {
				if err := ref.Check(); err != nil {
					return err
				}
			}
			if err := s.checkCredential(leg.relay, leg.relayTrust); err != nil {
				return err
			}
			validation, err := leg.relayTrust.ResolveCredential(leg.relay)
			if err != nil {
				return err
			}
			if err = t.checkOwner(issueCredentialNamespace(leg.relay.scope, 4|1<<uint64(side)), validation.Namespace); err != nil {
				return err
			}
			if parent == nil {
				continue
			}
			if parent.scope.ExpiresMS > leg.relay.scope.ExpiresMS {
				return CBORFailure("credential_lifetime")
			}
			grant, err := DeriveLiveGrantPreparation(parent, Direction(side), leg.grant, LiveGrantPreparationConfig{Service: leg.service, Audience: leg.audience, IssuedAt: parent.scope.IssuedMS, NotAfterMS: parent.scope.ExpiresMS}, s.reservation)
			if err != nil {
				return err
			}
			if issueCredentialNamespace(grant.Scope, 4|1<<uint64(side)) != leg.grantNamespace {
				return CBORFailure("credential_namespace_binding")
			}
			for _, policy := range []*CredentialPolicy{leg.grant.Policy, validation.Policy} {
				requirement := policy.Requirements()
				if parentRequirement.StalenessMS > requirement.StalenessMS || parentRequirement.SignerLifetimeMS > requirement.SignerLifetimeMS {
					return CBORFailure("credential_policy_parent_envelope")
				}
			}
		}
	}
	return nil
}

func (t *artifactTunnelIssuance) release() {
	if t == nil {
		return
	}
	for i := range t.legs {
		for side := range t.legs[i] {
			leg := &t.legs[i][side]
			leg.grantRef.Release()
			leg.relayRef.Release()
			*leg = artifactTunnelLeg{}
		}
	}
	clear(t.namespaces[:])
	clear(t.owners[:])
	clear(t.ownerRefs[:])
}

package controlv4

import (
	"bytes"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// ArtifactIssueSourceTunnel fixes the expected original candidate and role,
// independent Grant validation and relay identity before issuer I/O. The future
// Grant's initial issue/session bounds come from the newly verified Artifact;
// the authority must use that same original preparation when creating its TxA.
type ArtifactIssueSourceTunnel struct {
	CandidateIndex         uint64
	Role                   protocolv4.Direction
	Grant                  protocolv4.CredentialValidation
	Service, RelayAudience string
	RelayCertificate       []byte
	RelayTrust             *protocolv4.NamespaceTrustStore
}

type ArtifactIssueSourceConfig struct {
	Base    DirectIssueSourceConfig
	Tunnels []ArtifactIssueSourceTunnel
}

// The shared source owns the same original admission position and lease token.
// Its constructor fixes /issue/artifact; it never falls back to /issue/direct.
type ArtifactIssueSource = DirectIssueSource

type artifactIssueSourceTunnels struct {
	entries      [sessionv4.MaxLeaseTunnelMaterials]ArtifactIssueSourceTunnel
	credentials  [sessionv4.MaxLeaseTunnelMaterials]*protocolv4.Credential
	grantRefs    [sessionv4.MaxLeaseTunnelMaterials]resourcev4.Reference
	relayRefs    [sessionv4.MaxLeaseTunnelMaterials]resourcev4.Reference
	preparations [sessionv4.MaxLeaseTunnelMaterials]protocolv4.LiveGrantPreparation
	material     [sessionv4.MaxLeaseTunnelMaterials]sessionv4.ArtifactLeaseTunnelBytes
	owners       sessionv4.MaterialNamespaceSet
	codec        *protocolv4.SignedMapCodec
	count        int
}

func ArtifactIssueSourceCharge(c ArtifactIssueSourceConfig) (resourcev4.Vector, error) {
	charge, err := DirectIssueSourceCharge(c.Base)
	if err != nil {
		return charge, err
	}
	if len(c.Tunnels) > sessionv4.MaxLeaseTunnelMaterials {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	for i, entry := range c.Tunnels {
		if entry.CandidateIndex >= 16 || entry.Role > protocolv4.ServerToClient || entry.Grant.Namespace == nil || entry.Grant.Policy == nil || entry.Grant.Issuer.Schema != "Grant" || entry.Grant.Issuer.Key == ([32]byte{}) || entry.RelayTrust == nil || len(entry.RelayCertificate) == 0 || len(entry.RelayCertificate) > 8192 || len(entry.Service) == 0 || len(entry.Service) > 128 || len(entry.RelayAudience) == 0 || len(entry.RelayAudience) > 128 ||
			i > 0 && !poolTunnelOrder(c.Tunnels[i-1].CandidateIndex, c.Tunnels[i-1].Role, entry.CandidateIndex, entry.Role) {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
	}
	codec, err := protocolv4.SignedMapBackingBytes("Artifact", c.Base.MapBytes, c.Base.MapNodes)
	if err != nil {
		return resourcev4.Vector{}, err
	}
	credential, err := protocolv4.CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	parent, err := protocolv4.CredentialBackingBytes("Artifact")
	if err != nil {
		return resourcev4.Vector{}, err
	}
	return charge.Add(resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(artifactIssueSourceTunnels{})) + codec + parent + uint64(len(c.Tunnels))*(8192+credential+2048)})
}

func NewArtifactIssueSource(c ArtifactIssueSourceConfig, reservation, providerReservation, dependencies resourcev4.Reference) (*ArtifactIssueSource, error) {
	charge, err := ArtifactIssueSourceCharge(c)
	if err != nil {
		return nil, err
	}
	tunnels := c.Tunnels
	if tunnels == nil {
		tunnels = []ArtifactIssueSourceTunnel{}
	}
	return newArtifactIssueSource(c.Base, tunnels, charge, reservation, providerReservation, dependencies)
}

func (p *DirectIssueSource) prepareArtifactSourceTunnels(entries []ArtifactIssueSourceTunnel) error {
	t := &artifactIssueSourceTunnels{count: len(entries)}
	p.tunnels = t
	var err error
	for i, trust := range p.c.Trust {
		t.owners.Owners[i], err = trust.NamespaceForPreparation(p.c.Clock, p.reservation)
		if err != nil {
			return err
		}
	}
	t.owners.Count = 3
	t.codec, err = protocolv4.NewSignedMapCodec("Artifact", p.c.MapBytes, p.c.MapNodes)
	if err != nil {
		return err
	}
	codec, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, p.c.MapNodes)
	if err != nil {
		return err
	}
	client := p.credentials[0].Scope()
	for i, input := range entries {
		entry := &t.entries[i]
		*entry = input
		entry.Service, entry.RelayAudience = strings.Clone(input.Service), strings.Clone(input.RelayAudience)
		entry.Grant.Issuer.Schema = strings.Clone(input.Grant.Issuer.Schema)
		entry.RelayCertificate = bytes.Clone(input.RelayCertificate)
		t.grantRefs[i], err = entry.Grant.Namespace.PreparationReferenceFor(p.c.Clock, p.reservation)
		if err != nil {
			return err
		}
		t.relayRefs[i], err = entry.RelayTrust.ReferenceFor(p.c.Clock, p.reservation)
		if err != nil {
			return err
		}
		cert, err := codec.VerifyCredential(entry.RelayCertificate, entry.RelayTrust)
		if err != nil {
			return err
		}
		t.credentials[i], err = cert.DetachCredential()
		cert.Release()
		if err != nil {
			return err
		}
		scope := t.credentials[i].Scope()
		if scope.Role != 2 || scope.Tenant != client.Tenant || scope.Audience != entry.RelayAudience || scope.Profile != client.Profile {
			return resourcev4.ErrConfiguration
		}
		t.owners.Owners[3+2*i] = entry.Grant.Namespace
		t.owners.Owners[4+2*i], err = entry.RelayTrust.NamespaceForPreparation(p.c.Clock, p.reservation)
		if err != nil {
			return err
		}
		t.owners.Count += 2
	}
	return p.checkArtifactSourceTunnels()
}

func (p *DirectIssueSource) checkArtifactSourceTunnels() error {
	t := p.tunnels
	if t == nil {
		return nil
	}
	for i, entry := range t.entries[:t.count] {
		for _, ref := range []resourcev4.Reference{t.grantRefs[i], t.relayRefs[i]} {
			if err := ref.Check(); err != nil {
				return err
			}
		}
		validation, err := entry.RelayTrust.ResolveCredential(t.credentials[i])
		if err != nil {
			return err
		}
		if validation.Namespace != t.owners.Owners[4+2*i] {
			return resourcev4.ErrOwner
		}
		if _, err = validation.CheckMaterialCredential(t.credentials[i], t.credentials[i].Scope().ExpiresMS, p.reservation); err != nil {
			return err
		}
	}
	return nil
}

func (p *DirectIssueSource) populateArtifactSourceTunnels(config *sessionv4.ArtifactLeaseBytesConfig) (err error) {
	t := p.tunnels
	artifact, err := t.codec.VerifyCredential(config.Artifact, p.c.Trust[0])
	if err != nil {
		return err
	}
	defer artifact.Release()
	defer func() {
		if err != nil {
			t.clearMaterial()
		}
	}()
	parent, err := artifact.DetachCredential()
	if err != nil {
		return err
	}
	candidates := artifact.Field("candidates")
	var covered [16]bool
	for i, entry := range t.entries[:t.count] {
		if entry.CandidateIndex >= uint64(candidates.Len()) {
			return resourcev4.ErrConfiguration
		}
		candidate := candidates.Index(int(entry.CandidateIndex))
		kind, _ := candidate.Named("Candidate", "path_kind").Uint()
		if kind != 1 {
			return resourcev4.ErrConfiguration
		}
		if entry.Role == protocolv4.ClientToServer {
			covered[entry.CandidateIndex] = true
		}
		scope := parent.Scope()
		t.preparations[i], err = protocolv4.DeriveLiveGrantPreparation(parent, entry.Role, entry.Grant,
			protocolv4.LiveGrantPreparationConfig{Service: entry.Service, Audience: entry.RelayAudience, IssuedAt: scope.IssuedMS, NotAfterMS: scope.ExpiresMS}, p.reservation)
		if err != nil {
			return err
		}
		t.material[i] = sessionv4.ArtifactLeaseTunnelBytes{LiveGrant: &t.preparations[i], CandidateIndex: entry.CandidateIndex,
			Role: entry.Role, RelayCertificate: entry.RelayCertificate, RelayTrust: entry.RelayTrust}
	}
	for i := 0; i < candidates.Len(); i++ {
		kind, _ := candidates.Index(i).Named("Candidate", "path_kind").Uint()
		if kind == 1 && !covered[i] {
			return resourcev4.ErrConfiguration
		}
	}
	config.Tunnels = t.material[:t.count:t.count]
	return nil
}

// PreparationNamespaceSet reports every actual local dependency before the
// original request is sent, including both roles only when explicitly supplied.
func (p *DirectIssueSource) PreparationNamespaceSet(clock *timev4.Clock, environment resourcev4.Reference) (sessionv4.MaterialNamespaceSet, error) {
	if p == nil {
		return sessionv4.MaterialNamespaceSet{}, resourcev4.ErrOwner
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.preparationNamespaceSetLocked(clock, environment)
}

// preparationNamespaceSetLocked is shared by the source advertisement and an
// admitted acquisition token. Both views read the same immutable trust owners
// while the source gate is held; neither can substitute a later generation or
// create a second namespace manager.
func (p *DirectIssueSource) preparationNamespaceSetLocked(clock *timev4.Clock, environment resourcev4.Reference) (sessionv4.MaterialNamespaceSet, error) {
	if p.closed || clock != p.c.Clock {
		return sessionv4.MaterialNamespaceSet{}, resourcev4.ErrOwner
	}
	if err := p.reservation.CheckSameEnvironment(environment); err != nil {
		return sessionv4.MaterialNamespaceSet{}, err
	}
	if err := p.shared.Check(); err != nil {
		return sessionv4.MaterialNamespaceSet{}, err
	}
	var set sessionv4.MaterialNamespaceSet
	if p.tunnels != nil {
		for i := 0; i < p.tunnels.count; i++ {
			for _, ref := range []resourcev4.Reference{p.tunnels.grantRefs[i], p.tunnels.relayRefs[i]} {
				if err := ref.Check(); err != nil {
					return set, err
				}
			}
		}
		set = p.tunnels.owners
	}
	for i, trust := range p.c.Trust {
		owner, err := trust.NamespaceForPreparation(clock, environment)
		if err != nil {
			return sessionv4.MaterialNamespaceSet{}, err
		}
		if p.tunnels != nil && set.Owners[i] != owner {
			return sessionv4.MaterialNamespaceSet{}, resourcev4.ErrOwner
		}
		set.Owners[i] = owner
	}
	if p.tunnels == nil {
		set.Count = 3
	}
	return set, nil
}

func (t *artifactIssueSourceTunnels) clearMaterial() {
	clear(t.material[:])
	clear(t.preparations[:])
}
func (t *artifactIssueSourceTunnels) release() {
	if t == nil {
		return
	}
	t.clearMaterial()
	for i := 0; i < t.count; i++ {
		clear(t.entries[i].RelayCertificate)
		t.grantRefs[i].Release()
		t.relayRefs[i].Release()
		t.entries[i] = ArtifactIssueSourceTunnel{}
		t.credentials[i] = nil
	}
	t.codec = nil
	t.owners = sessionv4.MaterialNamespaceSet{}
}

var _ sessionv4.MaterialNamespaceSetProvider = (*ArtifactIssueSource)(nil)

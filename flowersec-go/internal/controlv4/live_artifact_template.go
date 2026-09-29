package controlv4

import (
	"bytes"
	"context"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// LiveArtifactPolicy is independent deployment authorization. Its checks are
// bounded and nonblocking; Authorize runs only within the original durable TxA.
// The retained host fixes the actual material, attempt and winner itself.
type LiveArtifactPolicy interface {
	CheckLiveAuthorizationShare(identity SQLiteLiveIdentity, rate, burst uint16) error
	CheckLiveArtifact(context.Context, [32]byte, protocolv4.ArtifactIssueFacts) error
	CheckLiveSpend(SQLiteLiveIdentity, protocolv4.LiveActivationFields) error
	AuthorizeLiveArtifact(context.Context, protocolv4.LiveActivationFields) (bool, error)
}

// A server registration is obtained only for the first original plan. Check
// validates the same authenticated recipient/incarnation; Close joins its work.
// Repeated client reads neither resolve nor publish another server instruction.
type LiveArtifactServerRegistration interface {
	Configuration() (LiveServerAllowConfig, error)
	Check(context.Context) error
	Close()
}
type LiveArtifactServerResolver interface {
	PrepareLiveServerAllow(context.Context, protocolv4.LiveActivationFields, LiveArtifactServerMaterial) (LiveArtifactServerRegistration, error)
}

// Material is borrowed read-only for the resolver invocation. Its secret
// Artifact may be delivered only to the independently authenticated server.
// The adapter joins delivery and admission of the original server registration
// before returning. A deferred registration prepares its physical leg only on
// the first valid allow. A remote server derives its own local validation
// owner for GrantScope; the authority's namespace capabilities are not exported.
type LiveArtifactServerMaterial struct {
	Artifact, ClientCertificate, ServerCertificate, RelayCertificate []byte
	GrantScope                                                       protocolv4.CredentialScope
}

func (LiveArtifactServerMaterial) String() string   { return "LiveArtifactServerMaterial(<redacted>)" }
func (LiveArtifactServerMaterial) GoString() string { return "LiveArtifactServerMaterial(<redacted>)" }
func (LiveArtifactServerMaterial) MarshalJSON() ([]byte, error) {
	return []byte(`"LiveArtifactServerMaterial(<redacted>)"`), nil
}

type LiveArtifactGrantConfig struct {
	Validation        protocolv4.CredentialValidation
	Service, Audience string
	Limits            protocolv4.RelayGrantLimits
	Signer            protocolv4.MapSigner
}
type LiveArtifactTunnelConfig struct {
	Grants           [2]LiveArtifactGrantConfig
	RelayCertificate []byte
	RelayTrust       *protocolv4.NamespaceTrustStore
	Server           LiveArtifactServerResolver
}

// Configuration is supplied by the trusted host. The original client TLS
// certificate digest is bound to the same fixed endpoint pair used by issuance.
// MaxArtifacts bounds resident secret material, original plans and cleanup tails.
// Each slot additionally needs the separately returned plan reservation.
type LiveArtifactHostConfig struct {
	Clock                                *timev4.Clock
	Trust                                [3]*protocolv4.NamespaceTrustStore
	ClientCertificate, ServerCertificate []byte
	ClientCertificateDigest              [32]byte
	Delegation, OnceAuthority            []byte
	Signer                               protocolv4.MapSigner
	Tunnels                              [16]*LiveArtifactTunnelConfig
	Policy                               LiveArtifactPolicy
	MaxArtifacts                         uint16
	RuntimeBytes                         uint64
}

type liveArtifactTemplate struct {
	config      LiveArtifactHostConfig
	endpoints   [2]*protocolv4.SignedMap
	credentials [2]*protocolv4.Credential
	relays      [16]*protocolv4.SignedMap
	trust       [19]resourcev4.Reference
	grants      [16][2]resourcev4.Reference
}

func liveArtifactTemplateBytes(c LiveArtifactHostConfig) (uint64, error) {
	if c.Clock == nil || c.Policy == nil || c.Signer == nil || c.ClientCertificateDigest == ([32]byte{}) || c.MaxArtifacts == 0 || c.MaxArtifacts > 256 || c.RuntimeBytes == 0 || len(c.Delegation) == 0 || len(c.Delegation) > 8192 || len(c.OnceAuthority) == 0 || len(c.OnceAuthority) > 8192 {
		return 0, resourcev4.ErrConfiguration
	}
	for _, trust := range c.Trust {
		if trust == nil {
			return 0, resourcev4.ErrConfiguration
		}
	}
	for _, cert := range [][]byte{c.ClientCertificate, c.ServerCertificate} {
		if len(cert) == 0 || len(cert) > 8192 {
			return 0, resourcev4.ErrConfiguration
		}
	}
	codec, err := protocolv4.SignedMapBackingBytes("IdentityCertificate", 8192, 4096)
	if err != nil {
		return 0, err
	}
	credential, err := protocolv4.CredentialBackingBytes("IdentityCertificate")
	if err != nil {
		return 0, err
	}
	n := uint64(unsafe.Sizeof(liveArtifactTemplate{})) + 2*(codec+credential) + 16384
	for _, tunnel := range c.Tunnels {
		if tunnel == nil {
			continue
		}
		if tunnel.Server == nil || tunnel.RelayTrust == nil || len(tunnel.RelayCertificate) == 0 || len(tunnel.RelayCertificate) > 8192 {
			return 0, resourcev4.ErrConfiguration
		}
		for _, g := range tunnel.Grants {
			if g.Signer == nil || g.Validation.Namespace == nil || g.Validation.Policy == nil || g.Validation.Issuer.Schema != "Grant" || len(g.Service) == 0 || len(g.Service) > 128 || len(g.Audience) == 0 || len(g.Audience) > 128 {
				return 0, resourcev4.ErrConfiguration
			}
		}
		n += codec + credential + uint64(unsafe.Sizeof(LiveArtifactTunnelConfig{})) + 2048
	}
	return n, nil
}

func (t *liveArtifactTemplate) initialize(c LiveArtifactHostConfig, environment resourcev4.Reference) (err error) {
	t.config = c
	t.config.Delegation = bytes.Clone(c.Delegation)
	t.config.OnceAuthority = bytes.Clone(c.OnceAuthority)
	t.config.ClientCertificate, t.config.ServerCertificate = nil, nil
	t.config.Tunnels = [16]*LiveArtifactTunnelConfig{}
	for i, trust := range c.Trust {
		t.trust[i], err = trust.ReferenceFor(c.Clock, environment)
		if err != nil {
			return err
		}
	}
	for i, wire := range [][]byte{c.ClientCertificate, c.ServerCertificate} {
		t.endpoints[i], err = liveArtifactCertificate(wire, c.Trust[i+1])
		if err != nil {
			return err
		}
		t.credentials[i], err = t.endpoints[i].DetachCredential()
		if err != nil {
			return err
		}
		if t.credentials[i].Scope().Role != uint64(i) {
			return resourcev4.ErrConfiguration
		}
	}
	client, server := t.credentials[0].Scope(), t.credentials[1].Scope()
	if client.Tenant != server.Tenant || client.Audience != server.Audience || client.Profile != server.Profile || t.credentials[0].Facts().Digest == t.credentials[1].Facts().Digest {
		return resourcev4.ErrConfiguration
	}
	for i, input := range c.Tunnels {
		if input == nil {
			continue
		}
		cloned := *input
		cloned.RelayCertificate = nil
		t.config.Tunnels[i] = &cloned
		t.trust[3+i], err = input.RelayTrust.ReferenceFor(c.Clock, environment)
		if err != nil {
			return err
		}
		t.relays[i], err = liveArtifactCertificate(input.RelayCertificate, input.RelayTrust)
		if err != nil {
			return err
		}
		for side := range cloned.Grants {
			g := &cloned.Grants[side]
			g.Service, g.Audience = strings.Clone(g.Service), strings.Clone(g.Audience)
			g.Validation.Issuer.Schema = strings.Clone(g.Validation.Issuer.Schema)
			if !bytes.Equal(g.Signer.PublicKey(), g.Validation.Issuer.Key[:]) {
				return resourcev4.ErrConfiguration
			}
			t.grants[i][side], err = g.Validation.Namespace.PreparationReferenceFor(c.Clock, environment)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func liveArtifactCertificate(wire []byte, trust *protocolv4.NamespaceTrustStore) (*protocolv4.SignedMap, error) {
	codec, err := protocolv4.NewSignedMapCodec("IdentityCertificate", 8192, 4096)
	if err != nil {
		return nil, err
	}
	return codec.VerifyCredential(wire, trust)
}

func (t *liveArtifactTemplate) check() error {
	for _, ref := range t.trust {
		if ref != (resourcev4.Reference{}) {
			if err := ref.Check(); err != nil {
				return err
			}
		}
	}
	for _, pair := range t.grants {
		for _, ref := range pair {
			if ref != (resourcev4.Reference{}) {
				if err := ref.Check(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// validateMaterial checks every candidate before publishing any original
// Artifact bytes to its client. Future Grant scopes use the parent's original
// issue/session bounds, exactly as the authenticated Artifact material source.
func (t *liveArtifactTemplate) validateMaterial(artifact *protocolv4.SignedMap, parent *protocolv4.Credential, environment resourcev4.Reference) error {
	if err := t.check(); err != nil {
		return err
	}
	validation, err := t.config.Trust[0].ResolveCredential(parent)
	if err != nil {
		return err
	}
	rules, err := t.config.Trust[0].Rules()
	if err != nil {
		return err
	}
	key := t.config.Signer.PublicKey()
	if len(key) != 32 {
		return resourcev4.ErrConfiguration
	}
	if err = validation.CheckLiveActivationSource(rules, parent, t.config.Delegation, t.config.OnceAuthority, [32]byte(key), environment); err != nil {
		return err
	}
	candidates := artifact.Field("candidates")
	if candidates.Len() == 0 || candidates.Len() > 16 {
		return resourcev4.ErrConfiguration
	}
	for i := 0; i < len(t.config.Tunnels); i++ {
		if i >= candidates.Len() {
			if t.config.Tunnels[i] != nil {
				return resourcev4.ErrConfiguration
			}
			continue
		}
		path, _ := candidates.Index(i).Named("Candidate", "path_kind").Uint()
		if (path == 1) != (t.config.Tunnels[i] != nil) {
			return resourcev4.ErrConfiguration
		}
		for side := protocolv4.ClientToServer; side <= protocolv4.ServerToClient; side++ {
			var closure *protocolv4.EndpointCredentials
			var bindings [5]protocolv4.CredentialValidation
			var err error
			bindings[0], err = t.config.Trust[0].ResolveCredential(parent)
			if err != nil {
				return err
			}
			for j, cert := range t.credentials {
				bindings[j+1], err = t.config.Trust[j+1].ResolveCredential(cert)
				if err != nil {
					return err
				}
			}
			count := 3
			if path == 1 {
				input := t.config.Tunnels[i]
				g := input.Grants[side]
				prep, e := protocolv4.DeriveLiveGrantPreparation(parent, side, g.Validation, protocolv4.LiveGrantPreparationConfig{Service: g.Service, Audience: g.Audience, IssuedAt: parent.Scope().IssuedMS, NotAfterMS: parent.Scope().ExpiresMS}, environment)
				if e != nil {
					return e
				}
				closure, err = protocolv4.BindLiveEndpointPreparation(side, artifact, uint64(i), t.endpoints[0], t.endpoints[1], t.relays[i], prep)
				if err != nil {
					return err
				}
				relay, e := t.relays[i].DetachCredential()
				if e != nil {
					return e
				}
				bindings[3] = g.Validation
				bindings[4], err = input.RelayTrust.ResolveCredential(relay)
				count = 5
			} else {
				closure, err = protocolv4.BindEndpointCredentials(side, artifact, uint64(i), t.endpoints[0], t.endpoints[1], nil, nil)
			}
			if err != nil {
				return err
			}
			if _, err = closure.CheckCurrent(bindings[:count], parent.Scope().ExpiresMS); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *liveArtifactTemplate) buildPlan(artifact *protocolv4.SignedMap, parent *protocolv4.Credential, q sessionv4.LiveAuthorizationRequest, reservation, environment resourcev4.Reference) (*protocolv4.LiveActivationPlan, error) {
	if err := t.check(); err != nil {
		return nil, err
	}
	rules, err := t.config.Trust[0].Rules()
	if err != nil {
		return nil, err
	}
	c := protocolv4.LiveActivationConfig{Index: q.Winner.Index, Attempt: q.Attempt, IssuedAt: parent.Scope().IssuedMS, ActivationEnd: q.ActivationNotAfterMS, SessionEnd: parent.Scope().ExpiresMS}
	if q.Winner.Index >= 16 {
		return nil, resourcev4.ErrConfiguration
	}
	if input := t.config.Tunnels[q.Winner.Index]; input != nil {
		var issuance [2]protocolv4.LiveGrantIssuance
		tunnel := protocolv4.LiveTunnelActivationConfig{Client: t.endpoints[0], Server: t.endpoints[1], Relay: t.relays[q.Winner.Index], Issuance: &issuance}
		tunnel.Bindings[0], err = t.config.Trust[0].ResolveCredential(parent)
		if err != nil {
			return nil, err
		}
		for i, credential := range t.credentials {
			tunnel.Bindings[i+1], err = t.config.Trust[i+1].ResolveCredential(credential)
			if err != nil {
				return nil, err
			}
		}
		relay, e := tunnel.Relay.DetachCredential()
		if e != nil {
			return nil, e
		}
		for side, g := range input.Grants {
			issuance[side].Preparation, err = protocolv4.DeriveLiveGrantPreparation(parent, protocolv4.Direction(side), g.Validation, protocolv4.LiveGrantPreparationConfig{Service: g.Service, Audience: g.Audience, IssuedAt: c.IssuedAt, NotAfterMS: c.SessionEnd}, environment)
			if err != nil {
				return nil, err
			}
			issuance[side].Limits, issuance[side].Signer = g.Limits, g.Signer
			tunnel.Bindings[3+side*2] = g.Validation
			tunnel.Bindings[4+side*2], err = input.RelayTrust.ResolveCredential(relay)
			if err != nil {
				return nil, err
			}
		}
		c.Tunnel = &tunnel
	}
	return protocolv4.NewLiveActivationPlan(artifact, rules, t.config.Delegation, t.config.OnceAuthority, t.config.Signer, c, reservation, environment, environment)
}

func (t *liveArtifactTemplate) close() {
	for _, m := range t.endpoints {
		if m != nil {
			m.Release()
		}
	}
	for _, m := range t.relays {
		if m != nil {
			m.Release()
		}
	}
	for _, ref := range t.trust {
		ref.Release()
	}
	for _, pair := range t.grants {
		for _, ref := range pair {
			ref.Release()
		}
	}
	*t = liveArtifactTemplate{}
}

func (t *liveArtifactTemplate) serverMaterial(artifact *protocolv4.SignedMap, parent *protocolv4.Credential, index uint64, environment resourcev4.Reference) (material LiveArtifactServerMaterial, err error) {
	if index >= 16 || t.config.Tunnels[index] == nil {
		return material, resourcev4.ErrConfiguration
	}
	maps := [4]*protocolv4.SignedMap{artifact, t.endpoints[0], t.endpoints[1], t.relays[index]}
	for i, dst := range []*[]byte{&material.Artifact, &material.ClientCertificate, &material.ServerCertificate, &material.RelayCertificate} {
		*dst, err = maps[i].Bytes()
		if err != nil {
			return LiveArtifactServerMaterial{}, err
		}
	}
	g := t.config.Tunnels[index].Grants[1]
	preparation, err := protocolv4.DeriveLiveGrantPreparation(parent, protocolv4.ServerToClient, g.Validation, protocolv4.LiveGrantPreparationConfig{Service: g.Service, Audience: g.Audience, IssuedAt: parent.Scope().IssuedMS, NotAfterMS: parent.Scope().ExpiresMS}, environment)
	if err != nil {
		return LiveArtifactServerMaterial{}, err
	}
	material.GrantScope = preparation.Scope
	return material, nil
}

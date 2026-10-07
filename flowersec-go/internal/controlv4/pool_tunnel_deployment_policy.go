package controlv4

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// PoolTunnelSigningRoute contains only original deployment choices: independent
// Grant issuer IDs/trust owners/private signers, the real relay certificate and
// finite forwarding limits. It contains no signed Grant, receipt or publication
// evidence, and cannot learn an issuer or root from a carrier/TopUp request.
type PoolTunnelSigningRoute struct {
	GrantIssuers           [2][16]byte
	GrantTrust             [2]*protocolv4.NamespaceTrustStore
	GrantSigners           [2]protocolv4.MapSigner
	RelayCertificate       []byte
	RelayTrust             *protocolv4.NamespaceTrustStore
	Service, RelayAudience string
	Limits                 [2]protocolv4.RelayGrantLimits
}

// PoolTunnelDeploymentPolicyConfig is the configuration entry for new original
// signing deployments. The three credential/activation trust owners and every
// physical identity/fence/share are installed independently in Deployment.
// Artifact.Tunnels, Batch.Tunnels and both verification route arrays must be
// empty; this constructor fixes them from the original signed issuer policies.
// Host/Issue namespace closures and share read ACLs remain independent inputs;
// resolving an issuance policy cannot enlarge them or manufacture read access.
type PoolTunnelDeploymentPolicyConfig struct {
	Deployment   PoolTunnelDeploymentConfig
	Routes       [16]*PoolTunnelSigningRoute
	RuntimeBytes uint64
}

type poolTunnelPolicyBacking struct {
	artifact    [16]protocolv4.ArtifactTunnelIssueConfig
	batch       [16]PoolTunnelIssueConfig
	publication [16]PoolRelayRouteConfig
}

func PoolTunnelDeploymentPolicyCharge(c PoolTunnelDeploymentPolicyConfig) (resourcev4.Vector, error) {
	if c.RuntimeBytes == 0 || c.Deployment.Root == nil || len(c.Deployment.Accounts) == 0 || len(c.Deployment.Accounts) > resourcev4.MaxAccountsPerCharge {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	n := uint64(unsafe.Sizeof(poolTunnelPolicyBacking{})) + uint64(unsafe.Sizeof(PoolTunnelDeploymentPolicyConfig{})) + 4096
	count := 0
	for i, route := range c.Routes {
		if c.Deployment.Authority.Artifact.Tunnels[i] != nil || c.Deployment.Authority.Batch.Tunnels[i] != nil || c.Deployment.Authority.Publication.Routes[i] != nil || c.Deployment.Source.Verification.Routes[i] != nil {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		if route == nil {
			continue
		}
		if i >= len(c.Deployment.Authority.Artifact.Base.Candidates) || len(route.RelayCertificate) == 0 || len(route.RelayCertificate) > 8192 || route.RelayTrust == nil || route.Service == "" || len(route.Service) > 128 || route.RelayAudience == "" || len(route.RelayAudience) > 128 {
			return resourcev4.Vector{}, resourcev4.ErrConfiguration
		}
		for side := range route.GrantIssuers {
			if route.GrantIssuers[side] == ([16]byte{}) || route.GrantTrust[side] == nil || route.GrantSigners[side] == nil {
				return resourcev4.Vector{}, resourcev4.ErrConfiguration
			}
		}
		n += 8192 + 4096
		count++
	}
	if count == 0 {
		return resourcev4.Vector{}, resourcev4.ErrConfiguration
	}
	return (resourcev4.Vector{resourcev4.SDKBytes: n, resourcev4.Items: 1, resourcev4.WorkSlots: 1}).Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytes})
}

// NewPoolTunnelDeploymentFromPolicy resolves the actual independently signed
// issuer permissions before constructing any signing owner. The later original
// Artifact issuance permit, whole-batch verification, outbox COMMIT and public
// publication remain separate mandatory gates. No sample Grant is signed or
// accepted as a substitute for any part of that durable chain.
func NewPoolTunnelDeploymentFromPolicy(ctx context.Context, c PoolTunnelDeploymentPolicyConfig, reservation, dependencies resourcev4.Reference) (_ *PoolTunnelDeployment, err error) {
	if ctx == nil {
		return nil, resourcev4.ErrConfiguration
	}
	cost, err := PoolTunnelDeploymentPolicyCharge(c)
	if err != nil {
		return nil, err
	}
	configuration := c.Deployment
	if err = reservation.CheckAllocationScope(configuration.Root, configuration.Owner, configuration.Accounts); err != nil {
		return nil, err
	}
	if err = reservation.CheckSameEnvironment(dependencies); err != nil {
		return nil, err
	}
	owned, err := reservation.Take(cost)
	if err != nil {
		return nil, err
	}
	shared, err := dependencies.Borrow()
	if err != nil {
		owned.Release()
		return nil, err
	}
	success := false
	defer func() {
		shared.Release()
		if !success {
			owned.Release()
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	base := configuration.Authority.Artifact.Base
	if base.Trust[0] == nil || base.Signer == nil {
		return nil, resourcev4.ErrConfiguration
	}
	parent, namespace, err := base.Trust[0].ResolveIssuerPolicy(protocolv4.IssuerPolicySelection{
		Schema: "Artifact", Issuer: base.IssuerKeyID, Audience: base.Audience, Profile: base.CryptoProfile,
		PolicyID: base.RevocationPolicyID, PolicyRevision: base.RevocationPolicyRevision,
	})
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(base.Signer.PublicKey(), parent.Issuer.Key[:]) {
		return nil, resourcev4.ErrOwner
	}
	activation, err := base.Trust[0].ResolveActivationIssuer(base.IssuerKeyID, configuration.Authority.Batch.ActivationSigningKeyID)
	if err != nil {
		return nil, err
	}
	if configuration.Authority.Batch.Signer == nil || !bytes.Equal(configuration.Authority.Batch.Signer.PublicKey(), activation.Key[:]) {
		return nil, resourcev4.ErrOwner
	}
	if configuration.Host.Policy.Issuer != base.IssuerKeyID || configuration.Issue.Policy.Issuer != base.IssuerKeyID || configuration.Host.Policy.PolicyID != base.RevocationPolicyID || configuration.Host.Policy.PolicyRevision != base.RevocationPolicyRevision || configuration.Issue.Policy.PolicyID != base.RevocationPolicyID || configuration.Issue.Policy.PolicyRevision != base.RevocationPolicyRevision {
		return nil, resourcev4.ErrOwner
	}
	backing := &poolTunnelPolicyBacking{}
	for index, route := range c.Routes {
		if route == nil {
			continue
		}
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		original, signed, publication := &backing.artifact[index], &backing.batch[index], &backing.publication[index]
		// Each signed relay certificate remains a fixed host input and is verified
		// by the original Artifact/batch owners against this exact shared trust.
		signed.RelayCertificate = bytes.Clone(route.RelayCertificate)
		signed.RelayTrust = route.RelayTrust
		parentMapping := namespace
		parentMapping.RoleMask = 7
		publication.Mapping = protocolv4.RelayIssuerMapping{
			Parent: parentMapping, ParentIssuer: base.IssuerKeyID, ParentKey: parent.Issuer.Key, Activation: activation,
			Service: strings.Clone(route.Service), RelayAudience: strings.Clone(route.RelayAudience), EndpointAudience: base.Audience, Profile: base.CryptoProfile,
		}
		publication.Grants = route.GrantTrust
		publication.RelayTrust = route.RelayTrust
		for side := range route.GrantIssuers {
			validation, grantNamespace, e := route.GrantTrust[side].ResolveIssuerPolicy(protocolv4.IssuerPolicySelection{
				Schema: "Grant", Issuer: route.GrantIssuers[side], Audience: route.RelayAudience, Service: route.Service, Role: uint64(side),
				Parent: namespace, ParentIssuer: base.IssuerKeyID, PolicyID: base.RevocationPolicyID, PolicyRevision: base.RevocationPolicyRevision,
			})
			if e != nil {
				return nil, e
			}
			if !bytes.Equal(route.GrantSigners[side].PublicKey(), validation.Issuer.Key[:]) {
				return nil, resourcev4.ErrOwner
			}
			original.Legs[side] = protocolv4.ArtifactTunnelLegIssueConfig{Grant: validation, Service: publication.Mapping.Service, RelayAudience: publication.Mapping.RelayAudience, RelayCertificate: signed.RelayCertificate, RelayTrust: route.RelayTrust}
			signed.Grants[side] = LiveArtifactGrantConfig{Validation: validation, Service: publication.Mapping.Service, Audience: publication.Mapping.RelayAudience, Limits: route.Limits[side], Signer: route.GrantSigners[side]}
			publication.Mapping.Grants[side] = protocolv4.RelayGrantIssuer{Namespace: grantNamespace, Issuer: validation.Issuer.Issuer, Key: validation.Issuer.Key}
		}
		configuration.Authority.Artifact.Tunnels[index] = original
		configuration.Authority.Batch.Tunnels[index] = signed
		configuration.Authority.Publication.Routes[index] = publication
		configuration.Source.Verification.Routes[index] = publication
	}
	if err = shared.Check(); err != nil {
		return nil, err
	}
	if err = owned.Check(); err != nil {
		return nil, err
	}
	configuration.Owner = c.Deployment.Owner
	if _, err = rand.Read(configuration.Owner.Instance[:]); err != nil {
		return nil, err
	}
	if _, err = rand.Read(configuration.Owner.Backing[:]); err != nil {
		return nil, err
	}
	charge, err := PoolTunnelDeploymentCharge(configuration)
	if err != nil {
		return nil, err
	}
	ref, err := configuration.Root.Reserve(configuration.Owner, charge, configuration.Accounts...)
	if err != nil {
		return nil, err
	}
	defer ref.Release()
	deployment, err := NewPoolTunnelDeployment(ctx, configuration, ref, dependencies)
	if err != nil {
		return nil, err
	}
	// This fixed policy backing stays charged through the actual child cleanup.
	// The original children capture their own immutable configurations and trust
	// borrows before the temporary resolver's shared reference is released.
	deployment.policy = owned
	deployment.policyBacking = backing
	success = true
	return deployment, nil
}

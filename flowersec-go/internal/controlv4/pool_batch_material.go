package controlv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

func (p *PoolBatchSigningIssuer) issueMaterial(wire, dst []byte, reservation resourcev4.Reference, request protocolv4.TopUpRequestFacts, guard func() error) (item protocolv4.TopUpIssueEntry, err error) {
	artifact, err := p.artifactCodec.VerifyCredential(wire, p.config.Trust[0])
	if err != nil {
		return item, err
	}
	defer artifact.Release()
	parent, err := artifact.DetachCredential()
	if err != nil {
		return item, err
	}
	scope := parent.Scope()
	if scope.Tenant != p.config.Tenant || scope.Audience != p.config.Audience || scope.Profile != p.config.CryptoProfile || scope.Issuer != p.config.ArtifactIssuerID {
		return item, resourcev4.ErrOwner
	}
	c := protocolv4.PoolActivationConfig{Indices: p.config.Indices, Budget: p.config.Budget, Client: p.endpoints[0], Server: p.endpoints[1]}
	c.Bindings[0], err = p.config.Trust[0].ResolveCredential(parent)
	if err != nil {
		return item, err
	}
	for i, credential := range p.credentials {
		c.Bindings[i+1], err = p.config.Trust[i+1].ResolveCredential(credential)
		if err != nil {
			return item, err
		}
	}
	activation, err := p.config.Trust[0].ResolveActivation(parent, p.config.ActivationSigningKeyID, p.delegation[:], p.once[:])
	if err != nil {
		return item, err
	}
	if !bytes.Equal(p.config.Signer.PublicKey(), activation.Key[:]) {
		return item, resourcev4.ErrOwner
	}
	var tunnels [16]protocolv4.LiveTunnelActivationConfig
	var issuance [16][2]protocolv4.LiveGrantIssuance
	for _, index := range p.config.Indices {
		path, ok := artifact.Field("candidates").Index(int(index)).Named("Candidate", "path_kind").Uint()
		if !ok || (path == 1) != (p.config.Tunnels[index] != nil) {
			return item, resourcev4.ErrConfiguration
		}
		input := p.config.Tunnels[index]
		if input == nil {
			continue
		}
		t := &tunnels[index]
		*t = protocolv4.LiveTunnelActivationConfig{Client: c.Client, Server: c.Server, Relay: p.relays[index], Issuance: &issuance[index]}
		copy(t.Bindings[:3], c.Bindings[:])
		relay, err := t.Relay.DetachCredential()
		if err != nil {
			return item, err
		}
		for side, g := range input.Grants {
			i := &issuance[index][side]
			i.Preparation, err = protocolv4.DeriveLiveGrantPreparation(parent, protocolv4.Direction(side), g.Validation, protocolv4.LiveGrantPreparationConfig{Service: g.Service, Audience: g.Audience, IssuedAt: scope.IssuedMS, NotAfterMS: scope.ExpiresMS}, p.reservation)
			if err != nil {
				return item, err
			}
			i.Limits, i.Signer = g.Limits, g.Signer
			t.Bindings[3+side*2] = g.Validation
			t.Bindings[4+side*2], err = input.RelayTrust.ResolveCredential(relay)
			if err != nil {
				return item, err
			}
		}
		c.Tunnels[index] = t
	}
	if err = guard(); err != nil {
		return item, err
	}
	plan, err := protocolv4.NewPoolActivationPlan(artifact, activation.Rules, activation.Delegation, activation.Once, p.config.Signer, c, reservation, p.reservation, p.reservation)
	if err != nil {
		return item, err
	}
	defer plan.Close()
	proofSize, grantSizes, err := plan.MaterialSizes()
	if err != nil {
		return item, err
	}
	bundle := PoolMaterialBundle{Artifact: wire, Activation: p.proof[:proofSize]}
	bundle.ClientCertificate, err = c.Client.Bytes()
	if err != nil {
		return item, err
	}
	bundle.ServerCertificate, err = c.Server.Bytes()
	if err != nil {
		return item, err
	}
	var entries [32]PoolTunnelMaterial
	count := 0
	for _, index := range c.Indices {
		if p.config.Tunnels[index] == nil {
			continue
		}
		relay, err := p.relays[index].Bytes()
		if err != nil {
			return item, err
		}
		for side := 0; side < 2; side++ {
			entries[count] = PoolTunnelMaterial{CandidateIndex: index, Role: protocolv4.Direction(side), Grant: p.grants[index][side][:grantSizes[index][side]], RelayCertificate: relay}
			count++
		}
	}
	bundle.Tunnels = entries[:count]
	if err = poolSigningBundleFits(bundle, request.MaxItemBytes); err != nil {
		return item, err
	}
	defer func() {
		clear(p.proof)
		for _, pair := range p.grants {
			for _, buffer := range pair {
				clear(buffer)
			}
		}
	}()
	n, sizes, err := plan.IssueMaterial(p.proof, p.grants, guard)
	if err != nil {
		return item, err
	}
	if n != proofSize || sizes != grantSizes {
		return item, ErrResponse
	}
	if err = guard(); err != nil {
		return item, err
	}
	n, err = EncodePoolMaterial(dst, bundle)
	if err != nil {
		return item, err
	}
	end, ok := artifact.Field("initiation_not_after_ms").Uint()
	if !ok {
		return item, ErrResponse
	}
	if err = guard(); err != nil {
		clear(dst[:n])
		return item, err
	}
	return protocolv4.TopUpIssueEntry{Material: dst[:n:n], ExpiryMS: end}, nil
}

// Size the entire paired bundle before signing any activation or Grant. There
// is no truncation, automatic candidate removal or endpoint-role filtering at
// this issuer boundary. TopUp max_item_bytes includes its bstr header.
func poolSigningBundleFits(b PoolMaterialBundle, maximum uint32) error {
	size := 1
	for _, part := range [][]byte{b.Artifact, b.Activation, b.ClientCertificate, b.ServerCertificate} {
		n, err := poolBytesSize(part)
		if err != nil {
			return err
		}
		size += n
	}
	if len(b.Tunnels) > 0 {
		size++
		if len(b.Tunnels) >= 24 {
			size++
		}
		for _, entry := range b.Tunnels {
			size += 3
			for _, part := range [][]byte{entry.Grant, entry.RelayCertificate} {
				n, err := poolBytesSize(part)
				if err != nil {
					return err
				}
				size += n
			}
		}
	}
	if size > 65536 {
		return resourcev4.ErrCapacity
	}
	// The material is at most 65536 bytes, whose canonical bstr header is five.
	header := 1
	if size >= 24 {
		header = 2
	}
	if size >= 256 {
		header = 3
	}
	if size >= 65536 {
		header = 5
	}
	if uint64(size+header) > uint64(maximum) {
		return resourcev4.ErrCapacity
	}
	return nil
}

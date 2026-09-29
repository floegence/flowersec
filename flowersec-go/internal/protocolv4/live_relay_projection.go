package protocolv4

import (
	"bytes"
	"crypto/sha256"
)

// LiveRelayProjectionBackingBytes covers detaching original public evidence
// after TxB. Its containing publication owner reserves it before TxA.
func LiveRelayProjectionBackingBytes() (uint64, error) {
	n, err := RelayParentProjectionBackingBytes()
	if err != nil {
		return 0, err
	}
	for _, schema := range []string{"ActivationAuthorization", "Grant"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return 0, err
		}
		codec, err := SignedMapBackingBytes(schema, limit, limit)
		if err != nil {
			return 0, err
		}
		n += codec
	}
	return n, nil
}

// RelayRegistrationBinding fixes the public destination and original selected
// key before TxA. It grants neither a committed receipt nor signing rights.
func (p *LiveActivationPlan) RelayRegistrationBinding(mapping RelayIssuerMapping, parent CredentialValidation) (RelayParentKey, error) {
	if p == nil {
		return RelayParentKey{}, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.issued || p.active || p.tunnel == nil || parent != p.tunnel.bindings[0][0] {
		return RelayParentKey{}, CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return RelayParentKey{}, err
	}
	if err := p.shared.Check(); err != nil {
		return RelayParentKey{}, err
	}
	if err := p.tunnel.checkCurrent(p.fields.SessionEnd); err != nil {
		return RelayParentKey{}, err
	}
	projection := p.relayProjection()
	if err := projection.MatchMapping(mapping); err != nil {
		return RelayParentKey{}, err
	}
	return projection.Key()
}

func (p *LiveActivationPlan) relayProjection() RelayParentProjection {
	t := p.tunnel
	return RelayParentProjection{parent: t.closures[0].credentials[0], activation: p.authority,
		grants: [2]*Credential{t.grants[0].credential, t.grants[1].credential}, relayIdentity: t.closures[0].credentials[4].facts.Digest}
}

// DetachRelayMaterial verifies the exact original proof and both Grant bytes
// against the frozen TxA projections. The result is public evidence only; its
// caller must separately establish the original complete committed TxB.
func (p *LiveActivationPlan) DetachRelayMaterial(material [3][]byte) (*RelayParentProjection, error) {
	if p == nil {
		return nil, CBORFailure("activation_owner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.issued || p.active || p.tunnel == nil {
		return nil, CBORFailure("activation_owner")
	}
	if err := p.reservation.Check(); err != nil {
		return nil, err
	}
	if err := p.shared.Check(); err != nil {
		return nil, err
	}
	if err := p.tunnel.checkCurrent(p.fields.SessionEnd); err != nil {
		return nil, err
	}
	var proofDigest [32]byte
	for _, schema := range []string{"ActivationAuthorization", "Grant"} {
		limit, err := SchemaByteLimit(schema)
		if err != nil {
			return nil, err
		}
		codec, err := NewSignedMapCodec(schema, limit, limit)
		if err != nil {
			return nil, err
		}
		start, end := 0, 1
		if schema == "Grant" {
			start, end = 1, 3
		}
		for i := start; i < end; i++ {
			key, unsigned := p.fields.Signer, p.unsigned
			context := DecodeContext{Selectors: map[string]string{"activation_source_profile": "live_authority"}}
			if i > 0 {
				key, unsigned, context = p.tunnel.grants[i-1].key, p.tunnel.grants[i-1].unsigned, DecodeContext{}
			}
			signed, err := codec.Verify(material[i], key, context)
			if err != nil {
				return nil, err
			}
			err = signed.MatchUnsignedProjection(unsigned)
			if err == nil && i == 0 {
				proofDigest, err = signed.Digest("activation_digest")
			}
			signed.Release()
			if err != nil {
				return nil, err
			}
		}
	}
	projection := p.relayProjection()
	projection.parentReference = sha256.Sum256(p.tunnel.grants[0].document.Root().Named("Grant", "parent_ref").Encoded())
	result := projection.Clone()
	result.activation.binding.proofDigest = proofDigest
	result.proof = bytes.Clone(material[0])
	for side := range result.grantBytes {
		result.grantBytes[side] = bytes.Clone(material[side+1])
	}
	return result, nil
}

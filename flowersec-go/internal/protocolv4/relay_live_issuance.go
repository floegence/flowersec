package protocolv4

import "bytes"

func (p *RelayParentProjection) CloneCommittedLiveMaterial(proof []byte, grants [2][]byte) (*RelayParentProjection, error) {
	if err := p.MatchCommittedLiveMaterial(proof, grants); err != nil {
		return nil, err
	}
	result := p.Clone()
	result.proof = bytes.Clone(proof)
	return result, nil
}

// MatchCommittedLiveMaterial matches a previously verified public projection
// to the complete original live TxB. The trusted caller must independently
// establish durable provenance and verify each signature against its TxA key.
// This match never reconstructs a publication or relay activation owner.
func (p *RelayParentProjection) MatchCommittedLiveMaterial(proof []byte, grants [2][]byte) error {
	if _, err := p.Key(); err != nil {
		return err
	}
	if p.activation.binding.source != "live_authority" {
		return ErrHopAuthContext
	}
	if err := p.activation.MatchProofBytes(proof); err != nil {
		return err
	}
	for side, wire := range grants {
		if p.grants[side] == nil || len(wire) == 0 {
			return ErrHopAuthContext
		}
		digest, err := credentialWireDigest("grant_digest", "Grant", wire, p.grants[side].key)
		if err != nil || digest != p.grants[side].facts.Digest {
			return ErrHopAuthContext
		}
	}
	return nil
}

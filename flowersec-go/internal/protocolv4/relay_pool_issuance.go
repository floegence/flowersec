package protocolv4

import "bytes"

// CompletePoolRelayParentCount checks the complete paired set used by the
// reference issuer's automatic relay registration. A single endpoint bundle
// cannot stand in for the original opposite leg's issuance evidence.
func CompletePoolRelayParentCount(doc *Document) (int, error) {
	if doc == nil {
		return 0, ErrHopAuthContext
	}
	root, wire := doc.Root(), doc.Bytes()
	if len(wire) == 0 {
		return 0, ErrHopAuthContext
	}
	if wire[0] == 0x84 && root.Len() == 4 {
		return 0, nil
	}
	if wire[0] != 0x85 || root.Len() != 5 {
		return 0, ErrHopAuthContext
	}
	set := root.Index(4)
	encoded := set.Encoded()
	if len(encoded) == 0 || encoded[0]>>5 != 4 || set.Len() < 2 || set.Len() > 32 || set.Len()%2 != 0 {
		return 0, ErrHopAuthContext
	}
	var previous uint64
	for i := 0; i < set.Len(); i += 2 {
		var candidate uint64
		for side := 0; side < 2; side++ {
			item := set.Index(i + side)
			encoded := item.Encoded()
			index, iok := item.Index(0).Uint()
			role, rok := item.Index(1).Uint()
			grant, gok := item.Index(2).ByteString()
			relay, cok := item.Index(3).ByteString()
			if len(encoded) == 0 || encoded[0] != 0x84 || item.Len() != 4 || !iok || index >= 16 || !rok || role != uint64(side) || !gok || len(grant) == 0 || !cok || len(relay) == 0 {
				return 0, ErrHopAuthContext
			}
			if side == 0 {
				candidate = index
				if i > 0 && index <= previous {
					return 0, ErrHopAuthContext
				}
			} else if index != candidate {
				return 0, ErrHopAuthContext
			}
		}
		previous = candidate
	}
	return set.Len() / 2, nil
}

// CloneIssuedPoolMaterial keeps the original public proof with the detached
// registration before the secret-bearing issuer outbox may be retired.
func (p *RelayParentProjection) CloneIssuedPoolMaterial(doc *Document, side Direction) (*RelayParentProjection, error) {
	if err := p.MatchIssuedPoolMaterial(doc, side); err != nil {
		return nil, err
	}
	proof, ok := doc.Root().Index(1).ByteString()
	if !ok {
		return nil, ErrHopAuthContext
	}
	result := p.Clone()
	result.proof = bytes.Clone(proof)
	return result, nil
}

// MatchIssuedPoolMaterial runs only at the original issuer boundary, where
// Artifact bytes are already available. The result is a match against this
// previously verified projection, never a new trust or signature decision.
// Neither the document nor its secret-bearing bytes may be sent to a relay.
func (p *RelayParentProjection) MatchIssuedPoolMaterial(doc *Document, side Direction) error {
	if _, err := p.Key(); err != nil {
		return err
	}
	if doc == nil || side > ServerToClient || p.activation.binding.source != "preauthorized_pool" {
		return ErrHopAuthContext
	}
	root, wire := doc.Root(), doc.Bytes()
	if len(wire) == 0 || wire[0] != 0x85 && wire[0] != 0x86 || root.Len() != 5 && root.Len() != 6 {
		return ErrHopAuthContext
	}
	match := func(grant, relay []byte) error {
		digest, err := credentialWireDigest("grant_digest", "Grant", grant, p.grants[side].key)
		if err != nil || digest != p.grants[side].facts.Digest {
			return ErrHopAuthContext
		}
		digest, err = fullMapDigest("certificate_digest", "IdentityCertificate", relay)
		if err != nil || digest != p.relayIdentity {
			return ErrHopAuthContext
		}
		return nil
	}
	b := p.activation.binding
	for i, expected := range [...]struct {
		domain, schema string
		digest         [32]byte
	}{
		{"artifact_digest", "Artifact", b.artifactDigest},
		{"activation_digest", "ActivationAuthorization", b.proofDigest},
		{"certificate_digest", "IdentityCertificate", b.clientDigest},
		{"certificate_digest", "IdentityCertificate", b.serverDigest},
	} {
		part, ok := root.Index(i).ByteString()
		if !ok || len(part) == 0 {
			return ErrHopAuthContext
		}
		digest, err := fullMapDigest(expected.domain, expected.schema, part)
		if err != nil || digest != expected.digest {
			return ErrHopAuthContext
		}
	}
	if root.Len() == 6 {
		grant, grantOK := root.Index(4).ByteString()
		relay, relayOK := root.Index(5).ByteString()
		if !grantOK || !relayOK || len(grant) == 0 || len(relay) == 0 {
			return ErrHopAuthContext
		}
		return match(grant, relay)
	}
	set := root.Index(4)
	encoded := set.Encoded()
	if len(encoded) == 0 || encoded[0]>>5 != 4 || set.Len() == 0 || set.Len() > 32 {
		return ErrHopAuthContext
	}
	var previous uint64
	matched := false
	for i := 0; i < set.Len(); i++ {
		item := set.Index(i)
		encoded := item.Encoded()
		if len(encoded) == 0 || encoded[0] != 0x84 || item.Len() != 4 {
			return ErrHopAuthContext
		}
		index, indexOK := item.Index(0).Uint()
		role, roleOK := item.Index(1).Uint()
		grant, grantOK := item.Index(2).ByteString()
		relay, relayOK := item.Index(3).ByteString()
		if !indexOK || index >= 16 || !roleOK || role > 1 || !grantOK || len(grant) == 0 || !relayOK || len(relay) == 0 ||
			i > 0 && index*2+role <= previous {
			return ErrHopAuthContext
		}
		previous = index*2 + role
		if index != b.winner.Index || role != uint64(side) {
			continue
		}
		if err := match(grant, relay); err != nil {
			return err
		}
		matched = true
	}
	if !matched {
		return ErrHopAuthContext
	}
	return nil
}

// MatchOriginalProjection joins public receipts for separately delivered
// endpoint material. Both legs must name the same complete original issuance;
// a receipt for one leg cannot substitute the uncommitted opposite Grant.
func (p *RelayParentProjection) MatchOriginalProjection(other *RelayParentProjection) error {
	if _, err := p.Key(); err != nil {
		return err
	}
	if _, err := other.Key(); err != nil {
		return err
	}
	if *p.parent != *other.parent || *p.activation.binding != *other.activation.binding ||
		p.activation.trust != other.activation.trust || p.parentReference != other.parentReference ||
		p.relayIdentity != other.relayIdentity || !bytes.Equal(p.proof, other.proof) {
		return ErrHopAuthContext
	}
	for role := range p.grants {
		if *p.grants[role] != *other.grants[role] || !bytes.Equal(p.grantBytes[role], other.grantBytes[role]) {
			return ErrHopAuthContext
		}
	}
	return nil
}

package protocolv4

import "bytes"

// bindHead captures one exact original trust interval before signature work.
// Callers own the exclusive verifier and pin the independent trust store for
// the whole invocation. No later update can substitute this interval.
func (t *NamespaceTrustStore) bindHead(decoder *Decoder, codec *SignedMapCodec, config, wire []byte) (*NamespaceHead, error) {
	return t.bindHeadRevision(decoder, codec, config, wire, 0)
}

func (t *NamespaceTrustStore) bindHeadRevision(decoder *Decoder, codec *SignedMapCodec, config, wire []byte, originalRevision uint64) (*NamespaceHead, error) {
	doc, err := decoder.DecodeMap(wire, "FreshnessHead", DecodeContext{})
	if err != nil {
		return nil, err
	}
	signer := trust16(doc.Root(), "FreshnessHead", "signing_key_id")
	doc.Release()
	sample, sampleErr := t.sampleCurrent()
	if sampleErr != nil {
		err := sampleErr
		return nil, err
	}
	t.mu.Lock()
	if err = t.checkCurrentLockedAt(sample); err != nil {
		t.mu.Unlock()
		return nil, err
	}
	c := &t.configurations[t.count-1]
	if originalRevision != 0 {
		if !t.restoring {
			t.mu.Unlock()
			return nil, CBORFailure("revocation_trust_owner")
		}
		c = nil
		for i := 0; i < t.count; i++ {
			if t.configurations[i].revision == originalRevision {
				c = &t.configurations[i]
				break
			}
		}
		if c == nil {
			t.mu.Unlock()
			return nil, CBORFailure("revocation_trust_binding")
		}
	}
	original, err := c.signed.Bytes()
	if err != nil || config != nil && !bytes.Equal(original, config) {
		t.mu.Unlock()
		return nil, CBORFailure("revocation_trust_binding")
	}
	var key [32]byte
	var delegation []byte
	for i, h := range c.heads {
		if h.signer == signer && !includesTrustID(c.rejectedHeads, signer) {
			v := c.signed.Field("head_delegations").Index(i)
			delegation = v.Encoded()
			key = trust32(v, "HeadSignerDelegation", "signer_public_key")
			break
		}
	}
	rules, generation, issued, end, revision := t.rules, c.generation, c.issued, c.end, c.revision
	t.mu.Unlock()
	if delegation == nil {
		return nil, CBORFailure("revocation_trust_binding")
	}
	signed, err := codec.Verify(wire, key, DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer signed.Release()
	head, err := rules.BindHead(signed, delegation, generation, issued, end)
	if err != nil {
		return nil, err
	}
	if originalRevision == 0 {
		if err = t.Head(NamespaceHeadTrust{Tenant: rules.tenant, Authority: rules.authority, Capacity: rules.capacityDigest, Delegation: head.delegationDigest, Signer: signer, Generation: generation, TrustIssuedMS: issued, TrustNotAfterMS: end}); err != nil {
			return nil, err
		}
	}
	head.trustRevision = revision
	return head, nil
}

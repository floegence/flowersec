package protocolv4

import "bytes"

// bindHead captures one exact original trust interval before signature work.
// Callers own the exclusive verifier and pin the independent trust store for
// the whole invocation. No later update can substitute this interval.
func (t *NamespaceTrustStore) bindHead(decoder *Decoder, codec *SignedMapCodec, config, wire []byte) (*NamespaceHead, error) {
	doc, err := decoder.DecodeMap(wire, "FreshnessHead", DecodeContext{})
	if err != nil {
		return nil, err
	}
	signer := trust16(doc.Root(), "FreshnessHead", "signing_key_id")
	doc.Release()
	t.mu.Lock()
	if err = t.checkCurrentLocked(); err != nil {
		t.mu.Unlock()
		return nil, err
	}
	c := &t.configurations[t.count-1]
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
	rules, generation, issued, end := t.rules, c.generation, c.issued, c.end
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
	if err = t.Head(NamespaceHeadTrust{Tenant: rules.tenant, Authority: rules.authority, Capacity: rules.capacityDigest, Delegation: head.delegationDigest, Signer: signer, Generation: generation, TrustIssuedMS: issued, TrustNotAfterMS: end}); err != nil {
		return nil, err
	}
	return head, nil
}

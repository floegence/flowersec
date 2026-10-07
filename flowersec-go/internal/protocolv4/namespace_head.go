package protocolv4

import (
	"bytes"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// bindHead captures one exact original trust interval before signature work.
// Callers own the exclusive verifier and pin the independent trust store for
// the whole invocation. No later update can substitute this interval.
func (t *NamespaceTrustStore) bindHead(decoder *Decoder, codec *SignedMapCodec, config, wire []byte) (*NamespaceHead, error) {
	head, _, err := t.bindHeadRevisionMode(decoder, codec, config, wire, 0, false)
	return head, err
}

// bindHeadBootstrap retains a pending lower-bound result while still verifying
// the complete signed Head and its fixed trust pairing. The bootstrap caller
// performs the final strict time gate after the original response is ready.
func (t *NamespaceTrustStore) bindHeadBootstrap(decoder *Decoder, codec *SignedMapCodec, config, wire []byte) (*NamespaceHead, uint64, error) {
	return t.bindHeadRevisionMode(decoder, codec, config, wire, 0, true)
}

func (t *NamespaceTrustStore) bindHeadRevision(decoder *Decoder, codec *SignedMapCodec, config, wire []byte, originalRevision uint64) (*NamespaceHead, error) {
	head, _, err := t.bindHeadRevisionMode(decoder, codec, config, wire, originalRevision, false)
	return head, err
}

func (t *NamespaceTrustStore) bindHeadRevisionMode(decoder *Decoder, codec *SignedMapCodec, config, wire []byte, originalRevision uint64, allowPending bool) (*NamespaceHead, uint64, error) {
	doc, err := decoder.DecodeMap(wire, "FreshnessHead", DecodeContext{})
	if err != nil {
		return nil, 0, err
	}
	signer := trust16(doc.Root(), "FreshnessHead", "signing_key_id")
	doc.Release()
	sample, sampleErr := t.clock.Sample()
	if sampleErr != nil {
		return nil, 0, sampleErr
	}
	var pending uint64
	t.mu.Lock()
	if err = t.checkCurrentLockedAt(sample); err != nil {
		if !allowPending || err != timev4.ErrPending {
			t.mu.Unlock()
			return nil, 0, err
		}
		pending = t.configurations[t.count-1].issued
	}
	c := &t.configurations[t.count-1]
	if originalRevision != 0 {
		if !t.restoring {
			t.mu.Unlock()
			return nil, 0, CBORFailure("revocation_trust_owner")
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
			return nil, 0, CBORFailure("revocation_trust_binding")
		}
	}
	original, err := c.signed.Bytes()
	if err != nil || config != nil && !bytes.Equal(original, config) {
		t.mu.Unlock()
		return nil, 0, CBORFailure("revocation_trust_binding")
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
		return nil, 0, CBORFailure("revocation_trust_binding")
	}
	signed, err := codec.Verify(wire, key, DecodeContext{})
	if err != nil {
		return nil, 0, err
	}
	defer signed.Release()
	head, err := rules.BindHead(signed, delegation, generation, issued, end)
	if err != nil {
		return nil, 0, err
	}
	if originalRevision == 0 {
		binding := NamespaceHeadTrust{Tenant: rules.tenant, Authority: rules.authority, Capacity: rules.capacityDigest, Delegation: head.delegationDigest, Signer: signer, Generation: generation, TrustIssuedMS: issued, TrustNotAfterMS: end}
		if allowPending {
			membershipPending, membershipErr := t.headAtPending(binding, sample)
			if membershipErr != nil {
				return nil, 0, membershipErr
			}
			pending = max(pending, membershipPending)
		} else if err = t.Head(binding); err != nil {
			return nil, 0, err
		}
	}
	head.trustRevision = revision
	return head, pending, nil
}

package protocolv4

import (
	"crypto/sha256"
	"math"
)

type TopUpEntryFacts struct {
	Sequence, Generation, ExpiryMS uint64
	Material, Identity             [32]byte
}
type TopUpResponseFacts struct {
	Operation, Source                   [16]byte
	Tenant                              string
	Generation, Highest, RetiredThrough uint64
	Gap                                 bool
	Digest                              [32]byte
	Count                               uint32
	Entries                             [4]TopUpEntryFacts
}
type TopUpBatch struct {
	codec    *TopUpCodec
	document *Document
	facts    TopUpResponseFacts
	request  TopUpRequestFacts
}

// ParseResponse checks intent binding and all original byte digests. It does
// not parse credentials, recover keys, prove durable history or install pool
// items. Unapplied source recovery must separately verify its original identity
// owner and current authorization before committing the complete batch.
func (c *TopUpCodec) ParseResponse(wire []byte, request TopUpRequestFacts) (_ *TopUpBatch, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeShape(wire, "TopUpResponse", DecodeContext{})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			doc.Release()
		}
	}()
	if err = doc.ValidateRules(DecodeContext{}); err != nil {
		return nil, err
	}
	get := func(name string) Value { return doc.Root().Named("TopUpResponse", name) }
	f := TopUpResponseFacts{Operation: [16]byte(topUpBytes(get("operation_id"))), Source: [16]byte(topUpBytes(get("source_incarnation"))), Tenant: topUpText(get("tenant_id")), Generation: topUpUint(get("binding_generation")), Highest: topUpUint(get("server_highest_artifact_sequence")), RetiredThrough: topUpUint(get("retired_artifact_through")), Digest: [32]byte(topUpBytes(get("response_digest")))}
	f.Gap, _ = get("gap_authorized").Bool()
	if f.Operation != request.Operation || f.Source != request.Source || f.Tenant != request.Tenant || f.Generation == 0 || f.Generation != request.Generation {
		return nil, CBORFailure("operation_conflict")
	}
	digest, err := rawTopUpDigest(doc, c.scratch, "topup_response_digest")
	if err != nil {
		return nil, err
	}
	if digest != f.Digest {
		return nil, CBORFailure("operation_conflict")
	}
	entries := get("entries")
	f.Count = uint32(entries.Len())
	if f.Count != request.DesiredCount {
		return nil, CBORFailure("sequence_gap")
	}
	for i := 0; i < entries.Len(); i++ {
		entry := entries.Index(i)
		field := func(name string) Value { return entry.Named("TopUpEntry", name) }
		item := TopUpEntryFacts{Sequence: topUpUint(field("artifact_sequence")), Generation: topUpUint(field("binding_generation")), ExpiryMS: topUpUint(field("expiry_ms")), Material: [32]byte(topUpBytes(field("material_digest"))), Identity: [32]byte(topUpBytes(field("client_identity_digest")))}
		material := topUpBytes(field("material"))
		if len(material) == 0 || len(material) > int(request.MaxItemBytes) || len(field("material").Encoded()) > int(request.MaxItemBytes) {
			return nil, CBORFailure("configuration_capacity")
		}
		if item.Identity != request.Identity {
			return nil, CBORFailure("source_contract_invalid")
		}
		if sha256.Sum256(material) != item.Material || item.Generation != f.Generation {
			return nil, CBORFailure("operation_conflict")
		}
		if item.Sequence == 0 || i > 0 && (f.Entries[i-1].Sequence == math.MaxUint64 || item.Sequence != f.Entries[i-1].Sequence+1) {
			return nil, CBORFailure("sequence_gap")
		}
		f.Entries[i] = item
	}
	if f.Highest < f.Entries[f.Count-1].Sequence {
		return nil, CBORFailure("sequence_gap")
	}
	batch := &TopUpBatch{codec: c, document: doc, facts: f, request: request}
	c.current = batch
	return batch, nil
}
func (b *TopUpBatch) Facts() (TopUpResponseFacts, error) {
	c := b.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != b {
		return TopUpResponseFacts{}, CBORFailure("document_released")
	}
	return b.facts, nil
}

// Material borrows immutable bytes until Release. The sole source owner must
// serialize use and release; copying requires its own admitted backing.
func (b *TopUpBatch) Material(index uint32) ([]byte, error) {
	c := b.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != b || index >= b.facts.Count {
		return nil, CBORFailure("document_released")
	}
	return topUpBytes(b.document.Root().Named("TopUpResponse", "entries").Index(int(index)).Named("TopUpEntry", "material")), nil
}
func (b *TopUpBatch) Release() {
	c := b.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == b {
		b.document.Release()
		b.document = nil
		b.facts = TopUpResponseFacts{}
		b.request = TopUpRequestFacts{}
		c.current = nil
	}
}

// CheckTopUpInstallSequence applies only to an unapplied batch. Already-Applied
// recovery compares retained facts and sends the original Ack without parsing
// or installing material, even after those credentials cease to be usable.
func CheckTopUpInstallSequence(f TopUpResponseFacts, frontier uint64) error {
	if f.Count < 1 || f.Count > 4 || frontier == math.MaxUint64 {
		return CBORFailure("sequence_gap")
	}
	first := f.Entries[0].Sequence
	if first == frontier+1 {
		return nil
	}
	if first <= frontier || !f.Gap || f.RetiredThrough == math.MaxUint64 || f.RetiredThrough < frontier || first != f.RetiredThrough+1 || f.Entries[f.Count-1].Sequence != f.Highest {
		return CBORFailure("sequence_gap")
	}
	return nil
}

// MatchesRequest binds storage use to the exact intent used for all original
// count, identity and per-item size checks. The owner fence may be renewed by
// a separate proof, but this original request remains immutable.
func (b *TopUpBatch) MatchesRequest(request TopUpRequestFacts) bool {
	c := b.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current == b && b.request == request
}

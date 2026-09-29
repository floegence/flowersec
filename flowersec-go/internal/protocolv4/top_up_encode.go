package protocolv4

import "crypto/sha256"

// TopUpIssueEntry is private issuer output. Encoding/digesting does not prove
// credential validity, commit a batch or authorize its delivery.
type TopUpIssueEntry struct {
	ExpiryMS uint64
	Material []byte
}

func topUpIntentFields(r TopUpRequestFacts) [8]Field {
	return [8]Field{{Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: ByteString, Bytes: r.Source[:]}, {Name: "desired_count", Number: uint64(r.DesiredCount)}, {Name: "max_item_bytes", Number: uint64(r.MaxItemBytes)}, {Name: "pool_digest", Kind: ByteString, Bytes: r.Pool[:]}, {Name: "request_deadline_ms", Number: r.DeadlineMS}, {Name: "client_identity_digest", Kind: ByteString, Bytes: r.Identity[:]}}
}
func encodeTopUpProjection(dst []byte, name string, fields []Field) ([]byte, error) {
	projections, err := topUpRawProjections()
	if err != nil {
		return nil, err
	}
	p, ok := projections[name]
	if !ok {
		return nil, CBORFailure("registry_unresolved")
	}
	registry, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	m := registry.Maps[p.schema]
	var omitted [2]string
	for i, id := range p.omitted[:p.count] {
		omitted[i] = m.byID[id].Name
	}
	for _, f := range fields {
		if f.Name == omitted[0] || f.Name == omitted[1] {
			return nil, CBORFailure("projection_field")
		}
	}
	sink := mapEncodingSink{dst: dst}
	if err = processMapExcept(&sink, p.schema, fields, omitted[0], omitted[1]); err != nil {
		return nil, err
	}
	return dst[:sink.offset:sink.offset], nil
}
func validTopUpIntent(r TopUpRequestFacts) bool {
	return len(r.Tenant) > 0 && len(r.Tenant) <= 128 && r.Source != ([16]byte{}) && r.Sequence() != 0 && r.DeadlineMS != 0 && r.DesiredCount >= 1 && r.DesiredCount <= 4 && r.MaxItemBytes >= 1 && r.MaxItemBytes <= 65536
}

// RequestDigest computes the registered canonical intent before requesting an
// authority-signed fence proof. It excludes generation and proof entirely and
// does not need a fabricated proof or a signer capability on the consumer.
func (c *TopUpCodec) RequestDigest(r TopUpRequestFacts) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return [32]byte{}, CBORFailure("decoder_busy")
	}
	return c.requestDigest(r)
}

// ComputeTopUpRequestDigest is the allocation-free validation boundary used
// by durable consumers before they persist a pending intent. It derives the
// digest from the immutable request fields and therefore never trusts a
// caller-provided Digest field. The projection is deliberately small and
// bounded by the registered TopUpRequest digest schema.
func ComputeTopUpRequestDigest(r TopUpRequestFacts) ([32]byte, error) {
	if !validTopUpIntent(r) {
		return [32]byte{}, CBORFailure("source_contract_invalid")
	}
	var scratch [4096]byte
	fields := topUpIntentFields(r)
	encoded, err := encodeTopUpProjection(scratch[:], "topup_request_digest", fields[:])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
func (c *TopUpCodec) requestDigest(r TopUpRequestFacts) ([32]byte, error) {
	if !validTopUpIntent(r) {
		return [32]byte{}, CBORFailure("source_contract_invalid")
	}
	fields := topUpIntentFields(r)
	encoded, err := encodeTopUpProjection(c.scratch, "topup_request_digest", fields[:])
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(c.scratch)
	return sha256.Sum256(encoded), nil
}

// EncodeRequest constructs one current-owner transmission of an immutable
// intent. The caller owns dst and proof for this invocation; authorization and
// proof freshness are checked again by the receiving transaction authority.
func (c *TopUpCodec) EncodeRequest(dst []byte, r TopUpRequestFacts, proof []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return 0, CBORFailure("decoder_busy")
	}
	digest, err := c.requestDigest(r)
	if err != nil {
		return 0, err
	}
	if r.Digest != digest || r.Generation == 0 || len(proof) > 512 {
		return 0, CBORFailure("operation_conflict")
	}
	intent := topUpIntentFields(r)
	var fields [10]Field
	copy(fields[:], intent[:])
	fields[8] = Field{Name: "binding_generation", Number: r.Generation}
	fields[9] = Field{Name: "owner_fence_proof", Kind: ByteString, Bytes: proof}
	return c.encodeTopUpMap(dst, "TopUpRequest", fields[:])
}
func (c *TopUpCodec) encodeTopUpMap(dst []byte, schema string, fields []Field) (int, error) {
	if len(dst) > 524288 {
		dst = dst[:524288]
	}
	encoded, err := EncodeMap(dst, schema, fields)
	if err != nil {
		return 0, err
	}
	doc, err := c.decoder.DecodeShape(encoded, schema, DecodeContext{})
	if err != nil {
		clear(encoded)
		return 0, err
	}
	defer doc.Release()
	if err = doc.ValidateRules(DecodeContext{}); err != nil {
		clear(encoded)
		return 0, err
	}
	return len(encoded), nil
}

// EncodeAck uses only installed response history. It intentionally never reads
// material bytes or revalidates the old identity, and cannot create Applied.
func (c *TopUpCodec) EncodeAck(dst []byte, r TopUpRequestFacts, f TopUpResponseFacts, generation uint64, proof []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return 0, CBORFailure("decoder_busy")
	}
	if !validTopUpIntent(r) || generation == 0 || len(proof) > 512 || r.Tenant != f.Tenant || r.Source != f.Source || r.Operation != f.Operation || r.Generation != f.Generation || f.Count != r.DesiredCount || f.Digest == ([32]byte{}) || !f.Gap && f.RetiredThrough != 0 {
		return 0, CBORFailure("operation_conflict")
	}
	var fields [10]Field
	copy(fields[:], []Field{{Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "pool_digest", Kind: ByteString, Bytes: r.Pool[:]}, {Name: "response_digest", Kind: ByteString, Bytes: f.Digest[:]}, {Name: "server_highest_artifact_sequence", Number: f.Highest}, {Name: "gap_authorized", Kind: Boolean}, {Name: "applied", Kind: Boolean, Number: 1}, {Name: "request_digest", Kind: ByteString, Bytes: r.Digest[:]}, {Name: "binding_generation", Number: generation}, {Name: "owner_fence_proof", Kind: ByteString, Bytes: proof}})
	count := 9
	if f.Gap {
		fields[4].Number = 1
		fields[9] = Field{Name: "retired_artifact_through", Number: f.RetiredThrough}
		count++
	}
	return c.encodeTopUpMap(dst, "TopUpAck", fields[:count])
}

// EncodeResponse prepares canonical private outbox bytes. server_committed is
// a delivery assertion: these bytes may only leave the issuer after its durable
// authority has actually committed this exact batch. The single scratch array
// holds entries first, then the digest projection; no second payload is queued.
func (c *TopUpCodec) EncodeResponse(dst []byte, r TopUpRequestFacts, first uint64, gap bool, retired uint64, items []TopUpIssueEntry) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return 0, CBORFailure("decoder_busy")
	}
	if !validTopUpIntent(r) || r.Generation == 0 || len(items) != int(r.DesiredCount) || first == 0 || first > ^uint64(0)-uint64(len(items)-1) || !gap && retired != 0 || gap && (retired == ^uint64(0) || first != retired+1) {
		return 0, CBORFailure("sequence_gap")
	}
	n, err := cborHead(c.scratch, 4, uint64(len(items)))
	if err != nil {
		return 0, err
	}
	defer clear(c.scratch)
	for i, item := range items {
		if len(item.Material) == 0 || uint64(len(item.Material)) > uint64(r.MaxItemBytes) {
			return 0, CBORFailure("configuration_capacity")
		}
		var head [9]byte
		width, _ := cborHead(head[:], 2, uint64(len(item.Material)))
		if len(item.Material)+width > int(r.MaxItemBytes) {
			return 0, CBORFailure("configuration_capacity")
		}
		digest := sha256.Sum256(item.Material)
		entry, err := EncodeMap(c.scratch[n:], "TopUpEntry", []Field{{Name: "artifact_sequence", Number: first + uint64(i)}, {Name: "binding_generation", Number: r.Generation}, {Name: "expiry_ms", Number: item.ExpiryMS}, {Name: "material", Kind: ByteString, Bytes: item.Material}, {Name: "material_digest", Kind: ByteString, Bytes: digest[:]}, {Name: "client_identity_digest", Kind: ByteString, Bytes: r.Identity[:]}})
		if err != nil {
			return 0, err
		}
		n += len(entry)
	}
	var digest [32]byte
	var fields [10]Field
	copy(fields[:], []Field{{Name: "operation_id", Kind: ByteString, Bytes: r.Operation[:]}, {Name: "tenant_id", Kind: TextString, Text: r.Tenant}, {Name: "source_incarnation", Kind: ByteString, Bytes: r.Source[:]}, {Name: "binding_generation", Number: r.Generation}, {Name: "entries", Kind: EncodedArray, Bytes: c.scratch[:n]}, {Name: "server_highest_artifact_sequence", Number: first + uint64(len(items)-1)}, {Name: "gap_authorized", Kind: Boolean}, {Name: "server_committed", Kind: Boolean, Number: 1}, {Name: "response_digest", Kind: ByteString, Bytes: digest[:]}})
	count := 9
	if gap {
		fields[6].Number = 1
		fields[9] = Field{Name: "retired_artifact_through", Number: retired}
		count++
	}
	if len(dst) > 524288 {
		dst = dst[:524288]
	}
	wire, err := EncodeMap(dst, "TopUpResponse", fields[:count])
	if err != nil {
		return 0, err
	}
	doc, err := c.decoder.DecodeShape(wire, "TopUpResponse", DecodeContext{})
	if err != nil {
		clear(wire)
		return 0, err
	}
	defer doc.Release()
	if err = doc.ValidateRules(DecodeContext{}); err != nil {
		clear(wire)
		return 0, err
	}
	// Hash the raw projection excluding the digest field, then replace only
	// its bstr payload at the registry-derived decoded position in caller dst.
	digest, err = rawTopUpDigest(doc, c.scratch, "topup_response_digest")
	if err != nil {
		clear(wire)
		return 0, err
	}
	value := doc.Root().Named("TopUpResponse", "response_digest")
	node := doc.decoder.nodes[value.index]
	copy(wire[node.end-32:node.end], digest[:])
	return len(wire), nil
}

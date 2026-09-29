package protocolv4

import (
	"bytes"
	"encoding/binary"
	"sync"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/timev4"
)

// TopUpRequestFacts are detached intent facts, not allocation or recovery
// authority. The control service must check permission and the current fence
// again at the actual durable transaction boundary.
type TopUpRequestFacts struct {
	Tenant                     string
	Source, Operation          [16]byte
	Pool, Identity, Digest     [32]byte
	Generation, DeadlineMS     uint64
	DesiredCount, MaxItemBytes uint32
}

func (r TopUpRequestFacts) Sequence() uint64 { return binary.BigEndian.Uint64(r.Operation[:8]) }

type TopUpFenceAuthority struct {
	KeyID     [16]byte
	PublicKey [32]byte
}

// TopUpCodec has one bounded parser and one owner-proof verifier. Its complete
// backing must be charged before construction. A retained response pins the
// parser until Release; no second batch or waiter queue is allocated.
type TopUpCodec struct {
	mu      sync.Mutex
	decoder *Decoder
	proof   *SignedMapCodec
	scratch []byte
	current *TopUpBatch
}

func TopUpCodecBackingBytes() (uint64, error) {
	decoder, err := DecoderBackingBytes(524288, 256)
	if err != nil {
		return 0, err
	}
	proof, err := SignedMapBackingBytes("OwnerFenceProof", 512, 64)
	if err != nil {
		return 0, err
	}
	return decoder + proof + 524288 + uint64(unsafe.Sizeof(TopUpCodec{})) + uint64(unsafe.Sizeof(TopUpBatch{})) + 256, nil
}
func NewTopUpCodec() (*TopUpCodec, error) {
	if _, err := TopUpCodecBackingBytes(); err != nil {
		return nil, err
	}
	d, err := NewDecoder(524288, 256)
	if err != nil {
		return nil, err
	}
	p, err := NewSignedMapCodec("OwnerFenceProof", 512, 64)
	if err != nil {
		return nil, err
	}
	return &TopUpCodec{decoder: d, proof: p, scratch: make([]byte, 524288)}, nil
}
func topUpUint(v Value) uint64  { n, _ := v.Uint(); return n }
func topUpBytes(v Value) []byte { b, _ := v.ByteString(); return b }
func topUpText(v Value) string  { s, _ := v.Text(); return s }

func (c *TopUpCodec) verifyFence(wire []byte, r TopUpRequestFacts, generation uint64, authority TopUpFenceAuthority, now timev4.Interval) error {
	if generation == 0 || authority.KeyID == ([16]byte{}) || authority.PublicKey == ([32]byte{}) || now.LowerMS > now.UpperMS {
		return CBORFailure("source_contract_invalid")
	}
	proof, err := c.proof.Verify(wire, authority.PublicKey, DecodeContext{})
	if err != nil {
		return err
	}
	defer proof.Release()
	if err = proof.document.ValidateRules(DecodeContext{}); err != nil {
		return err
	}
	if topUpText(proof.Field("tenant_id")) != r.Tenant || !bytes.Equal(topUpBytes(proof.Field("source_incarnation")), r.Source[:]) || !bytes.Equal(topUpBytes(proof.Field("operation_id")), r.Operation[:]) || !bytes.Equal(topUpBytes(proof.Field("request_digest")), r.Digest[:]) || !bytes.Equal(topUpBytes(proof.Field("authority_key_id")), authority.KeyID[:]) || topUpUint(proof.Field("current_generation")) != generation {
		return CBORFailure("operation_conflict")
	}
	issued, end := topUpUint(proof.Field("issued_at_ms")), topUpUint(proof.Field("expires_at_ms"))
	if err = now.LowerBound(issued, true); err != nil {
		return err
	}
	if !now.ValidBefore(end) {
		return timev4.ErrExpired
	}
	return nil
}

func (c *TopUpCodec) ParseRequest(wire []byte, authority TopUpFenceAuthority, now timev4.Interval) (r TopUpRequestFacts, err error) {
	return c.parseRequest(wire, &authority, now)
}

// InspectRequest returns unauthenticated intent for a read-only retired/fenced
// lookup. It never verifies an owner proof and cannot authorize any state write,
// response containing material, sequence occupation or takeover.
func (c *TopUpCodec) InspectRequest(wire []byte) (TopUpRequestFacts, error) {
	return c.parseRequest(wire, nil, timev4.Interval{})
}

func (c *TopUpCodec) parseRequest(wire []byte, authority *TopUpFenceAuthority, now timev4.Interval) (r TopUpRequestFacts, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return r, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeShape(wire, "TopUpRequest", DecodeContext{})
	if err != nil {
		return r, err
	}
	defer doc.Release()
	if err = doc.ValidateRules(DecodeContext{}); err != nil {
		return r, err
	}
	get := func(name string) Value { return doc.Root().Named("TopUpRequest", name) }
	r = TopUpRequestFacts{Tenant: topUpText(get("tenant_id")), Source: [16]byte(topUpBytes(get("source_incarnation"))), Operation: [16]byte(topUpBytes(get("operation_id"))), Pool: [32]byte(topUpBytes(get("pool_digest"))), Identity: [32]byte(topUpBytes(get("client_identity_digest"))), Generation: topUpUint(get("binding_generation")), DeadlineMS: topUpUint(get("request_deadline_ms")), DesiredCount: uint32(topUpUint(get("desired_count"))), MaxItemBytes: uint32(topUpUint(get("max_item_bytes")))}
	if r.Sequence() == 0 || r.Source == ([16]byte{}) || r.DeadlineMS == 0 {
		return TopUpRequestFacts{}, CBORFailure("source_contract_invalid")
	}
	r.Digest, err = rawTopUpDigest(doc, c.scratch, "topup_request_digest")
	if err != nil {
		return TopUpRequestFacts{}, err
	}
	if authority != nil {
		if err = c.verifyFence(topUpBytes(get("owner_fence_proof")), r, r.Generation, *authority, now); err != nil {
			return TopUpRequestFacts{}, err
		}
	}
	// A passed append deadline is retained as fact: the authority may still
	// occupy this exact next sequence with an expired terminal in one CAS.
	return r, nil
}

// VerifyAck checks current proof and all original response fields. It does not
// write retirement, alter an original generation or grant a sending capability.
func (c *TopUpCodec) VerifyAck(wire []byte, request TopUpRequestFacts, response TopUpResponseFacts, authority TopUpFenceAuthority, now timev4.Interval) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return 0, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeShape(wire, "TopUpAck", DecodeContext{})
	if err != nil {
		return 0, err
	}
	defer doc.Release()
	if err = doc.ValidateRules(DecodeContext{}); err != nil {
		return 0, err
	}
	get := func(name string) Value { return doc.Root().Named("TopUpAck", name) }
	gap, _ := get("gap_authorized").Bool()
	if !bytes.Equal(topUpBytes(get("operation_id")), request.Operation[:]) || request.Operation != response.Operation || request.Source != response.Source || request.Tenant != response.Tenant || !bytes.Equal(topUpBytes(get("pool_digest")), request.Pool[:]) || !bytes.Equal(topUpBytes(get("request_digest")), request.Digest[:]) || !bytes.Equal(topUpBytes(get("response_digest")), response.Digest[:]) || topUpUint(get("server_highest_artifact_sequence")) != response.Highest || gap != response.Gap || topUpUint(get("retired_artifact_through")) != response.RetiredThrough {
		return 0, CBORFailure("operation_conflict")
	}
	generation := topUpUint(get("binding_generation"))
	if err = c.verifyFence(topUpBytes(get("owner_fence_proof")), request, generation, authority, now); err != nil {
		return 0, err
	}
	return generation, nil
}

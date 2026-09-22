package protocolv4

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sync"
	"unsafe"
)

// ResumeCheckpoint owns its finite position. It cannot alias an application's
// mutable input or the reusable decoder used to validate it.
type ResumeCheckpoint struct {
	format        [128]byte
	position      [4096]byte
	formatBytes   uint8
	positionBytes uint16
	valid         bool
}

func (c ResumeCheckpoint) Format() string     { return string(c.format[:c.formatBytes]) }
func (c ResumeCheckpoint) PositionBytes() int { return int(c.positionBytes) }
func (c ResumeCheckpoint) CopyPosition(dst []byte) (int, error) {
	if !c.valid {
		return 0, CBORFailure("resume_checkpoint_required")
	}
	if len(dst) < int(c.positionBytes) {
		return 0, CBORFailure("encoder_capacity")
	}
	return copy(dst, c.position[:c.positionBytes]), nil
}

type ResumeClaims struct {
	Tenant, Caller, Audience, Namespace string
	Operation, RequestDigest, Nonce     [32]byte
	Checkpoint                          ResumeCheckpoint
	Generation, IssuedAtMS, ExpiresAtMS uint64
}

// ResumeToken contains canonical bytes and detached syntax only. Neither this
// value nor Claims grants current authorization, consumption or Start rights.
type ResumeToken struct {
	wire       [4980]byte
	bytes      uint16
	protection uint8
	keyID      [16]byte
	claims     ResumeClaims
	valid      bool
}

func (t ResumeToken) Claims() ResumeClaims { return t.claims }
func (t ResumeToken) KeyID() [16]byte      { return t.keyID }
func (t ResumeToken) Protection() uint8    { return t.protection }
func (t ResumeToken) EncodedBytes() int    { return int(t.bytes) }
func (t ResumeToken) CopyEncoded(dst []byte) (int, error) {
	if !t.valid {
		return 0, CBORFailure("resume_token_required")
	}
	if len(dst) < int(t.bytes) {
		return 0, CBORFailure("encoder_capacity")
	}
	return copy(dst, t.wire[:t.bytes]), nil
}
func (ResumeToken) String() string               { return "Flowersec.ResumeToken" }
func (ResumeToken) GoString() string             { return "Flowersec.ResumeToken" }
func (ResumeToken) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// VerifiedResumeToken proves only protection under the supplied independent
// recovery key. The service must still check time, policy, current principal,
// original execution and the atomic checkpoint consumption transaction.
type VerifiedResumeToken struct{ token ResumeToken }

func (t VerifiedResumeToken) Valid() bool                { return t.token.valid }
func (t VerifiedResumeToken) Claims() ResumeClaims       { return t.token.claims }
func (t VerifiedResumeToken) Token() ResumeToken         { return t.token }
func (VerifiedResumeToken) String() string               { return "Flowersec.VerifiedResumeToken" }
func (VerifiedResumeToken) GoString() string             { return "Flowersec.VerifiedResumeToken" }
func (VerifiedResumeToken) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

type ResumeRequest struct {
	Token            ResumeToken
	TransportContext [32]byte
	StreamID         uint64
}

type ResumeResult struct {
	Status      uint8
	HasProgress bool
	Checkpoint  ResumeCheckpoint
	Generation  uint64
}

// ResumeMAC computes exactly one admitted use of an independent application
// recovery key. Implementations retain no input aliases after returning. This
// capability is intentionally separate from Session record/key interfaces.
type ResumeMAC interface {
	ResumeMAC([]byte) ([32]byte, error)
}

type resumeCodecRegistry struct {
	macDomain []byte
	macID     uint64
	schemas   [2]string
}

var runtimeResumeCodec = sync.OnceValues(func() (resumeCodecRegistry, error) {
	var out resumeCodecRegistry
	out.schemas = [2]string{"ResumeSignedToken", "ResumeMACToken"}
	for name, limit := range map[string]int{"ResumeCheckpoint": 4232, "ResumeTokenClaims": 4893, "ResumeSignedToken": 4980, "ResumeMACToken": 4948, "ResumeRequest": 9345, "ResumeResult": 4248} {
		n, err := SchemaByteLimit(name)
		if err != nil || n != limit {
			return out, CBORFailure("registry_unresolved")
		}
	}
	r, err := runtimeSchema()
	if err != nil {
		return out, err
	}
	m := r.Maps["ResumeMACToken"]
	if m == nil || m.MACField == nil {
		return out, CBORFailure("registry_unresolved")
	}
	out.macID = *m.MACField
	var domains []signedDomain
	if err := json.Unmarshal([]byte(DomainRegistryJSON), &domains); err != nil {
		return out, err
	}
	for _, d := range domains {
		if d.Name != "resume_token_mac" {
			continue
		}
		if d.Operation != "hmac-sha256" || len(d.Input.Parts) != 1 || d.Input.Parts[0].Schema != "ResumeMACToken" || d.Input.Parts[0].Encoding != "lp-map" || d.Input.Parts[0].Projection != "without_mac" {
			return out, CBORFailure("registry_unresolved")
		}
		out.macDomain, err = hex.DecodeString(d.Label)
		if err != nil || len(out.macDomain) == 0 || len(out.macDomain) > 128 || out.macDomain[len(out.macDomain)-1] != 0 {
			return out, CBORFailure("registry_unresolved")
		}
	}
	if len(out.macDomain) == 0 {
		return out, CBORFailure("registry_unresolved")
	}
	return out, nil
})

// ValidateResumeMACInput bounds the narrow key capability to the registered
// application-recovery domain and one complete length-prefixed projection.
// Canonical token validation belongs to ResumeCodec before this key use.
func ValidateResumeMACInput(input []byte) error {
	r, err := runtimeResumeCodec()
	if err != nil {
		return err
	}
	offset := len(r.macDomain) + 4
	if len(input) <= offset || len(input)-offset > 4948 || !bytes.Equal(input[:len(r.macDomain)], r.macDomain) || uint64(binary.BigEndian.Uint32(input[len(r.macDomain):offset])) != uint64(len(input)-offset) {
		return CBORFailure("resume_mac_domain")
	}
	return nil
}

// ResumeCodec has one fixed parsing/signing workspace, no retained document,
// input queue, Session or key. Callers admit this backing and each detached
// token/request/result value before construction or application disclosure.
type ResumeCodec struct {
	mu         sync.Mutex
	decoder    *Decoder
	signed     *SignedMapCodec
	registry   resumeCodecRegistry
	checkpoint [4232]byte
	claims     [4893]byte
	encoded    [9345]byte
	macInput   [5080]byte
}

func ResumeCodecBackingBytes() (uint64, error) {
	if _, err := runtimeResumeCodec(); err != nil {
		return 0, err
	}
	n, err := decoderBackingBytes(9345, 128, 512)
	if err != nil {
		return 0, err
	}
	s, err := SignedMapBackingBytes("ResumeSignedToken", 4980, 64)
	return n + s + uint64(unsafe.Sizeof(ResumeCodec{})), err
}
func NewResumeCodec() (*ResumeCodec, error) {
	r, err := runtimeResumeCodec()
	if err != nil {
		return nil, err
	}
	d, err := newDecoder(9345, 128, 512)
	if err != nil {
		return nil, err
	}
	s, err := NewSignedMapCodec("ResumeSignedToken", 4980, 64)
	if err != nil {
		return nil, err
	}
	return &ResumeCodec{decoder: d, signed: s, registry: r}, nil
}

func resumeCheckpointValue(v Value) (out ResumeCheckpoint) {
	f, _ := v.Named("ResumeCheckpoint", "format").Text()
	p, _ := v.Named("ResumeCheckpoint", "position").ByteString()
	out.formatBytes = uint8(copy(out.format[:], f))
	out.positionBytes = uint16(copy(out.position[:], p))
	out.valid = true
	return
}
func resumeClaimsValue(v Value) (out ResumeClaims) {
	for _, field := range [...]struct {
		name string
		dst  *string
	}{{"tenant_id", &out.Tenant}, {"caller_identity", &out.Caller}, {"audience", &out.Audience}, {"service_namespace", &out.Namespace}} {
		*field.dst, _ = v.Named("ResumeTokenClaims", field.name).Text()
	}
	for _, field := range [...]struct {
		name string
		dst  *[32]byte
	}{{"operation_id", &out.Operation}, {"request_digest", &out.RequestDigest}, {"nonce", &out.Nonce}} {
		b, _ := v.Named("ResumeTokenClaims", field.name).ByteString()
		copy(field.dst[:], b)
	}
	for _, field := range [...]struct {
		name string
		dst  *uint64
	}{{"generation", &out.Generation}, {"issued_at_ms", &out.IssuedAtMS}, {"expires_at_ms", &out.ExpiresAtMS}} {
		*field.dst, _ = v.Named("ResumeTokenClaims", field.name).Uint()
	}
	out.Checkpoint = resumeCheckpointValue(v.Named("ResumeTokenClaims", "checkpoint"))
	return
}

func (c *ResumeCodec) CaptureCheckpoint(format string, position []byte) (ResumeCheckpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(c.checkpoint[:])
	wire, err := EncodeMap(c.checkpoint[:], "ResumeCheckpoint", []Field{{Name: "format", Kind: TextString, Text: format}, {Name: "position", Kind: ByteString, Bytes: position}})
	if err != nil {
		return ResumeCheckpoint{}, err
	}
	doc, err := c.decoder.DecodeMap(wire, "ResumeCheckpoint", DecodeContext{})
	if err != nil {
		return ResumeCheckpoint{}, err
	}
	defer doc.Release()
	return resumeCheckpointValue(doc.Root()), nil
}

func (c *ResumeCodec) encodeCheckpoint(p ResumeCheckpoint) ([]byte, error) {
	if !p.valid {
		return nil, CBORFailure("resume_checkpoint_required")
	}
	return EncodeMap(c.checkpoint[:], "ResumeCheckpoint", []Field{{Name: "format", Kind: TextString, Text: p.Format()}, {Name: "position", Kind: ByteString, Bytes: p.position[:p.positionBytes]}})
}
func (c *ResumeCodec) encodeClaims(claims ResumeClaims) ([]byte, error) {
	cp, err := c.encodeCheckpoint(claims.Checkpoint)
	if err != nil {
		return nil, err
	}
	wire, err := EncodeMap(c.claims[:], "ResumeTokenClaims", []Field{
		{Name: "tenant_id", Kind: TextString, Text: claims.Tenant}, {Name: "caller_identity", Kind: TextString, Text: claims.Caller}, {Name: "audience", Kind: TextString, Text: claims.Audience}, {Name: "service_namespace", Kind: TextString, Text: claims.Namespace},
		{Name: "operation_id", Kind: ByteString, Bytes: claims.Operation[:]}, {Name: "request_digest", Kind: ByteString, Bytes: claims.RequestDigest[:]}, {Name: "checkpoint", Kind: EncodedMap, Bytes: cp},
		{Name: "generation", Number: claims.Generation}, {Name: "issued_at_ms", Number: claims.IssuedAtMS}, {Name: "expires_at_ms", Number: claims.ExpiresAtMS}, {Name: "nonce", Kind: ByteString, Bytes: claims.Nonce[:]},
	})
	if err != nil {
		return nil, err
	}
	doc, err := c.decoder.DecodeMap(wire, "ResumeTokenClaims", DecodeContext{})
	if err != nil {
		return nil, err
	}
	doc.Release()
	return wire, nil
}
func (c *ResumeCodec) clear() {
	clear(c.checkpoint[:])
	clear(c.claims[:])
	clear(c.encoded[:])
	clear(c.macInput[:])
}

func (c *ResumeCodec) DecodeToken(wire []byte, protection uint8) (ResumeToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decodeToken(wire, protection)
}
func (c *ResumeCodec) decodeToken(wire []byte, protection uint8) (out ResumeToken, err error) {
	if protection > 1 {
		return out, CBORFailure("resume_protection")
	}
	schema := c.registry.schemas[protection]
	doc, err := c.decoder.DecodeMap(wire, schema, DecodeContext{})
	if err != nil {
		return out, err
	}
	defer doc.Release()
	out.claims = resumeClaimsValue(doc.Root().Named(schema, "claims"))
	id, _ := doc.Root().Named(schema, "key_id").ByteString()
	copy(out.keyID[:], id)
	out.bytes = uint16(copy(out.wire[:], wire))
	out.protection, out.valid = protection, true
	return out, nil
}

func (c *ResumeCodec) SignToken(claims ResumeClaims, keyID [16]byte, key [32]byte, signer MapSigner, guard func() error) (ResumeToken, error) {
	if !c.mu.TryLock() {
		return ResumeToken{}, CBORFailure("decoder_busy")
	}
	defer c.mu.Unlock()
	defer c.clear()
	wire, err := c.encodeClaims(claims)
	if err != nil {
		return ResumeToken{}, err
	}
	doc, err := c.signed.SignWith([]Field{{Name: "claims", Kind: EncodedMap, Bytes: wire}, {Name: "key_id", Kind: ByteString, Bytes: keyID[:]}}, key, signer, DecodeContext{}, guard)
	if err != nil {
		return ResumeToken{}, err
	}
	defer doc.Release()
	wire, err = doc.Bytes()
	if err != nil {
		return ResumeToken{}, err
	}
	return c.decodeToken(wire, 0)
}

func (c *ResumeCodec) VerifySignedToken(token ResumeToken, keyID [16]byte, public [32]byte) (VerifiedResumeToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !token.valid || token.protection != 0 || token.keyID != keyID {
		return VerifiedResumeToken{}, CBORFailure("resume_key_binding")
	}
	doc, err := c.signed.Verify(token.wire[:token.bytes], public, DecodeContext{})
	if err != nil {
		return VerifiedResumeToken{}, err
	}
	doc.Release()
	return VerifiedResumeToken{token: token}, nil
}

func (c *ResumeCodec) macInputFor(doc *Document) ([]byte, error) {
	offset := len(c.registry.macDomain) + 4
	unsigned, err := doc.copyWithout(c.macInput[offset:], c.registry.macID)
	if err != nil {
		return nil, err
	}
	copy(c.macInput[:], c.registry.macDomain)
	binary.BigEndian.PutUint32(c.macInput[len(c.registry.macDomain):offset], uint32(len(unsigned)))
	return c.macInput[:offset+len(unsigned)], nil
}

func (c *ResumeCodec) ProtectMACToken(claims ResumeClaims, keyID [16]byte, key ResumeMAC, guard func() error) (ResumeToken, error) {
	if key == nil || guard == nil {
		return ResumeToken{}, CBORFailure("resume_key_required")
	}
	if !c.mu.TryLock() {
		return ResumeToken{}, CBORFailure("decoder_busy")
	}
	defer c.mu.Unlock()
	defer c.clear()
	wire, err := c.encodeClaims(claims)
	if err != nil {
		return ResumeToken{}, err
	}
	var placeholder [32]byte
	wire, err = EncodeMap(c.encoded[:], "ResumeMACToken", []Field{{Name: "claims", Kind: EncodedMap, Bytes: wire}, {Name: "key_id", Kind: ByteString, Bytes: keyID[:]}, {Name: "mac", Kind: ByteString, Bytes: placeholder[:]}})
	if err != nil {
		return ResumeToken{}, err
	}
	doc, err := c.decoder.DecodeMap(wire, "ResumeMACToken", DecodeContext{})
	if err != nil {
		return ResumeToken{}, err
	}
	defer doc.Release()
	message, err := c.macInputFor(doc)
	if err == nil {
		err = guard()
	}
	if err != nil {
		return ResumeToken{}, err
	}
	tag, err := key.ResumeMAC(message)
	defer clear(tag[:])
	if err == nil {
		err = guard()
	}
	if err != nil {
		return ResumeToken{}, err
	}
	target, _ := doc.Root().Field(c.registry.macID).ByteString()
	copy(target, tag[:])
	var out ResumeToken
	out.claims = claims
	out.keyID = keyID
	out.protection = 1
	out.valid = true
	out.bytes = uint16(copy(out.wire[:], doc.Bytes()))
	return out, nil
}

func (c *ResumeCodec) VerifyMACToken(token ResumeToken, keyID [16]byte, key ResumeMAC, guard func() error) (VerifiedResumeToken, error) {
	if key == nil || guard == nil || !token.valid || token.protection != 1 || token.keyID != keyID {
		return VerifiedResumeToken{}, CBORFailure("resume_key_binding")
	}
	if !c.mu.TryLock() {
		return VerifiedResumeToken{}, CBORFailure("decoder_busy")
	}
	defer c.mu.Unlock()
	defer c.clear()
	doc, err := c.decoder.DecodeMap(token.wire[:token.bytes], "ResumeMACToken", DecodeContext{})
	if err != nil {
		return VerifiedResumeToken{}, err
	}
	defer doc.Release()
	message, err := c.macInputFor(doc)
	if err == nil {
		err = guard()
	}
	if err != nil {
		return VerifiedResumeToken{}, err
	}
	tag, err := key.ResumeMAC(message)
	defer clear(tag[:])
	if err == nil {
		err = guard()
	}
	if err != nil {
		return VerifiedResumeToken{}, err
	}
	expected, _ := doc.Root().Field(c.registry.macID).ByteString()
	if subtle.ConstantTimeCompare(tag[:], expected) != 1 {
		return VerifiedResumeToken{}, CBORFailure("resume_mac_invalid")
	}
	return VerifiedResumeToken{token: token}, nil
}

func (c *ResumeCodec) EncodeRequest(dst []byte, request ResumeRequest) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.clear()
	t := request.Token
	if !t.valid {
		return 0, CBORFailure("resume_token_required")
	}
	checkpoint, err := c.encodeCheckpoint(t.claims.Checkpoint)
	if err != nil {
		return 0, err
	}
	wire, err := EncodeMap(dst, "ResumeRequest", []Field{
		{Name: "original_operation_id", Kind: ByteString, Bytes: t.claims.Operation[:]}, {Name: "original_request_digest", Kind: ByteString, Bytes: t.claims.RequestDigest[:]}, {Name: "protection", Number: uint64(t.protection)},
		{Name: "token", Kind: ByteString, Bytes: t.wire[:t.bytes]}, {Name: "generation", Number: t.claims.Generation}, {Name: "expected_checkpoint", Kind: EncodedMap, Bytes: checkpoint},
		{Name: "transport_context_digest", Kind: ByteString, Bytes: request.TransportContext[:]}, {Name: "stream_id", Number: request.StreamID},
	})
	if err == nil {
		var doc *Document
		doc, err = c.decoder.DecodeMap(wire, "ResumeRequest", DecodeContext{})
		if err == nil {
			doc.Release()
		}
	}
	if err != nil {
		clear(wire)
		return 0, err
	}
	return len(wire), nil
}
func (c *ResumeCodec) DecodeRequest(wire []byte) (ResumeRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, err := c.decoder.DecodeMap(wire, "ResumeRequest", DecodeContext{})
	if err != nil {
		return ResumeRequest{}, err
	}
	r := doc.Root()
	var out ResumeRequest
	b, _ := r.Named("ResumeRequest", "transport_context_digest").ByteString()
	copy(out.TransportContext[:], b)
	out.StreamID, _ = r.Named("ResumeRequest", "stream_id").Uint()
	protection, _ := r.Named("ResumeRequest", "protection").Uint()
	body, _ := r.Named("ResumeRequest", "token").ByteString()
	out.Token.bytes = uint16(copy(out.Token.wire[:], body))
	doc.Release()
	out.Token, err = c.decodeToken(out.Token.wire[:out.Token.bytes], uint8(protection))
	return out, err
}

func (c *ResumeCodec) EncodeResult(dst []byte, result ResumeResult) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.clear()
	fields := [2]Field{{Name: "status", Number: uint64(result.Status)}}
	n := 1
	if result.HasProgress {
		checkpoint, err := c.encodeCheckpoint(result.Checkpoint)
		if err != nil {
			return 0, err
		}
		progress, err := EncodeMap(c.claims[:], "ResumeProgress", []Field{{Name: "confirmed_checkpoint", Kind: EncodedMap, Bytes: checkpoint}, {Name: "new_generation", Number: result.Generation}})
		if err != nil {
			return 0, err
		}
		fields[1] = Field{Name: "progress", Kind: EncodedMap, Bytes: progress}
		n = 2
	}
	wire, err := EncodeMap(dst, "ResumeResult", fields[:n])
	if err == nil {
		var doc *Document
		doc, err = c.decoder.DecodeMap(wire, "ResumeResult", DecodeContext{})
		if err == nil {
			doc.Release()
		}
	}
	if err != nil {
		clear(wire)
		return 0, err
	}
	return len(wire), nil
}
func (c *ResumeCodec) DecodeResult(wire []byte) (ResumeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, err := c.decoder.DecodeMap(wire, "ResumeResult", DecodeContext{})
	if err != nil {
		return ResumeResult{}, err
	}
	defer doc.Release()
	r := doc.Root()
	status, _ := r.Named("ResumeResult", "status").Uint()
	out := ResumeResult{Status: uint8(status)}
	progress := r.Named("ResumeResult", "progress")
	if progress.valid() {
		out.HasProgress = true
		out.Checkpoint = resumeCheckpointValue(progress.Named("ResumeProgress", "confirmed_checkpoint"))
		out.Generation, _ = progress.Named("ResumeProgress", "new_generation").Uint()
	}
	return out, nil
}

package protocolv4

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"math"
	"sync"
	"unsafe"
)

// Credential domains are taken exclusively from the generated registry. Only
// one-map signature/digest domains belong here; READY possession and handshake
// context domains have separate owners and cannot be substituted by name.
type signedDomain struct {
	Name, Operation string
	Label           string `json:"label_bytes"`
	Input           struct {
		Parts []struct {
			Encoding   string
			Schema     string `json:"schema_ref"`
			Projection string
		} `json:"parts"`
	} `json:"input_schema"`
	label []byte
}

type signedMapRegistry struct {
	signatures map[string]signedDomain
	digests    map[string]signedDomain
}

var runtimeSignedMaps = sync.OnceValues(func() (*signedMapRegistry, error) {
	var domains []signedDomain
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return nil, CBORFailure("registry_unresolved")
	}
	r := &signedMapRegistry{signatures: map[string]signedDomain{}, digests: map[string]signedDomain{}}
	maps, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if len(domain.Input.Parts) != 1 || domain.Input.Parts[0].Encoding != "lp-map" {
			continue
		}
		part := domain.Input.Parts[0]
		if domain.Operation != "ed25519" && domain.Operation != "sha256" {
			continue
		}
		domain.label, err = hex.DecodeString(domain.Label)
		if err != nil || len(domain.label) == 0 || domain.label[len(domain.label)-1] != 0 {
			return nil, CBORFailure("registry_unresolved")
		}
		if domain.Operation == "sha256" && (part.Projection == "full" || part.Projection == "without_signature") {
			r.digests[domain.Name] = domain
		} else if domain.Operation == "ed25519" && part.Projection == "without_signature" {
			m := maps.Maps[part.Schema]
			if m == nil || m.SignatureField == nil || m.byID[*m.SignatureField] == nil || r.signatures[part.Schema].Name != "" {
				return nil, CBORFailure("registry_unresolved")
			}
			r.signatures[part.Schema] = domain
		}
	}
	return r, nil
})

// SignedMapCodec reserves one decoder, signing-input buffer and encoding buffer
// for one fixed schema. It admits no waiter queue or second retained document.
// Limits/shape precede crypto. Signatures alone do not establish issuer trust,
// permissions, time, revocation, complete cross-field rules or activation rights.
type SignedMapCodec struct {
	mu               sync.Mutex
	decoder          *Decoder
	schema           string
	domain           signedDomain
	signatureID      uint64
	signatureName    string
	message, encoded []byte
	current          *SignedMap
}

// SignedMap is only a canonical-map/signature fact over exact original bytes.
// The trusted admission owner must independently resolve and authorize Key,
// validate all containing bindings and retain the document until use completes.
type SignedMap struct {
	codec                   *SignedMapCodec
	document                *Document
	key                     [32]byte
	activationSourceProfile string
}

func SignedMapBackingBytes(schema string, byteCap, nodeCap int) (uint64, error) {
	r, err := runtimeSignedMaps()
	if err != nil {
		return 0, err
	}
	domain, ok := r.signatures[schema]
	if !ok || byteCap <= 0 || byteCap > math.MaxInt-len(domain.label)-4 {
		return 0, CBORFailure("signature_schema")
	}
	decoder, err := DecoderBackingBytes(byteCap, nodeCap)
	if err != nil {
		return 0, err
	}
	extra := uint64(byteCap)*2 + uint64(len(domain.label)+4) + uint64(unsafe.Sizeof(SignedMapCodec{})) + uint64(unsafe.Sizeof(SignedMap{}))
	if decoder > math.MaxUint64-extra {
		return 0, CBORFailure("configuration_capacity")
	}
	return decoder + extra, nil
}

func NewSignedMapCodec(schema string, byteCap, nodeCap int) (*SignedMapCodec, error) {
	if _, err := SignedMapBackingBytes(schema, byteCap, nodeCap); err != nil {
		return nil, err
	}
	r, err := runtimeSignedMaps()
	if err != nil {
		return nil, err
	}
	domain, ok := r.signatures[schema]
	if !ok || byteCap <= 0 || byteCap > math.MaxInt-len(domain.label)-4 {
		return nil, CBORFailure("signature_schema")
	}
	decoder, err := NewDecoder(byteCap, nodeCap)
	if err != nil {
		return nil, err
	}
	m := decoder.registry.Maps[schema]
	return &SignedMapCodec{decoder: decoder, schema: schema, domain: domain, signatureID: *m.SignatureField, signatureName: m.byID[*m.SignatureField].Name, message: make([]byte, len(domain.label)+4+byteCap), encoded: make([]byte, byteCap)}, nil
}

func (c *SignedMapCodec) signingInput(doc *Document) ([]byte, error) {
	offset := len(c.domain.label) + 4
	unsigned, err := doc.copyWithout(c.message[offset:], c.signatureID)
	if err != nil || uint64(len(unsigned)) > math.MaxUint32 {
		return nil, CBORFailure("signature_projection")
	}
	copy(c.message, c.domain.label)
	binary.BigEndian.PutUint32(c.message[len(c.domain.label):offset], uint32(len(unsigned)))
	return c.message[:offset+len(unsigned)], nil
}

func (c *SignedMapCodec) Verify(input []byte, key [32]byte, context DecodeContext) (*SignedMap, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeShape(input, c.schema, context)
	if err != nil {
		return nil, err
	}
	return c.verifyDocument(doc, key, context)
}

// VerifyCredential resolves an untrusted issuer identifier only inside the
// caller's independently installed trust owner. The signature covers the same
// original decoder bytes used for this lookup. ResolveCredential and the live
// namespace gate must still authorize its full subject/purpose/scope.
func (c *SignedMapCodec) VerifyCredential(input []byte, trust *NamespaceTrustStore) (*SignedMap, error) {
	if trust == nil || c.schema != "Artifact" && c.schema != "IdentityCertificate" && c.schema != "Grant" {
		return nil, CBORFailure("credential_owner")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	doc, err := c.decoder.DecodeShape(input, c.schema, DecodeContext{})
	if err != nil {
		return nil, err
	}
	id, ok := doc.Root().Named(c.schema, "issuer_key_id").ByteString()
	if !ok || len(id) != 16 {
		doc.Release()
		return nil, CBORFailure("credential_issuer_permission")
	}
	key, err := trust.CredentialKey(c.schema, [16]byte(id))
	if err != nil {
		doc.Release()
		return nil, err
	}
	return c.verifyDocument(doc, key, DecodeContext{})
}

func (c *SignedMapCodec) verifyDocument(doc *Document, key [32]byte, context DecodeContext) (*SignedMap, error) {
	message, err := c.signingInput(doc)
	signature, ok := doc.Root().Field(c.signatureID).ByteString()
	valid := err == nil && ok && VerifyEd25519(signature, message, key[:])
	clear(c.message)
	if !valid {
		doc.Release()
		return nil, CBORFailure("signature_invalid")
	}
	v := &SignedMap{codec: c, document: doc, key: key, activationSourceProfile: context.Selectors["activation_source_profile"]}
	c.current = v
	return v, nil
}

// Sign is for the trusted issuer's bounded synchronous signing job. Callers
// supply only unsigned named fields; IDs and the excluded pair come from the
// registry. Canonical structural validation finishes before the signing call.
// The returned document owns its original bytes until Release. Trust, private
// key handle admission and issuance policy remain the issuer owner's duties.
func (c *SignedMapCodec) Sign(fields []Field, seed [32]byte, context DecodeContext) (*SignedMap, error) {
	defer clear(seed[:])
	return c.sign(fields, context, false, func(message []byte) ([32]byte, []byte, error) {
		key := ed25519.NewKeyFromSeed(seed[:])
		defer clear(key)
		return [32]byte(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, message), nil
	})
}

// MapSigner exposes only the public identity and this admitted signing use.
// The actual key provider retains purpose/profile/usage and cleanup ownership;
// no private key material crosses this interface. Sign returns caller-owned
// signature bytes and retains no message alias or unfinished task on return.
type MapSigner interface {
	PublicKey() []byte
	Sign([]byte) ([]byte, error)
}

// SignWith checks complete map rules and the exact original certificate key.
// guard belongs to the original invocation and rechecks its cancellation,
// key/trust and deadlines before/after actual provider work. A failed call is
// not permission to repeat a signature; that once gate belongs to its caller.
func (c *SignedMapCodec) SignWith(fields []Field, key [32]byte, signer MapSigner, context DecodeContext, guard func() error) (*SignedMap, error) {
	if signer == nil || guard == nil {
		return nil, CBORFailure("signature_owner")
	}
	return c.sign(fields, context, true, func(message []byte) ([32]byte, []byte, error) {
		if err := guard(); err != nil {
			return key, nil, err
		}
		public := signer.PublicKey()
		if len(public) != len(key) || [32]byte(public) != key {
			return key, nil, CBORFailure("signature_key_binding")
		}
		if err := guard(); err != nil {
			return key, nil, err
		}
		signature, err := signer.Sign(message)
		if err != nil {
			clear(signature)
			return key, nil, err
		}
		if err = guard(); err != nil {
			clear(signature)
			return key, nil, err
		}
		return key, signature, nil
	})
}

func (c *SignedMapCodec) sign(fields []Field, context DecodeContext, rules bool, sign func([]byte) ([32]byte, []byte, error)) (*SignedMap, error) {
	if !c.mu.TryLock() {
		return nil, CBORFailure("decoder_busy")
	}
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	var complete [128]Field
	if len(fields) >= len(complete) {
		return nil, CBORFailure("map_limit")
	}
	for _, f := range fields {
		if f.Name == c.signatureName {
			return nil, CBORFailure("projection_field")
		}
	}
	copy(complete[:], fields)
	var placeholder [64]byte
	complete[len(fields)] = Field{Name: c.signatureName, Kind: ByteString, Bytes: placeholder[:]}
	wire, err := EncodeMap(c.encoded, c.schema, complete[:len(fields)+1])
	if err != nil {
		clear(c.encoded)
		return nil, err
	}
	doc, err := c.decoder.DecodeShape(wire, c.schema, context)
	clear(c.encoded)
	if err != nil {
		return nil, err
	}
	if rules {
		if err = doc.ValidateRules(context); err != nil {
			doc.Release()
			return nil, err
		}
	}
	message, err := c.signingInput(doc)
	if err != nil {
		clear(c.message)
		doc.Release()
		return nil, err
	}
	public, signature, signErr := sign(message)
	valid := signErr == nil && VerifyEd25519(signature, message, public[:])
	clear(c.message)
	if !valid {
		clear(signature)
		doc.Release()
		if signErr != nil {
			return nil, signErr
		}
		return nil, errSignatureGeneration
	}
	// Only the fixed-size placeholder in a locally constructed document changes.
	// Received maps are never repaired, normalized or re-encoded for verification.
	target, _ := doc.Root().Field(c.signatureID).ByteString()
	copy(target, signature)
	clear(signature)
	v := &SignedMap{codec: c, document: doc, key: public, activationSourceProfile: context.Selectors["activation_source_profile"]}
	c.current = v
	return v, nil
}

func (m *SignedMap) Key() [32]byte { return m.key }

// Bytes and Field borrow this owned immutable document, with the same lifetime
// as Document/Value. Internal callers must not mutate or use them after Release.
func (m *SignedMap) Bytes() ([]byte, error) {
	m.codec.mu.Lock()
	defer m.codec.mu.Unlock()
	if m.codec.current != m {
		return nil, CBORFailure("document_released")
	}
	return m.document.Bytes(), nil
}
func (m *SignedMap) Field(name string) Value {
	m.codec.mu.Lock()
	defer m.codec.mu.Unlock()
	if m.codec.current != m {
		return Value{}
	}
	return m.document.Root().Named(m.codec.schema, name)
}

// Digest uses the registered projection of the original map. The only omitted
// field permitted by a digest domain is its registered signature field. A
// domain for another schema or a signature domain is rejected.
func (m *SignedMap) Digest(name string) ([32]byte, error) {
	m.codec.mu.Lock()
	defer m.codec.mu.Unlock()
	if m.codec.current != m {
		return [32]byte{}, CBORFailure("document_released")
	}
	return m.digestLocked(name)
}

func (m *SignedMap) digestLocked(name string) ([32]byte, error) {
	r, err := runtimeSignedMaps()
	if err != nil {
		return [32]byte{}, err
	}
	domain, ok := r.digests[name]
	if !ok || domain.Input.Parts[0].Schema != m.codec.schema {
		return [32]byte{}, CBORFailure("digest_schema")
	}
	wire := m.document.Bytes()
	if domain.Input.Parts[0].Projection == "without_signature" {
		wire, err = m.document.copyWithout(m.codec.encoded, m.codec.signatureID)
		defer clear(m.codec.encoded)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return hashMapDomain(domain, wire)
}

// fullMapDigest accepts only original validated bytes or a registry-built map.
// It is internal so a peer cannot bypass canonical decoding through a hash API.
func fullMapDigest(name, schema string, wire []byte) ([32]byte, error) {
	h, err := newFullMapHash(name, schema, len(wire))
	if err != nil {
		return [32]byte{}, err
	}
	_, _ = h.Write(wire)
	var result [32]byte
	h.Sum(result[:0])
	return result, nil
}

// The resumable fixed decoder uses this same domain and length prefix, then
// supplies at most one bounded original body range at each worker opportunity.
func newFullMapHash(name, schema string, size int) (hash.Hash, error) {
	r, err := runtimeSignedMaps()
	if err != nil {
		return nil, err
	}
	domain, ok := r.digests[name]
	if !ok || domain.Input.Parts[0].Schema != schema || domain.Input.Parts[0].Projection != "full" || size < 0 || uint64(size) > math.MaxUint32 {
		return nil, CBORFailure("digest_schema")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(size))
	h := sha256.New()
	_, _ = h.Write(domain.label)
	_, _ = h.Write(length[:])
	return h, nil
}

func hashMapDomain(domain signedDomain, wire []byte) ([32]byte, error) {
	if uint64(len(wire)) > math.MaxUint32 {
		return [32]byte{}, CBORFailure("digest_schema")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(wire)))
	h := sha256.New()
	_, _ = h.Write(domain.label)
	_, _ = h.Write(length[:])
	_, _ = h.Write(wire)
	var result [32]byte
	h.Sum(result[:0])
	return result, nil
}

func (m *SignedMap) Release() {
	c := m.codec
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == m {
		m.document.Release()
		clear(c.message)
		clear(c.encoded)
		c.current = nil
	}
}

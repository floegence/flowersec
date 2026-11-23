package protocolv4

import (
	"crypto/subtle"
	"sync"
	"unsafe"
)

// MessageStreamDefinition is the immutable local binding of both directions.
// It contains neither a peer-selected codec nor execution or replay authority.
// Fixed storage prevents a returned view from changing a captured definition.
type MessageStreamDefinition struct {
	kind, revision           [128]byte
	kindBytes, revisionBytes uint8
	directions               [2]MessageStreamDirection
	digest                   [32]byte
	valid                    bool
}

type MessageStreamDirection struct {
	SchemaDigest  [32]byte
	MaximumBytes  uint32
	revision      [128]byte
	revisionBytes uint8
}

func (d MessageStreamDirection) Revision() string  { return string(d.revision[:d.revisionBytes]) }
func (d MessageStreamDefinition) Kind() string     { return string(d.kind[:d.kindBytes]) }
func (d MessageStreamDefinition) Revision() string { return string(d.revision[:d.revisionBytes]) }
func (d MessageStreamDefinition) Digest() [32]byte { return d.digest }
func (d MessageStreamDefinition) Valid() bool      { return d.valid }

// Directions depend on who opened this Stream, never client/server identity.
func (d MessageStreamDefinition) Directions(localOpener bool) (inbound, outbound MessageStreamDirection, err error) {
	if !d.valid {
		return inbound, outbound, CBORFailure("typed_definition_required")
	}
	if localOpener {
		return d.directions[1], d.directions[0], nil
	}
	return d.directions[0], d.directions[1], nil
}

// MessageDefinitionCodec is fixed shared configuration/OPEN parsing workspace.
// Its backing must be admitted before construction. Methods return detached
// definitions or copy into caller-owned metadata; no document borrow escapes.
type MessageDefinitionCodec struct {
	mu                   sync.Mutex
	definition, metadata *Decoder
	values               [4096]byte
}

func MessageDefinitionCodecBackingBytes() (uint64, error) {
	a, err := decoderBackingBytes(8192, 32, 128)
	if err != nil {
		return 0, err
	}
	b, err := decoderBackingBytes(4096, 256, 128)
	if err != nil {
		return 0, err
	}
	return a + b + uint64(unsafe.Sizeof(MessageDefinitionCodec{})), nil
}

func NewMessageDefinitionCodec() (*MessageDefinitionCodec, error) {
	definition, err := newDecoder(8192, 32, 128)
	if err != nil {
		return nil, err
	}
	metadata, err := newDecoder(4096, 256, 128)
	if err != nil {
		return nil, err
	}
	return &MessageDefinitionCodec{definition: definition, metadata: metadata}, nil
}

func (c *MessageDefinitionCodec) Decode(wire []byte) (result MessageStreamDefinition, err error) {
	if c == nil {
		return result, CBORFailure("configuration_capacity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, err := c.definition.DecodeMap(wire, "MessageStreamDefinition", DecodeContext{})
	if err != nil {
		return result, err
	}
	defer doc.Release()
	root := doc.Root()
	kind, _ := root.Named("MessageStreamDefinition", "kind").Text()
	revision, _ := root.Named("MessageStreamDefinition", "revision").Text()
	result.kindBytes = uint8(copy(result.kind[:], kind))
	result.revisionBytes = uint8(copy(result.revision[:], revision))
	for i, name := range [...]string{"opener_to_acceptor", "acceptor_to_opener"} {
		v := root.Named("MessageStreamDefinition", name)
		digest, _ := v.Named("MessageStreamDirection", "codec_schema_digest").ByteString()
		revision, _ := v.Named("MessageStreamDirection", "codec_revision").Text()
		maximum, _ := v.Named("MessageStreamDirection", "max_message_bytes").Uint()
		direction := &result.directions[i]
		copy(direction.SchemaDigest[:], digest)
		direction.revisionBytes = uint8(copy(direction.revision[:], revision))
		direction.MaximumBytes = uint32(maximum)
	}
	result.digest, err = fullMapDigest("typed_message_definition_digest", "MessageStreamDefinition", doc.Bytes())
	if err != nil {
		return MessageStreamDefinition{}, err
	}
	result.valid = true
	return result, nil
}

// ComposeMetadata validates the ordinary application shell before building
// the sole reserved wrapper. Legal ordinary metadata may exceed the composed
// limit; this fails before an OPEN identity or native stream can be created.
func (c *MessageDefinitionCodec) ComposeMetadata(dst []byte, definition MessageStreamDefinition, application []byte) ([]byte, error) {
	if c == nil || !definition.valid {
		return nil, CBORFailure("typed_definition_required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(application) != 0 {
		doc, err := c.metadata.DecodeMap(application, "StreamMetadata", DecodeContext{})
		if err != nil {
			return nil, err
		}
		doc.Release()
	}
	if len(application) > 4006 {
		return nil, CBORFailure("encoded_size")
	}
	// Canonical ordering puts the ten-byte definition key before application.
	s := mapEncodingSink{dst: c.values[:]}
	defer clear(c.values[:])
	if err := s.head(5, 2); err != nil {
		return nil, err
	}
	for _, field := range [...]struct {
		name  string
		value []byte
	}{
		{"definition", definition.digest[:]}, {"application", application},
	} {
		if err := s.field(&Field{Kind: TextString, Text: field.name}); err != nil {
			return nil, err
		}
		if err := s.field(&Field{Kind: ByteString, Bytes: field.value}); err != nil {
			return nil, err
		}
	}
	namespace, err := ConstantField("TypedMessageMetadata", "namespace")
	if err != nil {
		return nil, err
	}
	version, err := ConstantField("TypedMessageMetadata", "version")
	if err != nil {
		return nil, err
	}
	out, err := EncodeMap(dst, "TypedMessageMetadata", []Field{namespace, version, {Name: "values", Kind: EncodedMap, Bytes: c.values[:s.offset]}})
	if err != nil {
		return nil, err
	}
	doc, err := c.metadata.DecodeMap(out, "TypedMessageMetadata", DecodeContext{})
	if err != nil {
		clear(out)
		return nil, err
	}
	doc.Release()
	return out, nil
}

// MatchMetadata returns only the original ordinary application metadata.
// A typed wrapper never installs a definition or grants namespace permission.
func (c *MessageDefinitionCodec) MatchMetadata(dst []byte, definition MessageStreamDefinition, wire []byte) (int, error) {
	if c == nil || !definition.valid {
		return 0, CBORFailure("typed_definition_required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, err := c.metadata.DecodeMap(wire, "TypedMessageMetadata", DecodeContext{})
	if err != nil {
		return 0, err
	}
	defer doc.Release()
	values := doc.Root().Named("TypedMessageMetadata", "values")
	var digest, application []byte
	for node := doc.decoder.nodes[values.index].first; node >= 0; {
		key := Value{doc, node}
		valueIndex := doc.decoder.nodes[node].next
		value := Value{doc, valueIndex}
		name, _ := key.Text()
		switch name {
		case "definition":
			digest, _ = value.ByteString()
		case "application":
			application, _ = value.ByteString()
		}
		node = doc.decoder.nodes[valueIndex].next
	}
	if subtle.ConstantTimeCompare(digest, definition.digest[:]) != 1 {
		return 0, CBORFailure("typed_definition_mismatch")
	}
	if len(dst) < len(application) {
		return 0, CBORFailure("encoder_capacity")
	}
	return copy(dst, application), nil
}

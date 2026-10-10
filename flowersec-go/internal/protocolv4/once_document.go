package protocolv4

// NewOnceDocument retains one completely validated original map. Its caller
// reserves the complete DecoderBackingBytes(byteCap, nodeCap) charge until
// cleanup. Only the Document escapes; there is no reusable Decoder or second
// retained input. Views keep their original bytes and node identity throughout
// the document's lifetime.
func NewOnceDocument(input []byte, schema string, byteCap, nodeCap int, context DecodeContext) (*Document, error) {
	reserved, err := DecoderBackingBytes(byteCap, nodeCap)
	if err != nil {
		return nil, err
	}
	if len(input) > byteCap {
		return nil, CBORFailure("map_size")
	}
	// Each parsed node consumes a distinct original CBOR header byte. An encoded
	// schema's outer byte-string header is separate from its body's node headers;
	// DecodeShape parses that body once, and ValidateRules walks existing nodes.
	// This upper bound cannot reject a map admitted by the original node limit.
	// A nonempty arena preserves the normal decoder's empty-input rejection
	// instead of changing constructor validity.
	inputCap := max(1, len(input))
	privateNodes := min(nodeCap, inputCap)
	// Before validation a scalar can occupy the entire original input. This
	// bound preserves generic syntax/field rejection order; only a successfully
	// validated document may compact to its actual largest text scalar.
	privateText := inputCap
	backing, err := decoderBackingBytes(inputCap, privateNodes, privateText)
	if err != nil {
		return nil, err
	}
	if backing > reserved {
		return nil, CBORFailure("configuration_capacity")
	}
	d, err := newDecoder(inputCap, privateNodes, privateText)
	if err != nil {
		return nil, err
	}
	doc, err := d.DecodeMap(input, schema, context)
	if err != nil {
		return nil, err
	}
	// Compact before publishing any view. Replacement overlap fits the original
	// full reservation; the generic reusable decoder keeps its declared arrays.
	doc.compactImmutableBacking(reserved - backing)
	return doc, nil
}

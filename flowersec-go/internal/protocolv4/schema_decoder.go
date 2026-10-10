package protocolv4

import "strings"

// Fixed-schema owners reserve their complete declared input and node capacities.
// Input and nodes follow each original input and are allocated before parsing;
// every node consumes a distinct CBOR header byte. Normalization arrays
// follow the largest legal text scalar, including nested and encoded schemas.
// The schema restriction prevents using these arrays for another wire grammar.
func schemaDecoderBackingBytes(schema string, byteCap, nodeCap int) (uint64, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	textCap, err := schemaTextCapacity(r, []string{schema})
	if err != nil {
		return 0, err
	}
	backing, err := decoderBackingBytes(byteCap, nodeCap, min(byteCap, textCap))
	if err != nil {
		return 0, err
	}
	if backing > ^uint64(0)-uint64(len(schema)) {
		return 0, CBORFailure("configuration_capacity")
	}
	return backing + uint64(len(schema)), nil
}

func newSchemaDecoder(schema string, byteCap, nodeCap int) (*Decoder, error) {
	if _, err := schemaDecoderBackingBytes(schema, byteCap, nodeCap); err != nil {
		return nil, err
	}
	r, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	textCap, err := schemaTextCapacity(r, []string{schema})
	if err != nil {
		return nil, err
	}
	// Complete original capacities were checked above. The private decoder keeps
	// its text workspace and defers retained input/nodes until a wire map exists.
	d, err := newDecoderWorkspace(byteCap, nodeCap, min(byteCap, textCap))
	if err != nil {
		return nil, err
	}
	d.byteLimit = byteCap
	d.nodeLimit = nodeCap
	d.fixedSchema = strings.Clone(schema)
	return d, nil
}

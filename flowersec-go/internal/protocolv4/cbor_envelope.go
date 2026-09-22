package protocolv4

import "math"

// encodeMapByteStringEnvelope writes the original canonical map around one
// byte-string body owned elsewhere. Prefix includes its length head; suffix
// contains all later fields. The omitted BODY is not an omitted map field.
// processMap supplies the same registry membership, ordering and required-field
// checks as EncodeMap. The caller owns and validates the original complete body.
func encodeMapByteStringEnvelope(dst []byte, schema string, fields []Field, name string, length int) (prefix, suffix []byte, err error) {
	if name == "" || length < 0 {
		return nil, nil, CBORFailure("field_type")
	}
	for _, f := range fields {
		if f.Name == name && (f.Kind != ByteString || len(f.Bytes) != 0) {
			return nil, nil, CBORFailure("field_type")
		}
	}
	sink := mapEncodingSink{dst: dst, sizedField: name, sizedBytes: length, envelope: true}
	if err := processMap(&sink, schema, fields, ""); err != nil {
		return nil, nil, err
	}
	if !sink.sized {
		return nil, nil, CBORFailure("unknown_schema_field")
	}
	if length > math.MaxInt-sink.offset {
		return nil, nil, CBORFailure("encoder_capacity")
	}
	return dst[:sink.bodyOffset:sink.bodyOffset], dst[sink.bodyOffset:sink.offset:sink.offset], nil
}

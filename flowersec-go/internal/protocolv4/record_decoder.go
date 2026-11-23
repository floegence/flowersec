package protocolv4

import "sync"

// Text normalization reuses one workspace for each scalar. Binary payloads and
// arrays of small scalars therefore do not require payload-sized rune storage.
// Discover the scalar bound from the generated record schemas, including every
// nested map. An unresolved future text grammar fails construction explicitly.
var recordTextCapacity = sync.OnceValues(func() (int, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	maximum := uint64(0)
	var visitMap func(string) error
	var visitField func(*wireField) error
	visitField = func(f *wireField) error {
		if f == nil {
			return nil
		}
		if f.Type == "text" {
			if f.MaxBytes == nil {
				return CBORFailure("record_text_bound_unresolved")
			}
			maximum = max(maximum, uint64(*f.MaxBytes))
		}
		for _, name := range []string{f.SchemaRef, f.EncodedSchemaRef} {
			if name != "" {
				if err := visitMap(name); err != nil {
					return err
				}
			}
		}
		for _, child := range []*wireField{f.Items, f.Keys, f.Values} {
			if err := visitField(child); err != nil {
				return err
			}
		}
		for _, group := range []map[string]*wireField{f.Entries, f.Cases} {
			for _, child := range group {
				if err := visitField(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	visitMap = func(name string) error {
		if seen[name] {
			return nil
		}
		m := r.Maps[name]
		if m == nil {
			return CBORFailure("unknown_schema")
		}
		seen[name] = true
		for _, field := range m.Fields {
			if err := visitField(field); err != nil {
				return err
			}
		}
		return nil
	}
	for name := range r.Maps {
		if recordSchema(name) {
			if err := visitMap(name); err != nil {
				return 0, err
			}
		}
	}
	if maximum > uint64(MaxPayloadLength) {
		return 0, CBORFailure("configuration_capacity")
	}
	return int(maximum), nil
})

func RecordDecoderBackingBytes(byteCap, nodeCap int) (uint64, error) {
	textCap, err := recordTextCapacity()
	if err != nil {
		return 0, err
	}
	return decoderBackingBytes(byteCap, nodeCap, min(byteCap, textCap))
}

func NewRecordDecoder(byteCap, nodeCap int) (*Decoder, error) {
	textCap, err := recordTextCapacity()
	if err != nil {
		return nil, err
	}
	return newDecoder(byteCap, nodeCap, min(byteCap, textCap))
}

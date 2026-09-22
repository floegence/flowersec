package protocolv4

import (
	"math"
	"sort"
)

// Field supplies values by registered name. Callers cannot invent field IDs.
// EncodedMap and EncodedArray must come from a canonical internal encoder;
// received bytes are never trusted by passing them through this API.
type Field struct {
	Name   string
	Kind   FieldKind
	Number uint64
	Bytes  []byte
	Text   string
}
type FieldKind uint8

const (
	Unsigned FieldKind = iota
	ByteString
	TextString
	Boolean
	EncodedMap
	EncodedArray
)

// RekeyPhaseInfo reads the fixed phase and sender from the generated closed map.
func RekeyPhaseInfo(schema string) (uint64, Direction, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.SenderRole == nil || *m.SenderRole > uint64(ServerToClient) || m.MACField == nil {
		return 0, 0, CBORFailure("frame_variant")
	}
	f, err := ConstantField(schema, "phase")
	return f.Number, Direction(*m.SenderRole), err
}

func ConstantField(schema, name string) (Field, error) {
	r, err := runtimeSchema()
	if err != nil {
		return Field{}, err
	}
	m := r.Maps[schema]
	if m == nil || m.byName[name] == nil || m.byName[name].constant == nil {
		return Field{}, CBORFailure("unknown_schema_field")
	}
	v := m.byName[name].constant
	f := Field{Name: name, Number: v.n}
	switch v.major {
	case 0:
	case 2:
		f.Kind = ByteString
		f.Bytes = []byte(v.text)
	case 3:
		f.Kind = TextString
		f.Text = v.text
	case 7:
		f.Kind = Boolean
		f.Number = v.n - 20
	default:
		return Field{}, CBORFailure("field_type")
	}
	return f, nil
}

func EnumValue(schema, name, label string) (uint64, error) {
	r, err := runtimeSchema()
	if err != nil {
		return 0, err
	}
	m := r.Maps[schema]
	if m == nil || m.byName[name] == nil {
		return 0, CBORFailure("unknown_schema_field")
	}
	n, ok := m.byName[name].Enum[label]
	if !ok {
		return 0, CBORFailure("enum_value")
	}
	return n, nil
}

func cborHead(dst []byte, major byte, n uint64) (int, error) {
	width, ai := 0, byte(n)
	if n >= 24 {
		width, ai = 1, 24
		for width < 8 && n >= uint64(1)<<(8*width) {
			width *= 2
			ai++
		}
	}
	if len(dst) < 1+width {
		return 0, CBORFailure("encoder_capacity")
	}
	dst[0] = major<<5 | ai
	for i := 0; i < width; i++ {
		dst[1+i] = byte(n >> (8 * (width - 1 - i)))
	}
	return 1 + width, nil
}

// EncodeMap writes into the caller's existing reservation. Schema membership,
// required fields and duplicate names are checked before writing. The protocol
// builder remains responsible for field values and cross-field state rules.
func EncodeMap(dst []byte, schema string, fields []Field) ([]byte, error) {
	return encodeMap(dst, schema, fields, "")
}

// MeasureMapByteString runs the original encoder without allocating payload or
// output backing. The named byte string uses the supplied length; all other
// fields use their actual values. This supports pre-admission bounds for a
// future payload, using the same registry IDs and canonical width decisions.
func MeasureMapByteString(schema string, fields []Field, name string, length int) (int, error) {
	if name == "" || length < 0 {
		return 0, CBORFailure("field_type")
	}
	sink := mapEncodingSink{measure: true, sizedField: name, sizedBytes: length}
	if err := processMap(&sink, schema, fields, ""); err != nil {
		return 0, err
	}
	if !sink.sized {
		return 0, CBORFailure("unknown_schema_field")
	}
	return sink.offset, nil
}

type mapEncodingSink struct {
	dst        []byte
	offset     int
	measure    bool
	sizedField string
	sizedBytes int
	sized      bool
	envelope   bool
	bodyOffset int
}

func (s *mapEncodingSink) advance(n int) error {
	if n < 0 || n > math.MaxInt-s.offset || !s.measure && n > len(s.dst)-s.offset {
		return CBORFailure("encoder_capacity")
	}
	s.offset += n
	return nil
}

func (s *mapEncodingSink) head(major byte, value uint64) error {
	var scratch [9]byte
	dst := scratch[:]
	if !s.measure {
		dst = s.dst[s.offset:]
	}
	n, err := cborHead(dst, major, value)
	if err != nil {
		return err
	}
	return s.advance(n)
}

func (s *mapEncodingSink) field(f *Field) error {
	switch f.Kind {
	case Unsigned, Boolean:
		major, value := byte(0), f.Number
		if f.Kind == Boolean {
			if value > 1 {
				return CBORFailure("field_type")
			}
			major, value = 7, value+20
		}
		return s.head(major, value)
	case ByteString, TextString:
		major, size := byte(2), len(f.Bytes)
		if f.Kind == TextString {
			major, size = 3, len(f.Text)
		}
		if (s.measure || s.envelope) && f.Name == s.sizedField {
			if f.Kind != ByteString {
				return CBORFailure("field_type")
			}
			size, s.sized = s.sizedBytes, true
		}
		if err := s.head(major, uint64(size)); err != nil {
			return err
		}
		if s.envelope && f.Name == s.sizedField {
			s.bodyOffset = s.offset
			return nil
		}
		start := s.offset
		if err := s.advance(size); err != nil {
			return err
		}
		if !s.measure {
			if f.Kind == TextString {
				copy(s.dst[start:], f.Text)
			} else {
				copy(s.dst[start:], f.Bytes)
			}
		}
		return nil
	case EncodedMap, EncodedArray:
		major := byte(5)
		if f.Kind == EncodedArray {
			major = 4
		}
		if len(f.Bytes) == 0 || f.Bytes[0]>>5 != major {
			return CBORFailure("field_type")
		}
		start := s.offset
		if err := s.advance(len(f.Bytes)); err != nil {
			return err
		}
		if !s.measure {
			copy(s.dst[start:], f.Bytes)
		}
		return nil
	default:
		return CBORFailure("field_type")
	}
}

// EncodeMACProjection omits only the MAC field explicitly registered for this
// closed map. The remaining numeric IDs keep their original values.
func EncodeMACProjection(dst []byte, schema string, fields []Field) ([]byte, error) {
	r, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	m := r.Maps[schema]
	if m == nil || m.MACField == nil || m.byID[*m.MACField] == nil {
		return nil, CBORFailure("projection_unresolved")
	}
	omitted := m.byID[*m.MACField].Name
	for _, f := range fields {
		if f.Name == omitted {
			return nil, CBORFailure("projection_field")
		}
	}
	return encodeMap(dst, schema, fields, omitted)
}

func encodeMap(dst []byte, schema string, fields []Field, omitted string) ([]byte, error) {
	sink := mapEncodingSink{dst: dst}
	if err := processMap(&sink, schema, fields, omitted); err != nil {
		return nil, err
	}
	return dst[:sink.offset:sink.offset], nil
}

func processMap(sink *mapEncodingSink, schema string, fields []Field, omitted string) error {
	r, err := runtimeSchema()
	if err != nil {
		return err
	}
	m := r.Maps[schema]
	if m == nil {
		return CBORFailure("unknown_schema")
	}
	if len(fields) > 128 {
		return CBORFailure("map_limit")
	}
	type entry struct {
		id    uint64
		field *Field
	}
	var entries [128]entry
	for i := range fields {
		f := m.byName[fields[i].Name]
		if f == nil {
			return CBORFailure("unknown_field")
		}
		entries[i] = entry{f.id, &fields[i]}
	}
	// The bounded insertion sort avoids reflection/interface allocation. The
	// maximum is the registry's fixed-map cap, independent of payload length.
	for i := 1; i < len(fields); i++ {
		for j := i; j > 0 && entries[j].id < entries[j-1].id; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	for i := 1; i < len(fields); i++ {
		if entries[i].id == entries[i-1].id {
			return CBORFailure("duplicate_key")
		}
	}
	for _, id := range m.Required {
		if omitted != "" && m.byID[id].Name == omitted {
			continue
		}
		i := sort.Search(len(fields), func(i int) bool { return entries[i].id >= id })
		if i == len(fields) || entries[i].id != id {
			return CBORFailure("missing_field")
		}
	}
	if err := sink.head(5, uint64(len(fields))); err != nil {
		return err
	}
	for _, e := range entries[:len(fields)] {
		if err := sink.head(0, e.id); err != nil {
			return err
		}
		if err := sink.field(e.field); err != nil {
			return err
		}
	}
	return nil
}

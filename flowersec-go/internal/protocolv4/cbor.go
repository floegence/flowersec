package protocolv4

import (
	"bytes"
	"strings"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/unicode151"
)

// CBORFailure identifies a rejected wire shape. Authentication, cross-field
// rules and lifecycle attribution are performed by the consuming protocol.
type CBORFailure string

func (e CBORFailure) Error() string { return "protocolv4: " + string(e) }

type cborNode struct {
	major                 byte
	n                     uint64
	start, end, dataStart int
	first, next, embedded int
}

// DecodeContext contains immutable local bounds and authenticated containing
// selectors. A discriminator present in the wire map takes precedence.
type DecodeContext struct {
	Limits    map[string]uint64
	Selectors map[string]string
}

type wireContext struct {
	external *DecodeContext
	parent   *wireContext
	m        *wireMap
	node     int
}

// Decoder owns fixed backing arrays. Admission must reserve BackingBytes before
// constructing it, including the two normalization workspaces and node arena.
// A Document holds exclusive use until Release; there is no waiter queue.
type Decoder struct {
	mu            sync.Mutex
	registry      *wireRegistry
	input         []byte
	nodes         []cborNode
	work, scratch []rune
	used, size    int
	textCap       int
	idna          wireIDNAWorkspace
	active        bool
	borrowed      bool // Private fixed-query decoders retain their original input owner.
	// Only ContractSnapshotCodec sets this private envelope mode. It verifies
	// every nested body with the original full codecs before returning data.
	snapshotEnvelope bool
	generation       uint64
}

func DecoderBackingBytes(byteCap, nodeCap int) (uint64, error) {
	return decoderBackingBytes(byteCap, nodeCap, byteCap)
}

func decoderBackingBytes(byteCap, nodeCap, textCap int) (uint64, error) {
	space, ok := unicode151.NormalizationSpace(textCap)
	if !ok || byteCap <= 0 || nodeCap <= 0 || textCap < 0 || textCap > byteCap || uint64(byteCap) > uint64(^uint32(0)) {
		return 0, CBORFailure("configuration_capacity")
	}
	// Each input byte costs one byte plus two worst-case rune workspaces.
	a, b := uint64(space)*8+uint64(byteCap), uint64(nodeCap)*uint64(unsafe.Sizeof(cborNode{}))
	overhead := uint64(unsafe.Sizeof(Decoder{})) + uint64(unsafe.Sizeof(Document{}))
	if b/uint64(unsafe.Sizeof(cborNode{})) != uint64(nodeCap) || a > ^uint64(0)-overhead || b > ^uint64(0)-overhead-a {
		return 0, CBORFailure("configuration_capacity")
	}
	return a + b + overhead, nil
}

func NewDecoder(byteCap, nodeCap int) (*Decoder, error) {
	return newDecoder(byteCap, nodeCap, byteCap)
}

func newDecoder(byteCap, nodeCap, textCap int) (*Decoder, error) {
	if _, err := decoderBackingBytes(byteCap, nodeCap, textCap); err != nil {
		return nil, err
	}
	r, err := runtimeSchema()
	if err != nil {
		return nil, err
	}
	space, _ := unicode151.NormalizationSpace(textCap)
	return &Decoder{registry: r, input: make([]byte, byteCap), nodes: make([]cborNode, nodeCap), textCap: textCap, work: make([]rune, space), scratch: make([]rune, space)}, nil
}

// Document is an owned immutable snapshot. Byte views and Values are valid
// only until Release; internal consumers must not mutate or retain those views.
// DecodeShape validates canonical syntax and fields, not signatures or rights.
type Document struct {
	decoder    *Decoder
	generation uint64
	root       int
	schema     string
}
type Value struct {
	document *Document
	index    int
}

func (doc *Document) Root() Value   { return Value{doc, doc.root} }
func (doc *Document) Bytes() []byte { return doc.decoder.input[:doc.decoder.size:doc.decoder.size] }
func (doc *Document) Release() {
	d := doc.decoder
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active && d.generation == doc.generation {
		if d.borrowed {
			d.input = nil
		} else {
			clear(d.input[:d.size])
			clear(d.nodes[:d.used])
		}
		clear(d.work)
		clear(d.scratch)
		clear(d.idna.work[:])
		clear(d.idna.scratch[:])
		d.used = 0
		d.size = 0
		d.active = false
	}
}
func (v Value) valid() bool {
	return v.document != nil && v.index >= 0 && v.document.decoder.active && v.document.generation == v.document.decoder.generation
}
func (v Value) Uint() (uint64, bool) {
	if !v.valid() {
		return 0, false
	}
	n := v.document.decoder.nodes[v.index]
	return n.n, n.major == 0
}
func (v Value) Bool() (bool, bool) {
	if !v.valid() {
		return false, false
	}
	n := v.document.decoder.nodes[v.index]
	return n.n == 21, n.major == 7 && (n.n == 20 || n.n == 21)
}
func (v Value) ByteString() ([]byte, bool) {
	if !v.valid() {
		return nil, false
	}
	d := v.document.decoder
	n := d.nodes[v.index]
	if n.major != 2 {
		return nil, false
	}
	return d.input[n.dataStart:n.end:n.end], true
}
func (v Value) Text() (string, bool) {
	if !v.valid() {
		return "", false
	}
	d := v.document.decoder
	n := d.nodes[v.index]
	if n.major != 3 {
		return "", false
	}
	return string(d.input[n.dataStart:n.end]), true
}
func (v Value) Encoded() []byte {
	if !v.valid() {
		return nil
	}
	d := v.document.decoder
	n := d.nodes[v.index]
	return d.input[n.start:n.end:n.end]
}
func (v Value) Field(id uint64) Value {
	if !v.valid() {
		return Value{}
	}
	return Value{v.document, v.document.decoder.lookup(v.index, id)}
}
func (v Value) Named(schema, name string) Value {
	id, err := FieldID(schema, name)
	if err != nil {
		return Value{}
	}
	return v.Field(id)
}
func (v Value) Len() int {
	if !v.valid() {
		return 0
	}
	n := v.document.decoder.nodes[v.index]
	if n.major != 4 && n.major != 5 {
		return 0
	}
	return int(n.n)
}

// CopyUints walks a bounded decoded array once, without retaining arena views
// or turning repeated Index calls into quadratic work for retirement batches.
func (v Value) CopyUints(dst []uint64) (int, bool) {
	if !v.valid() {
		return 0, false
	}
	d := v.document.decoder
	node := d.nodes[v.index]
	if node.major != 4 || node.n > uint64(len(dst)) {
		return 0, false
	}
	i := 0
	for child := node.first; child >= 0; child = d.nodes[child].next {
		if d.nodes[child].major != 0 {
			return 0, false
		}
		dst[i] = d.nodes[child].n
		i++
	}
	return i, true
}
func (v Value) Index(index int) Value {
	if !v.valid() || index < 0 {
		return Value{}
	}
	d := v.document.decoder
	n := d.nodes[v.index]
	if n.major != 4 {
		return Value{}
	}
	child := n.first
	for i := 0; i < index && child >= 0; i++ {
		child = d.nodes[child].next
	}
	return Value{v.document, child}
}

func (d *Decoder) DecodeShape(input []byte, schema string, context DecodeContext) (*Document, error) {
	if !d.mu.TryLock() {
		return nil, CBORFailure("decoder_busy")
	}
	defer d.mu.Unlock()
	if d.active || d.borrowed {
		return nil, CBORFailure("decoder_busy")
	}
	if d.snapshotEnvelope && schema != "ContractSnapshots" {
		return nil, CBORFailure("configuration_capacity")
	}
	if len(input) > len(d.input) {
		return nil, CBORFailure("map_size")
	}
	var field *wireField
	if schema != "" {
		m := d.registry.Maps[schema]
		if m == nil {
			return nil, CBORFailure("unknown_schema")
		}
		if err := mapLength(m, uint64(len(input)), &context); err != nil {
			return nil, err
		}
		field = &wireField{Type: "map", SchemaRef: schema}
	}
	copy(d.input, input)
	d.size = len(input)
	d.used = 0
	pos := 0
	root, err := d.item(&pos, len(input), 0, field, &context)
	if err == nil && pos != len(input) {
		err = CBORFailure("trailing_bytes")
	}
	if err == nil && field != nil {
		err = d.shape(root, field, &wireContext{external: &context})
	}
	if err != nil {
		clear(d.input[:d.size])
		clear(d.nodes[:d.used])
		clear(d.work)
		clear(d.scratch)
		clear(d.idna.work[:])
		clear(d.idna.scratch[:])
		d.size = 0
		d.used = 0
		return nil, err
	}
	if d.generation == ^uint64(0) {
		return nil, CBORFailure("decoder_retired")
	}
	d.generation++
	d.active = true
	return &Document{decoder: d, generation: d.generation, root: root, schema: schema}, nil
}

func mapLength(m *wireMap, n uint64, context *DecodeContext) error {
	if m.MaxEncodedBytes != nil && n > *m.MaxEncodedBytes || m.EncodedBytes != nil && n != *m.EncodedBytes {
		return CBORFailure("map_size")
	}
	if ref := m.MaxEncodedBytesRef; ref != "" {
		limit, ok := context.Limits[ref]
		if !ok || limit == 0 {
			return CBORFailure("limit_unresolved")
		}
		if n > limit {
			return CBORFailure("map_size")
		}
	}
	return nil
}

func (d *Decoder) itemHead(pos *int, end, depth int, field *wireField, context *DecodeContext) (int, error) {
	fail := func(s string) (int, error) { return -1, CBORFailure(s) }
	policy := d.registry.Encoding
	if depth > policy.MaxDepth {
		return fail("depth_limit")
	}
	if *pos >= end {
		return fail("truncated")
	}
	if d.used == len(d.nodes) {
		return fail("node_capacity")
	}
	index := d.used
	d.used++
	node := &d.nodes[index]
	*node = cborNode{start: *pos, first: -1, next: -1, embedded: -1}
	head := d.input[*pos]
	*pos++
	node.major = head >> 5
	ai := head & 31
	if ai == 31 {
		return fail("indefinite_length")
	}
	if node.major == 7 {
		if ai != 20 && ai != 21 && !(ai == 22 && field != nil && field.Type == "uint64" && field.Nullable) {
			return fail("unsupported_type")
		}
		node.n = uint64(ai)
		node.end = *pos
		return index, nil
	}
	if node.major != 0 && node.major != 2 && node.major != 3 && node.major != 4 && node.major != 5 {
		return fail("unsupported_type")
	}
	if ai > 27 {
		return fail("invalid_header")
	}
	node.n = uint64(ai)
	if ai >= 24 {
		width := 1 << (ai - 24)
		if width > end-*pos {
			return fail("truncated")
		}
		node.n = 0
		for _, b := range d.input[*pos : *pos+width] {
			node.n = node.n<<8 | uint64(b)
		}
		*pos += width
		if node.n < [...]uint64{24, 256, 65536, 4294967296}[ai-24] {
			return fail("non_shortest_integer")
		}
	}
	switch node.major {
	case 0:
	case 2, 3:
		if node.n > uint64(end-*pos) {
			return fail("truncated")
		}
		node.dataStart = *pos
		*pos += int(node.n)
		if node.major == 3 {
			raw := d.input[node.dataStart:*pos]
			if len(raw) > d.textCap {
				return fail("text_capacity")
			}
			if !utf8.Valid(raw) {
				return fail("invalid_utf8")
			}
			for offset := 0; offset < len(raw); {
				cp, n := utf8.DecodeRune(raw[offset:])
				if !unicode151.Assigned(cp) {
					return fail("unassigned_code_point")
				}
				offset += n
			}
			if !unicode151.IsNFC(raw, d.work, d.scratch) {
				return fail("non_canonical_text")
			}
		}
	}
	node.end = *pos
	return index, nil
}

func (d *Decoder) item(pos *int, end, depth int, field *wireField, context *DecodeContext) (int, error) {
	index, err := d.itemHead(pos, end, depth, field, context)
	if err != nil {
		return -1, err
	}
	node := &d.nodes[index]
	policy := d.registry.Encoding
	fail := func(s string) (int, error) { return -1, CBORFailure(s) }
	switch node.major {
	case 4:
		limit := policy.OrdinaryArrayItems
		var child *wireField
		if field != nil {
			child = field.Items
			if field.MaxItemsRef != "" {
				var ok bool
				limit, ok = context.Limits[field.MaxItemsRef]
				if !ok || limit > uint64(^uint32(0)) {
					return fail("limit_unresolved")
				}
			}
		}
		if node.n > limit {
			return fail("array_limit")
		}
		if node.n > uint64(end-*pos) {
			return fail("truncated")
		}
		previous := -1
		for range node.n {
			current, err := d.item(pos, end, depth+1, child, context)
			if err != nil {
				return -1, err
			}
			if previous < 0 {
				node.first = current
			} else {
				d.nodes[previous].next = current
			}
			previous = current
		}
	case 5:
		if node.n > policy.MaxMapEntries {
			return fail("map_limit")
		}
		if node.n > uint64((end-*pos)/2) {
			return fail("truncated")
		}
		textMap := field != nil && field.Type == "text_map"
		var m *wireMap
		if field != nil {
			m = d.registry.Maps[field.SchemaRef]
		}
		previousKey, previousValue := -1, -1
		for range node.n {
			key, err := d.item(pos, end, depth+1, nil, context)
			if err != nil {
				return -1, err
			}
			k := d.nodes[key]
			if textMap && k.major != 3 || !textMap && (k.major != 0 || k.n > policy.MaxFieldID) {
				return fail("field_id_type")
			}
			if previousKey >= 0 {
				p := d.nodes[previousKey]
				a, b := d.input[p.start:p.end], d.input[k.start:k.end]
				order := bytes.Compare(a, b)
				if order == 0 {
					return fail("duplicate_key")
				}
				if len(a) > len(b) || len(a) == len(b) && order > 0 {
					return fail("map_order")
				}
			}
			var child *wireField
			if m != nil {
				child = m.byID[k.n]
				if child == nil {
					return fail("unknown_field")
				}
			}
			if textMap {
				child = field.Values
				if field.Entries != nil {
					child = field.Entries[string(d.input[k.dataStart:k.end])]
					if child == nil {
						return fail("unknown_field")
					}
				}
			}
			value, err := d.item(pos, end, depth+1, child, context)
			if err != nil {
				return -1, err
			}
			d.nodes[key].next = value
			if previousValue < 0 {
				node.first = key
			} else {
				d.nodes[previousValue].next = key
			}
			previousKey = key
			previousValue = value
		}
	}
	node.end = *pos
	return index, nil
}

func (d *Decoder) lookup(index int, id uint64) int {
	if index < 0 || d.nodes[index].major != 5 {
		return -1
	}
	for key := d.nodes[index].first; key >= 0; {
		value := d.nodes[key].next
		if d.nodes[key].major == 0 && d.nodes[key].n == id {
			return value
		}
		key = d.nodes[value].next
	}
	return -1
}

func (d *Decoder) selector(context *wireContext, name string) (string, bool) {
	for c := context; c != nil; c = c.parent {
		if c.m != nil {
			if field, ok := c.m.ContextFields[name]; ok {
				f := c.m.byName[field]
				if f == nil {
					return "", false
				}
				v := d.lookup(c.node, f.id)
				if v < 0 || d.nodes[v].major != 0 {
					return "", false
				}
				for label, ordinal := range f.Enum {
					if d.nodes[v].n == ordinal {
						return label, true
					}
				}
				return "", false
			}
		}
	}
	text, ok := context.external.Selectors[name]
	return text, ok
}

func (d *Decoder) shape(index int, f *wireField, context *wireContext) error {
	return d.shapeStep(index, f, context, d.shape)
}

// shapeStep uses the same registry checks for synchronous and resumable walks.
// The visit operation only chooses when the child is checked.
func (d *Decoder) shapeStep(index int, f *wireField, context *wireContext, visit func(int, *wireField, *wireContext) error) error {
	if f == nil || index < 0 {
		return CBORFailure("schema_type_unresolved")
	}
	if f.Type == "context_variant" {
		label, ok := d.selector(context, f.Context)
		if !ok || f.Cases[label] == nil {
			return CBORFailure("context_unresolved")
		}
		return d.shapeStep(index, f.Cases[label], context, visit)
	}
	v := &d.nodes[index]
	if v.major == 7 && v.n == 22 && f.Type == "uint64" && f.Nullable {
		return nil
	}
	if f.width > 0 {
		if v.major != 0 {
			return CBORFailure("integer_type")
		}
		if f.width < 64 && v.n >= uint64(1)<<f.width {
			return CBORFailure("integer_range")
		}
		if f.Min != nil && v.n < uint64(*f.Min) || f.Max != nil && v.n > uint64(*f.Max) {
			return CBORFailure("field_range")
		}
		if f.Bitmask != nil && v.n & ^uint64(*f.Bitmask) != 0 {
			return CBORFailure("unknown_bits")
		}
		if f.enums != nil && !f.enums[v.n] {
			return CBORFailure("enum_value")
		}
	} else {
		switch f.Type {
		case "bytes", "text":
			major := byte(2)
			if f.Type == "text" {
				major = 3
			}
			if v.major != major {
				return CBORFailure("field_type")
			}
			n := v.n
			raw := d.input[v.dataStart:v.end]
			if f.Length != nil && n != uint64(*f.Length) || f.MinBytes != nil && n < uint64(*f.MinBytes) || f.MaxBytes != nil && n > uint64(*f.MaxBytes) {
				return CBORFailure("field_length")
			}
			if f.MaxRef != "" {
				max, ok := context.external.Limits[f.MaxRef]
				if !ok {
					return CBORFailure("limit_unresolved")
				}
				if n > max {
					return CBORFailure("field_length")
				}
			}
			if f.Nonzero {
				nonzero := false
				for _, b := range raw {
					nonzero = nonzero || b != 0
				}
				if !nonzero {
					return CBORFailure("field_nonzero")
				}
			}
			if f.texts != nil && !f.texts[string(raw)] {
				return CBORFailure("enum_value")
			}
			if f.pattern != nil && !f.pattern.Match(raw) {
				return CBORFailure("text_pattern")
			}
			if f.ForbiddenPrefix != nil && strings.HasPrefix(string(raw), *f.ForbiddenPrefix) {
				return CBORFailure("reserved_namespace")
			}
			if f.ProfilePublicKey {
				label, ok := d.selector(context, "crypto_profile_id")
				if !ok {
					return CBORFailure("context_unresolved")
				}
				p, err := Profile(label)
				if err != nil {
					return err
				}
				if n != uint64(p.DHPublicBytes) {
					return CBORFailure("field_length")
				}
				if p.DHAlgorithm == 1 && raw[0] != 4 {
					return CBORFailure("field_prefix")
				}
			}
			if f.EncodedSchemaRef != "" && !(f.AllowEmpty && n == 0) {
				m := d.registry.Maps[f.EncodedSchemaRef]
				if m == nil {
					return CBORFailure("unknown_schema")
				}
				if err := mapLength(m, n, context.external); err != nil {
					return err
				}
				if d.snapshotEnvelope && context.m == d.registry.Maps["ContractSnapshot"] && (f.EncodedSchemaRef == "ServiceContract" || f.EncodedSchemaRef == "AdmissionOffer") {
					// Byte length/outer variant are checked here. The private
					// query codec checks each complete body in one shared arena.
					break
				}
				pos := v.dataStart
				embedded := &wireField{Type: "map", SchemaRef: f.EncodedSchemaRef}
				root, err := d.item(&pos, v.end, 0, embedded, context.external)
				if err != nil {
					return err
				}
				if pos != v.end {
					return CBORFailure("trailing_bytes")
				}
				v.embedded = root
				if err := visit(root, embedded, context); err != nil {
					return err
				}
			}
		case "bool":
			if v.major != 7 || (v.n != 20 && v.n != 21) {
				return CBORFailure("field_type")
			}
		case "map":
			m := d.registry.Maps[f.SchemaRef]
			if m == nil {
				return CBORFailure("unknown_schema")
			}
			if v.major != 5 {
				return CBORFailure("map_type")
			}
			if err := mapLength(m, uint64(v.end-v.start), context.external); err != nil {
				return err
			}
			childContext := wireContext{external: context.external, parent: context, m: m, node: index}
			for key := v.first; key >= 0; {
				value := d.nodes[key].next
				child := m.byID[d.nodes[key].n]
				if d.nodes[key].major != 0 || child == nil {
					return CBORFailure("unknown_field")
				}
				if err := visit(value, child, &childContext); err != nil {
					return err
				}
				key = d.nodes[value].next
			}
			for _, id := range m.Required {
				if d.lookup(index, id) < 0 {
					return CBORFailure("missing_field")
				}
			}
		case "text_map":
			if v.major != 5 {
				return CBORFailure("map_type")
			}
			if f.MinItems == nil || f.MaxItems == nil {
				return CBORFailure("schema_type_unresolved")
			}
			if v.n < uint64(*f.MinItems) || v.n > uint64(*f.MaxItems) {
				return CBORFailure("map_length")
			}
			if f.Entries != nil && int(v.n) != len(f.Entries) {
				return CBORFailure("missing_field")
			}
			for key := v.first; key >= 0; {
				value := d.nodes[key].next
				if err := visit(key, f.Keys, context); err != nil {
					return err
				}
				child := f.Values
				if f.Entries != nil {
					k := d.nodes[key]
					child = f.Entries[string(d.input[k.dataStart:k.end])]
					if child == nil {
						return CBORFailure("unknown_field")
					}
				}
				if err := visit(value, child, context); err != nil {
					return err
				}
				key = d.nodes[value].next
			}
		case "array", "array<uint64>":
			if v.major != 4 {
				return CBORFailure("field_type")
			}
			limit := d.registry.Encoding.OrdinaryArrayItems
			if f.MaxItems != nil {
				limit = uint64(*f.MaxItems)
			}
			if f.MaxItemsRef != "" {
				var ok bool
				limit, ok = context.external.Limits[f.MaxItemsRef]
				if !ok || limit > uint64(^uint32(0)) {
					return CBORFailure("limit_unresolved")
				}
			}
			if f.MinItems == nil {
				return CBORFailure("schema_type_unresolved")
			}
			if v.n < uint64(*f.MinItems) || v.n > limit {
				return CBORFailure("array_length")
			}
			child := f.Items
			if f.Type == "array<uint64>" {
				child = &wireField{Type: "uint64", width: 64}
			}
			for item := v.first; item >= 0; item = d.nodes[item].next {
				if err := visit(item, child, context); err != nil {
					return err
				}
			}
		default:
			return CBORFailure("schema_type_unresolved")
		}
	}
	if c := f.constant; c != nil {
		if v.major != c.major || (v.major == 0 || v.major == 7) && v.n != c.n || (v.major == 2 || v.major == 3) && string(d.input[v.dataStart:v.end]) != c.text {
			return CBORFailure("constant_mismatch")
		}
	}
	return nil
}

package protocolv4

// This test-only syntax reader is independent of the Node vector codec. The
// registry controls nullable slots, text-map keys and capacity-bound arrays.
// Field membership/types, semantic rules, authentication and
// runtime byte/work ownership remain separate gates. Returned bytes borrow the
// immutable fixture input; this is not a public or production receiver API.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"unicode/utf8"
)

type cborRefError string

func (e cborRefError) Error() string { return string(e) }

type cborRefField struct {
	Name                      string
	Type                      string
	SchemaRef                 string `json:"schema_ref"`
	EncodedSchemaRef          string `json:"encoded_schema_ref"`
	AllowEmpty                bool   `json:"allow_empty"`
	Nullable                  bool
	MaxItemsRef               string `json:"max_items_ref"`
	Items                     *cborRefField
	Values                    *cborRefField
	Entries                   map[string]*cborRefField
	Keys                      *cborRefField
	Min, Max, Length, Bitmask *cborRefBound
	MinBytes                  *cborRefBound `json:"min_bytes"`
	MaxBytes                  *cborRefBound `json:"max_bytes"`
	MinItems                  *cborRefBound `json:"min_items"`
	MaxItems                  *cborRefBound `json:"max_items"`
	Const                     json.RawMessage
	Enum                      map[string]uint64
	EnumRef                   string  `json:"enum_ref"`
	TextEnumRef               string  `json:"text_enum_ref"`
	ConstRef                  string  `json:"const_ref"`
	PatternRef                string  `json:"pattern_ref"`
	TextFormat                string  `json:"text_format"`
	MaxRef                    string  `json:"max_ref"`
	ForbiddenPrefix           *string `json:"forbidden_prefix"`
	Nonzero                   bool
	ProfilePublicKey          bool `json:"profile_public_key"`
	Context                   string
	Cases                     map[string]*cborRefField
}

type cborRefMap struct {
	Fields             map[string]*cborRefField
	MaxEncodedBytes    *uint64 `json:"max_encoded_bytes"`
	MaxEncodedBytesRef string  `json:"max_encoded_bytes_ref"`
	EncodedBytes       *uint64 `json:"encoded_bytes"`
	Required           []uint64
	ContextFields      map[string]string `json:"context_fields"`
	SignatureField     *uint64           `json:"signature_field"`
	MACField           *uint64           `json:"mac_field"`
}

type cborRefRegistry struct {
	Encoding struct {
		MaxDepth           int    `json:"max_depth"`
		MaxMapEntries      uint64 `json:"max_map_entries"`
		OrdinaryArrayItems uint64 `json:"ordinary_array_items"`
		MaxFieldID         uint64 `json:"max_field_id"`
	}
	Maps           map[string]cborRefMap `json:"frame_maps"`
	MapProjections map[string]struct {
		Source, Target string
		Fields         []string
	} `json:"map_projections"`
	VariantRules    map[string][]json.RawMessage `json:"variant_rules"`
	RelationRules   map[string][]json.RawMessage `json:"relation_rules"`
	TextRules       map[string][]json.RawMessage `json:"text_rules"`
	FieldRegistries map[string]json.RawMessage   `json:"field_registries"`
	Unicode         struct {
		NFCData  struct{ Path, SHA256 string } `json:"nfc_data"`
		IDNAData struct{ Path, SHA256 string } `json:"idna_data"`
	}
}

type cborRefValue struct {
	major byte
	n     uint64
	data  []byte
	items []*cborRefValue
	pairs [][2]*cborRefValue
}

type cborReference struct {
	registry cborRefRegistry
	unicode  *nfcReference
}

func newCBORReference(t testing.TB) *cborReference {
	t.Helper()
	r := &cborReference{}
	if err := json.Unmarshal([]byte(CBORSyntaxRegistryJSON), &r.registry); err != nil {
		t.Fatal(err)
	}
	r.unicode = newNFCReference(t, r.registry.Unicode.NFCData.Path, r.registry.Unicode.NFCData.SHA256)
	return r
}

type cborRefReader struct {
	reference *cborReference
	input     []byte
	offset    int
	nodes     int
	limits    map[string]uint64
}

func (r *cborRefReader) take(n uint64) ([]byte, error) {
	// Compare in uint64 before any host-int conversion or offset arithmetic.
	if n > uint64(len(r.input)-r.offset) {
		return nil, cborRefError("truncated")
	}
	start := r.offset
	r.offset += int(n)
	return r.input[start:r.offset], nil
}

func (r *cborReference) decode(input []byte, name string, limits map[string]uint64, ownerByteCap uint64) (*cborRefValue, int, error) {
	// The owner cap is explicit even for schema-free input. No copy or parsed
	// node allocation happens before this check. It is a test input, not proof
	// that a live owner has reserved the corresponding physical memory.
	if ownerByteCap == 0 {
		return nil, 0, cborRefError("limit_unresolved")
	}
	var descriptor *cborRefField
	if name != "" {
		definition, ok := r.registry.Maps[name]
		if !ok {
			return nil, 0, cborRefError("unknown_schema")
		}
		if definition.MaxEncodedBytes != nil && *definition.MaxEncodedBytes < ownerByteCap {
			ownerByteCap = *definition.MaxEncodedBytes
		}
		if ref := definition.MaxEncodedBytesRef; ref != "" {
			cap, ok := limits[ref]
			if !ok || cap == 0 {
				return nil, 0, cborRefError("limit_unresolved")
			}
			if cap < ownerByteCap {
				ownerByteCap = cap
			}
		}
		descriptor = &cborRefField{Type: "map", SchemaRef: name}
	}
	if uint64(len(input)) > ownerByteCap {
		return nil, 0, cborRefError("map_size")
	}
	reader := cborRefReader{reference: r, input: input, limits: limits}
	value, err := reader.item(0, descriptor)
	if err == nil && reader.offset != len(input) {
		err = cborRefError("trailing_bytes")
	}
	if err != nil {
		return nil, reader.nodes, err
	}
	return value, reader.nodes, nil
}

func (r *cborRefReader) item(depth int, descriptor *cborRefField) (*cborRefValue, error) {
	policy := r.reference.registry.Encoding
	if depth > policy.MaxDepth {
		return nil, cborRefError("depth_limit")
	}
	head, err := r.take(1)
	if err != nil {
		return nil, err
	}
	major, ai := head[0]>>5, head[0]&31
	if ai == 31 {
		return nil, cborRefError("indefinite_length")
	}
	if major == 7 {
		if ai == 20 || ai == 21 || (ai == 22 && descriptor != nil && descriptor.Type == "uint64" && descriptor.Nullable) {
			r.nodes++
			return &cborRefValue{major: major, n: uint64(ai)}, nil
		}
		return nil, cborRefError("unsupported_type")
	}
	if major != 0 && major != 2 && major != 3 && major != 4 && major != 5 {
		return nil, cborRefError("unsupported_type")
	}
	if ai > 27 {
		return nil, cborRefError("invalid_header")
	}
	n := uint64(ai)
	if ai >= 24 {
		width := uint64(1) << (ai - 24)
		raw, err := r.take(width)
		if err != nil {
			return nil, err
		}
		n = 0
		for _, b := range raw {
			n = n<<8 | uint64(b)
		}
		minimum := [...]uint64{24, 256, 65536, 4294967296}[ai-24]
		if n < minimum {
			return nil, cborRefError("non_shortest_integer")
		}
	}
	if major == 2 || major == 3 {
		raw, err := r.take(n)
		if err != nil {
			return nil, err
		}
		if major == 3 {
			if !utf8.Valid(raw) {
				return nil, cborRefError("invalid_utf8")
			}
			text := string(raw)
			for _, cp := range text {
				if !r.reference.unicode.assigned(cp) {
					return nil, cborRefError("unassigned_code_point")
				}
			}
			if r.reference.unicode.normalize(text) != text {
				return nil, cborRefError("non_canonical_text")
			}
		}
		if major == 2 && descriptor != nil && descriptor.EncodedSchemaRef != "" && !(descriptor.AllowEmpty && len(raw) == 0) {
			// This is a separate encoded document, so its root depth/size rules
			// apply independently. Preserve the original bstr for signatures.
			_, nodes, err := r.reference.decode(raw, descriptor.EncodedSchemaRef, r.limits, uint64(len(raw))+1)
			r.nodes += nodes
			if err != nil {
				return nil, err
			}
		}
		r.nodes++
		return &cborRefValue{major: major, data: raw}, nil
	}
	if major == 0 {
		r.nodes++
		return &cborRefValue{major: major, n: n}, nil
	}
	if major == 4 {
		limit := policy.OrdinaryArrayItems
		var child *cborRefField
		if descriptor != nil {
			child = descriptor.Items
			if descriptor.MaxItemsRef != "" {
				var ok bool
				limit, ok = r.limits[descriptor.MaxItemsRef]
				if !ok || limit > uint64(^uint32(0)) {
					return nil, cborRefError("limit_unresolved")
				}
			}
		}
		if n > limit {
			return nil, cborRefError("array_limit")
		}
		if n > uint64(len(r.input)-r.offset) {
			return nil, cborRefError("truncated")
		}
		r.nodes++
		value := &cborRefValue{major: major, items: make([]*cborRefValue, 0, int(n))}
		for range n {
			item, err := r.item(depth+1, child)
			if err != nil {
				return nil, err
			}
			value.items = append(value.items, item)
		}
		return value, nil
	}
	if n > policy.MaxMapEntries {
		return nil, cborRefError("map_limit")
	}
	// Each pair consumes at least two bytes. Reject forged counts before
	// allocating pair slots, including a complete uint64 count on a 32-bit host.
	if n > uint64((len(r.input)-r.offset)/2) {
		return nil, cborRefError("truncated")
	}
	textMap := descriptor != nil && descriptor.Type == "text_map"
	var fields map[string]*cborRefField
	if descriptor != nil {
		fields = r.reference.registry.Maps[descriptor.SchemaRef].Fields
	}
	r.nodes++
	value := &cborRefValue{major: major, pairs: make([][2]*cborRefValue, 0, int(n))}
	var previous []byte
	seen := make(map[string]bool, int(n))
	for range n {
		start := r.offset
		key, err := r.item(depth+1, nil)
		if err != nil {
			return nil, err
		}
		if (textMap && key.major != 3) || (!textMap && (key.major != 0 || key.n > policy.MaxFieldID)) {
			return nil, cborRefError("field_id_type")
		}
		encoded := r.input[start:r.offset]
		if seen[string(encoded)] {
			return nil, cborRefError("duplicate_key")
		}
		if previous != nil && (len(previous) > len(encoded) || (len(previous) == len(encoded) && bytes.Compare(previous, encoded) >= 0)) {
			return nil, cborRefError("map_order")
		}
		seen[string(encoded)] = true
		previous = encoded
		child := fields[strconv.FormatUint(key.n, 10)]
		if textMap {
			child = descriptor.Entries[string(key.data)]
			if child == nil {
				child = descriptor.Values
			}
		}
		item, err := r.item(depth+1, child)
		if err != nil {
			return nil, err
		}
		value.pairs = append(value.pairs, [2]*cborRefValue{key, item})
	}
	return value, nil
}

func cborRefHead(out []byte, major byte, n uint64) []byte {
	if n < 24 {
		return append(out, major<<5|byte(n))
	}
	ai, width := byte(24), 1
	for width < 8 && n >= uint64(1)<<(8*width) {
		ai++
		width *= 2
	}
	out = append(out, major<<5|ai)
	for i := width - 1; i >= 0; i-- {
		out = append(out, byte(n>>(8*i)))
	}
	return out
}

func (v *cborRefValue) encode(out []byte) []byte {
	switch v.major {
	case 0:
		return cborRefHead(out, 0, v.n)
	case 2, 3:
		return append(cborRefHead(out, v.major, uint64(len(v.data))), v.data...)
	case 4:
		out = cborRefHead(out, 4, uint64(len(v.items)))
		for _, item := range v.items {
			out = item.encode(out)
		}
	case 5:
		out = cborRefHead(out, 5, uint64(len(v.pairs)))
		for _, pair := range v.pairs {
			out = pair[1].encode(pair[0].encode(out))
		}
	case 7:
		return append(out, 0xe0|byte(v.n))
	default:
		panic("invalid test syntax tree")
	}
	return out
}

type cborRefVector struct {
	ID, Kind, Hex, Schema, Decimal string
	ExpectedError                  string                     `json:"expected_error"`
	Limits                         map[string]json.RawMessage `json:"limits"`
	PoolDerivation                 *struct {
		ArtifactHex string `json:"artifact_hex"`
		Indices     []uint64
	} `json:"pool_derivation"`
	TypedDerivation *struct {
		DefinitionHex  string `json:"definition_hex"`
		ApplicationHex string `json:"application_hex"`
	} `json:"typed_derivation"`
}

func cborRefVectors(t testing.TB) []cborRefVector {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaSHA256 string `json:"schema_sha256"`
		Vectors      []cborRefVector
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaSHA256 != SchemaSHA256 {
		t.Fatal("CBOR corpus schema drift")
	}
	return corpus.Vectors
}

// v4.cbor.corpus
func TestCBORReferenceCorpus(t *testing.T) {
	r := newCBORReference(t)
	positive, negative := 0, 0
	// These are syntax errors only. Other corpus negatives require schema
	// fields/variants or semantic validation not yet present.
	syntaxErrors := map[string]bool{}
	for _, code := range []string{"non_canonical_text", "unassigned_code_point", "invalid_utf8", "unsupported_type", "array_limit", "duplicate_key", "non_shortest_integer", "map_order", "truncated", "trailing_bytes", "field_id_type", "indefinite_length", "depth_limit", "invalid_header", "map_limit"} {
		syntaxErrors[code] = true
	}
	for _, vector := range cborRefVectors(t) {
		if vector.ExpectedError != "" && !syntaxErrors[vector.ExpectedError] {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			limits := map[string]uint64{}
			for name, raw := range vector.Limits {
				var value uint64
				if json.Unmarshal(raw, &value) == nil {
					limits[name] = value
				}
			}
			value, nodes, err := r.decode(input, vector.Schema, limits, uint64(len(input)+1))
			if !bytes.Equal(input, original) || nodes > len(input) {
				t.Fatal("input mutation or unbounded syntax node count")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatal("accepted malformed CBOR")
				}
				// A complete syntax pass can reject before the semantic oracle.
				// Explicit syntax fixtures have exactly one authoritative error.
				if vector.Kind == "cbor_syntax" && err.Error() != vector.ExpectedError {
					t.Fatalf("want %s, got %v", vector.ExpectedError, err)
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value.encode(nil), input) {
				t.Fatal("canonical re-encoding differs")
			}
			if vector.Decimal != "" && strconv.FormatUint(value.n, 10) != vector.Decimal {
				t.Fatal("uint64 precision loss")
			}
		})
	}
	if positive == 0 || negative == 0 {
		t.Fatal("empty syntax coverage")
	}
	t.Logf("%d positive and %d syntax-negative vectors; semantic validation excluded", positive, negative)
}

// v4.cbor.limits
func TestCBORReferenceLimits(t *testing.T) {
	r := newCBORReference(t)
	for _, raw := range []string{"5bffffffffffffffff", "7bffffffffffffffff", "9bffffffffffffffff", "bbffffffffffffffff", "99040b", "b880"} {
		input, _ := hex.DecodeString(raw)
		if _, nodes, err := r.decode(input, "", nil, 64); err == nil || nodes != 0 {
			t.Fatalf("forged root count allocated nodes: %s (%d, %v)", raw, nodes, err)
		}
	}
	if _, nodes, err := r.decode([]byte{0xff, 0xff}, "", nil, 1); err != cborRefError("map_size") || nodes != 0 {
		t.Fatal("root cap was not checked before syntax")
	}
	if _, _, err := r.decode([]byte{0}, "", nil, 0); err != cborRefError("limit_unresolved") {
		t.Fatal("missing owner cap accepted")
	}
	if _, _, err := r.decode([]byte{0}, "RevocationState", nil, 1); err != cborRefError("limit_unresolved") {
		t.Fatal("missing original capacity accepted")
	}
	for _, n := range []uint64{128, 1035} {
		var input []byte
		if n == 128 {
			input = cborRefHead(nil, 5, n)
			for i := range n {
				input = append(cborRefHead(input, 0, i), 0)
			}
		} else {
			input = append(cborRefHead(nil, 4, n), make([]byte, n)...)
		}
		value, _, err := r.decode(input, "", nil, uint64(len(input)))
		if err != nil || !bytes.Equal(value.encode(nil), input) {
			t.Fatalf("legal maximum rejected: %d: %v", n, err)
		}
	}
}

// v4.cbor.context
func TestCBORReferenceContextSlots(t *testing.T) {
	r := newCBORReference(t)
	var seed cborRefVector
	for _, vector := range cborRefVectors(t) {
		if vector.ID == "revoked_issuer_minimum" {
			seed = vector
			break
		}
	}
	input, err := hex.DecodeString(seed.Hex)
	if err != nil || len(input) == 0 {
		t.Fatal("missing issuer seed")
	}
	limits := map[string]uint64{"max_state_encoded_bytes": 1 << 20, "max_revoked_issuer_authorizations": 1036}
	value, _, err := r.decode(input, seed.Schema, limits, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var array *cborRefValue
	for _, pair := range value.pairs {
		field := r.registry.Maps[seed.Schema].Fields[strconv.FormatUint(pair[0].n, 10)]
		if field != nil && field.MaxItemsRef == "max_revoked_issuer_authorizations" {
			array = pair[1]
		}
	}
	if array == nil || len(array.items) == 0 {
		t.Fatal("missing capacity array")
	}
	// Repetition is deliberately syntax-only; the schema's uniqueness rule is
	// a separate semantic obligation. This tests the capacity exception itself.
	item := array.items[0]
	array.items = make([]*cborRefValue, 1036)
	for i := range array.items {
		array.items[i] = item
	}
	input = value.encode(nil)
	if got, _, err := r.decode(input, seed.Schema, limits, uint64(len(input))); err != nil || !bytes.Equal(got.encode(nil), input) {
		t.Fatalf("declared capacity array rejected: %v", err)
	}
	limits["max_revoked_issuer_authorizations"] = 1035
	if _, _, err := r.decode(input, seed.Schema, limits, uint64(len(input))); err != cborRefError("array_limit") {
		t.Fatalf("count cap bypassed: %v", err)
	}
	limits["max_revoked_issuer_authorizations"] = 1 << 32
	if _, _, err := r.decode(input, seed.Schema, limits, uint64(len(input))); err != cborRefError("limit_unresolved") {
		t.Fatalf("unrepresentable count accepted: %v", err)
	}
	limits["max_revoked_issuer_authorizations"] = 1036
	limits["max_state_encoded_bytes"] = uint64(len(input) - 1)
	if _, nodes, err := r.decode(input, seed.Schema, limits, uint64(len(input))); err != cborRefError("map_size") || nodes != 0 {
		t.Fatal("original document cap bypassed")
	}
}

// v4.cbor.fuzz
func FuzzCBORReference(f *testing.F) {
	r := newCBORReference(f)
	for _, vector := range cborRefVectors(f) {
		if vector.Schema == "" {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(input)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		original := bytes.Clone(input)
		value, nodes, err := r.decode(input, "", nil, 4096)
		if !bytes.Equal(input, original) || nodes > len(input) {
			t.Fatal("input changed or node count exceeded byte envelope")
		}
		if err == nil && !bytes.Equal(value.encode(nil), input) {
			t.Fatal(fmt.Sprintf("accepted noncanonical input %x", input))
		}
	})
}

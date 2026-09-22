package protocolv4

// Test-only schema field validation over the independent canonical reader.
// Cross-field map_rules, host/Origin/IDNA formats, signatures and live context
// authority are deliberately outside this layer; valid shape grants no rights.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type cborRefBound uint64

func (b *cborRefBound) UnmarshalJSON(raw []byte) error {
	var text string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
	} else {
		text = string(raw)
	}
	n, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return err
	}
	*b = cborRefBound(n)
	return nil
}

type cborShapeContext struct {
	limits    map[string]uint64
	selectors map[string]string
}

func shapeContext(raw map[string]json.RawMessage) cborShapeContext {
	context := cborShapeContext{limits: map[string]uint64{}, selectors: map[string]string{}}
	for key, value := range raw {
		var n uint64
		var text string
		if json.Unmarshal(value, &n) == nil {
			context.limits[key] = n
		}
		if json.Unmarshal(value, &text) == nil {
			context.selectors[key] = text
		}
	}
	return context
}

func (r *cborReference) shape(input []byte, name string, context cborShapeContext, cap uint64) (*cborRefValue, error) {
	value, _, err := r.decode(input, name, context.limits, cap)
	if err != nil {
		return nil, err
	}
	if name != "" {
		if err := r.shapeMap(name, value, context); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func cborLookup(value *cborRefValue, id uint64) *cborRefValue {
	if value == nil || value.major != 5 {
		return nil
	}
	for _, pair := range value.pairs {
		if pair[0].major == 0 && pair[0].n == id {
			return pair[1]
		}
	}
	return nil
}

func (r *cborReference) mapShapeContext(name string, value *cborRefValue, context cborShapeContext) (cborShapeContext, error) {
	definition, ok := r.registry.Maps[name]
	if !ok {
		return context, cborRefError("unknown_schema")
	}
	if value == nil || value.major != 5 {
		return context, cborRefError("map_type")
	}
	// A signed containing discriminator takes precedence over caller context.
	// Clone only when a containing map establishes a new scope.
	if len(definition.ContextFields) > 0 {
		selectors := map[string]string{}
		for k, v := range context.selectors {
			selectors[k] = v
		}
		context.selectors = selectors
		for key, fieldName := range definition.ContextFields {
			found := false
			for id, field := range definition.Fields {
				if field.Name != fieldName {
					continue
				}
				n, err := strconv.ParseUint(id, 10, 16)
				if err != nil {
					return context, cborRefError("registry_unresolved")
				}
				input := cborLookup(value, n)
				if input == nil {
					return context, cborRefError("missing_field")
				}
				if input.major != 0 {
					return context, cborRefError("integer_type")
				}
				for label, ordinal := range field.Enum {
					if input.n == ordinal {
						selectors[key] = label
						found = true
						break
					}
				}
			}
			if !found {
				return context, cborRefError("context_unresolved")
			}
		}
	}
	return context, nil
}

func (r *cborReference) shapeMap(name string, value *cborRefValue, context cborShapeContext) error {
	context, err := r.mapShapeContext(name, value, context)
	if err != nil {
		return err
	}
	definition := r.registry.Maps[name]
	for _, pair := range value.pairs {
		if pair[0].major != 0 {
			return cborRefError("field_id_type")
		}
		field := definition.Fields[strconv.FormatUint(pair[0].n, 10)]
		if field == nil {
			return cborRefError("unknown_field")
		}
		if err := r.shapeField(field, pair[1], context); err != nil {
			return err
		}
	}
	for _, id := range definition.Required {
		if cborLookup(value, id) == nil {
			return cborRefError("missing_field")
		}
	}
	length := uint64(len(value.encode(nil)))
	if definition.MaxEncodedBytes != nil && length > *definition.MaxEncodedBytes {
		return cborRefError("map_size")
	}
	if definition.EncodedBytes != nil && length != *definition.EncodedBytes {
		return cborRefError("map_size")
	}
	if ref := definition.MaxEncodedBytesRef; ref != "" {
		limit, ok := context.limits[ref]
		if !ok || limit == 0 {
			return cborRefError("limit_unresolved")
		}
		if length > limit {
			return cborRefError("map_size")
		}
	}
	return nil
}

func (r *cborReference) fieldRegistry(name string) (map[string]json.RawMessage, error) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(r.registry.FieldRegistries[name], &entries); err != nil || len(entries) == 0 {
		return nil, cborRefError("registry_unresolved")
	}
	return entries, nil
}

func rawUint(raw json.RawMessage) (uint64, error) {
	var value cborRefBound
	err := json.Unmarshal(raw, &value)
	return uint64(value), err
}

func (r *cborReference) shapeField(field *cborRefField, value *cborRefValue, context cborShapeContext) error {
	if field == nil || value == nil {
		return cborRefError("schema_type_unresolved")
	}
	if field.Type == "context_variant" {
		resolved := field.Cases[context.selectors[field.Context]]
		if resolved == nil {
			return cborRefError("context_unresolved")
		}
		return r.shapeField(resolved, value, context)
	}
	if value.major == 7 && value.n == 22 && field.Type == "uint64" && field.Nullable {
		return nil
	}
	switch field.Type {
	case "uint8", "uint16", "uint32", "uint64":
		if value.major != 0 {
			return cborRefError("integer_type")
		}
		width, _ := strconv.Atoi(field.Type[4:])
		if width < 64 && value.n >= uint64(1)<<width {
			return cborRefError("integer_range")
		}
		if (field.Min != nil && value.n < uint64(*field.Min)) || (field.Max != nil && value.n > uint64(*field.Max)) {
			return cborRefError("field_range")
		}
		if field.Bitmask != nil && value.n & ^uint64(*field.Bitmask) != 0 {
			return cborRefError("unknown_bits")
		}
		if len(field.Const) > 0 {
			want, err := rawUint(field.Const)
			if err != nil || want != value.n {
				return cborRefError("constant_mismatch")
			}
		}
		if field.Enum != nil {
			found := false
			for _, ordinal := range field.Enum {
				if value.n == ordinal {
					found = true
					break
				}
			}
			if !found {
				return cborRefError("enum_value")
			}
		}
		if field.EnumRef != "" {
			entries, err := r.fieldRegistry(field.EnumRef)
			if err != nil {
				return err
			}
			found := false
			for _, raw := range entries {
				if len(raw) > 0 && raw[0] == '{' {
					var entry map[string]json.RawMessage
					if json.Unmarshal(raw, &entry) != nil {
						return cborRefError("registry_unresolved")
					}
					raw = entry["code"]
				}
				ordinal, err := rawUint(raw)
				if err != nil {
					return cborRefError("registry_unresolved")
				}
				if value.n == ordinal {
					found = true
				}
			}
			if !found {
				return cborRefError("enum_value")
			}
		}
	case "bytes", "text":
		wantMajor := byte(2)
		if field.Type == "text" {
			wantMajor = 3
		}
		if value.major != wantMajor {
			return cborRefError("field_type")
		}
		n := uint64(len(value.data))
		if (field.Length != nil && n != uint64(*field.Length)) || (field.MinBytes != nil && n < uint64(*field.MinBytes)) || (field.MaxBytes != nil && n > uint64(*field.MaxBytes)) {
			return cborRefError("field_length")
		}
		if field.Nonzero {
			nonzero := false
			for _, b := range value.data {
				nonzero = nonzero || b != 0
			}
			if !nonzero {
				return cborRefError("field_nonzero")
			}
		}
		if field.ProfilePublicKey {
			profiles, err := r.fieldRegistry("crypto_profiles")
			if err != nil {
				return err
			}
			var profile struct {
				DHBytes   uint64 `json:"dh_public_bytes"`
				Algorithm uint8  `json:"dh_algorithm"`
			}
			if json.Unmarshal(profiles[context.selectors["crypto_profile_id"]], &profile) != nil || profile.DHBytes == 0 {
				return cborRefError("context_unresolved")
			}
			if n != profile.DHBytes {
				return cborRefError("field_length")
			}
			if profile.Algorithm == 1 && value.data[0] != 4 {
				return cborRefError("field_prefix")
			}
		}
		for _, raw := range []json.RawMessage{field.Const, r.registry.FieldRegistries[field.ConstRef]} {
			if len(raw) == 0 {
				continue
			}
			var want string
			if json.Unmarshal(raw, &want) != nil || string(value.data) != want {
				return cborRefError("constant_mismatch")
			}
		}
		if field.ConstRef != "" && len(r.registry.FieldRegistries[field.ConstRef]) == 0 {
			return cborRefError("registry_unresolved")
		}
		if field.PatternRef != "" {
			patterns, err := r.fieldRegistry("text_patterns")
			if err != nil {
				return err
			}
			var pattern string
			if json.Unmarshal(patterns[field.PatternRef], &pattern) != nil {
				return cborRefError("pattern_unresolved")
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return cborRefError("pattern_unresolved")
			}
			match := re.FindIndex(value.data)
			if match == nil || match[0] != 0 || match[1] != len(value.data) {
				return cborRefError("text_pattern")
			}
		}
		if field.TextEnumRef != "" {
			entries, err := r.fieldRegistry(field.TextEnumRef)
			if err != nil {
				return err
			}
			if _, ok := entries[string(value.data)]; !ok {
				return cborRefError("enum_value")
			}
		}
		if field.ForbiddenPrefix != nil && strings.HasPrefix(string(value.data), *field.ForbiddenPrefix) {
			return cborRefError("reserved_namespace")
		}
		if field.EncodedSchemaRef != "" && !(field.AllowEmpty && n == 0) {
			if _, err := r.shape(value.data, field.EncodedSchemaRef, context, n+1); err != nil {
				return err
			}
		}
		if field.MaxRef != "" {
			limit, ok := context.limits[field.MaxRef]
			if !ok {
				return cborRefError("limit_unresolved")
			}
			if n > limit {
				return cborRefError("field_length")
			}
		}
	case "bool":
		if value.major != 7 || (value.n != 20 && value.n != 21) {
			return cborRefError("field_type")
		}
		if len(field.Const) > 0 {
			var want bool
			if json.Unmarshal(field.Const, &want) != nil || want != (value.n == 21) {
				return cborRefError("field_equality")
			}
		}
	case "map":
		return r.shapeMap(field.SchemaRef, value, context)
	case "text_map":
		if value.major != 5 {
			return cborRefError("map_type")
		}
		n := uint64(len(value.pairs))
		if field.MinItems == nil || field.MaxItems == nil {
			return cborRefError("schema_type_unresolved")
		}
		if n < uint64(*field.MinItems) || n > uint64(*field.MaxItems) {
			return cborRefError("map_length")
		}
		seen := map[string]bool{}
		for _, pair := range value.pairs {
			if err := r.shapeField(field.Keys, pair[0], context); err != nil {
				return err
			}
			key := string(pair[0].data)
			child := field.Values
			if field.Entries != nil {
				child = field.Entries[key]
			}
			if child == nil {
				return cborRefError("unknown_field")
			}
			if err := r.shapeField(child, pair[1], context); err != nil {
				return err
			}
			seen[key] = true
		}
		for key := range field.Entries {
			if !seen[key] {
				return cborRefError("missing_field")
			}
		}
	case "array", "array<uint64>":
		if value.major != 4 {
			return cborRefError("field_type")
		}
		limit := r.registry.Encoding.OrdinaryArrayItems
		if field.MaxItems != nil {
			limit = uint64(*field.MaxItems)
		}
		if field.MaxItemsRef != "" {
			var ok bool
			limit, ok = context.limits[field.MaxItemsRef]
			if !ok || limit > uint64(^uint32(0)) {
				return cborRefError("limit_unresolved")
			}
		}
		if field.MinItems == nil {
			return cborRefError("schema_type_unresolved")
		}
		if uint64(len(value.items)) < uint64(*field.MinItems) || uint64(len(value.items)) > limit {
			return cborRefError("array_length")
		}
		child := field.Items
		if field.Type == "array<uint64>" {
			child = &cborRefField{Type: "uint64"}
		}
		for _, item := range value.items {
			if err := r.shapeField(child, item, context); err != nil {
				return err
			}
		}
	default:
		return cborRefError("schema_type_unresolved")
	}
	return nil
}

// v4.cbor.shape
func TestCBORShapeReferenceCorpus(t *testing.T) {
	r := newCBORReference(t)
	// Only field/syntax oracle codes belong to this layer. Cross-field order,
	// variant, digest, host/Origin and ownership negatives remain excluded.
	fieldErrors := map[string]bool{}
	for _, code := range []string{"unknown_field", "missing_field", "integer_type", "integer_range", "constant_mismatch", "field_type", "field_length", "field_nonzero", "text_pattern", "reserved_namespace", "enum_value", "unknown_bits", "map_type", "map_length", "array_length", "map_size"} {
		fieldErrors[code] = true
	}
	positive, negative := 0, 0
	for _, vector := range cborRefVectors(t) {
		// These reuse field error names but their oracle belongs to map_rules:
		// FSA4's status-dependent registered code, and auth-method-specific
		// exporter length. A field-only validator must not claim their coverage.
		if vector.ID == "admission_rejected_unknown_code" || vector.ID == "context_auth_exporter_bytes" {
			continue
		}
		if vector.ExpectedError != "" && !fieldErrors[vector.ExpectedError] {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := r.shape(input, vector.Schema, shapeContext(vector.Limits), uint64(len(input))+1)
			if !bytes.Equal(input, original) {
				t.Fatal("shape validation changed original bytes")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatal("accepted invalid field shape")
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value.encode(nil), input) {
				t.Fatal("shape validation changed canonical output")
			}
		})
	}
	if positive == 0 || negative == 0 {
		t.Fatal("empty shape coverage")
	}
	t.Logf("%d positives and %d field-negative cases; map rules and host/Origin validation excluded", positive, negative)
}

// v4.cbor.shape_mutations
func TestCBORShapeReferenceRequiredAndUnknown(t *testing.T) {
	r := newCBORReference(t)
	seen := map[string]bool{}
	for _, vector := range cborRefVectors(t) {
		if vector.Schema == "" || vector.ExpectedError != "" || seen[vector.Schema] {
			continue
		}
		seen[vector.Schema] = true
		input, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatal(err)
		}
		context := shapeContext(vector.Limits)
		original, err := r.shape(input, vector.Schema, context, uint64(len(input))+1)
		if err != nil {
			t.Fatal(err)
		}
		definition := r.registry.Maps[vector.Schema]
		for _, id := range definition.Required {
			t.Run(fmt.Sprintf("%s/remove_%d", vector.Schema, id), func(t *testing.T) {
				modified := &cborRefValue{major: 5}
				for _, pair := range original.pairs {
					if pair[0].n != id {
						modified.pairs = append(modified.pairs, pair)
					}
				}
				if err := r.shapeMap(vector.Schema, modified, context); err == nil {
					t.Fatal("missing required field accepted")
				}
			})
		}
		if definition.Fields["65535"] != nil {
			t.Fatal("unknown-field test sentinel was allocated")
		}
		modified := &cborRefValue{major: 5, pairs: append(append([][2]*cborRefValue(nil), original.pairs...), [2]*cborRefValue{{major: 0, n: 65535}, {major: 0}})}
		if err := r.shapeMap(vector.Schema, modified, context); err != cborRefError("unknown_field") {
			t.Fatalf("%s: unexpected unknown-field result: %v", vector.Schema, err)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no root-map mutation coverage")
	}
	t.Logf("required/unknown field mutations cover %d root schemas; nested-only/other-corpus schemas remain outside this mutation set", len(seen))
}

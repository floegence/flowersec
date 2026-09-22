package protocolv4

// Test-only closed variants and numeric ranges from generated map_rules. This layer does not
// implement the other relational/digest/route-format rules or grant authority.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

type cborVariantBranch struct {
	Absent, Required, Nonzero []string
	Constants                 map[string]json.RawMessage
	EnumValues                map[string][]uint64 `json:"enum_values"`
	Equal                     [][2]string
	LessOrEqual               [][2]string       `json:"less_or_equal"`
	ZeroBytes                 []string          `json:"zero_bytes"`
	ByteLengths               map[string]uint64 `json:"byte_lengths"`
	BytePrefixes              map[string]string `json:"byte_prefixes"`
	Registered                map[string]string
}

type cborVariantRule struct {
	Op, Discriminator, Context string
	Field                      string
	Min, Max                   *cborRefBound
	When                       *cborRuleCondition
	Value                      json.RawMessage
	Cases                      map[string]cborVariantBranch
	cborVariantBranch
}

type cborRuleCondition struct {
	Field, Context string
	Value          json.RawMessage
}

func (r *cborReference) ruleApplies(name string, value *cborRefValue, when *cborRuleCondition, context cborShapeContext) (bool, error) {
	if when == nil {
		return true, nil
	}
	if when.Context != "" {
		text, ok := context.selectors[when.Context]
		if !ok {
			return false, cborRefError("context_unresolved")
		}
		return cborRawEqual(&cborRefValue{major: 3, data: []byte(text)}, when.Value), nil
	}
	actual, err := r.variantPath(name, value, when.Field, context)
	return cborRawEqual(actual, when.Value), err
}

func cborRawEqual(value *cborRefValue, raw json.RawMessage) bool {
	if value == nil || len(raw) == 0 {
		return false
	}
	if bytes.Equal(raw, []byte("true")) || bytes.Equal(raw, []byte("false")) {
		return value.major == 7 && ((value.n == 21) == bytes.Equal(raw, []byte("true"))) && (value.n == 20 || value.n == 21)
	}
	if raw[0] == '"' {
		var text string
		return json.Unmarshal(raw, &text) == nil && value.major == 3 && string(value.data) == text
	}
	n, err := rawUint(raw)
	return err == nil && value.major == 0 && value.n == n
}

func cborValuesEqual(a, b *cborRefValue) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.encode(nil), b.encode(nil))
}

func (r *cborReference) resolveShapeField(field *cborRefField, context cborShapeContext) (*cborRefField, error) {
	if field == nil {
		return nil, cborRefError("schema_type_unresolved")
	}
	if field.Type == "context_variant" {
		field = field.Cases[context.selectors[field.Context]]
		if field == nil {
			return nil, cborRefError("context_unresolved")
		}
	}
	return field, nil
}

func (r *cborReference) variantPath(name string, value *cborRefValue, fieldPath string, context cborShapeContext) (*cborRefValue, error) {
	field := &cborRefField{Type: "map", SchemaRef: name}
	for _, part := range strings.Split(fieldPath, ".") {
		if value == nil {
			return nil, nil
		}
		var err error
		field, err = r.resolveShapeField(field, context)
		if err != nil {
			return nil, err
		}
		if field.Type == "array" || field.Type == "array<uint64>" {
			index, err := strconv.ParseUint(part, 10, 64)
			if err != nil || value.major != 4 {
				return nil, cborRefError("unknown_rule_field")
			}
			if index >= uint64(len(value.items)) {
				return nil, nil
			}
			value = value.items[int(index)]
			field = field.Items
			continue
		}
		mapName := field.SchemaRef
		if field.EncodedSchemaRef != "" {
			mapName = field.EncodedSchemaRef
			value, _, err = r.decode(value.data, mapName, context.limits, uint64(len(value.data))+1)
			if err != nil {
				return nil, err
			}
		}
		definition, ok := r.registry.Maps[mapName]
		if !ok || value.major != 5 {
			return nil, cborRefError("unknown_rule_field")
		}
		context, err = r.mapShapeContext(mapName, value, context)
		if err != nil {
			return nil, err
		}
		found := false
		for id, child := range definition.Fields {
			if child.Name == part {
				ordinal, err := strconv.ParseUint(id, 10, 16)
				if err != nil {
					return nil, cborRefError("registry_unresolved")
				}
				field = child
				value = cborLookup(value, ordinal)
				found = true
				break
			}
		}
		if !found {
			return nil, cborRefError("unknown_rule_field")
		}
	}
	return value, nil
}

func (r *cborReference) checkVariantBranch(name string, value *cborRefValue, branch cborVariantBranch, context cborShapeContext) error {
	var pathError error
	get := func(path string) *cborRefValue {
		v, err := r.variantPath(name, value, path, context)
		if err != nil {
			pathError = err
		}
		return v
	}
	for _, path := range branch.Absent {
		if get(path) != nil {
			return cborRefError("variant_absent")
		}
	}
	for _, path := range branch.Required {
		if get(path) == nil {
			return cborRefError("variant_required")
		}
	}
	for path, constant := range branch.Constants {
		if !cborRawEqual(get(path), constant) {
			return cborRefError("variant_constant")
		}
	}
	for path, allowed := range branch.EnumValues {
		v := get(path)
		found := false
		if v != nil && v.major == 0 {
			for _, n := range allowed {
				found = found || v.n == n
			}
		}
		if !found {
			return cborRefError("enum_value")
		}
	}
	for _, pair := range branch.Equal {
		if !cborValuesEqual(get(pair[0]), get(pair[1])) {
			return cborRefError("field_equality")
		}
	}
	for _, pair := range branch.LessOrEqual {
		a, b := get(pair[0]), get(pair[1])
		if a == nil || b == nil || a.major != 0 || b.major != 0 || a.n > b.n {
			return cborRefError("field_order")
		}
	}
	for _, path := range branch.Nonzero {
		v := get(path)
		nonzero := v != nil && v.major == 0 && v.n > 0
		if v != nil && v.major == 2 {
			for _, b := range v.data {
				nonzero = nonzero || b != 0
			}
		}
		if !nonzero {
			return cborRefError("variant_nonzero")
		}
	}
	for _, path := range branch.ZeroBytes {
		v := get(path)
		if v == nil || v.major != 2 {
			return cborRefError("variant_zero_bytes")
		}
		for _, b := range v.data {
			if b != 0 {
				return cborRefError("variant_zero_bytes")
			}
		}
	}
	for path, length := range branch.ByteLengths {
		v := get(path)
		if v == nil || v.major != 2 || uint64(len(v.data)) != length {
			return cborRefError("field_length")
		}
	}
	for path, prefix := range branch.BytePrefixes {
		want, err := hex.DecodeString(prefix)
		if err != nil {
			return cborRefError("registry_unresolved")
		}
		v := get(path)
		if v == nil || v.major != 2 || !bytes.HasPrefix(v.data, want) {
			return cborRefError("field_prefix")
		}
	}
	for path, registry := range branch.Registered {
		entries, err := r.fieldRegistry(registry)
		if err != nil {
			return err
		}
		v := get(path)
		found := false
		if v != nil && v.major == 0 {
			for _, raw := range entries {
				if len(raw) > 0 && raw[0] == '{' {
					var entry map[string]json.RawMessage
					if json.Unmarshal(raw, &entry) != nil {
						return cborRefError("registry_unresolved")
					}
					raw = entry["code"]
				}
				n, err := rawUint(raw)
				if err != nil {
					return cborRefError("registry_unresolved")
				}
				found = found || n == v.n
			}
		}
		if !found {
			return cborRefError("enum_value")
		}
	}
	return pathError
}

type cborMapCheck func(string, *cborRefValue, cborShapeContext) error

// The field layer has already validated structure and bounds. Every rule layer
// uses this traversal so embedded documents and selector scopes stay identical.
func (r *cborReference) walkRuleMap(name string, value *cborRefValue, context cborShapeContext, check cborMapCheck) error {
	context, err := r.mapShapeContext(name, value, context)
	if err != nil {
		return err
	}
	for _, pair := range value.pairs {
		field := r.registry.Maps[name].Fields[strconv.FormatUint(pair[0].n, 10)]
		if err := r.walkRuleField(field, pair[1], context, check); err != nil {
			return err
		}
	}
	return check(name, value, context)
}

func (r *cborReference) checkVariants(name string, value *cborRefValue, context cborShapeContext) error {
	for _, raw := range r.registry.VariantRules[name] {
		var rule cborVariantRule
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&rule); err != nil {
			return cborRefError("rule_unresolved")
		}
		applies, err := r.ruleApplies(name, value, rule.When, context)
		if err != nil {
			return err
		}
		if !applies {
			continue
		}
		var branch cborVariantBranch
		switch rule.Op {
		case "range":
			actual, err := r.variantPath(name, value, rule.Field, context)
			if err != nil {
				return err
			}
			if rule.Min == nil || rule.Max == nil {
				return cborRefError("rule_unresolved")
			}
			if actual == nil || actual.major != 0 || actual.n < uint64(*rule.Min) || actual.n > uint64(*rule.Max) {
				return cborRefError("field_range")
			}
			continue
		case "variant":
			discriminator, err := r.variantPath(name, value, rule.Discriminator, context)
			if err != nil {
				return err
			}
			if !cborRawEqual(discriminator, rule.Value) {
				continue
			}
			branch = rule.cborVariantBranch
		case "context_variant":
			var ok bool
			branch, ok = rule.Cases[context.selectors[rule.Context]]
			if !ok {
				return cborRefError("context_unresolved")
			}
		default:
			return cborRefError("rule_unresolved")
		}
		if err := r.checkVariantBranch(name, value, branch, context); err != nil {
			return err
		}
	}
	return nil
}

func (r *cborReference) walkRuleField(field *cborRefField, value *cborRefValue, context cborShapeContext, check cborMapCheck) error {
	field, err := r.resolveShapeField(field, context)
	if err != nil {
		return err
	}
	switch field.Type {
	case "map":
		return r.walkRuleMap(field.SchemaRef, value, context, check)
	case "array":
		for _, item := range value.items {
			if err := r.walkRuleField(field.Items, item, context, check); err != nil {
				return err
			}
		}
	case "text_map":
		for _, pair := range value.pairs {
			child := field.Values
			if field.Entries != nil {
				child = field.Entries[string(pair[0].data)]
			}
			if err := r.walkRuleField(child, pair[1], context, check); err != nil {
				return err
			}
		}
	case "bytes":
		if field.EncodedSchemaRef != "" && !(field.AllowEmpty && len(value.data) == 0) {
			nested, _, err := r.decode(value.data, field.EncodedSchemaRef, context.limits, uint64(len(value.data))+1)
			if err != nil {
				return err
			}
			return r.walkRuleMap(field.EncodedSchemaRef, nested, context, check)
		}
	}
	return nil
}

func (r *cborReference) variants(input []byte, name string, context cborShapeContext, cap uint64) (*cborRefValue, error) {
	value, err := r.shape(input, name, context, cap)
	if err != nil {
		return nil, err
	}
	if name != "" {
		if err := r.walkRuleMap(name, value, context, r.checkVariants); err != nil {
			return nil, err
		}
	}
	return value, nil
}

// v4.cbor.variants
func TestCBORVariantReferenceCorpus(t *testing.T) {
	r := newCBORReference(t)
	positive, negative := 0, 0
	for _, vector := range cborRefVectors(t) {
		variantError := strings.HasPrefix(vector.ExpectedError, "variant_") || vector.ExpectedError == "field_range" || vector.ExpectedError == "field_prefix" || vector.ID == "admission_rejected_unknown_code" || vector.ID == "context_auth_exporter_bytes"
		if vector.ExpectedError != "" && !variantError {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := r.variants(input, vector.Schema, shapeContext(vector.Limits), uint64(len(input))+1)
			if !bytes.Equal(input, original) {
				t.Fatal("variant validation changed input")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatal("accepted invalid variant")
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value.encode(nil), input) {
				t.Fatal("variant changed canonical bytes")
			}
		})
	}
	if positive == 0 || negative == 0 {
		t.Fatal("empty variant coverage")
	}
	t.Logf("%d positives and %d variant-negative cases; other map_rules remain excluded", positive, negative)
}

// v4.cbor.variant_boundaries
func TestCBORVariantReferenceBoundaries(t *testing.T) {
	r := newCBORReference(t)
	seen := map[string]bool{}
	for _, vector := range cborRefVectors(t) {
		switch vector.ID {
		case "grant_certificate_maximum_fields", "route_direct_fields", "route_tunnel_mixed_fields", "activation_live_fields", "activation_pool_fields":
		default:
			continue
		}
		seen[vector.ID] = true
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			context := shapeContext(vector.Limits)
			if vector.Schema == "Route" {
				// Each signed containing map overrides this invalid external
				// selector without changing the caller's scope for its siblings.
				context.selectors["path_kind"] = "invalid-caller-selector"
			}
			value, err := r.variants(input, vector.Schema, context, uint64(len(input))+1)
			if err != nil {
				t.Fatal(err)
			}
			switch vector.Schema {
			case "IdentityCertificate":
				key, err := r.variantPath(vector.Schema, value, "noise_static_public_key.public_key_bytes", context)
				if err != nil || key == nil || len(key.data) == 0 {
					t.Fatalf("missing fixture key: %v", err)
				}
				// Preserve length and every other field. This checks only the
				// registered encoding prefix, not P-256 point membership.
				key.data = bytes.Clone(key.data)
				key.data[0] ^= 1
				modified := value.encode(nil)
				if _, err := r.shape(modified, vector.Schema, context, uint64(len(modified))+1); err != nil {
					t.Fatalf("prefix mutation changed field shape: %v", err)
				}
				if _, err := r.variants(modified, vector.Schema, context, uint64(len(modified))+1); err != cborRefError("field_prefix") {
					t.Fatalf("wrong prefix rejection: %v", err)
				}
			case "Route":
				if context.selectors["path_kind"] != "invalid-caller-selector" {
					t.Fatal("containing discriminator leaked into caller scope")
				}
			case "ActivationAuthorization":
				if _, err := r.variants(input, vector.Schema, shapeContext(nil), uint64(len(input))+1); err != cborRefError("context_unresolved") {
					t.Fatalf("absent source context was inferred: %v", err)
				}
			}
			original, err := hex.DecodeString(vector.Hex)
			if err != nil || !bytes.Equal(input, original) {
				t.Fatal("boundary validation changed fixture bytes")
			}
		})
	}
	if len(seen) != 5 {
		t.Fatalf("incomplete variant boundary fixtures: %d", len(seen))
	}
}

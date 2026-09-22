package protocolv4

// Test-only stateless relations over generated field/rule definitions. These
// checks do not establish authenticated history, authority or resource ownership.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
)

type cborRelationRule struct {
	Op, Field, Left, Right, Profile, Algorithm, Registry, Source, Domain string
	When                                                                 *cborRuleCondition
	Fields                                                               []string
	Pairs, Rows                                                          [][]uint64
	Max                                                                  *cborRefBound
	ItemFieldID                                                          *uint64  `json:"item_field_id"`
	ItemFields                                                           []string `json:"item_fields"`
	ItemField                                                            string   `json:"item_field"`
	Value                                                                json.RawMessage
	Feature                                                              string
	Present                                                              *bool
	CodeField                                                            string `json:"code_field"`
	TargetScopeField                                                     string `json:"target_scope_field"`
	StreamIDField                                                        string `json:"stream_id_field"`
	RetryAfterField                                                      string `json:"retry_after_field"`
	Selectors                                                            []struct{ Field, Context string }
}

func cborUnsignedPair(a, b *cborRefValue) bool {
	return a != nil && b != nil && a.major == 0 && b.major == 0
}

func cborCompare(a, b *cborRefValue) (int, error) {
	if cborUnsignedPair(a, b) {
		if a.n < b.n {
			return -1, nil
		}
		if a.n > b.n {
			return 1, nil
		}
		return 0, nil
	}
	if a != nil && b != nil && a.major == 2 && b.major == 2 {
		return bytes.Compare(a.data, b.data), nil
	}
	return 0, cborRefError("field_type")
}

func (r *cborReference) checkRelation(name string, value *cborRefValue, rule cborRelationRule, context cborShapeContext) error {
	var pathError error
	get := func(path string) *cborRefValue {
		v, err := r.variantPath(name, value, path, context)
		if err != nil {
			pathError = err
		}
		return v
	}
	switch rule.Op {
	case "is_null":
		v := get(rule.Field)
		if v == nil || v.major != 7 || v.n != 22 {
			return cborRefError("field_null")
		}
	case "at_least_one":
		found := false
		for _, field := range rule.Fields {
			found = get(field) != nil || found
		}
		if !found {
			return cborRefError("field_presence")
		}
	case "equal", "equal_if_present", "not_equal":
		a, b := get(rule.Left), get(rule.Right)
		if rule.Op == "equal_if_present" && (a == nil || b == nil) {
			break
		}
		equal := cborValuesEqual(a, b)
		if rule.Op == "not_equal" && equal {
			return cborRefError("field_distinctness")
		}
		if rule.Op != "not_equal" && !equal {
			return cborRefError("field_equality")
		}
	case "less_than", "less_or_equal", "max_difference", "bit_subset":
		a, b := get(rule.Left), get(rule.Right)
		if !cborUnsignedPair(a, b) {
			return cborRefError("integer_type")
		}
		switch rule.Op {
		case "less_than", "less_or_equal":
			if a.n > b.n || (rule.Op == "less_than" && a.n == b.n) {
				return cborRefError("field_order")
			}
		case "max_difference":
			if rule.Max == nil {
				return cborRefError("rule_unresolved")
			}
			// Check order before unsigned subtraction; never narrow timestamps.
			if a.n > b.n || b.n-a.n > uint64(*rule.Max) {
				return cborRefError("field_duration")
			}
		case "bit_subset":
			if a.n & ^b.n != 0 {
				return cborRefError("feature_subset")
			}
		}
	case "allowed_pairs", "allowed_tuples":
		fields, rows := rule.Fields, rule.Rows
		if rule.Op == "allowed_pairs" {
			fields, rows = []string{rule.Left, rule.Right}, rule.Pairs
		}
		found := false
		for _, row := range rows {
			if len(row) != len(fields) {
				return cborRefError("rule_unresolved")
			}
			matches := true
			for i, field := range fields {
				v := get(field)
				matches = matches && v != nil && v.major == 0 && v.n == row[i]
			}
			found = found || matches
		}
		if !found {
			if rule.Op == "allowed_pairs" {
				return cborRefError("field_pair")
			}
			return cborRefError("field_tuple")
		}
	case "feature_bit":
		entries, err := r.fieldRegistry("feature_registry")
		if err != nil {
			return err
		}
		var entry struct{ Bit *uint64 }
		if json.Unmarshal(entries[rule.Feature], &entry) != nil || entry.Bit == nil || *entry.Bit >= 64 || rule.Present == nil {
			return cborRefError("registry_unresolved")
		}
		v := get(rule.Field)
		if v == nil || v.major != 0 {
			return cborRefError("integer_type")
		}
		if (v.n&(uint64(1)<<*entry.Bit) != 0) != *rule.Present {
			return cborRefError("feature_policy")
		}
	case "profile_algorithm":
		entries, err := r.fieldRegistry("crypto_profiles")
		if err != nil {
			return err
		}
		profile, algorithm := get(rule.Profile), get(rule.Algorithm)
		if profile == nil || profile.major != 3 || algorithm == nil || algorithm.major != 0 {
			return cborRefError("field_type")
		}
		var entry struct {
			Algorithm *uint64 `json:"dh_algorithm"`
		}
		if json.Unmarshal(entries[string(profile.data)], &entry) != nil || entry.Algorithm == nil {
			return cborRefError("registry_unresolved")
		}
		if algorithm.n != *entry.Algorithm {
			return cborRefError("profile_algorithm")
		}
	case "error_scope":
		codes, err := r.fieldRegistry("error_codes")
		if err != nil {
			return err
		}
		metadata, err := r.fieldRegistry("error_code_metadata")
		if err != nil {
			return err
		}
		code := get(rule.CodeField)
		label := ""
		for key, raw := range codes {
			if cborRawEqual(code, raw) {
				label = key
				break
			}
		}
		if label == "" {
			return cborRefError("enum_value")
		}
		var policy struct {
			Scope     string
			Retryable bool
		}
		if json.Unmarshal(metadata[label], &policy) != nil {
			return cborRefError("registry_unresolved")
		}
		target, stream := get(rule.TargetScopeField), get(rule.StreamIDField)
		if target == nil || target.major != 0 {
			return cborRefError("error_scope")
		}
		switch policy.Scope {
		case "session":
			if target.n != 0 || stream != nil {
				return cborRefError("error_scope")
			}
		case "stream":
			if target.n == 0 || !cborUnsignedPair(target, stream) || stream.n != target.n {
				return cborRefError("error_scope")
			}
		default:
			return cborRefError("registry_unresolved")
		}
		if !policy.Retryable && get(rule.RetryAfterField) != nil {
			return cborRefError("retry_after_forbidden")
		}
	case "registry_tuple":
		tuple, err := r.fieldRegistry(rule.Registry)
		if err != nil {
			return err
		}
		for _, selector := range rule.Selectors {
			key := context.selectors[selector.Context]
			if selector.Context == "" {
				v := get(selector.Field)
				for _, field := range r.registry.Maps[name].Fields {
					if field.Name != selector.Field {
						continue
					}
					for label, ordinal := range field.Enum {
						if v != nil && v.major == 0 && v.n == ordinal {
							key = label
						}
					}
				}
			}
			var next map[string]json.RawMessage
			if key == "" || json.Unmarshal(tuple[key], &next) != nil || len(next) == 0 {
				return cborRefError("context_unresolved")
			}
			tuple = next
		}
		for _, field := range rule.Fields {
			if !cborRawEqual(get(field), tuple[field]) {
				return cborRefError("carrier_tuple")
			}
		}
	case "map_digest":
		source, target := get(rule.Source), get(rule.Field)
		if err := cborMapDigest(rule.Domain, source, target); err != nil {
			return err
		}
	case "unique_by", "increasing_tuple", "ordinal_indices", "increasing", "increasing_bytes", "increasing_cbor", "increasing_scopes", "exclusive_item":
		array := get(rule.Field)
		if array == nil && (rule.Op == "increasing_bytes" || rule.Op == "increasing_cbor") {
			break
		}
		if array == nil || array.major != 4 {
			return cborRefError("field_type")
		}
		var scopeMax uint64
		if rule.Op == "increasing_scopes" {
			caps, err := r.fieldRegistry("resource_caps")
			if err != nil {
				return err
			}
			var scope struct{ Max *cborRefBound }
			if json.Unmarshal(caps["scope_id"], &scope) != nil || scope.Max == nil {
				return cborRefError("registry_unresolved")
			}
			scopeMax = uint64(*scope.Max)
		}
		var previous []*cborRefValue
		var previousBytes []byte
		seen := map[string]bool{}
		for index, item := range array.items {
			current := item
			if rule.ItemFieldID != nil {
				current = cborLookup(item, *rule.ItemFieldID)
				if current == nil {
					return cborRefError("unknown_rule_field")
				}
			}
			base := rule.Field + "." + strconv.Itoa(index) + "."
			switch rule.Op {
			case "unique_by", "increasing_tuple":
				tuple := make([]*cborRefValue, 0, len(rule.ItemFields))
				for _, field := range rule.ItemFields {
					v := get(base + field)
					if v == nil {
						return cborRefError("unknown_rule_field")
					}
					tuple = append(tuple, v)
				}
				if rule.Op == "unique_by" {
					encoded := (&cborRefValue{major: 4, items: tuple}).encode(nil)
					if seen[string(encoded)] {
						return cborRefError("item_identity")
					}
					seen[string(encoded)] = true
				} else if previous != nil {
					order := 0
					for i := range tuple {
						var err error
						order, err = cborCompare(previous[i], tuple[i])
						if err != nil {
							return err
						}
						if order != 0 {
							break
						}
					}
					if order >= 0 {
						return cborRefError("item_order")
					}
				}
				previous = tuple
			case "ordinal_indices":
				if current.major != 0 || current.n != uint64(index) {
					return cborRefError("item_index")
				}
			case "increasing", "increasing_scopes":
				if current.major != 0 {
					return cborRefError("integer_type")
				}
				if rule.Op == "increasing_scopes" {
					if current.n == 0 || current.n > scopeMax || (previous != nil && current.n <= previous[0].n) {
						return cborRefError("scope_order")
					}
				} else if previous != nil && current.n <= previous[0].n {
					return cborRefError("item_order")
				}
				previous = []*cborRefValue{current}
			case "increasing_bytes", "increasing_cbor":
				var encoded []byte
				if rule.Op == "increasing_cbor" {
					encoded = current.encode(nil)
				} else {
					if current.major != 2 {
						return cborRefError("field_type")
					}
					encoded = current.data
				}
				// These arrays use bytewise order, independently of CBOR's
				// length-first ordering for map keys.
				if index > 0 && bytes.Compare(previousBytes, encoded) >= 0 {
					return cborRefError("item_order")
				}
				previousBytes = encoded
			case "exclusive_item":
				if cborRawEqual(get(base+rule.ItemField), rule.Value) && len(array.items) != 1 {
					return cborRefError("item_exclusive")
				}
			}
		}
	default:
		return cborRefError("rule_unresolved")
	}
	return pathError
}

// A map_digest rule uses the original embedded bytes or the independently
// reproduced complete map. It does not remove signatures or authenticate them.
func cborMapDigest(name string, source, target *cborRefValue) error {
	if source == nil || target == nil || target.major != 2 || (source.major != 2 && source.major != 5) {
		return cborRefError("field_type")
	}
	var domains []struct {
		Name, Operation string
		Label           string `json:"label_bytes"`
		OutputLength    uint64 `json:"output_length"`
		InputSchema     struct {
			Parts []struct{ Encoding, Projection string }
		} `json:"input_schema"`
	}
	if json.Unmarshal([]byte(DomainRegistryJSON), &domains) != nil {
		return cborRefError("registry_unresolved")
	}
	for _, domain := range domains {
		if domain.Name != name {
			continue
		}
		if domain.Operation != "sha256" || domain.OutputLength != 32 || len(domain.InputSchema.Parts) != 1 || domain.InputSchema.Parts[0].Encoding != "lp-map" || domain.InputSchema.Parts[0].Projection != "full" {
			return cborRefError("domain_projection")
		}
		input, err := hex.DecodeString(domain.Label)
		if err != nil {
			return cborRefError("registry_unresolved")
		}
		encoded := source.data
		if source.major == 5 {
			encoded = source.encode(nil)
		}
		if uint64(len(encoded)) > uint64(^uint32(0)) {
			return cborRefError("map_size")
		}
		input = binary.BigEndian.AppendUint32(input, uint32(len(encoded)))
		input = append(input, encoded...)
		digest := sha256.Sum256(input)
		if !bytes.Equal(target.data, digest[:]) {
			return cborRefError("map_digest_mismatch")
		}
		return nil
	}
	return cborRefError("registry_unresolved")
}

func (r *cborReference) relations(input []byte, name string, context cborShapeContext, cap uint64) (*cborRefValue, error) {
	value, err := r.shape(input, name, context, cap)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return value, nil
	}
	err = r.walkRuleMap(name, value, context, r.checkRelations)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (r *cborReference) checkRelations(name string, value *cborRefValue, context cborShapeContext) error {
	if err := r.checkVariants(name, value, context); err != nil {
		return err
	}
	for _, raw := range r.registry.RelationRules[name] {
		var rule cborRelationRule
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&rule) != nil {
			return cborRefError("rule_unresolved")
		}
		applies, err := r.ruleApplies(name, value, rule.When, context)
		if err != nil {
			return err
		}
		if applies {
			if err := r.checkRelation(name, value, rule, context); err != nil {
				return err
			}
		}
	}
	return nil
}

// v4.cbor.relations
func TestCBORRelationReferenceCorpus(t *testing.T) {
	r := newCBORReference(t)
	excluded := map[string]bool{}
	// Host/Origin/IDNA and external pool/open-digest oracles are not part of
	// the generated map-rule layer. Everything else in this corpus is checked.
	for _, code := range []string{"host_noncanonical", "host_loopback", "origin_endpoint", "origin_default_port", "origin_syntax", "pool_set_membership", "open_digest_mismatch"} {
		excluded[code] = true
	}
	positive, negative := 0, 0
	for _, vector := range cborRefVectors(t) {
		if excluded[vector.ExpectedError] {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(input)
			value, err := r.relations(input, vector.Schema, shapeContext(vector.Limits), uint64(len(input))+1)
			if !bytes.Equal(input, original) {
				t.Fatal("relation validation changed input")
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatalf("accepted invalid relation: %s", vector.ExpectedError)
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(value.encode(nil), input) {
				t.Fatal("relation changed canonical bytes")
			}
		})
	}
	if positive == 0 || negative == 0 {
		t.Fatal("empty relation coverage")
	}
	t.Logf("%d positives and %d negatives; host/Origin and external pool/open digest oracles excluded", positive, negative)
}

// v4.cbor.relation_boundaries
func TestCBORRelationReferenceBoundaries(t *testing.T) {
	r := newCBORReference(t)
	seen := map[string]bool{}
	for _, vector := range cborRefVectors(t) {
		if vector.ID != "tls_pin_full_window" && vector.ID != "hop_endpoint_hello_fields" {
			continue
		}
		seen[vector.ID] = true
		t.Run(vector.ID, func(t *testing.T) {
			input, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			context := shapeContext(vector.Limits)
			value, err := r.relations(input, vector.Schema, context, uint64(len(input))+1)
			if err != nil {
				t.Fatal(err)
			}
			get := func(schema string, root *cborRefValue, path string) *cborRefValue {
				t.Helper()
				v, err := r.variantPath(schema, root, path, context)
				if err != nil || v == nil {
					t.Fatalf("missing fixture path %s: %v", path, err)
				}
				return v
			}
			check := func(want error) {
				t.Helper()
				modified := value.encode(nil)
				if _, err := r.variants(modified, vector.Schema, context, uint64(len(modified))+1); err != nil {
					t.Fatalf("relation mutation changed field/variant shape: %v", err)
				}
				if _, err := r.relations(modified, vector.Schema, context, uint64(len(modified))+1); err != want {
					t.Fatalf("relation result: got %v, want %v", err, want)
				}
			}
			if vector.Schema == "TLSPin" {
				before, after := get(vector.Schema, value, "not_before_ms"), get(vector.Schema, value, "not_after_ms")
				var limit *cborRefBound
				for _, raw := range r.registry.RelationRules[vector.Schema] {
					var rule cborRelationRule
					if json.Unmarshal(raw, &rule) != nil {
						t.Fatal("invalid fixture rule")
					}
					if rule.Op == "max_difference" {
						limit = rule.Max
					}
				}
				if limit == nil || *limit == 0 {
					t.Fatal("missing duration limit")
				}
				after.n = ^uint64(0)
				before.n = after.n - uint64(*limit)
				check(nil)
				before.n--
				check(cborRefError("field_duration"))
				before.n, after.n = ^uint64(0), 1
				check(cborRefError("field_order"))
			} else {
				certificate := get(vector.Schema, value, "identity_certificate")
				parsed, _, err := r.decode(certificate.data, "IdentityCertificate", context.limits, uint64(len(certificate.data))+1)
				if err != nil {
					t.Fatal(err)
				}
				signature := get("IdentityCertificate", parsed, "signature")
				signature.data = bytes.Clone(signature.data)
				signature.data[0] ^= 1
				certificate.data = parsed.encode(nil)
				// The digest binds the signature too. Signature validity itself
				// remains a separate authenticated-crypto obligation.
				check(cborRefError("map_digest_mismatch"))
			}
			original, err := hex.DecodeString(vector.Hex)
			if err != nil || !bytes.Equal(input, original) {
				t.Fatal("mutation changed original fixture bytes")
			}
		})
	}
	if len(seen) != 2 {
		t.Fatal("incomplete relation boundary fixtures")
	}
}

// v4.cbor.relation_fuzz
func FuzzCBORRelationReference(f *testing.F) {
	r := newCBORReference(f)
	seeds := []cborRefVector{}
	seen := map[string]bool{}
	for _, vector := range cborRefVectors(f) {
		if vector.ExpectedError != "" || vector.Schema == "" || seen[vector.Schema] {
			continue
		}
		seen[vector.Schema] = true
		input, err := hex.DecodeString(vector.Hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint32(len(seeds)), input)
		seeds = append(seeds, vector)
	}
	if len(seeds) == 0 {
		f.Fatal("no schema fuzz seeds")
	}
	f.Fuzz(func(t *testing.T, selector uint32, input []byte) {
		const byteCap = 128 * 1024
		if len(input) > byteCap {
			return
		}
		seed := seeds[uint64(selector)%uint64(len(seeds))]
		original := bytes.Clone(input)
		value, err := r.relations(input, seed.Schema, shapeContext(seed.Limits), byteCap)
		if !bytes.Equal(input, original) {
			t.Fatal("relation validation changed original bytes")
		}
		if err == nil && (value == nil || !bytes.Equal(value.encode(nil), input)) {
			t.Fatal("accepted relation changed canonical bytes")
		}
	})
}

package protocolv4

// Test-only metadata composition. A matching local definition does not grant
// registration, OPEN admission, codec execution, stream ownership or I/O rights.
import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

func (r *cborReference) fieldConstant(name, fieldName string) (*cborRefValue, error) {
	_, field, err := r.namedField(name, fieldName)
	if err != nil {
		return nil, err
	}
	if field.Type == "text" {
		var text string
		if json.Unmarshal(field.Const, &text) != nil {
			return nil, cborRefError("registry_unresolved")
		}
		return &cborRefValue{major: 3, data: []byte(text)}, nil
	}
	if field.Type == "uint16" {
		n, err := rawUint(field.Const)
		if err != nil {
			return nil, err
		}
		return &cborRefValue{major: 0, n: n}, nil
	}
	return nil, cborRefError("registry_unresolved")
}

func cborTextMap(fields map[string]*cborRefValue) *cborRefValue {
	result := &cborRefValue{major: 5}
	for name, value := range fields {
		result.pairs = append(result.pairs, [2]*cborRefValue{{major: 3, data: []byte(name)}, value})
	}
	// Canonical ordering applies only to newly constructed maps. Wire keys
	// are checked in their original order by the syntax reader.
	sort.Slice(result.pairs, func(i, j int) bool {
		left, right := result.pairs[i][0].encode(nil), result.pairs[j][0].encode(nil)
		return len(left) < len(right) || len(left) == len(right) && bytes.Compare(left, right) < 0
	})
	return result
}

func cborTextLookup(value *cborRefValue, name string) *cborRefValue {
	if value == nil || value.major != 5 {
		return nil
	}
	for _, pair := range value.pairs {
		if pair[0].major == 3 && string(pair[0].data) == name {
			return pair[1]
		}
	}
	return nil
}

func (r *cborTextReference) streamMetadata(input []byte, ownerCap uint64) (string, *cborRefValue, error) {
	if ownerCap == 0 {
		return "", nil, cborRefError("limit_unresolved")
	}
	if len(input) == 0 {
		return "", nil, nil
	}
	// Both shells use the same syntax descriptors and whole metadata cap.
	// Only the original namespace selects the registered reserved shell.
	value, _, err := r.decode(input, "StreamMetadata", nil, ownerCap)
	if err != nil {
		return "", nil, err
	}
	namespace, err := r.namedValue("StreamMetadata", value, "namespace")
	if err != nil {
		return "", nil, err
	}
	typedNamespace, err := r.fieldConstant("TypedMessageMetadata", "namespace")
	if err != nil {
		return "", nil, err
	}
	name := "StreamMetadata"
	if namespace != nil && namespace.major == 3 && bytes.Equal(namespace.data, typedNamespace.data) {
		name = "TypedMessageMetadata"
	}
	value, err = r.wireMap(input, name, cborShapeContext{}, ownerCap)
	if err != nil {
		return "", nil, err
	}
	return name, value, nil
}

func (r *cborTextReference) definitionDigest(definition []byte, ownerCap uint64) ([]byte, error) {
	if _, err := r.wireMap(definition, "MessageStreamDefinition", cborShapeContext{}, ownerCap); err != nil {
		return nil, err
	}
	return cborSingleMapHash("typed_message_definition_digest", "MessageStreamDefinition", "full", definition)
}

func (r *cborTextReference) composeTypedMetadata(definition, application []byte, ownerCap uint64) ([]byte, error) {
	digest, err := r.definitionDigest(definition, ownerCap)
	if err != nil {
		return nil, err
	}
	if len(application) != 0 {
		if _, err := r.wireMap(application, "StreamMetadata", cborShapeContext{}, ownerCap); err != nil {
			return nil, err
		}
	}
	namespace, err := r.fieldConstant("TypedMessageMetadata", "namespace")
	if err != nil {
		return nil, err
	}
	version, err := r.fieldConstant("TypedMessageMetadata", "version")
	if err != nil {
		return nil, err
	}
	values := cborTextMap(map[string]*cborRefValue{
		"definition": {major: 2, data: digest}, "application": {major: 2, data: application},
	})
	value, err := r.namedMap("TypedMessageMetadata", map[string]*cborRefValue{"namespace": namespace, "version": version, "values": values})
	if err != nil {
		return nil, err
	}
	encoded := value.encode(nil)
	if _, err := r.wireMap(encoded, "TypedMessageMetadata", cborShapeContext{}, ownerCap); err != nil {
		return nil, err
	}
	return encoded, nil
}

func (r *cborTextReference) verifyTypedMetadata(input, expectedDefinition []byte, ownerCap uint64) ([]byte, error) {
	digest, err := r.definitionDigest(expectedDefinition, ownerCap)
	if err != nil {
		return nil, err
	}
	name, value, err := r.streamMetadata(input, ownerCap)
	if err != nil {
		return nil, err
	}
	if name != "TypedMessageMetadata" {
		return nil, cborRefError("typed_metadata_required")
	}
	values, err := r.namedValue(name, value, "values")
	if err != nil {
		return nil, err
	}
	definition, application := cborTextLookup(values, "definition"), cborTextLookup(values, "application")
	if definition == nil || application == nil || definition.major != 2 || application.major != 2 {
		return nil, cborRefError("field_type")
	}
	if !bytes.Equal(digest, definition.data) {
		return nil, cborRefError("typed_definition_mismatch")
	}
	return bytes.Clone(application.data), nil
}

// v4.cbor.metadata_corpus
func TestCBORMetadataReferenceCorpus(t *testing.T) {
	r := newCBORTextReference(t)
	expectedDefinition := oracleBytes(t, oracleSeed(t, "typed_definition_fields").Hex)
	positive, negative, bound := 0, 0, 0
	for _, vector := range cborRefVectors(t) {
		if vector.Schema != "StreamMetadata" && vector.Schema != "TypedMessageMetadata" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			input := oracleBytes(t, vector.Hex)
			original := bytes.Clone(input)
			name, value, err := r.streamMetadata(input, uint64(len(input))+1)
			if err == nil && vector.Schema == "TypedMessageMetadata" && name != vector.Schema {
				// A valid ordinary shell is accepted by ordinary metadata parsing,
				// but cannot satisfy this fixture's requested typed entry point.
				_, err = r.verifyTypedMetadata(input, expectedDefinition, 8192)
				if err != nil {
					value = nil
				}
			}
			if vector.ExpectedError != "" {
				negative++
				if err == nil || value != nil {
					t.Fatal("accepted malformed metadata")
				}
			} else {
				positive++
				if err != nil || name != vector.Schema {
					t.Fatal("wrong metadata shell", name, err)
				}
				if !bytes.Equal(input, value.encode(nil)) {
					t.Fatal("metadata changed canonical bytes")
				}
				if vector.TypedDerivation != nil {
					bound++
					definition := oracleBytes(t, vector.TypedDerivation.DefinitionHex)
					application := oracleBytes(t, vector.TypedDerivation.ApplicationHex)
					composed, err := r.composeTypedMetadata(definition, application, 8192)
					if err != nil || !bytes.Equal(composed, input) {
						t.Fatal("independent metadata composition differs", err)
					}
					got, err := r.verifyTypedMetadata(input, definition, 8192)
					if err != nil || !bytes.Equal(got, application) {
						t.Fatal("definition/application binding differs", err)
					}
				}
			}
			if !bytes.Equal(input, original) {
				t.Fatal("metadata input mutated")
			}
		})
	}
	if positive == 0 || negative == 0 || bound != 2 {
		t.Fatal("missing metadata coverage")
	}
	t.Logf("%d positive / %d negative metadata cases; %d independent definition/application compositions", positive, negative, bound)
}

// v4.cbor.metadata_boundaries
func TestCBORMetadataReferenceBoundaries(t *testing.T) {
	r := newCBORTextReference(t)
	seed := func(id string) []byte { return oracleBytes(t, oracleSeed(t, id).Hex) }
	definition := seed("typed_definition_fields")
	if name, value, err := r.streamMetadata(nil, 4096); name != "" || value != nil || err != nil {
		t.Fatal("empty sentinel changed")
	}
	if _, _, err := r.streamMetadata(nil, 0); err != cborRefError("limit_unresolved") {
		t.Fatal("missing owner cap accepted")
	}
	for _, application := range [][]byte{nil, seed("metadata_empty_values"), seed("metadata_4006")} {
		original := bytes.Clone(application)
		encoded, err := r.composeTypedMetadata(definition, application, 8192)
		if err != nil {
			t.Fatal(err)
		}
		if len(application) == 0 && len(encoded) != 88 || len(application) == 4006 && len(encoded) != 4096 {
			t.Fatal("composition boundary drift")
		}
		returned, err := r.verifyTypedMetadata(encoded, definition, 8192)
		if err != nil || !bytes.Equal(returned, original) {
			t.Fatal("application bytes differ", err)
		}
		clear(returned)
		if !bytes.Equal(application, original) {
			t.Fatal("returned bytes alias input")
		}
		clear(application)
		returned, err = r.verifyTypedMetadata(encoded, definition, 8192)
		if err != nil || !bytes.Equal(returned, original) {
			t.Fatal("composed bytes alias input", err)
		}
		clear(encoded)
		if !bytes.Equal(returned, original) {
			t.Fatal("returned application aliases wrapper")
		}
	}
	for _, id := range []string{"metadata_4007", "metadata_4096"} {
		application := seed(id)
		if _, err := r.wireMap(application, "StreamMetadata", cborShapeContext{}, 4096); err != nil {
			t.Fatal("ordinary legal metadata rejected", err)
		}
		if got, err := r.composeTypedMetadata(definition, application, 8192); err == nil || got != nil {
			t.Fatal("overfull composition accepted or truncated")
		}
	}
	if got, err := r.composeTypedMetadata(definition, seed("typed_metadata_empty"), 8192); err == nil || got != nil {
		t.Fatal("nested reserved wrapper accepted")
	}
	for _, input := range [][]byte{nil, seed("metadata_empty_values")} {
		if got, err := r.verifyTypedMetadata(input, definition, 8192); err != cborRefError("typed_metadata_required") || got != nil {
			t.Fatal("ordinary/empty metadata accepted as typed")
		}
	}
	if got, err := r.verifyTypedMetadata(seed("typed_metadata_bound_empty"), seed("typed_definition_maximum"), 8192); err != cborRefError("typed_definition_mismatch") || got != nil {
		t.Fatal("mismatched definition accepted")
	}
	if !bytes.Equal(definition, seed("typed_definition_fields")) {
		t.Fatal("captured definition mutated")
	}
}

// v4.cbor.metadata_definition_binding
func TestCBORMetadataDefinitionBinding(t *testing.T) {
	r := newCBORTextReference(t)
	definition := oracleBytes(t, oracleSeed(t, "typed_definition_fields").Hex)
	encoded, err := r.composeTypedMetadata(definition, nil, 8192)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"kind", "revision", "opener_to_acceptor.codec_schema_digest", "opener_to_acceptor.codec_revision", "opener_to_acceptor.max_message_bytes", "acceptor_to_opener.codec_schema_digest", "acceptor_to_opener.codec_revision", "acceptor_to_opener.max_message_bytes", "swap_directions"} {
		t.Run(path, func(t *testing.T) {
			value, err := r.wireMap(definition, "MessageStreamDefinition", cborShapeContext{}, 8192)
			if err != nil {
				t.Fatal(err)
			}
			if path == "swap_directions" {
				left := oracleField(t, r.cborReference, "MessageStreamDefinition", value, "opener_to_acceptor")
				right := oracleField(t, r.cborReference, "MessageStreamDefinition", value, "acceptor_to_opener")
				*left, *right = *right, *left
			} else {
				item, err := r.variantPath("MessageStreamDefinition", value, path, cborShapeContext{})
				if err != nil || item == nil {
					t.Fatal("missing definition path", err)
				}
				switch item.major {
				case 0:
					item.n--
				case 2:
					item.data = bytes.Clone(item.data)
					item.data[0] ^= 1
				case 3:
					item.data = append(bytes.Clone(item.data), 'x')
				default:
					t.Fatal("uncovered definition field type")
				}
			}
			changed := value.encode(nil)
			if _, err := r.wireMap(changed, "MessageStreamDefinition", cborShapeContext{}, 8192); err != nil {
				t.Fatal("mutation broke shape", err)
			}
			if got, err := r.verifyTypedMetadata(encoded, changed, 8192); err != cborRefError("typed_definition_mismatch") || got != nil {
				t.Fatal("definition semantic change accepted")
			}
		})
	}
}

// v4.cbor.metadata_error_scope
func TestCBORMetadataErrorScope(t *testing.T) {
	r := newCBORTextReference(t)
	seed := oracleSeed(t, "open_fields")
	for _, id := range []string{"metadata_bad_namespace_0", "metadata_value_wrong_type", "typed_metadata_nested_wrapper", "typed_metadata_missing_application"} {
		value, err := r.wireMap(oracleBytes(t, seed.Hex), seed.Schema, shapeContext(seed.Limits), 8192)
		if err != nil {
			t.Fatal(err)
		}
		metadata := oracleBytes(t, oracleSeed(t, id).Hex)
		oracleField(t, r.cborReference, seed.Schema, value, "metadata").data = metadata
		digest, err := r.openDigest(value)
		if err != nil {
			t.Fatal(err)
		}
		oracleField(t, r.cborReference, seed.Schema, value, "open_digest").data = digest
		if _, err := r.wireMap(value.encode(nil), seed.Schema, shapeContext(seed.Limits), 8192); err != nil {
			t.Fatal("metadata became outer OPEN error", err)
		}
		if _, _, err := r.streamMetadata(metadata, 4096); err == nil {
			t.Fatal("malformed inner metadata accepted")
		}
	}
}

// v4.cbor.metadata_fuzz
func FuzzCBORMetadataReference(f *testing.F) {
	r := newCBORTextReference(f)
	definition := oracleBytes(f, oracleSeed(f, "typed_definition_fields").Hex)
	for _, id := range []string{"metadata_empty_values", "metadata_key_order", "metadata_4006", "typed_metadata_bound_empty", "typed_metadata_bound_maximum", "typed_metadata_nested_wrapper"} {
		f.Add(oracleBytes(f, oracleSeed(f, id).Hex))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 8192 {
			return
		}
		original := bytes.Clone(input)
		name, value, err := r.streamMetadata(input, 4096)
		if !bytes.Equal(input, original) {
			t.Fatal("metadata parser changed input")
		}
		if err != nil {
			if value != nil {
				t.Fatal("partial failed metadata result")
			}
			return
		}
		if value != nil && !bytes.Equal(value.encode(nil), input) {
			t.Fatal("noncanonical metadata accepted")
		}
		if name == "TypedMessageMetadata" {
			application, err := r.verifyTypedMetadata(input, definition, 8192)
			if err != nil {
				return
			}
			encoded, err := r.composeTypedMetadata(definition, application, 8192)
			if err != nil || !bytes.Equal(encoded, input) {
				t.Fatal("typed metadata round-trip differs", err)
			}
			clear(application)
		} else {
			encoded, err := r.composeTypedMetadata(definition, input, 8192)
			if err != nil {
				return
			} // Legal ordinary metadata can exceed the composed cap.
			application, err := r.verifyTypedMetadata(encoded, definition, 8192)
			if err != nil || !bytes.Equal(application, input) {
				t.Fatal("application round-trip differs", err)
			}
			clear(application)
		}
		if !bytes.Equal(input, original) {
			t.Fatal("owned application aliases input")
		}
	})
}

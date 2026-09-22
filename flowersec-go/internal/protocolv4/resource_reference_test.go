package protocolv4

// Independent, test-only L1 arithmetic over trusted complete declarations.
// This neither derives legal selections nor owns or reserves real resources.
import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
)

type resourceSpec struct {
	Keys       []string `json:"owner_key_fields"`
	Bindings   []string `json:"binding_fields"`
	Boundaries []string `json:"control_boundaries"`
	Dimensions []string `json:"dimensions"`
	Components []string `json:"base_components"`
	Maximum    string   `json:"quantity_max"`
}
type resourceTotals map[string]map[string]string
type resourceCharge struct {
	key, binding, boundary string
	vector                 map[string]uint64
}
type resourceReference struct {
	spec     resourceSpec
	features []string
}

func newResourceReference(t testing.TB) resourceReference {
	t.Helper()
	var spec resourceSpec
	if err := json.Unmarshal([]byte(ResourceCompositionRegistryJSON), &spec); err != nil {
		t.Fatal(err)
	}
	var cbor struct {
		Registries struct {
			Features map[string]any `json:"feature_registry"`
		} `json:"field_registries"`
	}
	if err := json.Unmarshal([]byte(CBORSyntaxRegistryJSON), &cbor); err != nil {
		t.Fatal(err)
	}
	features := make([]string, 0, len(cbor.Registries.Features))
	for name := range cbor.Registries.Features {
		features = append(features, name)
	}
	slices.Sort(features)
	return resourceReference{spec, features}
}

func resourceObject(value any, allowed, required []string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("resource_object")
	}
	for key := range object {
		if !slices.Contains(allowed, key) {
			return nil, fmt.Errorf("resource_field")
		}
	}
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return nil, fmt.Errorf("resource_missing_field")
		}
	}
	return object, nil
}
func resourceArray(value any, limit uint64) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("resource_array")
	}
	if uint64(len(array)) > limit {
		return nil, fmt.Errorf("resource_reference_limit")
	}
	return array, nil
}
func resourceTuple(parts []string) string {
	// Encode each original UTF-8 component with its length, with no normalization.
	var result strings.Builder
	for _, part := range parts {
		result.WriteString(strconv.Itoa(len(part)))
		result.WriteByte(':')
		result.WriteString(part)
	}
	return result.String()
}
func (r resourceReference) charge(input any) (resourceCharge, error) {
	fields := append(append(slices.Clone(r.spec.Keys), r.spec.Bindings...), "control_boundary", "vector")
	object, err := resourceObject(input, fields, fields)
	if err != nil {
		return resourceCharge{}, err
	}
	identity := func(names []string) ([]string, error) {
		parts := make([]string, len(names))
		for i, name := range names {
			value, ok := object[name].(string)
			if !ok || len(value) == 0 || len(value) > 1024 || len(utf16.Encode([]rune(value))) > 256 {
				return nil, fmt.Errorf("resource_identity")
			}
			parts[i] = value
		}
		return parts, nil
	}
	keys, err := identity(r.spec.Keys)
	if err != nil {
		return resourceCharge{}, err
	}
	bindings, err := identity(r.spec.Bindings)
	if err != nil {
		return resourceCharge{}, err
	}
	boundary, ok := object["control_boundary"].(string)
	if !ok || !slices.Contains(r.spec.Boundaries, boundary) {
		return resourceCharge{}, fmt.Errorf("resource_control_boundary")
	}
	vector, err := resourceObject(object["vector"], r.spec.Dimensions, r.spec.Dimensions)
	if err != nil {
		return resourceCharge{}, err
	}
	maximum, err := strconv.ParseUint(r.spec.Maximum, 10, 64)
	if err != nil {
		return resourceCharge{}, err
	}
	quantities := map[string]uint64{}
	bindings = append(bindings, boundary)
	for _, dimension := range r.spec.Dimensions {
		text, ok := vector[dimension].(string)
		if !ok || text == "" || len(text) > 20 || (len(text) > 1 && text[0] == '0') || strings.IndexFunc(text, func(c rune) bool { return c < '0' || c > '9' }) != -1 {
			return resourceCharge{}, fmt.Errorf("resource_quantity")
		}
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil || n > maximum {
			return resourceCharge{}, fmt.Errorf("resource_quantity")
		}
		quantities[dimension] = n
		bindings = append(bindings, text)
	}
	return resourceCharge{resourceTuple(keys), resourceTuple(bindings), boundary, quantities}, nil
}

func (r resourceReference) minimum(input any) (resourceTotals, error) {
	fields := []string{"reference_limit", "base", "features", "legal_selections"}
	plan, err := resourceObject(input, fields, fields)
	if err != nil {
		return nil, err
	}
	n, ok := plan["reference_limit"].(json.Number)
	limit, limitErr := strconv.ParseUint(string(n), 10, 64)
	if !ok || limitErr != nil || limit == 0 || limit > 9007199254740991 {
		return nil, fmt.Errorf("resource_reference_limit")
	}
	base, err := resourceObject(plan["base"], r.spec.Components, r.spec.Components)
	if err != nil {
		return nil, err
	}
	features, err := resourceObject(plan["features"], r.features, nil)
	if err != nil {
		return nil, err
	}
	if len(r.features) > 16 {
		return nil, fmt.Errorf("resource_feature_registry")
	}
	selections, err := resourceArray(plan["legal_selections"], 1<<len(r.features))
	if err != nil {
		return nil, err
	}
	if len(selections) == 0 {
		return nil, fmt.Errorf("resource_legal_selections_missing")
	}
	selected := make([][]string, 0, len(selections))
	seen := map[string]bool{}
	for _, value := range selections {
		names, err := resourceArray(value, uint64(len(r.features)))
		if err != nil {
			return nil, err
		}
		set := []string{}
		for _, value := range names {
			name, ok := value.(string)
			if !ok || !slices.Contains(r.features, name) {
				return nil, fmt.Errorf("resource_feature_unknown")
			}
			if slices.Contains(set, name) {
				return nil, fmt.Errorf("resource_feature_duplicate")
			}
			set = append(set, name)
		}
		slices.Sort(set)
		key := resourceTuple(set)
		if seen[key] {
			return nil, fmt.Errorf("resource_selection_duplicate")
		}
		seen[key] = true
		for _, name := range set {
			if _, ok := features[name]; !ok {
				return nil, fmt.Errorf("resource_feature_missing")
			}
		}
		selected = append(selected, set)
	}
	owners := map[string]string{}
	capture := func(values any) ([]resourceCharge, error) {
		array, err := resourceArray(values, limit)
		if err != nil {
			return nil, err
		}
		limit -= uint64(len(array))
		result := make([]resourceCharge, 0, len(array))
		for _, value := range array {
			charge, err := r.charge(value)
			if err != nil {
				return nil, err
			}
			if binding, exists := owners[charge.key]; exists && binding != charge.binding {
				return nil, fmt.Errorf("resource_owner_conflict")
			}
			owners[charge.key] = charge.binding
			result = append(result, charge)
		}
		return result, nil
	}
	var common []resourceCharge
	for _, name := range r.spec.Components {
		charges, err := capture(base[name])
		if err != nil {
			return nil, err
		}
		common = append(common, charges...)
	}
	featureCharges := map[string][]resourceCharge{}
	for _, name := range r.features {
		if value, exists := features[name]; exists {
			charges, err := capture(value)
			if err != nil {
				return nil, err
			}
			featureCharges[name] = charges
		}
	}
	maximum := map[string]map[string]uint64{}
	for _, boundary := range r.spec.Boundaries {
		maximum[boundary] = map[string]uint64{}
	}
	for _, selection := range selected {
		union := map[string]resourceCharge{}
		for _, charge := range common {
			union[charge.key] = charge
		}
		for _, feature := range selection {
			for _, charge := range featureCharges[feature] {
				union[charge.key] = charge
			}
		}
		for _, boundary := range r.spec.Boundaries {
			for _, dimension := range r.spec.Dimensions {
				var total uint64
				for _, charge := range union {
					if charge.boundary != boundary {
						continue
					}
					amount := charge.vector[dimension]
					if total > math.MaxUint64-amount {
						return nil, fmt.Errorf("resource_sum_overflow")
					}
					total += amount
				}
				maximum[boundary][dimension] = max(maximum[boundary][dimension], total)
			}
		}
	}
	result := resourceTotals{}
	for boundary, vector := range maximum {
		result[boundary] = map[string]string{}
		for dimension, value := range vector {
			result[boundary][dimension] = strconv.FormatUint(value, 10)
		}
	}
	return result, nil
}

func TestV4ResourceComposition(t *testing.T) {
	r := newResourceReference(t)
	raw, err := os.ReadFile("../../../testdata/transport_v4/resources.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID       string
			Input    any
			Expected resourceTotals `json:"expected_ready_min"`
			Error    string         `json:"expected_error"`
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			original, _ := json.Marshal(vector.Input)
			result, err := r.minimum(vector.Input)
			if vector.Error != "" {
				if err == nil || err.Error() != vector.Error {
					t.Fatalf("wanted %s, got %v", vector.Error, err)
				}
			} else if err != nil || !reflect.DeepEqual(result, vector.Expected) {
				t.Fatalf("result %#v, error %v, wanted %#v", result, err, vector.Expected)
			}
			after, _ := json.Marshal(vector.Input)
			if string(original) != string(after) {
				t.Fatal("input mutated")
			}
		})
	}
	if len(corpus.Vectors) != 19 {
		t.Fatal("missing resource vectors")
	}
}

func resourceBasic(t testing.TB) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/transport_v4/resources.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID    string
			Input map[string]any
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		if vector.ID == "resources_empty_features" {
			return vector.Input
		}
	}
	t.Fatal("missing basic resource vector")
	return nil
}

func TestV4ResourceIdentity(t *testing.T) {
	r := newResourceReference(t)
	for _, field := range append(slices.Clone(r.spec.Keys), r.spec.Bindings...) {
		input := resourceBasic(t)
		base := input["base"].(map[string]any)
		first := base["transport_core"].([]any)[0].(map[string]any)
		second := map[string]any{}
		for key, value := range first {
			second[key] = value
		}
		second[field] = "other"
		base["actual_shared_refs"] = []any{second}
		result, err := r.minimum(input)
		if slices.Contains(r.spec.Keys, field) {
			if err != nil || result["sdk_owned"]["bytes"] != "200" {
				t.Fatalf("key %s: %v, %v", field, result, err)
			}
		} else if err == nil || err.Error() != "resource_owner_conflict" {
			t.Fatalf("binding %s: %v", field, err)
		}
	}
	input := resourceBasic(t)
	base := input["base"].(map[string]any)
	first := base["transport_core"].([]any)[0].(map[string]any)
	second := map[string]any{}
	for key, value := range first {
		second[key] = value
	}
	first["environment_id"] = "é"
	second["environment_id"] = "e\u0301"
	base["actual_shared_refs"] = []any{second}
	result, err := r.minimum(input)
	if err != nil || result["sdk_owned"]["bytes"] != "200" {
		t.Fatalf("raw identity: %v, %v", result, err)
	}
}

func TestV4ResourceArithmetic(t *testing.T) {
	r := newResourceReference(t)
	for _, dimension := range r.spec.Dimensions {
		for _, bad := range []any{json.Number("1"), "01", "-1", "18446744073709551616", nil} {
			input := resourceBasic(t)
			first := input["base"].(map[string]any)["transport_core"].([]any)[0].(map[string]any)
			first["vector"].(map[string]any)[dimension] = bad
			if _, err := r.minimum(input); err == nil || err.Error() != "resource_quantity" {
				t.Fatalf("bad quantity: %v", err)
			}
		}
		input := resourceBasic(t)
		base := input["base"].(map[string]any)
		first := base["transport_core"].([]any)[0].(map[string]any)
		second := resourceBasic(t)["base"].(map[string]any)["transport_core"].([]any)[0].(map[string]any)
		second["owner_instance_id"] = "other"
		second["vector"].(map[string]any)[dimension] = "1"
		first["vector"].(map[string]any)[dimension] = "18446744073709551615"
		base["actual_shared_refs"] = []any{second}
		if _, err := r.minimum(input); err == nil || err.Error() != "resource_sum_overflow" {
			t.Fatalf("sum overflow: %v", err)
		}
	}
}

package protocolv4

// Independent test-only partial resource costs from generated coefficients.
// Results neither reserve resources nor establish a complete admission vector.
import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func resourceCostReference(input any) (map[string]any, error) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(ResourceFormulaRegistryJSON), &spec); err != nil {
		return nil, err
	}
	fields := []string{"max_frame_bytes", "small_auth_slots", "application_profile", "rpc_max_general_outstanding"}
	c, err := resourceObject(input, fields, fields[:3])
	if err != nil {
		return nil, err
	}
	decl := func(m map[string]any, key string) uint64 { return uint64(m[key].(float64)) }
	integer := func(value any, min, max uint64, code string) (uint64, error) {
		n, ok := value.(json.Number)
		v, err := strconv.ParseUint(string(n), 10, 64)
		if !ok || err != nil || v < min || v > max {
			return 0, fmt.Errorf("%s", code)
		}
		return v, nil
	}
	codec, bitmap, app := spec["codec"].(map[string]any), spec["bitmap"].(map[string]any), spec["application"].(map[string]any)
	m, err := integer(c["max_frame_bytes"], 1, decl(spec, "max_frame_bytes"), "resource_frame_limit")
	if err != nil {
		return nil, err
	}
	n, err := integer(c["small_auth_slots"], 0, decl(codec, "small_slots_max"), "resource_auth_slots")
	if err != nil {
		return nil, err
	}
	name, ok := c["application_profile"].(string)
	profile, exists := app["profiles"].(map[string]any)[name].(map[string]any)
	if !ok || !exists {
		return nil, fmt.Errorf("resource_application_profile")
	}
	rpc, notify, management := decl(profile, "rpc_channels"), decl(profile, "notify_channels"), decl(profile, "management_channels")
	_, present := c["rpc_max_general_outstanding"]
	if present != (rpc > 0) {
		return nil, fmt.Errorf("resource_rpc_limit_presence")
	}
	var k uint64
	if rpc > 0 {
		limit := spec["rpc_general_limit"].(map[string]any)
		k, err = integer(c["rpc_max_general_outstanding"], decl(limit, "min"), decl(limit, "max"), "resource_rpc_limit")
		if err != nil {
			return nil, err
		}
	}
	var arithmeticErr error
	mul := func(values ...uint64) uint64 {
		v := uint64(1)
		for _, x := range values {
			if x != 0 && v > math.MaxUint64/x {
				arithmeticErr = fmt.Errorf("resource_cost_overflow")
				return 0
			}
			v *= x
		}
		return v
	}
	add := func(values ...uint64) uint64 {
		var v uint64
		for _, x := range values {
			if v > math.MaxUint64-x {
				arithmeticErr = fmt.Errorf("resource_cost_overflow")
				return 0
			}
			v += x
		}
		return v
	}
	full := mul(decl(codec, "full_body_slots"), decl(codec, "buffers_per_slot"), m)
	small := mul(n, decl(codec, "buffers_per_slot"), min(m, decl(codec, "small_body_ceiling_bytes")))
	bitmapBytes := mul(decl(spec, "common_scope_ordinals"), decl(bitmap, "roles"), decl(bitmap, "bits_per_scope")) / decl(bitmap, "bits_per_byte")
	var reply, assoc, query uint64
	if rpc > 0 {
		reply = add(k, decl(app, "query_slots"))
		assoc = mul(k, decl(app, "fragment_associations_per_general"))
		query = decl(app, "query_reserve_bytes")
	}
	internal := add(rpc, notify)
	promise := mul(add(internal, management), decl(app, "channel_direction_bytes"))
	amounts := map[string]uint64{"reply_slots": mul(reply, decl(app, "reply_slot_bytes")), "fragment_associations": mul(assoc, decl(app, "fragment_association_bytes")),
		"query_reserve": query, "rpc_error_output": mul(rpc, decl(app, "rpc_error_output_bytes_per_channel")), "internal_receive": promise, "internal_send": promise}
	bytes := map[string]string{}
	var total uint64
	str := func(n uint64) string { return strconv.FormatUint(n, 10) }
	for key, value := range amounts {
		total = add(total, value)
		bytes[key] = str(value)
	}
	bytes["total"] = str(total)
	result := map[string]any{
		"codec_body_bytes":       map[string]string{"full_slots": str(full), "small_slots": str(small), "total": str(add(full, small))},
		"permanent_bitmap_bytes": str(bitmapBytes),
		"application_counts":     map[string]uint64{"internal_active": internal, "management_active": management, "reply_slots": reply, "fragment_associations": assoc},
		"application_bytes":      bytes,
	}
	if arithmeticErr != nil {
		return nil, arithmeticErr
	}
	return result, nil
}

func TestV4ResourceCosts(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/transport_v4/resource_costs.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID       string
			Input    any
			Expected any
			Error    string `json:"expected_error"`
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 18 {
		t.Fatal("incomplete cost corpus")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			before, _ := json.Marshal(v.Input)
			actual, err := resourceCostReference(v.Input)
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatalf("want %s, got %v", v.Error, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				got, _ := json.Marshal(actual)
				want, _ := json.Marshal(v.Expected)
				if string(got) != string(want) {
					t.Fatalf("got %s; want %s", got, want)
				}
			}
			after, _ := json.Marshal(v.Input)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("input mutated")
			}
		})
	}
	for _, bad := range []any{true, "1", json.Number("0.5"), json.Number("-1"), json.Number("4294967296"), nil} {
		_, err := resourceCostReference(map[string]any{"max_frame_bytes": json.Number("131072"), "small_auth_slots": bad, "application_profile": "transport"})
		if err == nil || err.Error() != "resource_auth_slots" {
			t.Fatalf("bad slots %v: %v", bad, err)
		}
	}
}

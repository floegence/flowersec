package protocolv4

// Independent test-only charges. Actual eligibility and atomic usage are separate.
import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"
)

type usageSpec struct {
	Maximum    string                     `json:"quantity_max"`
	Block      uint64                     `json:"authentication_block_bytes"`
	Length     uint64                     `json:"length_blocks"`
	Fields     []string                   `json:"charge_fields"`
	Operations []string                   `json:"operations"`
	Profiles   map[string]json.RawMessage `json:"profiles"`
}

func usageCharge(t testing.TB, profile string, input any) (map[string]string, error) {
	t.Helper()
	var spec usageSpec
	var profiles map[string]struct {
		Tag uint64 `json:"tag_bytes"`
	}
	if err := json.Unmarshal([]byte(CryptoUsageRegistryJSON), &spec); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(CryptoProfilesJSON), &profiles); err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Profiles[profile]; !ok {
		return nil, fmt.Errorf("crypto_usage_profile")
	}
	object, ok := input.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("crypto_usage_input")
	}
	if len(object) != len(spec.Fields) {
		return nil, fmt.Errorf("crypto_usage_fields")
	}
	for key := range object {
		if !slices.Contains(spec.Fields, key) {
			return nil, fmt.Errorf("crypto_usage_fields")
		}
	}
	operation, ok := object["operation"].(string)
	if !ok || !slices.Contains(spec.Operations, operation) {
		return nil, fmt.Errorf("crypto_usage_operation")
	}
	maximum, err := strconv.ParseUint(spec.Maximum, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	integer := func(input any) (uint64, error) {
		text, ok := input.(string)
		if !ok || len(text) == 0 || len(text) > len(spec.Maximum) || len(text) > 1 && text[0] == '0' {
			return 0, fmt.Errorf("crypto_usage_integer")
		}
		for _, c := range text {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("crypto_usage_integer")
			}
		}
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value > maximum {
			return 0, fmt.Errorf("crypto_usage_integer")
		}
		return value, nil
	}
	aad, err := integer(object["aad_bytes"])
	if err != nil {
		return nil, err
	}
	bytes, err := integer(object["input_bytes"])
	if err != nil {
		return nil, err
	}
	tag := profiles[profile].Tag
	payload, ciphertext := bytes, bytes
	if operation == "seal" {
		if tag > maximum-bytes {
			return nil, fmt.Errorf("crypto_usage_overflow")
		}
		ciphertext += tag
	} else {
		if bytes < tag {
			return nil, fmt.Errorf("crypto_usage_ciphertext")
		}
		payload -= tag
	}
	blocks := func(n uint64) uint64 {
		result := n / spec.Block
		if n%spec.Block != 0 {
			result++
		}
		return result
	}
	a, b := blocks(aad), blocks(payload)
	if b > maximum-a || spec.Length > maximum-a-b {
		return nil, fmt.Errorf("crypto_usage_overflow")
	}
	return map[string]string{"calls": "1", "authentication_blocks": strconv.FormatUint(a+b+spec.Length, 10), "ciphertext_bytes": strconv.FormatUint(ciphertext, 10)}, nil
}
func TestV4CryptoUsageCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/transport_v4/crypto_usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID       string            `json:"id"`
			Profile  string            `json:"profile"`
			Input    map[string]any    `json:"input"`
			Expected map[string]string `json:"expected"`
			Error    string            `json:"expected_error"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) != 28 {
		t.Fatal("incomplete corpus")
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			before, _ := json.Marshal(v.Input)
			result, err := usageCharge(t, v.Profile, v.Input)
			if v.Error != "" {
				if err == nil || err.Error() != v.Error {
					t.Fatalf("got %v want %s", err, v.Error)
				}
			} else if err != nil || !reflect.DeepEqual(result, v.Expected) {
				t.Fatalf("got %v %v want %v", result, err, v.Expected)
			}
			after, _ := json.Marshal(v.Input)
			if string(before) != string(after) {
				t.Fatal("input changed")
			}
		})
	}
}
func TestV4CryptoUsageBlocksAndTypes(t *testing.T) {
	var spec usageSpec
	if err := json.Unmarshal([]byte(CryptoUsageRegistryJSON), &spec); err != nil {
		t.Fatal(err)
	}
	for profile := range spec.Profiles {
		for aad := 0; aad <= 33; aad++ {
			for payload := 0; payload <= 33; payload++ {
				seal, err := usageCharge(t, profile, map[string]any{"operation": "seal", "aad_bytes": strconv.Itoa(aad), "input_bytes": strconv.Itoa(payload)})
				if err != nil {
					t.Fatal(err)
				}
				open, err := usageCharge(t, profile, map[string]any{"operation": "open", "aad_bytes": strconv.Itoa(aad), "input_bytes": strconv.Itoa(payload + 16)})
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(seal, open) || seal["authentication_blocks"] != strconv.Itoa((aad+15)/16+(payload+15)/16+1) {
					t.Fatal("wrong charge")
				}
			}
		}
		for _, bad := range []any{1, true, nil, "", "01", "-1", "+1", "1.0", "1\n", "١", "18446744073709551616"} {
			_, err := usageCharge(t, profile, map[string]any{"operation": "seal", "aad_bytes": bad, "input_bytes": "0"})
			if err == nil || err.Error() != "crypto_usage_integer" {
				t.Fatal("accepted invalid integer", bad, err)
			}
		}
	}
}
